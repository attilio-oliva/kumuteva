//! Construction of the throwaway pods the isolation probes run.
//!
//! ## Why these are built from typed structs rather than `json!`
//!
//! k8s-openapi's deserialiser silently discards keys it does not recognise:
//! `_ => Field::Other`, then `Field::Other => { let _: IgnoredAny = ... }`. A
//! `json!` literal containing `"hostPid": true` — the wrong capitalisation —
//! therefore produces a `PodSpec` with `host_pid: None`. No error, no panic,
//! nothing in the log.
//!
//! The consequence is not a crash but a wrong answer, in the reassuring
//! direction. A probe that fails to request hostPID sees none of the other
//! tenant's processes, finds no breach, and the run reports Hard isolation. It
//! is indistinguishable downstream from a cluster that is genuinely isolated.
//!
//! Building from `k8s_openapi` structs turns that class of mistake into a
//! compile error. The builder exists only to keep them readable: the probes
//! differ along a handful of axes and agree on everything else, so the
//! defaults carry the agreement and each probe states just its own difference.
//!
//! ## Reading a probe
//!
//! The interesting line should be the first one:
//!
//! ```ignore
//! ProbePod::new(name).requests(HostAccess::Pid).build()
//! ```
//!
//! against the twenty-eight lines of JSON that used to say the same thing with
//! `"hostPID": true` buried in the middle.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, HostPathVolumeSource, Pod, PodSecurityContext, PodSpec,
    ResourceRequirements, SeccompProfile, SecurityContext, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::ObjectMeta;

/// Default probe image. Small, and carries a shell.
const DEFAULT_IMAGE: &str = "alpine:latest";

/// What most probes run: exist briefly, then exit.
const DEFAULT_COMMAND: [&str; 2] = ["sleep", "1"];

/// The resource footprint nearly every probe declared by hand.
const REQUEST_CPU: &str = "250m";
const REQUEST_MEMORY: &str = "64Mi";
const LIMIT_CPU: &str = "500m";
const LIMIT_MEMORY: &str = "128Mi";

/// A host facility a probe deliberately asks for.
///
/// The request *is* the experiment. A probe that asks for the host PID
/// namespace and is refused has demonstrated isolation; one that asks and
/// succeeds has demonstrated a breach. Either is a result — which is why these
/// pods must not be made to satisfy a restrictive Pod Security Standard, and
/// why their refusal is recorded rather than treated as an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAccess {
    /// See every process on the node.
    Pid,
    /// Reach the node's System V IPC objects.
    Ipc,
    /// Use the node's network stack directly.
    Network,
    /// Share the host user namespace, so UIDs are not remapped.
    Users,
    /// Full privilege: all capabilities, no seccomp, device access.
    Privileged,
    /// Mount a path from the node's filesystem at the given container path.
    HostPath { host: String, mount: String },
}

/// How a probe presents itself to admission control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posture {
    /// Compliant with the `restricted` Pod Security Standard.
    ///
    /// For probes that need no privilege — measuring reachability, or serving
    /// a marker. Without this a tenant enforcing `restricted` refuses the pod,
    /// and the question goes unmeasured rather than being answered. That is the
    /// difference between a result and a gap on solutions such as
    /// `capsule-hardened`.
    ///
    /// Implies an unprivileged port: `runAsNonRoot` cannot bind below 1024.
    Restricted,
    /// Asks for exactly these host facilities and nothing else.
    Requests(Vec<HostAccess>),
    /// Neither hardened nor privileged — whatever the cluster's default admits.
    ///
    /// For probes whose subject is something other than the pod's own
    /// privilege, where imposing `restricted` would add a second variable.
    Plain,
}

/// One entry in a probe's port list.
#[derive(Debug, Clone, Copy)]
struct PortSpec {
    container_port: i32,
    host_port: Option<i32>,
    protocol: Option<&'static str>,
}

/// A throwaway pod that attempts one thing and is observed.
#[derive(Debug, Clone)]
pub struct ProbePod {
    name: String,
    container_name: String,
    image: String,
    command: Vec<String>,
    args: Option<Vec<String>>,
    labels: BTreeMap<String, String>,
    ports: Vec<PortSpec>,
    node_name: Option<String>,
    run_as_user: Option<i64>,
    /// `Some("Never")` for a probe that makes its attempt once — the default.
    /// `None` leaves the field unset, so Kubernetes applies its own `Always`,
    /// which suits a probe acting as a long-lived server the test connects to.
    restart_policy: Option<String>,
    posture: Posture,
}

impl ProbePod {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            container_name: "probe".to_string(),
            image: DEFAULT_IMAGE.to_string(),
            command: DEFAULT_COMMAND.iter().map(|s| s.to_string()).collect(),
            args: None,
            labels: BTreeMap::new(),
            ports: Vec::new(),
            node_name: None,
            run_as_user: None,
            restart_policy: Some("Never".to_string()),
            posture: Posture::Plain,
        }
    }

    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    /// Override the container name.
    ///
    /// Cosmetic to Kubernetes here — every probe has exactly one container and
    /// nothing selects one by name — but some probe scripts filter their own
    /// process out of `ps` output by matching a literal that happens to be the
    /// container name. Keeping the original name means such a script cannot
    /// start matching itself, or stop matching, as a side effect of tidying.
    pub fn container(mut self, name: impl Into<String>) -> Self {
        self.container_name = name.into();
        self
    }

    /// Run this through `sh -c`, the form most probe scripts take.
    ///
    /// The script goes in `command`, not `args`. Functionally the same to
    /// Kubernetes, but it matches the manifests these probes replaced, and
    /// callers reach for `command[2]` to inspect the script — which silently
    /// becomes an out-of-bounds panic if the script moves to `args`.
    ///
    /// `sh` rather than `/bin/sh` for the same reason. The absolute path would
    /// be marginally better, being independent of `PATH`, but changing it here
    /// would make the builder conversion something other than a no-op — and the
    /// value of this refactor rests on it being provably one. Worth doing
    /// deliberately and separately, if at all.
    pub fn shell(mut self, script: impl Into<String>) -> Self {
        self.command = vec!["sh".to_string(), "-c".to_string(), script.into()];
        self.args = None;
        self
    }

    pub fn command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = command.into_iter().map(Into::into).collect();
        self.args = None;
        self
    }

    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Expose a container port, leaving the protocol unset.
    ///
    /// Kubernetes defaults it to TCP on admission, so omitting it and stating
    /// it produce the same stored object. Omitted here to match the manifests
    /// being replaced.
    pub fn port(mut self, container_port: i32) -> Self {
        self.ports.push(PortSpec {
            container_port,
            host_port: None,
            protocol: None,
        });
        self
    }

    /// Expose a container port, stating TCP explicitly.
    pub fn port_tcp(mut self, container_port: i32) -> Self {
        self.ports.push(PortSpec {
            container_port,
            host_port: None,
            protocol: Some("TCP"),
        });
        self
    }

    /// A container port also published on the node.
    pub fn host_port(mut self, port: i32) -> Self {
        self.ports.push(PortSpec {
            container_port: port,
            host_port: Some(port),
            protocol: Some("TCP"),
        });
        self
    }

    /// Pin to a node.
    ///
    /// Required whenever a probe must observe something another pod is doing:
    /// host namespaces are per-node, so a spy scheduled elsewhere looks at an
    /// unrelated machine, finds nothing, and reports isolation it never tested.
    pub fn on_node(mut self, node: impl Into<String>) -> Self {
        self.node_name = Some(node.into());
        self
    }

    /// Ask for one host facility. Repeatable.
    pub fn requests(mut self, access: HostAccess) -> Self {
        match &mut self.posture {
            Posture::Requests(existing) => existing.push(access),
            _ => self.posture = Posture::Requests(vec![access]),
        }
        self
    }

    /// Leave `restartPolicy` unset, so the cluster's default (`Always`) applies.
    ///
    /// For a probe that serves traffic for the duration of a test rather than
    /// running once: if its server exits it should be brought back, where a
    /// one-shot probe should not.
    pub fn restart_on_failure_default(mut self) -> Self {
        self.restart_policy = None;
        self
    }

    /// Run the container as a specific UID.
    ///
    /// Used by the user-namespace probe, which must be UID 0 for its reading of
    /// `/proc/self/uid_map` to mean anything: the question is whether root in
    /// the container is root on the host, and asking it as an ordinary user
    /// answers something else.
    pub fn run_as_user(mut self, uid: i64) -> Self {
        self.run_as_user = Some(uid);
        self
    }

    /// Comply with the `restricted` Pod Security Standard.
    pub fn restricted(mut self) -> Self {
        self.posture = Posture::Restricted;
        self
    }

    pub fn build(self) -> Pod {
        let restricted = self.posture == Posture::Restricted;
        let requested: &[HostAccess] = match &self.posture {
            Posture::Requests(list) => list,
            _ => &[],
        };
        let asks_for = |want: &HostAccess| requested.contains(want);

        let host_path = requested.iter().find_map(|access| match access {
            HostAccess::HostPath { host, mount } => Some((host.clone(), mount.clone())),
            _ => None,
        });

        let container = Container {
            name: self.container_name,
            image: Some(self.image),
            command: Some(self.command),
            args: self.args,
            ports: (!self.ports.is_empty()).then(|| {
                self.ports
                    .iter()
                    .map(|port| ContainerPort {
                        container_port: port.container_port,
                        host_port: port.host_port,
                        protocol: port.protocol.map(str::to_string),
                        ..Default::default()
                    })
                    .collect()
            }),
            // Always declared. A tenant with a compute ResourceQuota makes
            // limits mandatory, and a pod without them is turned away by quota
            // admission before the policy under test is ever reached — so an
            // unresourced probe reports on the quota, not on the thing it
            // claims to measure.
            resources: Some(ResourceRequirements {
                requests: Some(quantities(REQUEST_CPU, REQUEST_MEMORY)),
                limits: Some(quantities(LIMIT_CPU, LIMIT_MEMORY)),
                ..Default::default()
            }),
            volume_mounts: host_path.as_ref().map(|(_, mount)| {
                vec![VolumeMount {
                    name: "hostpath".to_string(),
                    mount_path: mount.clone(),
                    ..Default::default()
                }]
            }),
            // Omitted entirely when the probe asks for nothing, rather than
            // sent as an empty object. Equivalent to the API server, but it
            // keeps a plain probe's manifest identical to the hand-written JSON
            // it replaced, so the conversion is provably a no-op.
            security_context: (restricted || asks_for(&HostAccess::Privileged)).then(|| {
                SecurityContext {
                    privileged: asks_for(&HostAccess::Privileged).then_some(true),
                    allow_privilege_escalation: restricted.then_some(false),
                    capabilities: restricted.then(|| Capabilities {
                        drop: Some(vec!["ALL".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }),
            ..Default::default()
        };

        Pod {
            metadata: ObjectMeta {
                name: Some(self.name),
                labels: (!self.labels.is_empty()).then_some(self.labels),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![container],
                // `Never`: a probe that has made its attempt has produced its
                // result. Restarting it would re-run the attempt and could
                // overwrite the evidence.
                restart_policy: self.restart_policy,
                node_name: self.node_name,
                host_pid: asks_for(&HostAccess::Pid).then_some(true),
                host_ipc: asks_for(&HostAccess::Ipc).then_some(true),
                host_network: asks_for(&HostAccess::Network).then_some(true),
                host_users: asks_for(&HostAccess::Users).then_some(true),
                volumes: host_path.map(|(host, _)| {
                    vec![Volume {
                        name: "hostpath".to_string(),
                        host_path: Some(HostPathVolumeSource {
                            path: host,
                            type_: Some("DirectoryOrCreate".to_string()),
                        }),
                        ..Default::default()
                    }]
                }),
                security_context: (restricted || self.run_as_user.is_some()).then(|| {
                    PodSecurityContext {
                        run_as_non_root: restricted.then_some(true),
                        // `restricted` needs *a* non-root UID; an explicit one
                        // wins, which is how the user-namespace probe asks for
                        // UID 0 without claiming to be hardened.
                        run_as_user: self.run_as_user.or(restricted.then_some(1000)),
                        seccomp_profile: restricted.then(|| SeccompProfile {
                            type_: "RuntimeDefault".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

fn quantities(cpu: &str, memory: &str) -> BTreeMap<String, Quantity> {
    BTreeMap::from([
        ("cpu".to_string(), Quantity(cpu.to_string())),
        ("memory".to_string(), Quantity(memory.to_string())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(pod: &Pod) -> &PodSpec {
        pod.spec.as_ref().expect("a probe always has a spec")
    }

    #[test]
    fn a_plain_probe_asks_for_nothing() {
        let pod = ProbePod::new("p").build();
        let s = spec(&pod);
        assert_eq!(s.host_pid, None);
        assert_eq!(s.host_ipc, None);
        assert_eq!(s.host_network, None);
        assert_eq!(s.host_users, None);
        assert_eq!(s.restart_policy.as_deref(), Some("Never"));
    }

    #[test]
    fn each_host_facility_reaches_the_field_that_grants_it() {
        // The whole point of the type: these four are one typo apart from
        // silently not being requested at all.
        assert_eq!(
            spec(&ProbePod::new("p").requests(HostAccess::Pid).build()).host_pid,
            Some(true)
        );
        assert_eq!(
            spec(&ProbePod::new("p").requests(HostAccess::Ipc).build()).host_ipc,
            Some(true)
        );
        assert_eq!(
            spec(&ProbePod::new("p").requests(HostAccess::Network).build()).host_network,
            Some(true)
        );
        assert_eq!(
            spec(&ProbePod::new("p").requests(HostAccess::Users).build()).host_users,
            Some(true)
        );
    }

    #[test]
    fn privilege_lands_on_the_container_not_the_pod() {
        let pod = ProbePod::new("p").requests(HostAccess::Privileged).build();
        let ctx = spec(&pod).containers[0]
            .security_context
            .as_ref()
            .expect("security context");
        assert_eq!(ctx.privileged, Some(true));
    }

    #[test]
    fn several_requests_compose() {
        let pod = ProbePod::new("p")
            .requests(HostAccess::Pid)
            .requests(HostAccess::Privileged)
            .on_node("node-1")
            .build();
        assert_eq!(spec(&pod).host_pid, Some(true));
        assert_eq!(spec(&pod).node_name.as_deref(), Some("node-1"));
        assert_eq!(
            spec(&pod).containers[0]
                .security_context
                .as_ref()
                .unwrap()
                .privileged,
            Some(true)
        );
    }

    #[test]
    fn restricted_satisfies_every_clause_of_the_standard() {
        // All four are required together; a pod missing any one is refused, and
        // the refusal costs a measurement rather than producing one.
        let pod = ProbePod::new("p").restricted().build();
        let pod_ctx = spec(&pod).security_context.as_ref().expect("pod context");
        assert_eq!(pod_ctx.run_as_non_root, Some(true));
        assert_eq!(
            pod_ctx.seccomp_profile.as_ref().map(|p| p.type_.as_str()),
            Some("RuntimeDefault")
        );

        let ctx = spec(&pod).containers[0]
            .security_context
            .as_ref()
            .expect("container context");
        assert_eq!(ctx.allow_privilege_escalation, Some(false));
        assert_eq!(
            ctx.capabilities.as_ref().unwrap().drop,
            Some(vec!["ALL".to_string()])
        );
        assert_eq!(ctx.privileged, None);
    }

    #[test]
    fn a_hostpath_request_creates_both_the_volume_and_its_mount() {
        // Declaring one without the other yields a pod that is admitted and
        // reads nothing — an inconclusive probe that looks like a clean pass.
        let pod = ProbePod::new("p")
            .requests(HostAccess::HostPath {
                host: "/host".to_string(),
                mount: "/mnt/host".to_string(),
            })
            .build();

        let volume = &spec(&pod).volumes.as_ref().expect("volume")[0];
        assert_eq!(volume.host_path.as_ref().unwrap().path, "/host");

        let mount = &spec(&pod).containers[0]
            .volume_mounts
            .as_ref()
            .expect("mount")[0];
        assert_eq!(mount.mount_path, "/mnt/host");
        assert_eq!(mount.name, volume.name);
    }

    #[test]
    fn a_host_port_is_published_as_well_as_exposed() {
        let pod = ProbePod::new("p").host_port(31337).build();
        let port = &spec(&pod).containers[0].ports.as_ref().expect("ports")[0];
        assert_eq!(port.container_port, 31337);
        assert_eq!(port.host_port, Some(31337));
    }
}
