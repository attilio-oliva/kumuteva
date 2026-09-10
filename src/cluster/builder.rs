use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Duration};

use anyhow::{anyhow, Context, Ok};
use k8s_openapi::api::{core::v1::Secret, networking::v1::NetworkPolicy};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::{api::ObjectMeta, runtime::reflector::Lookup};
use tokio::time::sleep;

use crate::{
    cluster::HostClusterType,
    external_crds::{capsule, create_tenant},
};

use super::KubernetesClient;

use serde_json::json;

#[derive(Debug, Clone)]
pub enum IsolationTechnology {
    ControlPlane(ControlPlaneIsolation),
    DataPlane(DataPlaneIsolation),
}

/// The Capsule chart version the operator and its proxy are both pinned to.
///
/// 0.10.0 is the version the submitted measurements were taken on, so this is
/// the pin that reproduces them. Capsule's behaviour differs enough between
/// 0.10.0 and 0.13.x that the version belongs beside any number derived from
/// it — see [`KubernetesClusterBuilder::capsule_chart_source`] for what moves.
///
/// Overridable per component, so comparing versions needs no edit here.
const CAPSULE_CHART_VERSION: &str = "0.10.0";

/// Kube-OVN's join subnet, which carries pod-to-node traffic.
///
/// A private tenant subnet has to allow it or the tenant's pods lose their
/// route to the node, and with it kubelet's health checks.
const KUBE_OVN_JOIN_CIDR: &str = "100.64.0.0/16";

/// How much policy the Capsule Tenant carries.
///
/// Capsule enforces almost nothing on its own. Its Tenant CR is a container for
/// policy, and every field is optional; what a tenant may do is decided by
/// which of those fields are filled in, not by installing Capsule. Notably
/// Capsule does not implement pod security itself — it *propagates* Pod
/// Security Admission labels onto tenant namespaces when told to.
///
/// The distinction is worth provisioning both ways because it is the single
/// biggest confounder in comparing this tool against kubectl-mtb. A tenant with
/// only an owner set fails 12 of the 19 benchmarks; the same Capsule, same
/// version, with the policy fields populated, passes them. The score describes
/// the Tenant CR, not Capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleTenantPolicy {
    /// Owner only, every policy field left at its default. What a user gets by
    /// installing Capsule and declaring a tenant, and the configuration the
    /// original measurements were taken under.
    Default,
    /// The policy fields the benchmarks actually look for, filled in.
    Hardened,
}

#[derive(Debug, Clone)]
pub enum ControlPlaneIsolation {
    /// Do not isolate the control plane, just create a new namespace
    None(String),
    /// Capsule with a tenant confined in the given namespace
    Capsule(String),
    /// The same Capsule, with the Tenant's policy fields populated.
    CapsuleHardened(String),
    CapsuleProxy(String),
    /// vCluster virtual control plane in the given namespace
    VCluster(String),
    KubeVirt(String),
    /// Kamaji tenant control plane in the given namespace
    Kamaji(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum DataPlaneIsolation {
    Network(NetworkIsolationStrategy),
    Storage(StorageIsolationStrategy),
    Workload(WorkloadIsolation),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum NetworkIsolationStrategy {
    NetworkPolicy(String),
    /// A private Kube-OVN Subnet of the given tenant's own, under the *default*
    /// VPC.
    ///
    /// Both tenants still share one logical router, so a route between them
    /// exists and the isolation is an ACL on that router — measured, this drops
    /// packets silently and is indistinguishable from a NetworkPolicy, which is
    /// to say it can only ever score Soft. Kept as the contrast for the VPC row
    /// rather than as a serious isolation claim.
    KubeOvnPrivateSubnet(String),
    /// A Kube-OVN VPC of the tenant's own, with a Subnet inside it.
    ///
    /// One VPC is one logical router. Two tenants in two VPCs have no route
    /// between them at all — not a rule that drops packets, but an absence of
    /// any path for them to take. That is the difference the subnet variant
    /// cannot express, and the only configuration here that can earn Hard.
    KubeOvnTenantVpc(String),
    /// A DNS server of the tenant's own that answers only for that tenant's
    /// namespace.
    ///
    /// Generic on purpose: ordinary pods and an ordinary Service, so it layers
    /// onto any CNI and any control-plane solution rather than belonging to one.
    ScopedTenantDns(String),
}

/// The Kata configuration the shim is pointed at.
///
/// Named explicitly because the Rust build ships no Go-runtime config, so the
/// tree's own `configuration.toml` symlink dangles and picking "the default"
/// finds nothing.
const KATA_CONFIG: &str =
    "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml";

/// A container runtime that sandboxes the workload, installed alongside runc.
///
/// Not a replacement: the handler is registered as an additional containerd
/// runtime and pods opt in through a `RuntimeClass`. That is how a tenant would
/// use one, and it is also why a sandbox verdict has to be checked rather than
/// assumed — a pod that silently fell back to runc reports the same isolation
/// the sandbox would have, only without the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxRuntime {
    /// gVisor: a user-space kernel. Syscalls are serviced by `runsc` rather
    /// than by the host kernel, which is what the privileged-syscall and
    /// host-namespace properties are asking about.
    GVisor,
    /// Kata Containers: each pod in its own lightweight virtual machine, with
    /// a real guest kernel behind a hardware boundary.
    ///
    /// The interesting contrast with gVisor is not that the boundary is
    /// stronger but that it is less restrictive: gVisor refuses to start a
    /// privileged container at all, whereas Kata runs one *inside the guest*,
    /// where privilege buys the tenant its own VM and nothing of the node. A
    /// property gVisor can only forbid, Kata can permit and still isolate.
    Kata,
}

impl SandboxRuntime {
    /// Pinned, because a sandbox version is part of what produced a number.
    const GVISOR_RELEASE: &'static str = "20260817";
    /// Kata 4.x, whose runtime is the Rust rewrite (`runtime-rs`) rather than
    /// the original Go one. Chosen over the settled 3.x line deliberately: the
    /// lighter runtime is what the fairness campaign will later measure, and
    /// running isolation and fairness against different runtimes would make
    /// the two halves of the results incomparable.
    const KATA_RELEASE: &'static str = "4.1.0";

    pub fn name(&self) -> &'static str {
        match self {
            SandboxRuntime::GVisor => "gvisor",
            SandboxRuntime::Kata => "kata",
        }
    }

    /// The release this runtime is pinned to, for the log line that records
    /// what a run actually installed.
    fn version(&self) -> &'static str {
        match self {
            SandboxRuntime::GVisor => Self::GVISOR_RELEASE,
            SandboxRuntime::Kata => Self::KATA_RELEASE,
        }
    }

    /// The containerd runtime handler pods select through their RuntimeClass.
    fn handler(&self) -> &'static str {
        match self {
            SandboxRuntime::GVisor => "runsc",
            SandboxRuntime::Kata => "kata",
        }
    }

    /// Host paths the node needs for this runtime to work.
    ///
    /// Kata boots a real VM, so the node container needs the host's KVM
    /// device. Without it the shim falls back to nothing usable and pods stay
    /// in `ContainerCreating` — which the sandbox control would catch, but
    /// only after a full cluster build.
    pub fn extra_mounts(&self) -> Vec<(String, String)> {
        match self {
            SandboxRuntime::GVisor => Vec::new(),
            SandboxRuntime::Kata => vec![("/dev/kvm".to_string(), "/dev/kvm".to_string())],
        }
    }

    /// Registers the handler in containerd's configuration.
    ///
    /// A cluster-level patch, applied when the node boots. A `RuntimeClass`
    /// naming a handler containerd does not know leaves pods in
    /// `ContainerCreating` rather than failing at admission, so this has to be
    /// in place before anything tries to use it.
    pub fn containerd_patch(&self) -> String {
        match self {
            SandboxRuntime::GVisor => concat!(
                "[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runsc]\n",
                "  runtime_type = \"io.containerd.runsc.v1\"\n"
            )
            .to_string(),
            // `runtime_path` because the Rust shim lives under /opt/kata
            // rather than on the node's PATH, and copying it out of its own
            // tree would separate it from the configuration and firmware it
            // resolves relative to nothing — every path in Kata's config is
            // absolute under /opt/kata.
            //
            // `privileged_without_host_devices` is the setting that makes the
            // privileged-syscall property meaningful here: without it a
            // privileged pod would be handed the node's devices straight
            // through the VM boundary, which is the boundary being measured.
            // With it, privilege is granted inside the guest and stops there.
            //
            // `ConfigPath` is not optional decoration. The shim does *not*
            // read /etc/kata-containers/configuration.toml here — proven by
            // putting invalid TOML there and watching the failure not change —
            // so without this it silently runs on built-in defaults and every
            // setting below is inert.
            SandboxRuntime::Kata => format!(
                "[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.kata]\n\
                 \x20 runtime_type = \"io.containerd.kata.v2\"\n\
                 \x20 runtime_path = \"/opt/kata/runtime-rs/bin/containerd-shim-kata-v2\"\n\
                 \x20 privileged_without_host_devices = true\n\
                 [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.kata.options]\n\
                 \x20 ConfigPath = \"{KATA_CONFIG}\"\n"
            ),
        }
    }

    /// What has to reach the node, and in what shape.
    fn payload(&self) -> SandboxPayload {
        match self {
            SandboxRuntime::GVisor => SandboxPayload::Binaries(
                ["runsc", "containerd-shim-runsc-v1"]
                    .into_iter()
                    .map(|name| {
                        (
                            name,
                            format!(
                            "https://storage.googleapis.com/gvisor/releases/release/{}/x86_64/{name}",
                            Self::GVISOR_RELEASE
                        ),
                        )
                    })
                    .collect(),
            ),
            SandboxRuntime::Kata => SandboxPayload::Archive {
                archive: format!("kata-static-{}-amd64.tar.zst", Self::KATA_RELEASE),
                url: format!(
                    "https://github.com/kata-containers/kata-containers/releases/download/{}/kata-static-{}-amd64.tar.zst",
                    Self::KATA_RELEASE,
                    Self::KATA_RELEASE
                ),
                tree: "opt/kata",
                destination: "/opt",
            },
        }
    }

    /// Commands to run inside the node once the payload is in place.
    fn post_install(&self) -> Vec<Vec<&'static str>> {
        match self {
            SandboxRuntime::GVisor => Vec::new(),
            // Kata's Rust runtime creates its sandbox and overhead cgroups
            // through systemd, over dbus. A kind node runs systemd as PID 1
            // but ships no dbus, so the shim fails at
            // `add runtime to sandbox cgroup` with a bare ENOENT on
            // /run/dbus/system_bus_socket and no pod ever starts.
            //
            // Installing the bus rather than switching to cgroupfs, because
            // cgroupfs is not reachable from configuration: `runtime-rs` 4.1.0
            // exposes no cgroup-driver setting, and it still chose systemd
            // with kubelet on the cgroupfs driver and a cgroupfs-style path —
            // it selects the manager from the host being systemd-booted. The
            // alternatives were both worse: `sandbox_cgroup_only` and
            // `static_sandbox_resource_mgmt` only move which cgroup fails, and
            // they change resource accounting, which the fairness campaign
            // later measures.
            //
            // apt's own start is refused by policy-rc.d inside the node, hence
            // the explicit start afterwards.
            SandboxRuntime::Kata => vec![
                vec!["apt-get", "update", "-qq"],
                vec!["apt-get", "install", "-y", "-qq", "dbus"],
                vec!["systemctl", "start", "dbus.socket", "dbus.service"],
                // Each guest is backed by a `memory-backend-file` on /dev/shm
                // sized to the VM's memory — 2 GiB by default. A container's
                // /dev/shm is 64 MiB, so QEMU cannot allocate it, dies before
                // it opens its monitor socket, and the only symptom the shim
                // reports is `QMP not ready yet: qmp handshake failed`. The
                // pod then sits in ContainerCreating until the sandbox
                // deadline, which looks like a slow VM rather than a full
                // filesystem.
                //
                // Sized as a share of host RAM rather than a constant, because
                // the number of concurrent guests is set by whatever is being
                // run, not by this file. 8 GiB was chosen for the isolation
                // probes, which start one target and one intruder; the fairness
                // campaign escalates the workload subsystem to 5 pods x 10 =
                // 50 intruder VMs alongside 5 victim VMs, and died on the 17th
                // with `Pod tenant2/workload-fairness-16 was not Running after
                // 290s`. That reads as a scheduling problem and is not one —
                // the node had memory, /dev/shm did not.
                //
                // 50% is what a host gives /dev/shm by default, so this is the
                // container inheriting the convention it was cut off from
                // rather than a figure tuned to one campaign. tmpfs occupies
                // only what is written, so the cap costs nothing until used.
                vec!["mount", "-o", "remount,size=50%", "/dev/shm"],
                // Copied as well as pointed at: the shim is given this path
                // through containerd's `ConfigPath`, but tools run by hand on
                // the node look in /etc, and having the two disagree is how a
                // diagnosis goes wrong.
                // Keep the VMM out of the pod's own cgroup.
                //
                // With `sandbox_cgroup_only = true` every Kata process, QEMU
                // included, is placed in the sandbox cgroup — which carries
                // the pod's memory limit. Every probe here declares
                // `limits.memory = 128Mi`, and a QEMU backing a 2 GiB guest is
                // killed the instant it touches that memory. The guest dies
                // before its agent registers, and the only thing the shim
                // reports is `ENODEV` connecting to the guest's vsock CID,
                // which reads as a missing device rather than an OOM kill.
                //
                // Setting it false moves the VMM into a separate overhead
                // cgroup, which is the honest accounting anyway: the VM is the
                // sandbox's cost, not the tenant's container memory. Worth
                // remembering when the fairness campaign measures Kata — the
                // guest's overhead is deliberately not charged to the pod's
                // limit here.
                vec![
                    "sed",
                    "-i",
                    "s/^sandbox_cgroup_only = true/sandbox_cgroup_only = false/",
                    KATA_CONFIG,
                ],
                vec!["mkdir", "-p", "/etc/kata-containers"],
                vec!["cp", KATA_CONFIG, "/etc/kata-containers/configuration.toml"],
            ],
        }
    }
}

/// The Retain-policy StorageClass belonging to one tenant.
///
/// Per tenant rather than shared, because a Retain volume outlives its claim:
/// the whole point of the property is what happens to the volume afterwards,
/// and two tenants provisioning through one class would be indistinguishable.
pub fn retain_storage_class_name(tenant_namespace: &str) -> String {
    format!("kumuteva-{tenant_namespace}-retain")
}

/// The Delete-policy StorageClass belonging to one tenant.
///
/// The counterpart of the Retain class, and the one the plain `Create And Mount
/// Volume` property provisions through. Without it that property declared no
/// class at all, fell through to whichever class the cluster marks default —
/// `standard`, shared by both tenants — and reported on a technology that was
/// never in its path.
pub fn delete_storage_class_name(tenant_namespace: &str) -> String {
    format!("kumuteva-{tenant_namespace}")
}

/// Admission rule confining a namespace to StorageClasses of its own.
///
/// Per-tenant classes alone isolate nothing. A StorageClass is cluster-scoped,
/// so any namespace may name any class, and the cross-tenant probe binds a
/// released PersistentVolume *by name* while quoting whatever class that volume
/// already carries — a path that never consults a class for provisioning at
/// all. Separating the classes without restricting who may cite them changes
/// the labels on the volumes and nothing else.
///
/// A `ValidatingAdmissionPolicy` is what makes the separation binding. It is
/// used in preference to a policy engine because Kubernetes has carried this
/// natively since 1.30 and the cluster here runs 1.33: no operator, no pinned
/// chart, and — since the same clusters are later measured for fairness — no
/// admission controller of our own consuming CPU on the node under test.
///
/// The rule is deliberately narrow. It constrains the *class a claim may name*,
/// nothing else: the tenant still creates, mounts, resizes and deletes volumes
/// freely within its own classes, so the operation stays available and the
/// property keeps its autonomy. What it removes is reaching a volume that
/// belongs to the other tenant.
///
/// Narrow enough took two attempts. Requiring a tenant class outright also
/// refused the claim a tenant makes against a `PersistentVolume` it built
/// itself, which names the volume directly and carries no class at all —
/// `Use HostPath through a PersistentVolume` went from a breach to an
/// unavailable operation, storage autonomy fell to 2/4, and the property
/// reported isolation it had not earned. So a classless claim bound to a named
/// volume is allowed through.
///
/// That is not a hole. Kubernetes binds a claim to a volume only when their
/// classes agree, so a classless claim can reach only a classless volume —
/// never one provisioned through the other tenant's class. What it can still
/// reach is a hostPath volume, and that is the finding the row already makes:
/// a path on the node names the same bytes whoever asks, and no storage
/// configuration can isolate it while still granting it.
///
/// Expect `Soft`, not `Hard`. The refusal is a 403 that names a policy, which
/// tells the intruder there was something there to be refused — exactly the
/// distinction `AccessResult::IntruderBlockedByPolicy` draws. Hard isolation
/// would require the cross-tenant read to return what a single tenant would
/// have seen, which admission cannot do and only encryption would.
fn tenant_storage_class_policy() -> String {
    // `request.namespace` rather than a namespace baked into the CEL, so one
    // policy object serves every tenant and each binding scopes it.
    r#"apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kumuteva-tenant-storage-classes
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["persistentvolumeclaims"]
  validations:
    - expression: >-
        (has(object.spec.storageClassName) &&
         object.spec.storageClassName.startsWith('kumuteva-' + request.namespace)) ||
        (has(object.spec.volumeName) && object.spec.volumeName != '' &&
         (!has(object.spec.storageClassName) || object.spec.storageClassName == ''))
      message: >-
        forbidden: a PersistentVolumeClaim in this namespace may only name a
        StorageClass belonging to it
"#
    .to_string()
}

/// Scope the policy above to one tenant namespace.
///
/// `kubernetes.io/metadata.name` is set by the API server on every namespace,
/// so this needs no label of ours and cannot be defeated by a tenant editing
/// its own namespace. Binding per tenant rather than cluster-wide keeps the
/// rule off `kube-system` and off the provisioner's own claims, which name
/// classes this policy would otherwise reject.
fn tenant_storage_class_policy_binding(tenant_namespace: &str) -> String {
    format!(
        r#"apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: kumuteva-tenant-storage-classes-{tenant_namespace}
spec:
  policyName: kumuteva-tenant-storage-classes
  validationActions: ["Deny"]
  matchResources:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: {tenant_namespace}
"#
    )
}

/// A StorageClass of this tenant's own, provisioned by whatever kind already
/// runs.
///
/// `rancher.io/local-path` deliberately: it is the provisioner the cluster
/// ships with, so this row adds a *configuration* rather than a storage
/// backend, and it needs no iSCSI. That last point is not a detail — an
/// iSCSI-backed CSI cannot work on a kind node at all, because the kernel
/// registers `NETLINK_ISCSI` in the initial network namespace only and a kind
/// node has its own. Measured directly: `sendmsg` to that socket returns
/// `ECONNREFUSED` from a container namespace and succeeds from the host's.
///
/// `WaitForFirstConsumer` because local-path provisions a directory on the
/// node that runs the pod, so it cannot choose one until the pod is scheduled.
fn tenant_storage_class(name: &str, reclaim_policy: &str) -> String {
    format!(
        "apiVersion: storage.k8s.io/v1\n\
         kind: StorageClass\n\
         metadata:\n\
         \x20 name: {name}\n\
         provisioner: rancher.io/local-path\n\
         reclaimPolicy: {reclaim_policy}\n\
         volumeBindingMode: WaitForFirstConsumer\n"
    )
}

/// Where downloaded artefacts are kept between runs.
///
/// `$XDG_CACHE_HOME` if set, otherwise `~/.cache`, otherwise the temporary
/// directory as a last resort.
fn dirs_cache_home() -> std::path::PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache"))
        })
        .unwrap_or_else(std::env::temp_dir)
}

/// Fetch a file once and keep it.
fn download_if_absent(local: &std::path::Path, url: &str, what: &str) -> anyhow::Result<()> {
    if local.exists() {
        return Ok(());
    }
    println!("  downloading {what}");
    let output = Command::new("curl")
        .arg("-fL")
        .arg("--retry")
        .arg("3")
        .arg("-o")
        .arg(local)
        .arg(url)
        .output()
        .with_context(|| format!("Failed to download {what}"))?;
    if !output.status.success() {
        // A partial file would be taken for a complete one next time.
        let _ = std::fs::remove_file(local);
        return Err(terminal_stderr_to_error(output));
    }
    Ok(())
}

/// How a runtime's files are published, which decides how they are installed.
enum SandboxPayload {
    /// Individual executables, dropped into the node's PATH.
    Binaries(Vec<(&'static str, String)>),
    /// One compressed tree, unpacked and copied in whole.
    ///
    /// Kata is not a binary but a distribution: a guest kernel, a root
    /// filesystem image, QEMU, virtiofsd and a shim, all referring to each
    /// other by absolute path. It has to arrive as a tree or not at all.
    Archive {
        url: String,
        /// Local filename for the download, so it can be cached between runs.
        archive: String,
        /// The directory inside the extracted archive to install.
        tree: &'static str,
        /// Where in the node that directory belongs.
        destination: &'static str,
    },
}

/// A CNI installed in place of the provider's default.
///
/// Host-scoped, unlike everything else here: there is one CNI per cluster, and
/// it is not something a tenant has. It also cannot be applied through
/// [`KubernetesClusterBuilder`], which runs once per tenant — installing it
/// twice would be at best wasted work and at worst two conflicting daemonsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CniPlugin {
    /// Calico, the reference NetworkPolicy implementation.
    ///
    /// The reason a policy row needs it at all: kind's default `kindnet` does
    /// not implement NetworkPolicy, by design. A deny-all policy on kindnet is
    /// accepted by the API server, stored, and enforced by nobody — so the
    /// measurement would report that NetworkPolicy does not work, when what it
    /// actually observed is that nothing was asked to enforce it.
    Calico,
    /// Kube-OVN, an OVN-backed CNI.
    ///
    /// Enforces NetworkPolicy like Calico, and additionally offers isolation
    /// the policy API cannot express: per-tenant Subnets under the default VPC,
    /// and separate logical routers through custom VPCs. Those are layered on
    /// top of this by the technologies that select it — installing the CNI
    /// alone changes no isolation property, which is exactly what makes it a
    /// useful baseline for the rows that do.
    KubeOvn,
}

impl CniPlugin {
    /// The CNI every cluster gets unless a technology names its own.
    ///
    /// Not a preference between equals. kind's own `kindnet` is unusable as a
    /// baseline here for two independent reasons: it ignores NetworkPolicy, so
    /// a policy row on it measures a policy nobody enforces; and it addresses
    /// pods `/24`, a netmask a KubeVirt guest inherits through its `bridge`
    /// binding — leaving two tenants' VMs on one node convinced they are
    /// on-link, ARPing for each other, and never answered, because kindnet
    /// routes pods rather than bridging them. Calico's `/32` has no on-link
    /// subnet to be wrong about.
    pub const DEFAULT: Self = Self::Calico;

    /// Pinned: a CNI version is part of what produced a number, and `latest`
    /// would make results irreproducible the moment upstream tags a release.
    const CALICO_VERSION: &'static str = "v3.30.0";
    const KUBE_OVN_VERSION: &'static str = "v1.16.2";

    fn version(&self) -> &'static str {
        match self {
            CniPlugin::Calico => Self::CALICO_VERSION,
            CniPlugin::KubeOvn => Self::KUBE_OVN_VERSION,
        }
    }

    /// The pod CIDR this CNI expects the cluster to have been created with.
    ///
    /// Calico's default IP pool is 192.168.0.0/16 while kind allocates node
    /// PodCIDRs from 10.244.0.0/16. Calico's own IPAM would paper over the
    /// mismatch, but leaving the two disagreeing is the kind of detail that
    /// produces an unexplainable network result three phases later.
    pub fn pod_subnet(&self) -> &'static str {
        match self {
            CniPlugin::Calico => "192.168.0.0/16",
            // Kube-OVN's own default. Left as upstream ships it so the CIDR is
            // one less thing differing from a stock deployment.
            CniPlugin::KubeOvn => "10.16.0.0/16",
        }
    }

    fn name(&self) -> &'static str {
        match self {
            CniPlugin::Calico => "calico",
            CniPlugin::KubeOvn => "kube-ovn",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum StorageIsolationStrategy {
    /// Give this tenant a StorageClass of its own, with `reclaimPolicy:
    /// Retain`.
    ///
    /// Isolates nothing by itself, and is not meant to: it is what makes the
    /// reclaim-policy property measurable, by offering the documented route to
    /// a Retain volume instead of a hand-built hostPath PersistentVolume.
    PerTenantStorageClass(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum WorkloadIsolation {
    VM(VirtualMachineSandboxing),
    UserspaceKernel(UserspaceKernelSandboxing),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum VirtualMachineSandboxing {
    KataContainers,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum UserspaceKernelSandboxing {
    GVisor,
}

impl From<ControlPlaneIsolation> for IsolationTechnology {
    fn from(tech: ControlPlaneIsolation) -> Self {
        IsolationTechnology::ControlPlane(tech)
    }
}

impl From<DataPlaneIsolation> for IsolationTechnology {
    fn from(tech: DataPlaneIsolation) -> Self {
        IsolationTechnology::DataPlane(tech)
    }
}

impl From<NetworkIsolationStrategy> for DataPlaneIsolation {
    fn from(tech: NetworkIsolationStrategy) -> Self {
        DataPlaneIsolation::Network(tech)
    }
}

impl From<NetworkIsolationStrategy> for IsolationTechnology {
    fn from(tech: NetworkIsolationStrategy) -> Self {
        DataPlaneIsolation::Network(tech).into()
    }
}

pub struct KubernetesClusterBuilder {
    host_cluster: HostClusterType,
    kubeconfig_path: PathBuf,
    isolation_technologies: Vec<IsolationTechnology>,
}

impl KubernetesClusterBuilder {
    pub fn new(host_cluster: HostClusterType) -> Self {
        Self {
            host_cluster,
            kubeconfig_path: PathBuf::new(),
            isolation_technologies: vec![],
        }
    }

    // A single builder method taking any type that converts into IsolationTechnology.
    pub fn with_isolation_technology<T: Into<IsolationTechnology>>(
        mut self,
        technology: T,
    ) -> Self {
        self.isolation_technologies.push(technology.into());
        self
    }

    pub fn with_kubeconfig_path(mut self, kubeconfig_path: PathBuf) -> Self {
        self.kubeconfig_path = kubeconfig_path;
        self
    }

    pub async fn build(self) -> anyhow::Result<KubernetesClient> {
        let control_plane_isolation_technologies: Vec<ControlPlaneIsolation> = self
            .isolation_technologies
            .iter()
            .filter_map(|isolation_technology| match isolation_technology {
                IsolationTechnology::ControlPlane(control_plane_isolation_technology) => {
                    Some(control_plane_isolation_technology.clone())
                }
                _ => None,
            })
            .collect();

        let data_plane_isolation_technologies: Vec<DataPlaneIsolation> = self
            .isolation_technologies
            .iter()
            .filter_map(|isolation_technology| match isolation_technology {
                IsolationTechnology::DataPlane(data_plane_isolation_technology) => {
                    Some(data_plane_isolation_technology.clone())
                }
                _ => None,
            })
            .collect();

        for control_plane_isolation_technology in control_plane_isolation_technologies {
            self.apply_control_plane_isolation_technology(control_plane_isolation_technology)
                .await?;
        }

        // Ensure that the cluster is ready before applying data plane isolation technologies
        let _ = KubernetesClient::load(self.host_cluster.kubeconfig_path())
            .await?
            .ensure_cluster_is_ready()
            .await;

        for data_plane_isolation_technology in data_plane_isolation_technologies {
            self.apply_data_plane_isolation_technology(data_plane_isolation_technology)
                .await?;
        }

        let kubernetes_cluster = KubernetesClient::load(&self.kubeconfig_path).await?;
        Ok(kubernetes_cluster)
    }

    async fn apply_control_plane_isolation_technology(
        &self,
        control_plane_isolation_technology: ControlPlaneIsolation,
    ) -> anyhow::Result<()> {
        match control_plane_isolation_technology {
            ControlPlaneIsolation::Capsule(namespace) => {
                self.deploy_capsule_tenant(&namespace).await
            }
            ControlPlaneIsolation::CapsuleHardened(namespace) => {
                self.deploy_capsule_hardened_tenant(&namespace).await
            }
            ControlPlaneIsolation::CapsuleProxy(namespace) => {
                self.deploy_capsule_proxy(&namespace).await
            }

            ControlPlaneIsolation::VCluster(namespace) => self.deploy_vcluster(&namespace).await,

            ControlPlaneIsolation::None(namespace) => {
                self.dummy_control_plane_isolation(&namespace).await
            }

            ControlPlaneIsolation::KubeVirt(namespace) => {
                println!("Deploying KubeVirt cluster in namespace: {}", namespace);
                self.deploy_kubevirt_cluster(&namespace).await
            }

            ControlPlaneIsolation::Kamaji(namespace) => {
                println!(
                    "Deploying Kamaji tenant control plane in namespace: {}",
                    namespace
                );
                self.deploy_kamaji_cluster(&namespace).await
            }
        }
    }

    async fn apply_data_plane_isolation_technology(
        &self,
        data_plane_isolation_technology: DataPlaneIsolation,
    ) -> anyhow::Result<()> {
        match data_plane_isolation_technology {
            DataPlaneIsolation::Network(network_isolation_strategy) => {
                match network_isolation_strategy {
                    NetworkIsolationStrategy::NetworkPolicy(tenant_namespace) => {
                        self.isolate_network_between_namespaces(&tenant_namespace)
                            .await
                    }
                    NetworkIsolationStrategy::KubeOvnPrivateSubnet(tenant_namespace) => {
                        self.create_kube_ovn_private_subnet(&tenant_namespace).await
                    }
                    NetworkIsolationStrategy::KubeOvnTenantVpc(tenant_namespace) => {
                        self.create_kube_ovn_tenant_vpc(&tenant_namespace).await
                    }
                    NetworkIsolationStrategy::ScopedTenantDns(tenant_namespace) => {
                        self.deploy_tenant_dns(&tenant_namespace).await
                    }
                }
            }
            DataPlaneIsolation::Storage(storage_isolation_strategy) => {
                match storage_isolation_strategy {
                    StorageIsolationStrategy::PerTenantStorageClass(tenant_namespace) => {
                        self.provision_tenant_storage_class(&tenant_namespace).await
                    }
                }
            }
            DataPlaneIsolation::Workload(_workload_isolation_technology) => {
                Err(anyhow!("Workload isolation is not implemented yet"))
            }
        }
    }

    /// Install a CNI on the host cluster, and wait until it is carrying traffic.
    ///
    /// Runs once, between cluster creation and the first tenant. It cannot wait
    /// for the per-tenant data-plane loop: a cluster created with
    /// `disableDefaultCNI` has no pod networking at all, so its nodes never go
    /// Ready and the control-plane solution's own operator — Capsule's
    /// controller, vcluster's syncer — would never schedule.
    ///
    /// Waiting for nodes to become Ready is the honest check. It is the
    /// condition kubelet reports only once a CNI has written its configuration
    /// and is serving, so it cannot be satisfied by a manifest that applied
    /// cleanly and then failed to run.
    fn install_calico(kubeconfig: &std::path::Path) -> anyhow::Result<()> {
        let manifest = format!(
            "https://raw.githubusercontent.com/projectcalico/calico/{}/manifests/calico.yaml",
            CniPlugin::CALICO_VERSION
        );

        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .arg("apply")
            .arg("-f")
            .arg(manifest)
            .output()
            .context("Failed to run kubectl apply for the Calico manifest")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    /// Install Kube-OVN, which needs more than a manifest.
    ///
    /// The controller runs only on nodes carrying `kube-ovn/role=master`, and
    /// on a cluster with no CNI there is no scheduler-visible way to discover
    /// them — so the label goes on first. Without it the chart installs
    /// cleanly and nothing ever comes up, which on a CNI is indistinguishable
    /// from a cluster that simply never becomes Ready.
    fn install_kube_ovn(kubeconfig: &std::path::Path) -> anyhow::Result<()> {
        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .arg("label")
            .arg("node")
            .arg("-lnode-role.kubernetes.io/control-plane")
            .arg("kube-ovn/role=master")
            .arg("--overwrite")
            .output()
            .context("Failed to label the control-plane node for Kube-OVN")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg("kubeovn")
            .arg("https://kubeovn.github.io/kube-ovn/")
            .output()
            .context("Failed to add the Kube-OVN helm repo")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        let output = Command::new("helm")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .arg("install")
            .arg("kube-ovn")
            .arg("kubeovn/kube-ovn")
            .arg("--version")
            .arg(CniPlugin::KUBE_OVN_VERSION)
            .arg("-n")
            .arg("kube-system")
            .arg("--set")
            .arg(format!("POD_CIDR={}", CniPlugin::KubeOvn.pod_subnet()))
            // The wait matters more here than for a manifest CNI: the chart
            // brings up OVN's databases, a controller and a per-node agent, and
            // the cluster has no pod network at all until the whole set is
            // running.
            .arg("--wait")
            .arg("--timeout")
            .arg("10m")
            .output()
            .context("Failed to install the Kube-OVN helm chart")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    /// Put a sandboxed runtime on the node and publish its RuntimeClass.
    ///
    /// containerd already knows the handler — the patch went into the node's
    /// configuration when the cluster was created — but the binaries it names
    /// do not exist yet. The shim is exec'd per container rather than loaded
    /// once, so dropping the binaries in is enough and containerd needs no
    /// restart.
    ///
    /// Downloaded on the host and copied in, rather than fetched from inside
    /// the node: the node image carries no download tool, and doing it here
    /// means the version is pinned by this repository instead of by whatever
    /// the node could reach.
    pub async fn install_sandbox_runtime(
        host_cluster: &HostClusterType,
        runtime: SandboxRuntime,
    ) -> anyhow::Result<()> {
        let HostClusterType::Kind(kind) = host_cluster else {
            return Err(anyhow!(
                "sandboxed runtimes are only wired up for the kind provider"
            ));
        };
        let node = format!("{}-control-plane", kind.name);

        println!(
            "Installing {} ({}) on {node}",
            runtime.name(),
            runtime.version()
        );

        // Under the user's cache rather than /tmp: Kata's archive is close to
        // a gigabyte and /tmp is a tmpfs on many hosts, so unpacking it there
        // spends RAM rather than disk. Persisting it also means a re-run does
        // not re-download it.
        let cache = dirs_cache_home().join(format!("kumuteva-{}", runtime.name()));
        std::fs::create_dir_all(&cache)?;

        match runtime.payload() {
            SandboxPayload::Binaries(binaries) => {
                for (binary, url) in binaries {
                    let local = cache.join(binary);
                    download_if_absent(&local, &url, binary)?;
                    let mut permissions = std::fs::metadata(&local)?.permissions();
                    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
                    std::fs::set_permissions(&local, permissions)?;

                    let output = Command::new("docker")
                        .arg("cp")
                        .arg(&local)
                        .arg(format!("{node}:/usr/local/bin/{binary}"))
                        .output()
                        .with_context(|| format!("Failed to copy {binary} into {node}"))?;
                    if !output.status.success() {
                        return Err(terminal_stderr_to_error(output));
                    }
                }
            }
            SandboxPayload::Archive {
                url,
                archive,
                tree,
                destination,
            } => {
                let local = cache.join(&archive);
                download_if_absent(&local, &url, &archive)?;

                let unpacked = cache.join("tree");
                if !unpacked.join(tree).exists() {
                    std::fs::create_dir_all(&unpacked)?;
                    println!("  unpacking {archive}");
                    let output = Command::new("tar")
                        .arg("--zstd")
                        .arg("-xf")
                        .arg(&local)
                        .arg("-C")
                        .arg(&unpacked)
                        .arg(format!("./{tree}"))
                        .output()
                        .with_context(|| format!("Failed to unpack {archive}"))?;
                    if !output.status.success() {
                        return Err(terminal_stderr_to_error(output));
                    }
                }

                println!("  copying {tree} into {node}:{destination}");
                let output = Command::new("docker")
                    .arg("cp")
                    .arg(unpacked.join(tree))
                    .arg(format!("{node}:{destination}"))
                    .output()
                    .with_context(|| format!("Failed to copy {tree} into {node}"))?;
                if !output.status.success() {
                    return Err(terminal_stderr_to_error(output));
                }
            }
        }

        for command in runtime.post_install() {
            let output = Command::new("docker")
                .arg("exec")
                .arg(&node)
                .args(&command)
                .output()
                .with_context(|| format!("Failed to run {command:?} in {node}"))?;
            if !output.status.success() {
                return Err(terminal_stderr_to_error(output));
            }
        }

        // The RuntimeClass is what a pod names. Without it the handler exists
        // and nothing can ask for it.
        let runtime_class = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": { "name": runtime.name() },
            "handler": runtime.handler()
        });
        Self::kubectl_apply(
            host_cluster.kubeconfig_path(),
            &serde_yaml::to_string(&runtime_class)?,
            "RuntimeClass",
        )?;

        println!(
            "{} is installed and its RuntimeClass published",
            runtime.name()
        );
        Ok(())
    }

    pub async fn install_cni(host_cluster: &HostClusterType, cni: CniPlugin) -> anyhow::Result<()> {
        let kubeconfig = host_cluster.kubeconfig_path();
        println!(
            "Installing {} ({}) as the cluster CNI",
            cni.name(),
            cni.version()
        );

        match cni {
            CniPlugin::Calico => Self::install_calico(kubeconfig)?,
            CniPlugin::KubeOvn => Self::install_kube_ovn(kubeconfig)?,
        }

        println!("Waiting for nodes to become Ready under {}", cni.name());
        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .arg("wait")
            .arg("--for=condition=Ready")
            .arg("nodes")
            .arg("--all")
            .arg("--timeout=300s")
            .output()
            .context("Failed to wait for nodes to become Ready")?;

        if !output.status.success() {
            return Err(anyhow!(
                "nodes did not become Ready after installing {} — the cluster \
                 has no working pod network, so nothing measured on it would \
                 mean anything: {}",
                cni.name(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        println!("{} is up", cni.name());
        Ok(())
    }

    /// Give a tenant its own private Kube-OVN Subnet.
    ///
    /// `private: true` makes OVN drop traffic between this subnet and any
    /// other, so two tenants on their own subnets cannot reach each other at
    /// all — no policy involved, and nothing the tenant can rescind.
    ///
    /// `allowSubnets` then punches back exactly what the tenant legitimately
    /// needs: the default subnet, where CoreDNS and the rest of kube-system
    /// live, and the join subnet that carries pod-to-node traffic. Without
    /// these the tenant loses DNS and its own Services, and the row would show
    /// magnificent isolation for a tenant that cannot work — which is the
    /// failure this whole table is built to expose, so it would be a poor place
    /// to commit it.
    async fn create_kube_ovn_private_subnet(&self, tenant_namespace: &str) -> anyhow::Result<()> {
        let cidr = Self::tenant_subnet_cidr(tenant_namespace);
        println!("Creating private Kube-OVN subnet {cidr} for {tenant_namespace}");

        let subnet = serde_json::json!({
            "apiVersion": "kubeovn.io/v1",
            "kind": "Subnet",
            "metadata": { "name": format!("{tenant_namespace}-subnet") },
            "spec": {
                "protocol": "IPv4",
                "cidrBlock": cidr,
                "namespaces": [tenant_namespace],
                "private": true,
                "allowSubnets": [
                    CniPlugin::KubeOvn.pod_subnet(),
                    KUBE_OVN_JOIN_CIDR,
                ],
                "natOutgoing": true,
            }
        });

        Self::kubectl_apply(
            self.host_cluster.kubeconfig_path(),
            &serde_yaml::to_string(&subnet)?,
            "Kube-OVN Subnet",
        )
    }

    /// Give a tenant a VPC of its own, and a Subnet inside it.
    ///
    /// A VPC is a logical router. Putting each tenant behind its own means
    /// there is no route between them to drop traffic on — the other tenant is
    /// simply not in this one's routing world. That is what separates this from
    /// [`Self::create_kube_ovn_private_subnet`], where both tenants hang off
    /// the default router and an ACL does the work.
    ///
    /// The cost is real and is the other half of what this row measures:
    /// upstream is explicit that a custom VPC gives up NodePort, node access,
    /// and cluster DNS, because those live in the default VPC. The autonomy
    /// columns are where that shows up, and it should not be papered over.
    async fn create_kube_ovn_tenant_vpc(&self, tenant_namespace: &str) -> anyhow::Result<()> {
        let vpc_name = format!("{tenant_namespace}-vpc");
        let cidr = Self::tenant_subnet_cidr(tenant_namespace);
        println!("Creating Kube-OVN VPC {vpc_name} with subnet {cidr}");

        let vpc = serde_json::json!({
            "apiVersion": "kubeovn.io/v1",
            "kind": "Vpc",
            "metadata": { "name": vpc_name },
            "spec": { "namespaces": [tenant_namespace] }
        });
        Self::kubectl_apply(
            self.host_cluster.kubeconfig_path(),
            &serde_yaml::to_string(&vpc)?,
            "Kube-OVN Vpc",
        )?;

        // No `private` and no `allowSubnets`: there is nothing to allow or deny
        // across, because the router this subnet hangs off serves only this
        // tenant. Stating them would suggest the isolation came from a rule.
        let subnet = serde_json::json!({
            "apiVersion": "kubeovn.io/v1",
            "kind": "Subnet",
            "metadata": { "name": format!("{tenant_namespace}-subnet") },
            "spec": {
                "protocol": "IPv4",
                "vpc": vpc_name,
                "cidrBlock": cidr,
                "namespaces": [tenant_namespace],
                "natOutgoing": true,
            }
        });
        Self::kubectl_apply(
            self.host_cluster.kubeconfig_path(),
            &serde_yaml::to_string(&subnet)?,
            "Kube-OVN Subnet",
        )
    }

    /// Give the tenant a DNS server of its own that answers only for the
    /// tenant's namespace.
    ///
    /// Cluster DNS resolves every Service in the cluster for every client, so
    /// one tenant can enumerate another's services by name whether or not it
    /// can reach them. Closing that needs a resolver with a narrower view, and
    /// CoreDNS's `namespaces` directive is exactly that: this one answers for
    /// the tenant's namespace and `kube-system`, and returns NXDOMAIN for
    /// everything else.
    ///
    /// Deliberately independent of any CNI or control-plane solution. It is an
    /// ordinary Deployment and Service using ordinary cluster networking, so it
    /// composes with whatever else is under test rather than belonging to one
    /// row — which is what makes it a layer rather than a feature of Kube-OVN.
    ///
    /// The namespace list is the tenant's own plus `default` and `kube-system`,
    /// which is the split CoreDNS's own multi-tenancy guidance describes: a
    /// tenant resolves its own Services and the cluster's, and nothing else.
    ///
    /// `default` is not padding. The API server is published as
    /// `kubernetes.default.svc.cluster.local`, so leaving it out costs the
    /// tenant the one name every client library looks for — measured, and
    /// caught by asking the tenant to resolve it rather than by assuming.
    async fn deploy_tenant_dns(&self, tenant_namespace: &str) -> anyhow::Result<()> {
        println!("Deploying a namespace-scoped CoreDNS for {tenant_namespace}");

        let corefile = format!(
            ".:53 {{\n    errors\n    health\n    ready\n    \
             kubernetes cluster.local in-addr.arpa ip6.arpa {{\n      \
             namespaces {tenant_namespace} default kube-system\n      pods insecure\n      \
             fallthrough in-addr.arpa ip6.arpa\n    }}\n    cache 30\n    \
             loop\n    reload\n}}\n"
        );

        let manifest = serde_json::json!([
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": { "name": "tenant-dns", "namespace": tenant_namespace }
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": { "name": format!("tenant-dns-{tenant_namespace}") },
                // CoreDNS's kubernetes plugin watches cluster-scoped lists and
                // filters them by the `namespaces` directive. The read is wide;
                // what it will *answer* is not. This is platform infrastructure
                // run on the tenant's behalf, not something the tenant controls.
                "rules": [{
                    "apiGroups": [""],
                    "resources": ["endpoints", "services", "pods", "namespaces"],
                    "verbs": ["list", "watch"]
                }, {
                    "apiGroups": ["discovery.k8s.io"],
                    "resources": ["endpointslices"],
                    "verbs": ["list", "watch"]
                }]
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": { "name": format!("tenant-dns-{tenant_namespace}") },
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": format!("tenant-dns-{tenant_namespace}")
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "tenant-dns",
                    "namespace": tenant_namespace
                }]
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": "tenant-dns", "namespace": tenant_namespace },
                "data": { "Corefile": corefile }
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": { "name": "tenant-dns", "namespace": tenant_namespace },
                "spec": {
                    "selector": { "app": "tenant-dns" },
                    "ports": [
                        { "name": "dns", "port": 53, "protocol": "UDP", "targetPort": 53 },
                        { "name": "dns-tcp", "port": 53, "protocol": "TCP", "targetPort": 53 }
                    ]
                }
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": { "name": "tenant-dns", "namespace": tenant_namespace },
                "spec": {
                    "replicas": 1,
                    "selector": { "matchLabels": { "app": "tenant-dns" } },
                    "template": {
                        "metadata": { "labels": { "app": "tenant-dns" } },
                        "spec": {
                            "serviceAccountName": "tenant-dns",
                            "containers": [{
                                "name": "coredns",
                                "image": "coredns/coredns:1.11.3",
                                "args": ["-conf", "/etc/coredns/Corefile"],
                                "volumeMounts": [{
                                    "name": "config",
                                    "mountPath": "/etc/coredns"
                                }]
                            }],
                            "volumes": [{
                                "name": "config",
                                "configMap": { "name": "tenant-dns" }
                            }]
                        }
                    }
                }
            }
        ]);

        let documents: Vec<serde_json::Value> = serde_json::from_value(manifest)?;
        let joined = documents
            .iter()
            .map(serde_yaml::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("---\n");

        Self::kubectl_apply(
            self.host_cluster.kubeconfig_path(),
            &joined,
            "tenant DNS server",
        )
    }

    /// A distinct CIDR per tenant, outside the default subnet.
    ///
    /// Deterministic so a rerun addresses the same tenant the same way, and
    /// kept clear of `10.16.0.0/16`, which the default subnet already holds.
    fn tenant_subnet_cidr(tenant_namespace: &str) -> String {
        let octet = match tenant_namespace {
            "tenant1" => 17,
            "tenant2" => 18,
            // Anything else lands somewhere stable and unused; the campaign
            // only ever runs two tenants, so this is a guard rather than a
            // scheme.
            other => 20 + (other.len() as u8 % 200),
        };
        format!("10.{octet}.0.0/16")
    }

    /// Apply a manifest through kubectl.
    ///
    /// Kube-OVN's CRDs have no generated bindings in this repository, and
    /// generating them to create two objects would be a lot of machinery for
    /// something whose shape is fixed and small.
    fn kubectl_apply(
        kubeconfig: &std::path::Path,
        manifest: &str,
        what: &str,
    ) -> anyhow::Result<()> {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .arg("apply")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to run kubectl apply for the {what}"))?;

        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(manifest.as_bytes())
            .with_context(|| format!("Failed to send the {what} manifest to kubectl"))?;

        let output = child
            .wait_with_output()
            .with_context(|| format!("Failed to apply the {what}"))?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    /// Give one tenant a StorageClass of its own.
    ///
    /// Reclaim policy is a property of the StorageClass, and a tenant with no
    /// Retain class can only obtain a Retain volume by hand-building a
    /// hostPath PersistentVolume — which is what the storage probe used to do,
    /// and it quietly turned `Create And Mount Volume with Retain Reclaim
    /// Policy` into a question about hostPath. Giving each tenant its own
    /// Retain class is what lets that property measure reclaim policy.
    async fn provision_tenant_storage_class(&self, tenant_namespace: &str) -> anyhow::Result<()> {
        let kubeconfig = self.host_cluster.kubeconfig_path();

        // Both reclaim policies, because the two `Create And Mount Volume`
        // properties differ only in that and each has to provision through a
        // class of the tenant's own. Only the Retain class existed before, so
        // the plain property silently used the cluster default.
        Self::kubectl_apply(
            kubeconfig,
            &tenant_storage_class(&delete_storage_class_name(tenant_namespace), "Delete"),
            "per-tenant Delete StorageClass",
        )?;
        Self::kubectl_apply(
            kubeconfig,
            &tenant_storage_class(&retain_storage_class_name(tenant_namespace), "Retain"),
            "per-tenant Retain StorageClass",
        )?;

        // The classes are only labels until something refuses a claim that
        // names someone else's.
        Self::kubectl_apply(
            kubeconfig,
            &tenant_storage_class_policy(),
            "StorageClass admission policy",
        )?;
        Self::kubectl_apply(
            kubeconfig,
            &tenant_storage_class_policy_binding(tenant_namespace),
            "StorageClass admission policy binding",
        )?;

        println!(
            "StorageClasses {} and {} are provisioned for {tenant_namespace}, \
             and its claims are confined to them",
            delete_storage_class_name(tenant_namespace),
            retain_storage_class_name(tenant_namespace),
        );
        Ok(())
    }

    async fn isolate_network_between_namespaces(
        &self,
        tenant_namespace: &str,
    ) -> anyhow::Result<()> {
        let admin_cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        // Read the API server's real addresses rather than assuming them: the
        // `kubernetes` Service in `default` publishes them, and they differ by
        // provider.
        let api_server_ips = admin_cluster
            .get_resource_in_namespace::<k8s_openapi::api::core::v1::Endpoints>(
                "kubernetes",
                "default",
            )
            .await
            .ok()
            .and_then(|endpoints| endpoints.subsets)
            .map(|subsets| {
                subsets
                    .into_iter()
                    .filter_map(|subset| subset.addresses)
                    .flatten()
                    .map(|address| address.ip)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if api_server_ips.is_empty() {
            println!(
                "Warning: could not read the API server endpoints; the tenant's \
                 egress policy will not permit reaching it"
            );
        }

        let (deny_all_network_policy, allow_dns_network_policy) =
            tenant_network_policies(&api_server_ips)?;

        admin_cluster
            .create_namespaced_resource::<NetworkPolicy>(&deny_all_network_policy, tenant_namespace)
            .await?;
        admin_cluster
            .create_namespaced_resource::<NetworkPolicy>(
                &allow_dns_network_policy,
                tenant_namespace,
            )
            .await?;

        Ok(())
    }
}

/// The pair of NetworkPolicies that confine a tenant to its own namespace.
///
/// Separated from the call that posts them so they can be asserted on without a
/// cluster, the same reason `cluster_config` is separated from `create`. These
/// are the kind of object whose defects are silent: a policy that denies more
/// than intended still applies cleanly, and only shows up as isolation that
/// looks too good.
fn tenant_network_policies(
    api_server_ips: &[String],
) -> anyhow::Result<(NetworkPolicy, NetworkPolicy)> {
    let deny_all_network_policy = json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "deny-other-namespaces",
        },
        "spec": {
            "podSelector": {
                "matchLabels": {}
            },
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{
                    "podSelector": {}
                }]
            }],
        }
    });

    // Egress: the tenant's own namespace, plus kube-system for DNS.
    //
    // The same-namespace rule is load-bearing and was missing. A policy
    // carrying an `egress` block gets `policyTypes: [Egress]` inferred, so
    // listing only kube-system does not *add* DNS to an otherwise open
    // namespace — it restricts the namespace to kube-system and nothing
    // else, cutting the tenant off from its own pods and Services.
    //
    // That has been invisible because kind's default CNI ignores
    // NetworkPolicy entirely. Under an enforcing CNI it would have read as
    // excellent network isolation that is really a tenant with no network,
    // with the autonomy columns as the only clue.
    //
    // `policyTypes` is now stated rather than inferred, because the
    // inference is exactly what made the bug quiet.
    let allow_dns_network_policy = serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
          "name": "allow-traffic-to-kube-system",
        },
        "spec": {
          "podSelector": {},
          "policyTypes": ["Egress"],
          "egress": [
            {
              "to": [
                { "podSelector": {} }
              ]
            },
            {
              "to": [
                {
                  "namespaceSelector": {
                    "matchLabels": {
                      "kubernetes.io/metadata.name": "kube-system"
                    }
                  }
                }
              ],
            },
            // The API server, by address rather than by selector.
            //
            // It is not a pod in any namespace a selector can name: clients
            // reach it at the `kubernetes` Service, which DNATs to the control
            // plane's host address, so only an ipBlock can express it.
            //
            // Leaving it out looks harmless and is not. Anything the tenant
            // runs that talks to Kubernetes stops working — measured, a
            // per-tenant CoreDNS could not list Services and answered SERVFAIL
            // to every query, which the assessment then had to record as an
            // unknown. A tenant cut off from the API server is over-restricted,
            // not isolated.
            {
              "to": api_server_ips
                  .iter()
                  .map(|ip| json!({ "ipBlock": { "cidr": format!("{ip}/32") } }))
                  .collect::<Vec<_>>()
            }
          ]
        }
    });

    Ok((
        serde_json::from_value(deny_all_network_policy)?,
        serde_json::from_value(allow_dns_network_policy)?,
    ))
}

impl KubernetesClusterBuilder {
    fn install_capsule() -> anyhow::Result<()> {
        let repo_name = "projectcapsule";
        let repo_url = "https://projectcapsule.github.io/charts";
        let chart = "capsule";

        let capsule_namespace = "capsule-system";
        let (chart_path, capsule_version) = Self::capsule_chart_source(chart);

        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg(repo_name)
            .arg(repo_url)
            .output()
            .context("Failed to add capsule helm repo")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        // Check if Capsule is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--filter")
            .arg(chart)
            .output()
            .context("Failed to check if capsule is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if helm_list_output.contains(chart) {
            println!("Capsule is already installed, skipping installation");
            return Ok(());
        }

        let output = Command::new("helm")
            .arg("install")
            .arg(chart)
            .arg(chart_path)
            .arg("--version")
            .arg(capsule_version)
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--create-namespace")
            // Keep capsule self-contained, as it was at 0.10.0.
            //
            // From 0.13 the chart defaults to `certManager.generateCertificates
            // = true` and templates a cert-manager Certificate and Issuer for
            // its webhooks. Without cert-manager already in the cluster the
            // install fails outright — "no matches for kind Certificate in
            // version cert-manager.io/v1" — because the CRDs are absent.
            //
            // Disabling that makes capsule generate its own webhook TLS instead
            // (`tls.create`) and run the controller that injects the CA into
            // the webhook configurations (`tls.enableController`). The
            // alternative, installing cert-manager alongside, would add a
            // cluster-wide dependency to a solution that did not have one and
            // change what is being measured.
            .arg("--set")
            .arg("certManager.generateCertificates=false")
            .arg("--set")
            .arg("tls.create=true")
            .arg("--set")
            .arg("tls.enableController=true")
            // Without this, `helm install` returns as soon as the objects are
            // accepted and the tenant is declared against a controller that may
            // not be running yet.
            .arg("--wait")
            .arg("--timeout")
            .arg("5m")
            .output()
            .context("Failed to install capsule helm chart")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    /// Block until Capsule's admission webhooks are registered.
    ///
    /// `helm --wait` covers the controller pod, and from 0.13 that is not
    /// enough: the chart no longer templates the webhook configurations, the
    /// controller creates them at runtime once it starts. Between those two
    /// moments the API server enforces nothing Capsule claims to enforce.
    ///
    /// Measuring in that window is how a run silently disagrees with itself.
    /// It produced exactly one difference between two runs of the same commit
    /// on the same host — `Namespace / UPDATE` moved because the tenant's
    /// permissions were still being reconciled — and a single unexplained
    /// verdict is enough to put every number in a table in doubt.
    ///
    /// Matching on the name prefix rather than an exact name because it changed
    /// between the versions this tool can install: 0.10.0 registers
    /// `capsule-validating-webhook-configuration`, 0.13.9
    /// `capsule-dynamic-webhook`.
    async fn wait_for_capsule_webhooks(kubeconfig: &std::path::Path) -> anyhow::Result<()> {
        const ATTEMPTS: u32 = 60;

        for attempt in 1..=ATTEMPTS {
            let output = Command::new("kubectl")
                .arg("--kubeconfig")
                .arg(kubeconfig)
                .arg("get")
                .arg("validatingwebhookconfigurations")
                .arg("-o")
                .arg("name")
                .output()
                .context("Failed to list validating webhook configurations")?;

            if output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("capsule")
            {
                println!("Capsule admission webhooks are registered");
                return Ok(());
            }

            if attempt == ATTEMPTS {
                return Err(anyhow!(
                    "Capsule registered no validating webhooks within {}s — it \
                     enforces nothing until they exist, so anything measured now \
                     would describe the gap rather than the solution",
                    ATTEMPTS * 2
                ));
            }
            sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    /// Which Helm chart reference and version to install a Capsule component from.
    ///
    /// The pin is [`CAPSULE_CHART_VERSION`], and the operator and its proxy are
    /// kept equal: the proxy is an addon that reads the operator's Tenant CRDs,
    /// so a skew between the two is its own failure mode.
    ///
    /// Both are overridable, because the pin moved and the numbers moved with
    /// it. The default is the version the submitted measurements were taken on;
    /// to compare against a newer Capsule without editing the constant:
    ///
    /// ```text
    /// CAPSULE_CHART_VERSION=0.13.9 CAPSULE_PROXY_CHART_VERSION=0.13.9 \
    ///   kumuteva setup --type capsule ...
    /// ```
    ///
    /// The OCI registry serves the same charts and is the fallback if a version
    /// ever leaves the HTTP index:
    ///
    /// ```text
    /// CAPSULE_CHART=oci://ghcr.io/projectcapsule/charts/capsule \
    /// CAPSULE_PROXY_CHART=oci://ghcr.io/projectcapsule/charts/capsule-proxy
    /// ```
    ///
    /// This matters beyond convenience. Between 0.10.0 and 0.13.9 Capsule
    /// stopped intercepting NetworkPolicy UPDATE and DELETE, dropped the
    /// namespace-patching webhook, moved its webhooks from chart-rendered to
    /// controller-registered, and replaced `spec.imagePullPolicies` with the
    /// rules API. Measured tenant autonomy moves with all of that, and nothing
    /// in this repository changes — `Namespace / UPDATE` alone accounts for the
    /// difference between scope autonomy 1/15 and 2/15. Which chart version
    /// produced a number is part of the number.
    fn capsule_chart_source(chart: &str) -> (String, String) {
        let prefix = chart.to_uppercase().replace('-', "_");
        let reference = std::env::var(format!("{prefix}_CHART"))
            .unwrap_or_else(|_| format!("projectcapsule/{chart}"));
        let version = std::env::var(format!("{prefix}_CHART_VERSION"))
            .unwrap_or_else(|_| CAPSULE_CHART_VERSION.to_string());
        println!("Installing {reference} at version {version}");
        (reference, version)
    }

    fn install_capsule_proxy(nodeport: u16) -> anyhow::Result<()> {
        let repo_name = "projectcapsule";
        let repo_url = "https://projectcapsule.github.io/charts";
        let chart = "capsule-proxy";

        let capsule_namespace = "capsule-system";
        let (chart_path, capsule_version) = Self::capsule_chart_source(chart);

        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg(repo_name)
            .arg(repo_url)
            .output()
            .context("Failed to add capsule helm repo")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        // Check if Capsule Proxy is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--filter")
            .arg(chart)
            .output()
            .context("Failed to check if capsule is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if helm_list_output.contains(chart) {
            println!("Capsule Proxy is already installed, skipping installation");
            return Ok(());
        }

        let output = Command::new("helm")
            .arg("install")
            .arg(chart)
            .arg(chart_path)
            .arg("--version")
            .arg(capsule_version)
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--create-namespace")
            .arg("--set")
            .arg("crds.install=true")
            .arg("--set")
            .arg("service.type=NodePort")
            .arg("--set")
            .arg(format!("service.nodePort={}", nodeport))
            // Same reason as install_capsule: from 0.13 the chart defaults to
            // issuing its serving certificate through cert-manager, which is
            // not present. `options.generateCertificates` is the proxy's own
            // self-signed path, and it keeps the solution self-contained
            // instead of pulling in a cluster-wide dependency it did not have.
            .arg("--set")
            .arg("certManager.generateCertificates=false")
            .arg("--set")
            .arg("options.generateCertificates=true")
            .output()
            .context("Failed to install capsule helm chart")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    async fn deploy_capsule_proxy(&self, tenant_name: &str) -> anyhow::Result<()> {
        // Use tenant1 port mapping: container_port for nodeport, host_port for kubeconfig
        let tenant_mapping = &self.host_cluster.port_mappings().tenant1;
        let nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

        Self::install_capsule()?;
        Self::install_capsule_proxy(nodeport)?;

        // Deploy tenant but skip namespace creation (we'll do it after adjusting kubeconfig)
        self.deploy_capsule_tenant_without_namespace(tenant_name, CapsuleTenantPolicy::Default)
            .await?;

        // Modify the kubeconfig to use the correct port and skip TLS verification
        // Only if using kind provider
        if matches!(self.host_cluster, HostClusterType::Kind(_)) {
            self.adjust_capsule_proxy_kubeconfig(host_port)?;
        }

        // Now create the namespace using the adjusted kubeconfig
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 10).await?;
        tenant_cluster.create_namespace(tenant_name).await?;

        Ok(())
    }

    fn adjust_capsule_proxy_kubeconfig(&self, host_port: u16) -> anyhow::Result<()> {
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;

        // Parse the kubeconfig as YAML to modify the server URL and add insecure-skip-tls-verify
        let mut kubeconfig_yaml: serde_yaml::Value = serde_yaml::from_str(&kubeconfig)?;

        if let Some(clusters) = kubeconfig_yaml
            .get_mut("clusters")
            .and_then(|c| c.as_sequence_mut())
        {
            for cluster_entry in clusters.iter_mut() {
                if let Some(cluster) = cluster_entry
                    .get_mut("cluster")
                    .and_then(|c| c.as_mapping_mut())
                {
                    // Get the current server URL and replace the port
                    if let Some(server) = cluster.get_mut("server").and_then(|s| s.as_str()) {
                        // Extract the host part and replace with new port
                        // Server URL format: https://host:port or https://host
                        let new_server = if let Some(idx) = server.rfind(':') {
                            // Check if there's a port after the last colon
                            let after_colon = &server[idx + 1..];
                            if after_colon.chars().all(|c| c.is_ascii_digit()) {
                                format!("{}:{}", &server[..idx], host_port)
                            } else {
                                format!("{}:{}", server, host_port)
                            }
                        } else {
                            format!("{}:{}", server, host_port)
                        };
                        cluster.insert(
                            serde_yaml::Value::String("server".to_string()),
                            serde_yaml::Value::String(new_server),
                        );
                    }

                    // Remove certificate-authority-data and add insecure-skip-tls-verify
                    cluster.remove(&serde_yaml::Value::String(
                        "certificate-authority-data".to_string(),
                    ));
                    cluster.insert(
                        serde_yaml::Value::String("insecure-skip-tls-verify".to_string()),
                        serde_yaml::Value::Bool(true),
                    );
                }
            }
        }

        let modified_kubeconfig = serde_yaml::to_string(&kubeconfig_yaml)?;
        std::fs::write(&self.kubeconfig_path, modified_kubeconfig)?;

        Ok(())
    }

    /// The Tenant CR for a given policy level.
    ///
    /// `Default` sets an owner and nothing else — the tenant you get from
    /// following Capsule's quickstart. `Hardened` additionally fills in the
    /// fields the multi-tenancy benchmarks look for. Each is annotated with
    /// what it is there for, because the mapping is the point of the
    /// comparison: none of this is Capsule behaving differently, it is Capsule
    /// being asked for something.
    fn capsule_tenant_spec(
        tenant_admin_user: &str,
        policy: CapsuleTenantPolicy,
        supports_rules: bool,
    ) -> capsule::TenantSpec {
        let owners = Some(vec![capsule::TenantOwners {
            kind: capsule::TenantOwnersKind::User,
            name: tenant_admin_user.to_string(),
            cluster_roles: None,
            proxy_settings: None,
            annotations: None,
            labels: None,
        }]);

        if policy == CapsuleTenantPolicy::Default {
            return capsule::TenantSpec {
                owners,
                ..Default::default()
            };
        }

        // Pod Security Admission, enforced at `restricted`.
        //
        // Capsule has no pod security logic of its own; it stamps these labels
        // onto every namespace it creates for the tenant and the API server's
        // built-in admission plugin does the work. `restricted` is what makes
        // eight benchmarks pass at once — privileged containers, privilege
        // escalation, added capabilities, run-as-non-root, hostPath, host
        // networking and ports, hostPID, hostIPC. Those benchmarks genuinely
        // try to create the offending pod, so this is enforcement, not a
        // declaration.
        let mut namespace_labels = BTreeMap::new();
        namespace_labels.insert(
            "pod-security.kubernetes.io/enforce".to_string(),
            "restricted".to_string(),
        );
        namespace_labels.insert(
            "pod-security.kubernetes.io/enforce-version".to_string(),
            "latest".to_string(),
        );

        // Compute quota. `configure_ns_quotas` joins the quota's resource names
        // and requires the strings "cpu", "memory" and "ephemeral-storage" to
        // appear, so the `limits.`/`requests.` prefixes satisfy it.
        let mut compute: BTreeMap<String, IntOrString> = BTreeMap::new();
        for (resource, amount) in [
            ("limits.cpu", "8"),
            ("limits.memory", "16Gi"),
            ("limits.ephemeral-storage", "20Gi"),
            ("requests.cpu", "8"),
            ("requests.memory", "16Gi"),
            ("requests.ephemeral-storage", "20Gi"),
        ] {
            compute.insert(
                resource.to_string(),
                IntOrString::String(amount.to_string()),
            );
        }

        // Object-count quota. `configure_ns_object_quota` checks for all nine
        // of these names, so every one has to be present even where the limit
        // itself is generous. The values are headroom for the probes, not
        // policy: the benchmark tests that a ceiling exists.
        let mut objects: BTreeMap<String, IntOrString> = BTreeMap::new();
        for (resource, count) in [
            ("pods", "100"),
            ("services", "50"),
            ("replicationcontrollers", "20"),
            ("resourcequotas", "10"),
            ("secrets", "100"),
            ("configmaps", "100"),
            ("persistentvolumeclaims", "50"),
            ("services.nodeports", "0"),
            ("services.loadbalancers", "0"),
        ] {
            objects.insert(resource.to_string(), IntOrString::String(count.to_string()));
        }

        // Default limits and requests for any container that omits them.
        //
        // Not decoration — without it the compute quota above silently decides
        // most of the benchmark suite. A ResourceQuota naming `limits.cpu`
        // makes that field mandatory for every pod in the namespace, and
        // kubectl-mtb's probe pods do not set it, so the quota rejects them
        // before admission ever reaches Pod Security or Capsule's webhooks.
        //
        // That matters because the benchmarks accept *any* rejection as a
        // pass: `block_privileged_containers` fails only if the create call
        // returns no error at all. A tenant whose quota turns away every pod
        // therefore scores nearly full marks without a single policy being
        // enforced, and the run cannot tell the two situations apart.
        //
        // With defaults injected the quota is satisfied, and the pod is then
        // judged on what it actually asks for. `require_always_pull_image` is
        // the one benchmark that reads the rejection message rather than its
        // presence — it looks for the string "admission webhook" — so it is
        // also the only one that exposed the masking.
        let mut default_limits: BTreeMap<String, IntOrString> = BTreeMap::new();
        let mut default_requests: BTreeMap<String, IntOrString> = BTreeMap::new();
        for (resource, limit, request) in [
            ("cpu", "500m", "100m"),
            ("memory", "512Mi", "64Mi"),
            ("ephemeral-storage", "1Gi", "512Mi"),
        ] {
            default_limits.insert(resource.to_string(), IntOrString::String(limit.to_string()));
            default_requests.insert(
                resource.to_string(),
                IntOrString::String(request.to_string()),
            );
        }

        capsule::TenantSpec {
            owners,
            limit_ranges: Some(capsule::TenantLimitRanges {
                items: Some(vec![capsule::TenantLimitRangesItems {
                    limits: vec![capsule::TenantLimitRangesItemsLimits {
                        r#type: "Container".to_string(),
                        default: Some(default_limits),
                        default_request: Some(default_requests),
                        max: None,
                        min: None,
                        max_limit_request_ratio: None,
                    }],
                }]),
            }),
            namespace_options: Some(capsule::TenantNamespaceOptions {
                additional_metadata: Some(capsule::TenantNamespaceOptionsAdditionalMetadata {
                    labels: Some(namespace_labels),
                    annotations: None,
                }),
                ..Default::default()
            }),
            resource_quotas: Some(capsule::TenantResourceQuotas {
                scope: Some(capsule::TenantResourceQuotasScope::Namespace),
                items: Some(vec![
                    capsule::TenantResourceQuotasItems {
                        hard: Some(compute),
                        scope_selector: None,
                        scopes: None,
                    },
                    capsule::TenantResourceQuotasItems {
                        hard: Some(objects),
                        scope_selector: None,
                        scopes: None,
                    },
                ]),
            }),
            // "Block use of NodePort services". A NodePort punches a hole in
            // every node, so a tenant that can open one reaches past its
            // namespace by construction.
            service_options: Some(capsule::TenantServiceOptions {
                allowed_services: Some(capsule::TenantServiceOptionsAllowedServices {
                    node_port: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            // "Require always imagePullPolicy": with Always, a tenant cannot
            // reach an image already cached on the node without presenting
            // credentials for it.
            //
            // Expressed through the rules API rather than the `imagePullPolicies`
            // field beside it. That field still exists and still validates, but
            // v1beta2 marks it deprecated and capsule 0.13 no longer acts on it,
            // so setting it looks like a policy and enforces nothing — the
            // benchmark went on failing against a tenant that appeared to
            // configure exactly what it asked for.
            //
            // The semantics are match-then-constrain, not match-then-forbid: a
            // registry reaching a final `allow` decision must then satisfy the
            // `policy` list. So the rule allows every registry — `.*` — and the
            // constraint it carries is that the pull policy be Always. Using
            // `action: deny` here would do the opposite of what is wanted, since
            // a final deny refuses the image outright and never consults the
            // pull policy at all.
            //
            // Which of the two fields carries it depends on the Capsule that is
            // installed, because they were never both available. `rules` arrived
            // in 0.13, and 0.10.0's CRD has no such field.
            //
            // `create_tenant` submits the Tenant by server-side apply, which
            // validates against the schema rather than pruning, so sending
            // `rules` to 0.10.0 fails the whole setup outright:
            //
            //     failed to create typed patch object (/tenant1;
            //     capsule.clastix.io/v1beta2, Kind=Tenant):
            //     .spec.rules: field not declared in schema
            //
            // Loud, which is the good case — a plain `create` would have pruned
            // the field and produced a tenant that looks hardened and enforces
            // nothing. Either way the fix is to ask the cluster which mechanism
            // it implements, which is what makes `capsule-hardened` runnable at
            // the version the submitted measurements were taken on.
            rules: supports_rules.then(|| {
                vec![capsule::TenantRules {
                    enforce: Some(capsule::TenantRulesEnforce {
                        action: Some(capsule::TenantRulesEnforceAction::Allow),
                        workloads: Some(capsule::TenantRulesEnforceWorkloads {
                            // Init and ephemeral containers pull images too, and
                            // a cached image is just as reachable from them.
                            targets: Some(vec![
                                "pod/containers".to_string(),
                                "pod/initcontainers".to_string(),
                                "pod/ephemeralcontainers".to_string(),
                            ]),
                            registries: Some(vec![
                                capsule::TenantRulesEnforceWorkloadsRegistries {
                                    exp: Some(".*".to_string()),
                                    policy: Some(vec!["Always".to_string()]),
                                    exact: None,
                                    negate: None,
                                },
                            ]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]
            }),
            // The pre-0.13 spelling of the same policy. Deprecated from v1beta2
            // and no longer acted on by 0.13, so it is set only where it is the
            // mechanism that actually works — setting both would put a field in
            // the object that the running operator ignores, which is the kind of
            // decoration that later reads as configuration.
            image_pull_policies: (!supports_rules).then(|| vec!["Always".to_string()]),
            ..Default::default()
        }
    }

    async fn deploy_capsule_tenant(&self, tenant_name: &str) -> anyhow::Result<()> {
        self.deploy_capsule_tenant_with_policy(tenant_name, CapsuleTenantPolicy::Default)
            .await
    }

    async fn deploy_capsule_hardened_tenant(&self, tenant_name: &str) -> anyhow::Result<()> {
        self.deploy_capsule_tenant_with_policy(tenant_name, CapsuleTenantPolicy::Hardened)
            .await
    }

    async fn deploy_capsule_tenant_with_policy(
        &self,
        tenant_name: &str,
        policy: CapsuleTenantPolicy,
    ) -> anyhow::Result<()> {
        self.deploy_capsule_tenant_without_namespace(tenant_name, policy)
            .await?;

        // create a namespace for the tenant
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 5).await?;
        tenant_cluster.create_namespace(tenant_name).await?;

        Ok(())
    }

    async fn deploy_capsule_tenant_without_namespace(
        &self,
        tenant_name: &str,
        policy: CapsuleTenantPolicy,
    ) -> anyhow::Result<()> {
        Self::install_capsule()?;
        Self::wait_for_capsule_webhooks(self.host_cluster.kubeconfig_path()).await?;

        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        let tenant_admin_user = format!("{}-admin", tenant_name);
        // Create the tenant crd

        let tenant_metadata = ObjectMeta {
            name: Some(String::from(tenant_name)),
            ..Default::default()
        };

        // Ask the installed CRD which pull-policy mechanism it understands, so a
        // downgraded Capsule gets a tenant it can actually enforce rather than
        // one whose policy is silently pruned.
        let supports_rules = cluster
            .crd_spec_has_field("tenants.capsule.clastix.io", "v1beta2", "rules")
            .await
            .unwrap_or(false);
        if policy == CapsuleTenantPolicy::Hardened {
            println!(
                "Tenant pull-policy enforcement via {}",
                if supports_rules {
                    "spec.rules (Rules Enforcement API)"
                } else {
                    "spec.imagePullPolicies (pre-0.13 mechanism)"
                }
            );
        }

        let tenant_spec = Self::capsule_tenant_spec(&tenant_admin_user, policy, supports_rules);

        let tenant_resource = capsule::Tenant {
            metadata: tenant_metadata,
            spec: tenant_spec,
            ..Default::default()
        };

        // create this crd resource
        create_tenant(&cluster, tenant_resource).await?;

        let output = Command::new("provisioner/capsule/create-user.sh")
            .arg(&tenant_admin_user)
            .arg(tenant_name)
            .output()
            .context("Failed to create capsule user")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        // move all the generated files to the kubeconfig path
        let generated_files_prefix = format!("{}-{}", tenant_admin_user, tenant_name);

        let kubeconfig_files = vec![
            format!("{}.kubeconfig", generated_files_prefix),
            format!("{}.crt", generated_files_prefix),
            format!("{}.key", generated_files_prefix),
        ];

        for file in kubeconfig_files {
            let dest = if file.ends_with(".kubeconfig") {
                self.kubeconfig_path.clone()
            } else {
                self.kubeconfig_path.with_file_name(&file)
            };
            std::fs::copy(&file, dest)?;
            std::fs::remove_file(&file)?;
        }

        Ok(())
    }

    async fn deploy_vcluster(&self, namespace: &str) -> anyhow::Result<()> {
        let vcluster_values_path = "vcluster.yaml";
        save_vcluster_helm_values(vcluster_values_path)?;

        let release_name = format!("vcluster-{}", namespace);
        let chart_name = "vcluster";

        let output = Command::new("helm")
            .arg("upgrade")
            .arg("--install")
            .arg(&release_name)
            .arg(chart_name)
            .arg("--values")
            .arg("vcluster.yaml")
            .arg("--repo")
            .arg("https://charts.loft.sh")
            .arg("--namespace")
            .arg(namespace)
            .arg("--create-namespace")
            .arg("--kubeconfig")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to execute helm upgrade command")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        // Wait for the vcluster api server pod to appear.
        let label = "app=vcluster";
        let mut pods = cluster
            .list_pods_with_label_in_namespace(label, namespace)
            .await?;

        // retry up to 10 times

        for _ in 0..10 {
            if !pods.items.is_empty() {
                break;
            }
            sleep(Duration::from_secs(5)).await;
            pods = cluster.list_pods_with_label(label).await?;
        }

        let pod_name = pods
            .items
            .first()
            .and_then(|pod| pod.name())
            .ok_or_else(|| anyhow!("vcluster pod name not found"))?;

        println!("Waiting for vcluster pod to be ready: {:?}", pod_name);
        cluster
            .wait_for_pod_to_be_ready(&pod_name, namespace)
            .await?;

        let vcluster_kubeconfig: String =
            Self::get_vcluster_kubeconfig(&cluster, namespace, &release_name).await?;
        // save new kubeconfig
        std::fs::write(&self.kubeconfig_path, vcluster_kubeconfig)?;

        // kind cluster exposes the api server on a different port
        // We need to force the API server port to be on a specific port
        // because the kind mapping takes it and maps it to a different host port
        let tenant_mapping = match namespace {
            "tenant1" => &self.host_cluster.port_mappings().tenant1,
            "tenant2" => &self.host_cluster.port_mappings().tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        let mut nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

        // if the cluster is not kind the nodeport = host_port
        match self.host_cluster {
            HostClusterType::Kind(_) => {
                // For kind, we need to create a NodePort service to expose the vcluster API server
                println!(
                    "Creating NodePort service for vcluster in namespace {} on port {}",
                    namespace, nodeport
                );
            }
            _ => {
                // For other clusters, we assume the host_port is already set correctly
                println!(
                    "Using host port {} for vcluster in namespace {}",
                    host_port, namespace
                );
                nodeport = host_port;
            }
        }

        let selector = Some({
            let mut map = BTreeMap::new();
            map.insert("app".to_string(), "vcluster".to_string());
            map.insert(
                "release".to_string(),
                format!("vcluster-{}", namespace).to_string(),
            );
            map
        });
        let service = cluster
            .create_nodeport_service(namespace, selector, Some(nodeport.into()))
            .await?;

        //get the nodeport
        let _nodeport = service
            .spec
            .and_then(|spec| spec.ports)
            .and_then(|ports| ports.first().and_then(|port| port.node_port))
            .ok_or_else(|| anyhow!("Nodeport not found"))?;

        // adjust kubeconfig to use the new port (8443 is the default one)
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;
        let kubeconfig = kubeconfig.replace("8443", &host_port.to_string());
        std::fs::write(&self.kubeconfig_path, kubeconfig)?;

        // create a namespace to deploy workloads
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 10).await?;
        tenant_cluster.ensure_cluster_is_ready().await?;
        tenant_cluster.create_namespace(namespace).await?;

        Ok(())
    }

    async fn get_vcluster_kubeconfig(
        cluster: &KubernetesClient,
        namespace: &str,
        vcluster_name: &str,
    ) -> anyhow::Result<String> {
        let secret_name = format!("vc-{}", vcluster_name);

        cluster
            .wait_for_resource_creation::<Secret>(&secret_name, namespace)
            .await?;

        let secret = cluster
            .get_secret_in_namespace(&secret_name, namespace)
            .await?;

        // Extract and decode config
        let config_b64 = secret
            .data
            .and_then(|data| data.get("config").cloned())
            .ok_or_else(|| anyhow::anyhow!("Config data not found in secret"))?;

        // Parse as string (kube-rs already decodes from base64)
        let config: String = String::from_utf8(config_b64.0)
            .context("Failed to parse config data from secret as UTF-8 string")?;
        Ok(config)
    }
    async fn dummy_control_plane_isolation(&self, namespace: &str) -> anyhow::Result<()> {
        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;
        cluster.create_namespace(namespace).await?;
        // use the kind kubeconfig as the tenant kubeconfig
        // Basically, we are not isolating the control plane and reusing the same kubeconfig
        let kubeconfig = std::fs::read_to_string(self.host_cluster.kubeconfig_path())?;
        std::fs::write(&self.kubeconfig_path, kubeconfig)?;
        Ok(())
    }

    async fn deploy_kubevirt_cluster(&self, namespace: &str) -> anyhow::Result<()> {
        // sleep for a while to ensure the host cluster is ready
        sleep(Duration::from_secs(10)).await;

        println!("Deploying KubeVirt on host cluster...");
        println!(
            "  Running: provisioner/kubevirt/deploy-kubevirt.sh {}",
            self.host_cluster.kubeconfig_path().to_string_lossy()
        );
        // Use the shell script to deploy KubeVirt
        let output = Command::new("provisioner/kubevirt/deploy-kubevirt.sh")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to execute KubeVirt deployment script")?;
        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        } else {
            println!(
                "Kubevirt deployment output: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        println!("Deploying CAPI provider on host cluster...");
        println!(
            "  Running: provisioner/kubevirt/deploy-capi-provider.sh {}",
            self.host_cluster.kubeconfig_path().to_string_lossy()
        );
        let output = Command::new("provisioner/kubevirt/deploy-capi-provider.sh")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to execute CAPI provider deployment script")?;
        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        } else {
            println!(
                "CAPI provider deployment output: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        let tenant_mapping = match namespace {
            "tenant1" => &self.host_cluster.port_mappings().tenant1,
            "tenant2" => &self.host_cluster.port_mappings().tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        println!(
            "Creating KubeVirt cluster for tenant in namespace: {}",
            namespace
        );
        println!(
            "  Running: provisioner/kubevirt/create-kubevirt-cluster.sh {} {} {} {} {}",
            self.host_cluster.kubeconfig_path().to_string_lossy(),
            self.kubeconfig_path.to_str().unwrap(),
            namespace,
            tenant_mapping.container_port,
            tenant_mapping.host_port,
        );

        // If kind cluster, expose the API server as nodeport
        let should_use_nodeport = matches!(self.host_cluster, HostClusterType::Kind(_))
            .then(|| "y")
            .unwrap_or("n");

        let output = Command::new("provisioner/kubevirt/create-kubevirt-cluster.sh")
            .arg(self.host_cluster.kubeconfig_path())
            .arg(self.kubeconfig_path.to_str().unwrap())
            .arg(namespace)
            .arg(should_use_nodeport)
            .arg(tenant_mapping.container_port.to_string())
            .arg(tenant_mapping.host_port.to_string())
            .output()
            .context("Failed to execute CAPI controller deployment script")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        } else {
            println!(
                "CAPI controller deployment output: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        // Wait for KubeVirt to be ready
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 10).await?;
        tenant_cluster.ensure_cluster_is_ready().await?;
        tenant_cluster.create_namespace(namespace).await?;

        Ok(())
    }

    async fn deploy_kamaji_cluster(&self, namespace: &str) -> anyhow::Result<()> {
        // Get port mappings for the tenant
        let tenant_mapping = match namespace {
            "tenant1" => &self.host_cluster.port_mappings().tenant1,
            "tenant2" => &self.host_cluster.port_mappings().tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        let nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

        // Install dependencies (cert-manager, metallb) and Kamaji
        Self::install_kamaji_dependencies(self.host_cluster.kubeconfig_path().to_str().unwrap())?;
        Self::install_kamaji(self.host_cluster.kubeconfig_path().to_str().unwrap())?;

        // Create the tenant control plane
        self.create_kamaji_tenant_control_plane(namespace, nodeport)
            .await?;

        // Wait for the tenant control plane to be ready and get the kubeconfig
        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;
        self.wait_for_kamaji_tenant_ready(&cluster, namespace)
            .await?;

        // Extract kubeconfig from the secret and save it
        let kubeconfig = self.get_kamaji_kubeconfig(&cluster, namespace).await?;
        std::fs::write(&self.kubeconfig_path, &kubeconfig)?;

        // Adjust kubeconfig to use the correct port (host_port)
        self.adjust_kamaji_kubeconfig(host_port)?;

        // Wait for the tenant cluster to be ready
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 15).await?;
        tenant_cluster.ensure_cluster_is_ready().await?;
        tenant_cluster.create_namespace(namespace).await?;

        Ok(())
    }

    fn install_kamaji_dependencies(kubeconfig_path: &str) -> anyhow::Result<()> {
        // Install cert-manager (required by Kamaji)
        println!("Installing cert-manager...");

        // Add jetstack repo (official cert-manager)
        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg("jetstack")
            .arg("https://charts.jetstack.io")
            .output()
            .context("Failed to add jetstack helm repo")?;

        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("already exists")
        {
            return Err(terminal_stderr_to_error(output));
        }

        // Update helm repos
        let _ = Command::new("helm").arg("repo").arg("update").output();

        // Check if cert-manager is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg("cert-manager")
            .arg("--filter")
            .arg("cert-manager")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .output()
            .context("Failed to check if cert-manager is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if !helm_list_output.contains("cert-manager") {
            let output = Command::new("helm")
                .arg("upgrade")
                .arg("--install")
                .arg("cert-manager")
                .arg("jetstack/cert-manager")
                .arg("--namespace")
                .arg("cert-manager")
                .arg("--create-namespace")
                .arg("--set")
                .arg("crds.enabled=true")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .arg("--wait")
                .arg("--timeout")
                .arg("5m")
                .output()
                .context("Failed to install cert-manager")?;

            if !output.status.success() {
                return Err(terminal_stderr_to_error(output));
            }
            println!("cert-manager installed successfully");
        } else {
            println!("cert-manager is already installed, skipping");
        }

        // Install MetalLB for LoadBalancer support
        println!("Installing MetalLB...");

        let check_output = Command::new("kubectl")
            .arg("get")
            .arg("namespace")
            .arg("metallb-system")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .output()
            .context("Failed to check if metallb is installed")?;

        if !check_output.status.success() {
            let output = Command::new("kubectl")
                .arg("apply")
                .arg("-f")
                .arg("https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output()
                .context("Failed to install metallb")?;

            if !output.status.success() {
                return Err(terminal_stderr_to_error(output));
            }

            // Wait for MetalLB controller to be ready
            println!("Waiting for MetalLB controller to be ready...");
            let _ = Command::new("kubectl")
                .arg("wait")
                .arg("--namespace")
                .arg("metallb-system")
                .arg("--for=condition=ready")
                .arg("pod")
                .arg("--selector=app=metallb,component=controller")
                .arg("--timeout=120s")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output();

            // Wait for MetalLB speaker to be ready
            println!("Waiting for MetalLB speaker to be ready...");
            let _ = Command::new("kubectl")
                .arg("wait")
                .arg("--namespace")
                .arg("metallb-system")
                .arg("--for=condition=ready")
                .arg("pod")
                .arg("--selector=app=metallb,component=speaker")
                .arg("--timeout=120s")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output();

            // Additional wait for webhook to be fully operational
            std::thread::sleep(std::time::Duration::from_secs(15));

            // Configure MetalLB IP address pool
            Self::configure_metallb_ip_pool(kubeconfig_path)?;

            println!("MetalLB installed successfully");
        } else {
            println!("MetalLB is already installed, skipping");
        }

        Ok(())
    }

    fn configure_metallb_ip_pool(kubeconfig_path: &str) -> anyhow::Result<()> {
        // Get the gateway IP of the kind network
        let output = Command::new("docker")
            .arg("network")
            .arg("inspect")
            .arg("-f")
            .arg("{{range .IPAM.Config}}{{.Gateway}}{{end}}")
            .arg("kind")
            .output()
            .context("Failed to get kind network gateway IP")?;

        if !output.status.success() {
            // If kind network doesn't exist, use a default
            println!("Warning: Could not get kind network gateway, using default IP range");
            return Ok(());
        }

        let gateway_ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if gateway_ip.is_empty() {
            println!("Warning: Empty gateway IP, skipping MetalLB IP pool configuration");
            return Ok(());
        }

        // Extract first two octets and create IP range
        let parts: Vec<&str> = gateway_ip.split('.').collect();
        if parts.len() < 2 {
            println!("Warning: Invalid gateway IP format, skipping MetalLB IP pool configuration");
            return Ok(());
        }

        let net_prefix = format!("{}.{}", parts[0], parts[1]);

        let ip_pool_yaml = format!(
            r#"apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kind-ip-pool
  namespace: metallb-system
spec:
  addresses:
  - {}.255.200-{}.255.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
"#,
            net_prefix, net_prefix
        );

        // Write to temp file and apply
        let temp_path = "/tmp/metallb-config.yaml";
        std::fs::write(temp_path, &ip_pool_yaml)?;

        // Retry applying MetalLB config with backoff (webhook may take time to be ready)
        let mut last_error = String::new();
        for attempt in 1..=5 {
            println!(
                "Applying MetalLB IP pool configuration (attempt {}/5)...",
                attempt
            );

            let output = Command::new("kubectl")
                .arg("apply")
                .arg("-f")
                .arg(temp_path)
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output()
                .context("Failed to apply metallb IP pool configuration")?;

            if output.status.success() {
                println!("MetalLB IP pool configured successfully");
                return Ok(());
            }

            last_error = String::from_utf8_lossy(&output.stderr).to_string();

            // Check if it's a webhook error (need to wait more)
            if last_error.contains("webhook") || last_error.contains("connection refused") {
                println!("MetalLB webhook not ready yet, waiting...");
                std::thread::sleep(std::time::Duration::from_secs(10 * attempt as u64));
            } else {
                // Some other error, might already exist
                break;
            }
        }

        // Don't fail if this doesn't work, it may already exist
        println!(
            "Warning: MetalLB IP pool configuration may have failed: {}",
            last_error
        );

        Ok(())
    }

    fn install_kamaji(kubeconfig_path: &str) -> anyhow::Result<()> {
        println!("Installing Kamaji...");

        // Add clastix repo
        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg("clastix")
            .arg("https://clastix.github.io/charts")
            .output()
            .context("Failed to add clastix helm repo")?;

        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("already exists")
        {
            return Err(terminal_stderr_to_error(output));
        }

        // Update helm repos
        let _ = Command::new("helm").arg("repo").arg("update").output();

        // Check if Kamaji is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg("kamaji-system")
            .arg("--filter")
            .arg("kamaji")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .output()
            .context("Failed to check if kamaji is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if helm_list_output.contains("kamaji") && !helm_list_output.contains("kamaji-") {
            println!("Kamaji is already installed, skipping");
            return Ok(());
        }

        // Check specifically if kamaji (not kamaji-tenant-*) is installed
        if helm_list_output.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.first() == Some(&"kamaji")
        }) {
            println!("Kamaji is already installed, skipping");
            return Ok(());
        }

        let output = Command::new("helm")
            .arg("upgrade")
            .arg("--install")
            .arg("kamaji")
            .arg("clastix/kamaji")
            .arg("--namespace")
            .arg("kamaji-system")
            .arg("--create-namespace")
            .arg("--set")
            .arg("resources=null")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .arg("--wait")
            .arg("--timeout")
            .arg("5m")
            .output()
            .context("Failed to install kamaji")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        println!("Kamaji installed successfully");
        Ok(())
    }

    async fn create_kamaji_tenant_control_plane(
        &self,
        namespace: &str,
        nodeport: u16,
    ) -> anyhow::Result<()> {
        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        // Create namespace for the tenant control plane
        cluster.create_namespace(namespace).await?;

        // Create the TenantControlPlane resource
        let tcp_name = format!("tcp-{}", namespace);

        let tcp_yaml = format!(
            r#"apiVersion: kamaji.clastix.io/v1alpha1
kind: TenantControlPlane
metadata:
  name: {}
  namespace: {}
spec:
  dataStore: default
  controlPlane:
    deployment:
      replicas: 1
    service:
      serviceType: LoadBalancer
      additionalMetadata:
        labels:
          tenant: {}
  kubernetes:
    version: "v1.30.0"
    kubelet:
      cgroupfs: systemd
    admissionControllers:
      - ResourceQuota
      - LimitRanger
  networkProfile:
    port: {}
  addons:
    coreDNS: {{}}
    kubeProxy: {{}}
    konnectivity:
      server:
        port: 8132
"#,
            tcp_name, namespace, namespace, nodeport
        );

        // Write to temp file and apply
        let temp_path = format!("/tmp/kamaji-tcp-{}.yaml", namespace);
        std::fs::write(&temp_path, &tcp_yaml)?;

        let output = Command::new("kubectl")
            .arg("apply")
            .arg("-f")
            .arg(&temp_path)
            .arg("--kubeconfig")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to create kamaji tenant control plane")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        println!(
            "Created Kamaji TenantControlPlane {} in namespace {}",
            tcp_name, namespace
        );
        Ok(())
    }

    async fn wait_for_kamaji_tenant_ready(
        &self,
        _cluster: &KubernetesClient,
        namespace: &str,
    ) -> anyhow::Result<()> {
        let tcp_name = format!("tcp-{}", namespace);
        println!(
            "Waiting for Kamaji TenantControlPlane {} to be ready...",
            tcp_name
        );

        // Wait for the tenant control plane to be ready by checking the status
        for i in 0..60 {
            let output = Command::new("kubectl")
                .arg("get")
                .arg("tcp")
                .arg(&tcp_name)
                .arg("-n")
                .arg(namespace)
                .arg("-o")
                .arg("jsonpath={.status.kubernetesResources.version.status}")
                .arg("--kubeconfig")
                .arg(self.host_cluster.kubeconfig_path())
                .output()
                .context("Failed to get tcp status")?;

            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "Ready" {
                println!("Kamaji TenantControlPlane {} is ready", tcp_name);
                return Ok(());
            }

            if i % 10 == 0 {
                println!(
                    "Still waiting for TenantControlPlane {} (status: {})...",
                    tcp_name,
                    if status.is_empty() {
                        "pending"
                    } else {
                        &status
                    }
                );
            }
            sleep(Duration::from_secs(5)).await;
        }

        Err(anyhow!(
            "Timeout waiting for Kamaji TenantControlPlane {} to be ready",
            tcp_name
        ))
    }

    async fn get_kamaji_kubeconfig(
        &self,
        cluster: &KubernetesClient,
        namespace: &str,
    ) -> anyhow::Result<String> {
        let tcp_name = format!("tcp-{}", namespace);

        // First, get the secret name from the TCP status
        let output = Command::new("kubectl")
            .arg("get")
            .arg("tcp")
            .arg(&tcp_name)
            .arg("-n")
            .arg(namespace)
            .arg("-o")
            .arg("jsonpath={.status.kubeconfig.admin.secretName}")
            .arg("--kubeconfig")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to get kubeconfig secret name")?;

        let secret_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if secret_name.is_empty() {
            // Try default secret name pattern
            let secret_name = format!("{}-admin-kubeconfig", tcp_name);
            return Self::get_kubeconfig_from_secret(cluster, namespace, &secret_name).await;
        }

        Self::get_kubeconfig_from_secret(cluster, namespace, &secret_name).await
    }

    async fn get_kubeconfig_from_secret(
        cluster: &KubernetesClient,
        namespace: &str,
        secret_name: &str,
    ) -> anyhow::Result<String> {
        // Wait for secret to exist
        cluster
            .wait_for_resource_creation::<Secret>(secret_name, namespace)
            .await?;

        let secret = cluster
            .get_secret_in_namespace(secret_name, namespace)
            .await?;

        // Extract and decode the kubeconfig - try different possible key names
        let possible_keys = ["admin.conf", "super-admin.conf", "kubeconfig"];

        for key in possible_keys {
            if let Some(config_b64) = secret.data.as_ref().and_then(|data| data.get(key).cloned()) {
                let config = String::from_utf8(config_b64.0)
                    .context("Failed to parse kubeconfig data as UTF-8 string")?;
                return Ok(config);
            }
        }

        Err(anyhow!(
            "Kubeconfig data not found in secret {}. Available keys: {:?}",
            secret_name,
            secret.data.as_ref().map(|d| d.keys().collect::<Vec<_>>())
        ))
    }

    fn adjust_kamaji_kubeconfig(&self, host_port: u16) -> anyhow::Result<()> {
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;

        // Parse the kubeconfig as YAML to modify the server URL
        let mut kubeconfig_yaml: serde_yaml::Value = serde_yaml::from_str(&kubeconfig)?;

        if let Some(clusters) = kubeconfig_yaml
            .get_mut("clusters")
            .and_then(|c| c.as_sequence_mut())
        {
            for cluster_entry in clusters.iter_mut() {
                if let Some(cluster) = cluster_entry
                    .get_mut("cluster")
                    .and_then(|c| c.as_mapping_mut())
                {
                    // Get the current server URL and replace the port
                    if let Some(server) = cluster.get("server").and_then(|s| s.as_str()) {
                        // Server URL format: https://host:port
                        // Replace the port with host_port and change host to localhost
                        let new_server = if let Some(idx) = server.rfind(':') {
                            let after_colon = &server[idx + 1..];
                            if after_colon.chars().all(|c| c.is_ascii_digit()) {
                                // Replace both host and port for kind clusters
                                format!("https://127.0.0.1:{}", host_port)
                            } else {
                                format!("{}:{}", server, host_port)
                            }
                        } else {
                            format!("{}:{}", server, host_port)
                        };
                        cluster.insert(
                            serde_yaml::Value::String("server".to_string()),
                            serde_yaml::Value::String(new_server),
                        );
                    }

                    // Add insecure-skip-tls-verify for localhost connections
                    cluster.remove(&serde_yaml::Value::String(
                        "certificate-authority-data".to_string(),
                    ));
                    cluster.insert(
                        serde_yaml::Value::String("insecure-skip-tls-verify".to_string()),
                        serde_yaml::Value::Bool(true),
                    );
                }
            }
        }

        let modified_kubeconfig = serde_yaml::to_string(&kubeconfig_yaml)?;
        std::fs::write(&self.kubeconfig_path, modified_kubeconfig)?;

        Ok(())
    }
}

fn terminal_stderr_to_error(output: std::process::Output) -> anyhow::Error {
    anyhow::anyhow!(
        "{}\nCommand failed with exit code: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )
}

fn save_vcluster_helm_values(path: &str) -> anyhow::Result<()> {
    let json_values = json!({
        "controlPlane": {
            "distro": {
                "k8s": {
                    "enabled": true
                },
            },
            "backingStore": {
                "etcd": {
                    "deploy": {
                        "enabled": true
                    }
                }
            },
            /*
            "proxy": {
                "extraSANs": ["localhost", "172.23.0.3"]
            }
            */
        },
        "exportKubeConfig": {
            //"server": "https://172.23.0.3:30080",
            "insecure": true,
        },
        "sync": {
                "fromHost": {
                    "nodes": {
                        //"enabled": true,
                        //"syncBackChanges": true
                    },
                },
                "toHost": {
                    "persistentVolumes": {
                        "enabled": true,
                    },
                    "storageClasses": {
                        "enabled": true
                    },
                }
            }

        // "policies": {
        //     "podSecurityStandard": "baseline",
        //     "resourceQuota": {
        //         "enabled": true
        //     },
        //     "limitRange": {
        //         "enabled": true
        //     }
        // },
        // "exportKubeConfig": {
        //     "context": "vcluster-context",
        //     "secret": {
        //         "name": "vc-kubeconfig"
        //     }
        // }
    });

    let yaml_values = serde_yaml::from_str::<serde_yaml::Value>(&json_values.to_string())?;
    std::fs::write(path, serde_yaml::to_string(&yaml_values)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cluster::KindCluster;

    use super::*;
    use std::path::PathBuf;

    const CLUSTER_NAME_PREFIX: &str = "k8s-env";

    struct TestCluster {
        pub name: String,
        pub kubeconfig_path: PathBuf,
    }

    impl TestCluster {
        async fn create(name: &str) -> anyhow::Result<Self> {
            let kubeconfig_path = temp_kubeconfig_path(name);
            let _ = KindCluster::create(
                name,
                kubeconfig_path.clone(),
                Default::default(),
                &Default::default(),
            )
            .await
            .context("Failed to create kind cluster")?;
            Ok(Self {
                name: name.to_string(),
                kubeconfig_path,
            })
        }
    }

    fn temp_kubeconfig_path(name: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push(format!("{}.kubeconfig", name));
        path
    }

    async fn teardown_kind_cluster(cluster: TestCluster) -> anyhow::Result<()> {
        let kind_cluster = KindCluster::load(&cluster.name, cluster.kubeconfig_path).await?;
        kind_cluster.delete().await
    }

    // Provisions a real kind cluster via Docker, so it cannot run on a clean
    // checkout or in CI. Run explicitly with `cargo test -- --ignored`.
    #[ignore]
    #[tokio::test]
    async fn setup_vcluster() {
        let temp_cluster_name = format!("{}-vcluster", CLUSTER_NAME_PREFIX);
        let temp_cluster = TestCluster::create(&temp_cluster_name).await.unwrap();

        let kind_kubeconfig_path = temp_cluster.kubeconfig_path.clone();
        let vcluster_kubeconfig_path =
            temp_kubeconfig_path(format!("{}-inner", temp_cluster_name).as_str());

        let namespace = "tenant1";
        let host_cluster = HostClusterType::Kind(
            KindCluster::load(&temp_cluster_name, kind_kubeconfig_path.clone())
                .await
                .unwrap(),
        );

        let cluster = KubernetesClusterBuilder::new(host_cluster)
            .with_kubeconfig_path(vcluster_kubeconfig_path)
            .with_isolation_technology(ControlPlaneIsolation::VCluster(String::from(namespace)))
            .build()
            .await;
        assert!(
            cluster.is_ok(),
            "Failed to create client: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();
        let pods = cluster.list_all_pods().await;
        assert!(pods.is_ok(), "Failed to get pods: {:?}", pods.err());

        let _ = teardown_kind_cluster(temp_cluster).await;
    }
}

/// What a sandboxed runtime needs decided before the node boots.
///
/// These are cheap assertions about strings, and they are here because the
/// failure they guard is expensive: a handler containerd does not recognise,
/// or a missing device, leaves pods in `ContainerCreating` and is only
/// discovered after a full cluster build.
/// The per-tenant StorageClass is small, and the parts that matter are easy to
/// lose in a string.
#[cfg(test)]
mod tenant_storage_class_tests {
    use super::*;

    /// The reason this technology exists: without a Retain class, a tenant can
    /// only obtain a Retain volume by hand-building a hostPath
    /// PersistentVolume, and the reclaim-policy property ends up measuring
    /// hostPath instead.
    #[test]
    fn the_reclaim_policy_is_what_the_caller_asked_for() {
        assert!(tenant_storage_class("c", "Retain").contains("reclaimPolicy: Retain"));
        assert!(tenant_storage_class("c", "Delete").contains("reclaimPolicy: Delete"));
    }

    /// local-path provisions a directory on whichever node runs the pod, so it
    /// cannot pick one before the pod is scheduled. `Immediate` binding leaves
    /// the claim pending forever.
    #[test]
    fn it_waits_for_a_consumer_because_local_path_must() {
        let class = tenant_storage_class("c", "Retain");
        assert!(
            class.contains("provisioner: rancher.io/local-path"),
            "{class}"
        );
        assert!(
            class.contains("volumeBindingMode: WaitForFirstConsumer"),
            "{class}"
        );
    }

    /// One class per tenant, named for the tenant — the probe finds it by
    /// looking for its own namespace in the name.
    #[test]
    fn each_tenant_gets_a_class_named_for_it() {
        assert_eq!(
            retain_storage_class_name("tenant1"),
            "kumuteva-tenant1-retain"
        );
        assert_ne!(
            retain_storage_class_name("tenant1"),
            retain_storage_class_name("tenant2")
        );
    }

    #[test]
    fn it_parses_as_the_yaml_it_claims_to_be() {
        let class: serde_yaml::Value =
            serde_yaml::from_str(&tenant_storage_class("kumuteva-tenant1-retain", "Retain"))
                .expect("the StorageClass must be valid YAML");
        assert_eq!(class["kind"].as_str(), Some("StorageClass"));
        assert_eq!(
            class["metadata"]["name"].as_str(),
            Some("kumuteva-tenant1-retain")
        );
    }
}

#[cfg(test)]
mod sandbox_runtime_tests {
    use super::*;

    #[test]
    fn kata_registers_its_rust_shim_by_path() {
        let patch = SandboxRuntime::Kata.containerd_patch();

        assert!(
            patch.contains("containerd.runtimes.kata"),
            "the handler name must match the RuntimeClass: {patch}"
        );
        // The Rust shim is not on the node's PATH, so containerd has to be
        // told where it is.
        assert!(
            patch.contains("/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"),
            "{patch}"
        );
    }

    /// Without this, a privileged pod is handed the node's devices straight
    /// through the VM boundary — the boundary the property is measuring.
    #[test]
    fn kata_keeps_host_devices_out_of_privileged_containers() {
        assert!(SandboxRuntime::Kata
            .containerd_patch()
            .contains("privileged_without_host_devices = true"));
    }

    #[test]
    fn kata_asks_for_kvm_and_gvisor_asks_for_nothing() {
        assert_eq!(
            SandboxRuntime::Kata.extra_mounts(),
            vec![("/dev/kvm".to_string(), "/dev/kvm".to_string())]
        );
        assert!(SandboxRuntime::GVisor.extra_mounts().is_empty());
    }

    /// The handler in the patch and the handler in the RuntimeClass are the
    /// same string in two places; if they drift, pods never schedule.
    #[test]
    fn every_runtimes_handler_appears_in_its_own_patch() {
        for runtime in [SandboxRuntime::GVisor, SandboxRuntime::Kata] {
            let patch = runtime.containerd_patch();
            assert!(
                patch.contains(&format!("containerd.runtimes.{}", runtime.handler())),
                "{} handler missing from its patch: {patch}",
                runtime.name()
            );
        }
    }

    #[test]
    fn each_runtime_is_pinned_to_a_release() {
        for runtime in [SandboxRuntime::GVisor, SandboxRuntime::Kata] {
            assert!(
                !runtime.version().is_empty(),
                "an unpinned runtime makes a result irreproducible"
            );
        }
    }
}

#[cfg(test)]
mod tenant_network_policy_tests {
    use super::tenant_network_policies;

    fn policies() -> (serde_json::Value, serde_json::Value) {
        let (deny, egress) =
            tenant_network_policies(&["172.19.0.2".to_string()]).expect("policies must build");
        (
            serde_json::to_value(deny).expect("deny policy must serialise"),
            serde_json::to_value(egress).expect("egress policy must serialise"),
        )
    }

    /// Both policies say which directions they govern.
    ///
    /// Kubernetes infers `policyTypes` from which blocks are present, and that
    /// inference is what hid the egress defect below: adding an `egress` rule
    /// to permit DNS silently converted the namespace to egress-restricted.
    /// Stating it means a reader sees the direction without knowing the rule.
    #[test]
    fn policy_types_are_stated_not_inferred() {
        let (deny, egress) = policies();
        assert_eq!(deny["spec"]["policyTypes"], serde_json::json!(["Ingress"]));
        assert_eq!(egress["spec"]["policyTypes"], serde_json::json!(["Egress"]));
    }

    /// A tenant confined to its namespace must still work *inside* it.
    ///
    /// This is the regression that matters. The egress policy once listed only
    /// kube-system, which does not add DNS to an open namespace — it restricts
    /// the namespace to kube-system and nothing else, so the tenant loses its
    /// own pods and Services. It went unnoticed because kind's default CNI
    /// ignores NetworkPolicy entirely; under Calico it would have reported
    /// excellent network isolation for a tenant that had no network at all.
    #[test]
    fn egress_permits_the_tenants_own_namespace_as_well_as_dns() {
        let (_, egress) = policies();
        let rules = egress["spec"]["egress"]
            .as_array()
            .expect("egress must be a list of rules");

        let same_namespace = rules.iter().any(|rule| {
            rule["to"].as_array().is_some_and(|to| {
                to.iter().any(|peer| {
                    peer.get("podSelector").is_some() && peer.get("namespaceSelector").is_none()
                })
            })
        });
        assert!(
            same_namespace,
            "without a same-namespace rule the tenant cannot reach its own pods: {egress}"
        );

        let dns = rules.iter().any(|rule| {
            rule["to"].as_array().is_some_and(|to| {
                to.iter().any(|peer| {
                    peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        == "kube-system"
                })
            })
        });
        assert!(dns, "CoreDNS lives in kube-system: {egress}");
    }

    /// A tenant must still be able to reach the API server.
    ///
    /// It is not selectable by namespace — clients reach it through the
    /// `kubernetes` Service, which DNATs to the control plane's host address —
    /// so the egress policy has to name it by address or cut the tenant off
    /// from Kubernetes entirely. That is not a hypothetical: composing this
    /// policy with a per-tenant CoreDNS produced a resolver that could not list
    /// Services and answered SERVFAIL to everything, its own tenant's names
    /// included.
    #[test]
    fn egress_permits_the_api_server_by_address() {
        let (_, egress) = policies();
        let rules = egress["spec"]["egress"].as_array().expect("egress rules");

        let api = rules.iter().any(|rule| {
            rule["to"].as_array().is_some_and(|to| {
                to.iter()
                    .any(|peer| peer["ipBlock"]["cidr"] == "172.19.0.2/32")
            })
        });
        assert!(
            api,
            "without this the tenant cannot talk to Kubernetes at all: {egress}"
        );
    }

    /// Ingress is what actually blocks the other tenant: same namespace only.
    #[test]
    fn ingress_admits_only_the_tenants_own_pods() {
        let (deny, _) = policies();
        let from = deny["spec"]["ingress"][0]["from"]
            .as_array()
            .expect("one from-clause");
        assert_eq!(from.len(), 1, "a second peer would widen the hole: {deny}");
        assert!(
            from[0].get("namespaceSelector").is_none(),
            "a namespaceSelector here would admit another namespace: {deny}"
        );
    }
}

#[cfg(test)]
mod capsule_tenant_policy_tests {
    use super::{CapsuleTenantPolicy, KubernetesClusterBuilder};

    fn spec_json(policy: CapsuleTenantPolicy) -> serde_json::Value {
        spec_json_for(policy, true)
    }

    fn spec_json_for(policy: CapsuleTenantPolicy, supports_rules: bool) -> serde_json::Value {
        let spec =
            KubernetesClusterBuilder::capsule_tenant_spec("tenant1-admin", policy, supports_rules);
        serde_json::to_value(spec).expect("the Tenant spec must serialise")
    }

    /// The hardened tenant pins the pull policy through whichever field the
    /// installed Capsule implements, and never both.
    ///
    /// Sending `spec.rules` to 0.10.0 fails the entire setup — server-side apply
    /// validates rather than prunes — and sending only `imagePullPolicies` to
    /// 0.13 configures a field that version no longer acts on, which is a policy
    /// that exists in the object and nowhere in the cluster. Either mistake
    /// makes `capsule-hardened` describe something other than what ran.
    #[test]
    fn the_pull_policy_uses_the_mechanism_the_crd_implements() {
        let modern = spec_json_for(CapsuleTenantPolicy::Hardened, true);
        assert!(modern.get("rules").is_some(), "{modern}");
        assert!(
            modern.get("imagePullPolicies").is_none(),
            "0.13 ignores this field, so setting it would be decoration: {modern}"
        );
        assert_eq!(
            modern["rules"][0]["enforce"]["workloads"]["registries"][0]["policy"][0],
            "Always"
        );

        let legacy = spec_json_for(CapsuleTenantPolicy::Hardened, false);
        assert!(
            legacy.get("rules").is_none(),
            "0.10.0 rejects an undeclared field outright: {legacy}"
        );
        assert_eq!(legacy["imagePullPolicies"], serde_json::json!(["Always"]));
    }

    /// Neither mechanism belongs on the unconfigured tenant, whichever Capsule
    /// is installed — that arm exists to show what Capsule does on its own.
    #[test]
    fn the_default_tenant_pins_no_pull_policy_on_either_version() {
        for supports_rules in [true, false] {
            let spec = spec_json_for(CapsuleTenantPolicy::Default, supports_rules);
            assert!(spec.get("rules").is_none(), "{spec}");
            assert!(spec.get("imagePullPolicies").is_none(), "{spec}");
        }
    }

    #[test]
    fn the_default_tenant_carries_an_owner_and_no_policy() {
        // The point of the `capsule` arm: what installing Capsule and declaring
        // a tenant actually gives you. If this ever starts carrying policy, the
        // comparison against `capsule-hardened` stops meaning anything.
        let spec = spec_json(CapsuleTenantPolicy::Default);
        assert_eq!(spec["owners"][0]["name"], "tenant1-admin");
        for field in [
            "namespaceOptions",
            "resourceQuotas",
            "serviceOptions",
            "rules",
        ] {
            assert!(spec.get(field).is_none(), "{field} must be unset");
        }
    }

    #[test]
    fn the_hardened_tenant_requires_always_through_the_rules_api() {
        // Regression: the pull policy was first written to `imagePullPolicies`,
        // which v1beta2 deprecates and capsule 0.13 ignores. It validated, it
        // serialised, and it enforced nothing — the benchmark kept failing
        // against a tenant that looked correctly configured.
        //
        // The rule reads "allow every registry, but only with Always", because
        // the policy list is consulted only after a registry reaches a final
        // allow. A deny action would refuse the image and never check it.
        let spec = spec_json(CapsuleTenantPolicy::Hardened);
        let enforce = &spec["rules"][0]["enforce"];
        assert_eq!(enforce["action"], "allow");

        let registry = &enforce["workloads"]["registries"][0];
        assert_eq!(registry["exp"], ".*");
        assert_eq!(registry["policy"][0], "Always");

        let targets = enforce["workloads"]["targets"]
            .as_array()
            .expect("targets must be a list");
        // Init and ephemeral containers pull images too.
        for target in [
            "pod/containers",
            "pod/initcontainers",
            "pod/ephemeralcontainers",
        ] {
            assert!(
                targets.iter().any(|t| t == target),
                "{target} must be enforced"
            );
        }
    }

    #[test]
    fn the_hardened_tenant_sets_the_quota_keys_the_benchmarks_read() {
        // kubectl-mtb joins the quota's resource names into one string and
        // looks for substrings, so a missing key is a silent failure rather
        // than an error.
        let spec = spec_json(CapsuleTenantPolicy::Hardened);
        let quotas = spec["resourceQuotas"]["items"]
            .as_array()
            .expect("quota items");
        let keys: Vec<String> = quotas
            .iter()
            .flat_map(|item| item["hard"].as_object().unwrap().keys().cloned())
            .collect();
        let joined = keys.join(" ");

        for compute in ["cpu", "memory", "ephemeral-storage"] {
            assert!(joined.contains(compute), "{compute} missing from quotas");
        }
        for object in [
            "pods",
            "services",
            "replicationcontrollers",
            "resourcequotas",
            "secrets",
            "configmaps",
            "persistentvolumeclaims",
            "services.nodeports",
            "services.loadbalancers",
        ] {
            assert!(joined.contains(object), "{object} missing from quotas");
        }
    }

    #[test]
    fn the_hardened_tenant_defaults_limits_so_the_quota_does_not_mask_admission() {
        // Regression for a silent inflation of the benchmark score.
        //
        // Naming `limits.cpu` in a ResourceQuota makes it mandatory for every
        // pod in the namespace. kubectl-mtb's probes omit it, so the quota
        // rejected them before Pod Security or Capsule's webhooks were ever
        // consulted — and since the benchmarks treat any rejection as a pass,
        // the tenant scored well for refusing everything rather than for
        // enforcing anything.
        let spec = spec_json(CapsuleTenantPolicy::Hardened);
        let limits = &spec["limitRanges"]["items"][0]["limits"][0];
        assert_eq!(limits["type"], "Container");
        for resource in ["cpu", "memory", "ephemeral-storage"] {
            assert!(
                !limits["default"][resource].is_null(),
                "{resource} needs a default limit"
            );
            assert!(
                !limits["defaultRequest"][resource].is_null(),
                "{resource} needs a default request"
            );
        }
    }

    #[test]
    fn the_hardened_tenant_enforces_pod_security_and_blocks_nodeports() {
        let spec = spec_json(CapsuleTenantPolicy::Hardened);
        assert_eq!(
            spec["namespaceOptions"]["additionalMetadata"]["labels"]
                ["pod-security.kubernetes.io/enforce"],
            "restricted"
        );
        assert_eq!(spec["serviceOptions"]["allowedServices"]["nodePort"], false);
    }
}
