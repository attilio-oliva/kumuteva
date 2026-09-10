//! The cross-tenant breach experiment.
//!
//! Every data-plane isolation test in this tool asks one question in one shape:
//!
//! 1. the victim plants a secret in its own namespace
//! 2. we confirm the secret really exists
//! 3. the intruder attempts to observe it from the other tenant
//! 4. observed ⇒ no isolation; not observed ⇒ isolated
//!
//! A platform that refuses to let the intruder even try has itself prevented
//! the breach, and that is a verdict rather than a failed run.
//!
//! This module is that algorithm, written once. Each experiment supplies only
//! what distinguishes it: which pods, how to read the secret, and what counts
//! as having seen it.
//!
//! ## Why it is centralised
//!
//! The step that matters most is (2), and it is the one hand-written
//! experiments kept omitting. Without it, a target that failed to start — image
//! pull error, a denied `ipcmk`, an evicted pod — leaves the intruder with
//! nothing to find, and "found nothing" is recorded as **isolation**. The
//! experiment did not run and the report says the platform is secure. Here that
//! case is `Unknown`, once, for every experiment.

use std::time::Duration;

use anyhow::Result;
use k8s_openapi::api::core::v1::{Pod, Service};
use tokio::time::sleep;
use tracing::info;

/// How long to wait for a pod's IP to appear in its status after it reports
/// Running, in one-second attempts.
const ADDRESS_ATTEMPTS: u32 = 30;

/// How long to wait for the target's secret to appear in its logs after it
/// reports Ready, in one-second attempts.
///
/// Generous because the cost of being wrong is asymmetric: waiting too long
/// slows a run, while giving up too early throws the experiment away as
/// `Unknown` and looks like a property that could not be measured.
const SECRET_ATTEMPTS: u32 = 60;

use crate::assessment::{
    admission_refusal, CrossTenantResult, IsolationLevel, TenantClusterConfig,
};

/// One tenant plants a secret; the other tries to read it.
pub struct BreachExperiment {
    /// Human-readable name, used in the details a reader sees in the report.
    pub what: &'static str,
    /// Runs in the victim's namespace. Plants the secret and prints it.
    pub target: Pod,
    /// Optional Service fronting the target.
    ///
    /// When present, [`PlantedSecret::address`] becomes its ClusterIP rather
    /// than the pod's — "the address the intruder should aim at" is the
    /// interesting quantity, and which of the two it is depends on what the
    /// experiment is testing rather than on anything the intruder needs to know.
    pub target_service: Option<Service>,
    /// How to recover the secret from the target's own logs.
    pub secret: Secret,
    /// Runs in the intruder's namespace.
    pub intruder: Intruder,
    /// What in the intruder's output means it saw the secret.
    pub breach: BreachCondition,
}

/// How the intruder depends on where the target ended up.
///
/// The only part that cannot be a plain value. The variants name the reason
/// rather than hiding it behind a closure, because getting it wrong is silent:
/// an intruder placed on the wrong node inspects an unrelated machine, finds
/// nothing, and reports isolation it never tested.
pub enum Intruder {
    /// Must share the target's node — host namespaces are per-node.
    OnTargetNode(fn(node: &str) -> Pod),
    /// Must know the target's address — reachability probes.
    AtTargetAddress(fn(address: &str) -> Pod),
    /// Placement-independent. Boxed: a `Pod` dwarfs the other variants,
    /// which are function pointers.
    Anywhere(Box<Pod>),
    /// Needs more of the target than where it landed.
    ///
    /// One case: the privileged-escape probe reads the host kernel's identity
    /// out of the target's logs — the target is the only thing that can report
    /// it, since a container shares the host kernel but not its distribution —
    /// and picks a build image to match.
    FromTarget(fn(&PlantedSecret) -> Pod),
}

/// What the target publishes to identify a breach and how to read it out of its logs.
///
/// Every variant answers the same question — *did the target actually do its
/// job?* — with the best evidence that experiment can offer. Ordered strongest
/// to weakest.
pub enum Secret {
    /// The target prints a value; take the token after this prefix.
    /// `Published("Fingerprint:")` recovers `a1b2c3` from `Fingerprint: a1b2c3`.
    ///
    /// The strongest control: the value is unpredictable, so the intruder
    /// repeating it cannot be coincidence.
    Published(&'static str),
    /// The target prints this exact line, proving it got far enough to plant
    /// something. Used where the breach is judged on the intruder's own
    /// conclusion rather than on a value.
    ///
    /// Owned rather than `&'static str` because several experiments generate
    /// their marker at run time — `TENANT1_NODEPORT_MARKER_<uuid>` — which is
    /// the strongest control of all: unpredictable *and* known in advance, so
    /// the intruder repeating it cannot be coincidence or a stale artefact of
    /// an earlier run.
    ConfirmedBy(String),
    /// The target prints nothing, so readiness is the only confirmation
    /// available.
    ///
    /// Currently unused, and that is the healthy state: every experiment now
    /// has its target publish something checkable. Kept because it names the
    /// weakest control available, and a future experiment reaching for it
    /// should have to see what it is settling for.
    #[allow(dead_code)]
    ///
    /// Weaker, and the weakness is real: a pod can be `Ready` while its
    /// workload has not done what the experiment needs. Used only where the
    /// target is a bare long-running process with nothing to report.
    ReadinessOnly,
}

/// What counts as having seen it.
pub enum BreachCondition {
    /// The intruder's output contains the secret itself.
    IntruderRepeatsSecret,
    /// The intruder reached its own conclusion and said so, e.g.
    /// `TENANT2_PROCESS_FOUND`.
    IntruderReports(&'static str),
    /// The outcome is not binary, so the experiment classifies it itself.
    ///
    /// Exactly one experiment needs this, and the reason is real rather than
    /// convenience: the privileged-escape probe distinguishes four outcomes —
    /// it saw another tenant, it loaded a module but saw nobody, it was denied
    /// EPERM, or its toolchain never built — which map onto `None`, `Hard`,
    /// `Soft` and `Unknown` respectively. Collapsing that to seen/not-seen
    /// would throw away the distinction between "isolated" and "we failed to
    /// test".
    ///
    /// It still gets the pipeline: marker/secret control, node pinning, refusal
    /// handling, cleanup. Only the judgement is its own. A second experiment
    /// reaching for this would be a sign the abstraction is not paying for
    /// itself.
    Decided(fn(intruder_output: &str) -> CrossTenantResult),
}

/// What the target turned out to be once the cluster had scheduled it.
///
/// Produced by [`plant_secret`]; nothing declares one. This is the only route
/// by which an [`Intruder`] learns the node or address it needs.
pub struct PlantedSecret {
    pub node: String,
    /// Where the intruder should aim: the Service's ClusterIP when the
    /// experiment declares one, otherwise the target pod's own IP.
    pub address: String,
    pub secret: String,
    /// Everything the target printed. Most experiments need only the secret;
    /// the privileged-escape probe reads the host kernel identity from here.
    pub logs: String,
}

/// What happened when the intruder tried.
enum Observation {
    /// The platform would not let the intruder run at all.
    Refused(String),
    /// The intruder had to share the victim's node, and that node is not one
    /// this tenant can place a pod on.
    TargetNodeUnreachable(String),
    /// Admission accepted it and the runtime then would not start it.
    CouldNotRun {
        reason: String,
        /// Whether the pod that was turned away had asked for privilege or a
        /// host namespace, which is what separates a sandbox declining a
        /// dangerous request from a probe that is simply broken.
        asked_for_host_privilege: bool,
    },
    /// It ran; this is what it printed.
    Saw(String),
}

/// Run one experiment end to end.
///
/// The four numbered steps of the method, and nothing else. Everything
/// subsystem-specific lives in `exp`.
pub async fn run_breach_experiment(
    exp: &BreachExperiment,
    intruder_tenant: &TenantClusterConfig,
    victim_tenant: &TenantClusterConfig,
) -> Result<CrossTenantResult> {
    let target_name = pod_name(&exp.target);

    // The body runs to completion and cleanup follows on every path out of it.
    // Rust has no async Drop, so this is what makes that true even for the
    // early returns below — a leaked probe pod takes out a later experiment,
    // because probe names are fixed and the second create fails.
    let outcome = async {
        // 1 & 2 — plant, and confirm it is really there.
        let Some(planted) = plant_secret(exp, victim_tenant).await? else {
            return Ok(nothing_was_planted(exp, victim_tenant));
        };

        // 3 — the intruder can only be built now that placement is known.
        match observe(exp, intruder_tenant, &planted).await? {
            Observation::Refused(why) => Ok(platform_refused(exp, &why)),
            Observation::TargetNodeUnreachable(why) => Ok(target_node_unreachable(exp, &why)),
            Observation::CouldNotRun {
                reason,
                asked_for_host_privilege,
            } => Ok(runtime_would_not_run(
                exp,
                asked_for_host_privilege,
                &reason,
            )),
            // 4
            Observation::Saw(output) => Ok(judge(exp, &planted.secret, &output)),
        }
    }
    .await;

    clean_up(exp, intruder_tenant, victim_tenant, &target_name).await;
    outcome
}

/// Steps 1 and 2: create the target, wait for it, and read back both its
/// placement and the secret it planted.
///
/// `None` means it planted nothing, which is not a measurement.
async fn plant_secret(
    exp: &BreachExperiment,
    victim: &TenantClusterConfig,
) -> Result<Option<PlantedSecret>> {
    let name = pod_name(&exp.target);

    victim
        .cluster
        .create_pod_in_namespace(&exp.target, &victim.namespace)
        .await?;
    victim
        .cluster
        .wait_for_pod_to_be_ready(&name, &victim.namespace)
        .await?;

    // Only now does the target have a node and an address.
    let pod = victim
        .cluster
        .get_pod_in_namespace(&name, &victim.namespace)
        .await?;
    let node = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.clone())
        .unwrap_or_default();
    // The address the intruder will aim at. Retried, because a pod can report
    // Running a moment before its IP appears in status — Kube-OVN is slower to
    // populate it than the CNIs this was written against.
    //
    // `unwrap_or_default()` here used to hand the intruder an empty string. It
    // then connected to nothing, observed no secret, and the run recorded Hard
    // isolation for a cluster enforcing none — the intruder had never been
    // pointed anywhere. Verified by hand on Kube-OVN: pod-to-pod curl succeeds
    // while the probe reported the tenants isolated.
    let mut address = pod
        .status
        .as_ref()
        .and_then(|status| status.pod_ip.clone())
        .unwrap_or_default();

    for _ in 0..ADDRESS_ATTEMPTS {
        if !address.is_empty() {
            break;
        }
        sleep(Duration::from_secs(1)).await;
        address = victim
            .cluster
            .get_pod_in_namespace(&name, &victim.namespace)
            .await
            .ok()
            .and_then(|pod| pod.status.and_then(|status| status.pod_ip))
            .unwrap_or_default();
    }

    // A Service, where the experiment declares one. Created after the target so
    // it has a pod to select, and its ClusterIP supersedes the pod IP as the
    // address the intruder aims at.
    if let Some(service) = &exp.target_service {
        victim
            .cluster
            .create_namespaced_resource::<Service>(service, &victim.namespace)
            .await?;
        let created = victim
            .cluster
            .get_resource_in_namespace::<Service>(
                service.metadata.name.as_deref().unwrap_or_default(),
                &victim.namespace,
            )
            .await?;
        address = created
            .spec
            .and_then(|spec| spec.cluster_ip)
            .unwrap_or(address);
    }

    // Aiming an intruder at nowhere produces silence, and silence is what this
    // executor reads as isolation — so refuse to run rather than report it.
    if address.is_empty() && matches!(exp.intruder, Intruder::AtTargetAddress(_)) {
        info!(
            "{}: the target never reported an address, so the intruder has nothing to aim at",
            exp.what
        );
        return Ok(None);
    }

    // Readiness means the pod is Running, not that its script has finished
    // printing. Reading the logs once, right here, is a race the harness lost
    // intermittently: under gVisor the same `ipc-target` planted its
    // fingerprint on three runs out of four, and the fourth reported that the
    // target "never planted its secret" — a slower runtime, not a difference
    // in isolation. Verified by hand afterwards: all three `ipcmk` calls
    // succeed under `runsc`, so nothing was ever wrong but the timing.
    //
    // Polling keeps the control honest rather than weakening it: a target that
    // truly plants nothing still reports nothing, it just takes the full
    // window to say so.
    let mut logs = String::new();
    let mut secret = String::new();
    for _ in 0..SECRET_ATTEMPTS {
        logs = victim
            .cluster
            .get_pod_logs(&name, &victim.namespace)
            .await
            .unwrap_or_default();
        secret = recover_secret(&exp.secret, &logs);
        if !secret.is_empty() {
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    if secret.is_empty() {
        info!(
            "{}: the target in {} planted nothing",
            exp.what, victim.namespace
        );
        return Ok(None);
    }

    Ok(Some(PlantedSecret {
        node,
        address,
        secret,
        logs,
    }))
}

/// Step 3: build the intruder for this target, run it, and collect its output.
async fn observe(
    exp: &BreachExperiment,
    intruder_tenant: &TenantClusterConfig,
    planted: &PlantedSecret,
) -> Result<Observation> {
    let intruder = build_intruder(&exp.intruder, planted);
    let name = pod_name(&intruder);

    if let Err(error) = intruder_tenant
        .cluster
        .create_pod_in_namespace(&intruder, &intruder_tenant.namespace)
        .await
    {
        return match admission_refusal(&error) {
            Some(message) => Ok(Observation::Refused(message)),
            // Not a refusal: something is wrong with the run itself, and
            // reporting it as isolation would be an invention.
            None => Err(error),
        };
    }

    wait_for_completion(intruder_tenant, &name).await;

    // Before reading logs, ask whether there was ever a process to write them.
    let landed = intruder_tenant
        .cluster
        .get_pod_in_namespace(&name, &intruder_tenant.namespace)
        .await
        .ok();
    // Pinned to a node this cluster does not have.
    //
    // Host namespaces are per-node, so these intruders name the victim's node
    // directly. Where the tenants are separate clusters — KubeVirt gives each
    // its own VMs — that name means nothing on the intruder's side: the pod is
    // never scheduled, never runs, and writes no logs. Read as output, the
    // silence says "the intruder looked and saw nothing", and the marker-based
    // experiments scored it as isolation. The property was never tested.
    if let Some(reason) = landed.as_ref().and_then(never_placed) {
        // Confirm it rather than infer it: ask this tenant which nodes it has.
        // A pinned pod that never ran for some *other* reason must not be
        // reported as an absent node.
        let pinned = intruder.spec.as_ref().and_then(|spec| spec.node_name.clone());
        let absent = match (&pinned, intruder_tenant.cluster.list_nodes().await) {
            (Some(node), Ok(nodes)) => !nodes
                .iter()
                .any(|known| known.metadata.name.as_deref() == Some(node.as_str())),
            // No node list to check against — the tenant may not read nodes at
            // all. The pod being pinned and never claimed is the evidence left.
            (Some(_), Err(_)) => true,
            (None, _) => false,
        };

        if absent {
            return Ok(Observation::TargetNodeUnreachable(reason));
        }

        return Ok(Observation::CouldNotRun {
            reason,
            asked_for_host_privilege: asks_for_host_privilege(&intruder),
        });
    }

    if let Some(reason) = landed.as_ref().and_then(never_started) {
        return Ok(Observation::CouldNotRun {
            reason,
            asked_for_host_privilege: asks_for_host_privilege(&intruder),
        });
    }

    Ok(Observation::Saw(
        intruder_tenant
            .cluster
            .get_pod_logs(&name, &intruder_tenant.namespace)
            .await
            .unwrap_or_default(),
    ))
}

/// Why this pod never got onto a node, if it never did.
///
/// Two shapes, and the second is the one that matters here.
///
/// A pod the *scheduler* rejected carries `PodScheduled=False` with a message.
/// But these intruders are pinned with `spec.nodeName`, which bypasses the
/// scheduler completely — nothing ever evaluates them, so no condition is
/// written at all. Naming a node that does not exist simply leaves the pod
/// Pending forever, with no conditions, no events and no container statuses.
///
/// Reading only the first shape missed every one of them, which is how a probe
/// that never ran kept reaching the verdict stage with empty logs.
fn never_placed(pod: &Pod) -> Option<String> {
    let status = pod.status.as_ref()?;
    if status.phase.as_deref() != Some("Pending") {
        return None;
    }

    if let Some(condition) = status.conditions.as_ref().and_then(|conditions| {
        conditions
            .iter()
            .find(|condition| condition.type_ == "PodScheduled" && condition.status == "False")
    }) {
        return Some(
            condition
                .message
                .clone()
                .unwrap_or_else(|| condition.reason.clone().unwrap_or_default()),
        );
    }

    // Pinned, and no kubelet ever claimed it. A pod on a real node reports
    // container statuses well before this point — the executor has already
    // waited for it to finish.
    let pinned = pod.spec.as_ref()?.node_name.as_deref()?;
    let never_ran = status
        .container_statuses
        .as_ref()
        .is_none_or(|statuses| statuses.is_empty());
    never_ran.then(|| format!("pinned to node {pinned}, which never accepted it"))
}

/// The intruder had to stand on the victim's node and cannot.
///
/// `Hard`, and it is earned rather than assumed: the tenant asked the platform
/// to place a pod on that node and was told there is no such node here. Host
/// namespaces are per-node, so a node the intruder cannot reach carries no
/// namespace it could share — which is exactly what a lone tenant sees, its own
/// nodes and no others.
///
/// Distinct from silence. The pod never ran, so nothing it failed to print is
/// evidence of anything, and reading those empty logs as "looked and saw
/// nothing" is what scored this as isolation without testing it.
fn target_node_unreachable(exp: &BreachExperiment, why: &str) -> CrossTenantResult {
    CrossTenantResult {
        isolation: IsolationLevel::Hard,
        autonomy: true,
        details: format!(
            "{}: the victim's node is not one this tenant can place a pod on, so they \
             share no node and no per-node namespace — {why}",
            exp.what
        ),
    }
}

/// Why the pod's containers never started, if they never did.
///
/// A container that fails to start still answers a log request — containerd
/// puts *its own* error there, and that error quotes the container's argv. A
/// probe's argv carries the very markers `judge` searches for, so reading
/// those logs as probe output reports a breach for a probe that never ran.
///
/// Seen under gVisor, which refuses privileged containers: the log of the
/// refused `spy-process` pod is `starting container: ... [sh -c ... grep -i
/// 'TENANT2_UNIQUE_MARKER' ...]`, and the marker in that echoed command line
/// was enough to score the property as breached.
fn never_started(pod: &Pod) -> Option<String> {
    let statuses = pod.status.as_ref()?.container_statuses.as_ref()?;

    statuses.iter().find_map(|status| {
        let state = status.state.as_ref()?;
        // Terminated with nothing ever having run: the runtime rejected the
        // container rather than the container exiting.
        if let Some(terminated) = &state.terminated {
            if terminated.reason.as_deref() == Some("StartError") {
                return Some(
                    terminated
                        .message
                        .clone()
                        .unwrap_or_else(|| "StartError".to_string()),
                );
            }
        }
        // Still waiting, in one of the states kubelet uses for "the runtime
        // would not take this container".
        let waiting = state.waiting.as_ref()?;
        let reason = waiting.reason.as_deref()?;
        matches!(
            reason,
            "CreateContainerError" | "RunContainerError" | "CreateContainerConfigError"
        )
        .then(|| match &waiting.message {
            Some(message) => format!("{reason}: {message}"),
            None => reason.to_string(),
        })
    })
}

/// Did this pod ask for privilege or for one of the node's namespaces?
///
/// The discriminator for a start failure. A sandbox turning away a request
/// like this is the isolation mechanism working; anything else failing to
/// start is the harness at fault, and the two must not report the same thing.
fn asks_for_host_privilege(pod: &Pod) -> bool {
    let Some(spec) = &pod.spec else {
        return false;
    };

    let host_namespace = [
        spec.host_pid,
        spec.host_ipc,
        spec.host_network,
        spec.host_users,
    ]
    .contains(&Some(true));

    host_namespace
        || spec.containers.iter().any(|container| {
            container
                .security_context
                .as_ref()
                .and_then(|context| context.privileged)
                == Some(true)
        })
}

fn build_intruder(intruder: &Intruder, planted: &PlantedSecret) -> Pod {
    match intruder {
        Intruder::OnTargetNode(build) => build(&planted.node),
        Intruder::AtTargetAddress(build) => build(&planted.address),
        Intruder::Anywhere(pod) => (**pod).clone(),
        Intruder::FromTarget(build) => build(planted),
    }
}

async fn wait_for_completion(tenant: &TenantClusterConfig, name: &str) {
    let _ = tenant
        .cluster
        .watch_pod_until_condition(name, &tenant.namespace, |event| async move {
            match event {
                kube::core::WatchEvent::Modified(pod) => pod
                    .status
                    .as_ref()
                    .and_then(|status| status.phase.as_deref())
                    .is_some_and(|phase| phase == "Succeeded" || phase == "Failed"),
                _ => false,
            }
        })
        .await;
}

async fn clean_up(
    exp: &BreachExperiment,
    intruder_tenant: &TenantClusterConfig,
    victim_tenant: &TenantClusterConfig,
    target_name: &str,
) {
    // The intruder's name is only knowable by building it, and by this point
    // the placement may be gone — but the name does not depend on placement,
    // so any target facts will do to recover it.
    let placeholder = PlantedSecret {
        node: String::new(),
        address: String::new(),
        secret: String::new(),
        logs: String::new(),
    };
    let intruder_name = pod_name(&build_intruder(&exp.intruder, &placeholder));

    let pods = [
        (victim_tenant, target_name),
        (intruder_tenant, intruder_name.as_str()),
    ];

    // Delete both first, then wait for both: deletion is the slow part, and
    // serialising it doubles the wait for no benefit.
    for (tenant, name) in pods {
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(name, &tenant.namespace)
            .await;
    }

    // Waiting is not optional. Probe names are fixed and reused across
    // experiments within a subsystem, so returning while a pod is still
    // Terminating makes the *next* experiment's create fail with
    // `AlreadyExists: object is being deleted`. That is neither an admission
    // refusal nor a measurement, so it propagates and aborts the whole
    // assessment — which is exactly what it did the first time this ran.
    for (tenant, name) in pods {
        let _ = tenant
            .cluster
            .wait_for_pod_deletion(name, &tenant.namespace)
            .await;
    }

    if let Some(service) = &exp.target_service {
        let _ = victim_tenant
            .cluster
            .delete_resource_in_namespace::<Service>(
                service.metadata.name.as_deref().unwrap_or_default(),
                &victim_tenant.namespace,
            )
            .await;
    }
}

// =============================================================================
// The judgements. All pure, all testable without a cluster.
// =============================================================================

/// Pull the secret out of the target's logs.
fn recover_secret(secret: &Secret, logs: &str) -> String {
    match secret {
        // Readiness was already established by the caller; there is nothing in
        // the logs to find, so report a placeholder that is never compared.
        Secret::ReadinessOnly => "<ready>".to_string(),
        Secret::ConfirmedBy(marker) => {
            if logs.contains(marker.as_str()) {
                marker.clone()
            } else {
                String::new()
            }
        }
        Secret::Published(prefix) => logs
            .lines()
            .find(|line| line.contains(prefix))
            .and_then(|line| line.split(prefix).nth(1))
            .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default(),
    }
}

/// Step 4.
fn judge(exp: &BreachExperiment, secret: &str, intruder_output: &str) -> CrossTenantResult {
    let saw_it = match &exp.breach {
        // An empty secret would make `contains` trivially true, which is why
        // `plant_secret` refuses to return one.
        BreachCondition::IntruderRepeatsSecret => {
            !secret.is_empty() && intruder_output.contains(secret)
        }
        BreachCondition::IntruderReports(marker) => intruder_output.contains(marker),
        // Judged by the experiment; the binary path below does not apply.
        BreachCondition::Decided(classify) => return classify(intruder_output),
    };

    if saw_it {
        CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: format!(
                "{}: the intruder observed the other tenant's secret — not isolated",
                exp.what
            ),
        }
    } else {
        CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: format!(
                "{}: the secret was planted and the intruder could not observe it",
                exp.what
            ),
        }
    }
}

/// The platform would not let the intruder run.
///
/// `Soft`, not `Hard`: being refused is the platform preventing the attempt,
/// and the refusal itself tells the intruder the restriction exists. The three
/// hand-written experiments disagreed about this — two said `Hard`, one said
/// `Soft` — and having one pipeline forces one answer.
fn platform_refused(exp: &BreachExperiment, why: &str) -> CrossTenantResult {
    CrossTenantResult {
        isolation: IsolationLevel::Soft(format!("Intruder refused at admission: {why}")),
        autonomy: false,
        details: format!(
            "{}: the platform refused to run the intruder at all — {why}",
            exp.what
        ),
    }
}

/// Admission let the intruder through and the runtime would not start it.
///
/// The same verdict as [`platform_refused`], reached one stage later. What
/// decides soft or hard is not *where* the request died but what the tenant
/// can infer from its dying: an intruder turned away because the thing it
/// asked for is not permitted learns that a restriction exists, and that is
/// soft. Hard is reserved for the case where the operation runs and returns
/// what a lone tenant would have got anyway.
///
/// So a sandbox refusing a privileged pod is soft, not hard. It never reaches
/// the point of trying to observe the other tenant; the request itself is
/// what was stopped. Autonomy is false for the same reason — the operation,
/// taken on its own, was not allowed.
///
/// Kept separate from `platform_refused` only so the details line can say
/// which stage refused, which is the difference between a policy webhook and
/// a runtime that cannot honour the request.
fn runtime_would_not_run(
    exp: &BreachExperiment,
    asked_for_host_privilege: bool,
    why: &str,
) -> CrossTenantResult {
    // Nothing unusual was asked for, so nothing explains the refusal: this is
    // the "random error in the middle" case, and it is not a measurement.
    // Calling it isolation would be the reassuring answer to a broken probe.
    if !asked_for_host_privilege {
        return CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "{}: the intruder never started, and it had asked for no \
                 privilege that would explain a runtime refusing it — {why}",
                exp.what
            ),
        };
    }

    CrossTenantResult {
        isolation: IsolationLevel::Soft(format!(
            "Runtime would not start a container asking for host privilege: {why}"
        )),
        autonomy: false,
        details: format!(
            "{}: the request for host privilege was refused by the runtime, so \
             the intruder never got to attempt the cross-tenant operation — {why}",
            exp.what
        ),
    }
}

/// The target planted nothing, so nothing was measured.
fn nothing_was_planted(exp: &BreachExperiment, victim: &TenantClusterConfig) -> CrossTenantResult {
    CrossTenantResult {
        isolation: IsolationLevel::Unknown,
        autonomy: true,
        details: format!(
            "{}: the target in {} never planted its secret, so the intruder \
             finding nothing proves nothing about isolation",
            exp.what, victim.namespace
        ),
    }
}

/// The pod's own name, so nothing has to be passed alongside it and drift.
fn pod_name(pod: &Pod) -> String {
    pod.metadata.name.clone().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::probe::ProbePod;

    pub(super) fn experiment(breach: BreachCondition) -> BreachExperiment {
        BreachExperiment {
            what: "test",
            target: ProbePod::new("target").build(),
            target_service: None,
            secret: Secret::Published("Fingerprint:"),
            intruder: Intruder::Anywhere(Box::new(ProbePod::new("intruder").build())),
            breach,
        }
    }

    #[test]
    fn a_published_secret_is_the_token_after_the_prefix() {
        let logs = "starting up\nFingerprint: a1b2c3\ndone\n";
        assert_eq!(
            recover_secret(&Secret::Published("Fingerprint:"), logs),
            "a1b2c3"
        );
    }

    #[test]
    fn a_missing_published_secret_recovers_as_empty() {
        // The case the hand-written experiments mishandled: the target ran but
        // published nothing, and they read that as isolation.
        assert_eq!(
            recover_secret(&Secret::Published("Fingerprint:"), "crashed early\n"),
            ""
        );
    }

    #[test]
    fn a_confirmation_marker_must_actually_appear() {
        assert_eq!(
            recover_secret(
                &Secret::ConfirmedBy("TENANT2_MARKER".to_string()),
                "log\nTENANT2_MARKER: up\n"
            ),
            "TENANT2_MARKER"
        );
        // Absent means the target never got far enough, which is the whole
        // point of asking: the run is Unknown rather than isolated.
        assert_eq!(
            recover_secret(
                &Secret::ConfirmedBy("TENANT2_MARKER".to_string()),
                "crashed\n"
            ),
            ""
        );
    }

    #[test]
    fn readiness_only_is_satisfied_without_logs() {
        // The weakest control, and deliberately non-empty so the executor
        // proceeds — for a target that prints nothing, readiness is all there
        // is.
        assert!(!recover_secret(&Secret::ReadinessOnly, "").is_empty());
    }

    #[test]
    fn repeating_the_secret_is_a_breach() {
        let exp = experiment(BreachCondition::IntruderRepeatsSecret);
        let verdict = judge(&exp, "a1b2c3", "I can see a1b2c3 from here");
        assert_eq!(verdict.isolation, IsolationLevel::None);
    }

    #[test]
    fn not_repeating_it_is_isolation() {
        let exp = experiment(BreachCondition::IntruderRepeatsSecret);
        let verdict = judge(&exp, "a1b2c3", "nothing visible");
        assert_eq!(verdict.isolation, IsolationLevel::Hard);
    }

    #[test]
    fn an_empty_secret_can_never_read_as_a_breach() {
        // `"anything".contains("")` is true, so without this guard an
        // experiment whose target published nothing would report a breach
        // against every intruder. `plant_secret` stops it earlier; this is the
        // second line of defence.
        let exp = experiment(BreachCondition::IntruderRepeatsSecret);
        assert_eq!(
            judge(&exp, "", "anything at all").isolation,
            IsolationLevel::Hard
        );
    }

    #[test]
    fn an_intruder_reporting_its_own_marker_is_a_breach() {
        let exp = experiment(BreachCondition::IntruderReports("TENANT2_PROCESS_FOUND"));
        let verdict = judge(&exp, "unused", "scanning...\nTENANT2_PROCESS_FOUND\n");
        assert_eq!(verdict.isolation, IsolationLevel::None);
    }

    #[test]
    fn the_intruder_is_built_from_what_the_target_turned_out_to_be() {
        let planted = PlantedSecret {
            node: "node-7".to_string(),
            address: "10.0.0.9".to_string(),
            secret: "s".to_string(),
            logs: String::new(),
        };

        let on_node = Intruder::OnTargetNode(|node| ProbePod::new("i").on_node(node).build());
        let built = build_intruder(&on_node, &planted);
        assert_eq!(
            built.spec.unwrap().node_name.as_deref(),
            Some("node-7"),
            "an intruder on the wrong node inspects an unrelated machine"
        );

        let at_address =
            Intruder::AtTargetAddress(|ip| ProbePod::new("i").shell(format!("curl {ip}")).build());
        let built = build_intruder(&at_address, &planted);
        let command = built.spec.unwrap().containers[0].command.clone().unwrap();
        assert!(command[2].contains("10.0.0.9"));
    }
}

/// A container that never started must not be read as one that ran.
///
/// The failure these pin down was silent and inverted: under gVisor a
/// privileged probe is refused by the runtime, `kubectl logs` answers with
/// containerd's own error, and that error quotes the container's command line
/// — which for these probes contains the breach markers themselves. The
/// property scored as breached by a probe that had never executed.
#[cfg(test)]
mod a_probe_that_never_ran {
    use super::*;
    use crate::assessment::probe::{HostAccess, ProbePod};
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus, PodStatus,
    };

    fn pod_whose_container(state: ContainerState) -> Pod {
        Pod {
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    state: Some(state),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_start_error_is_recognised_as_never_having_run() {
        let pod = pod_whose_container(ContainerState {
            terminated: Some(ContainerStateTerminated {
                reason: Some("StartError".to_string()),
                message: Some("starting container: sub-container refused".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });

        assert_eq!(
            never_started(&pod).as_deref(),
            Some("starting container: sub-container refused")
        );
    }

    /// A pod pinned to a node this cluster does not have never runs, and its
    /// silence is not a measurement.
    ///
    /// Host namespaces are per-node, so these intruders name the victim's node.
    /// Under KubeVirt each tenant is its own cluster with its own VMs, so that
    /// name resolves to nothing on the intruder's side: the pod stays Pending,
    /// writes no logs, and the marker-based experiments read "no marker" as
    /// isolation — a passing verdict from a probe that never executed.
    #[test]
    fn a_pod_pinned_to_a_node_that_does_not_exist_is_recognised() {
        let pod = Pod {
            status: Some(PodStatus {
                phase: Some("Pending".to_string()),
                conditions: Some(vec![k8s_openapi::api::core::v1::PodCondition {
                    type_: "PodScheduled".to_string(),
                    status: "False".to_string(),
                    reason: Some("Unschedulable".to_string()),
                    message: Some(
                        "0/1 nodes are available: 1 node(s) didn't match Pod's node affinity"
                            .to_string(),
                    ),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(never_placed(&pod).is_some_and(|why| why.contains("didn't match")));
    }

    /// A pod waiting on its image is not unschedulable.
    #[test]
    fn a_pending_pod_that_was_scheduled_is_not_reported_as_unschedulable() {
        let pod = Pod {
            status: Some(PodStatus {
                phase: Some("Pending".to_string()),
                conditions: Some(vec![k8s_openapi::api::core::v1::PodCondition {
                    type_: "PodScheduled".to_string(),
                    status: "True".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(never_placed(&pod), None);
    }

    /// The shape that actually occurs: `spec.nodeName` bypasses the scheduler,
    /// so a node that does not exist leaves the pod Pending with **no**
    /// conditions at all — nothing ever evaluated it. Requiring a
    /// `PodScheduled=False` condition missed every one of these.
    #[test]
    fn a_pod_pinned_by_node_name_that_no_kubelet_claimed_is_recognised() {
        let pod = Pod {
            spec: Some(k8s_openapi::api::core::v1::PodSpec {
                node_name: Some("tenant1-kv-control-plane-abcde".to_string()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                phase: Some("Pending".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(never_placed(&pod)
            .is_some_and(|why| why.contains("tenant1-kv-control-plane-abcde")));
    }

    /// A pinned pod that did land and is starting up is not "never placed".
    #[test]
    fn a_pinned_pod_whose_container_is_starting_is_not_reported() {
        let pod = Pod {
            spec: Some(k8s_openapi::api::core::v1::PodSpec {
                node_name: Some("node-1".to_string()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                phase: Some("Pending".to_string()),
                container_statuses: Some(vec![ContainerStatus {
                    state: Some(ContainerState {
                        waiting: Some(ContainerStateWaiting {
                            reason: Some("ContainerCreating".to_string()),
                            message: None,
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(never_placed(&pod), None);
    }

    #[test]
    fn a_container_that_ran_and_exited_is_not_confused_with_one_that_never_started() {
        let pod = pod_whose_container(ContainerState {
            terminated: Some(ContainerStateTerminated {
                reason: Some("Completed".to_string()),
                exit_code: 0,
                ..Default::default()
            }),
            ..Default::default()
        });

        assert_eq!(never_started(&pod), None);
    }

    #[test]
    fn the_runtime_refusing_to_create_the_container_counts_too() {
        let pod = pod_whose_container(ContainerState {
            waiting: Some(ContainerStateWaiting {
                reason: Some("CreateContainerError".to_string()),
                message: Some("no such runtime".to_string()),
            }),
            ..Default::default()
        });

        assert_eq!(
            never_started(&pod).as_deref(),
            Some("CreateContainerError: no such runtime")
        );
    }

    #[test]
    fn a_pod_still_pulling_its_image_has_not_failed_to_start() {
        let pod = pod_whose_container(ContainerState {
            waiting: Some(ContainerStateWaiting {
                reason: Some("ContainerCreating".to_string()),
                message: None,
            }),
            ..Default::default()
        });

        assert_eq!(never_started(&pod), None);
    }

    #[test]
    fn privilege_and_host_namespaces_are_both_recognised_as_dangerous_requests() {
        for pod in [
            ProbePod::new("p").requests(HostAccess::Privileged).build(),
            ProbePod::new("p").requests(HostAccess::Pid).build(),
            ProbePod::new("p").requests(HostAccess::Ipc).build(),
            ProbePod::new("p").requests(HostAccess::Network).build(),
            ProbePod::new("p").requests(HostAccess::Users).build(),
        ] {
            assert!(asks_for_host_privilege(&pod));
        }

        assert!(!asks_for_host_privilege(&ProbePod::new("p").build()));
    }

    /// A refused request is soft however late the refusal comes.
    ///
    /// Hard means the cross-tenant operation ran and returned what a lone
    /// tenant would have got. An intruder stopped before it could attempt
    /// anything has instead learnt that a restriction exists, which is the
    /// definition of soft — and it is soft whether a webhook said no at
    /// admission or the runtime said no at start.
    #[test]
    fn a_sandbox_turning_away_a_privileged_probe_is_soft_isolation_at_a_cost() {
        let result = runtime_would_not_run(
            &super::tests::experiment(BreachCondition::IntruderReports("MARKER")),
            true,
            "StartSubcontainer failed",
        );

        assert!(
            matches!(result.isolation, IsolationLevel::Soft(_)),
            "the intruder never attempted the cross-tenant operation, so this \
             cannot be hard: {:?}",
            result.isolation
        );
        assert!(!result.autonomy, "the operation itself was not allowed");
    }

    /// Guards the reassuring answer. An ordinary pod failing to start is the
    /// harness breaking, and reporting that as isolation is how a dead probe
    /// turns into a perfect score.
    #[test]
    fn an_ordinary_probe_failing_to_start_is_not_isolation() {
        let result = runtime_would_not_run(
            &super::tests::experiment(BreachCondition::IntruderReports("MARKER")),
            false,
            "image pull failed",
        );

        assert_eq!(result.isolation, IsolationLevel::Unknown);
    }
}

#[cfg(test)]
mod probe_scripts_are_valid_shell {
    //! Every generated probe script must at least parse as a shell script.
    //!
    //! Twice now a probe has been broken by quoting rather than by logic. The
    //! second time, an apostrophe inside a single-quoted `echo` closed the
    //! string early, so the whole `if` block was a syntax error: the pod ran,
    //! printed nothing, and the experiment reported `Hard` — isolation it had
    //! never tested. Nothing downstream can tell that apart from a real result,
    //! which is why it needs catching here rather than on a cluster.
    //!
    //! Balanced single quotes is a cheap proxy for "parses", and it is exactly
    //! the failure that has actually occurred.

    /// Single quotes outside of any double-quoted span, which is where the
    /// shell treats them as string delimiters.
    fn unbalanced_single_quotes(script: &str) -> bool {
        let mut in_double = false;
        let mut singles = 0usize;
        for ch in script.chars() {
            match ch {
                '"' => in_double = !in_double,
                '\'' if !in_double => singles += 1,
                _ => {}
            }
        }
        singles % 2 != 0
    }

    #[test]
    fn the_checker_catches_the_bug_it_was_written_for() {
        // The exact shape that broke the DNS probe.
        assert!(unbalanced_single_quotes(
            r"echo 'the other tenant\'s service resolves'"
        ));
        assert!(!unbalanced_single_quotes(r"echo 'the name resolves'"));
        // An apostrophe inside double quotes is fine and must not trip it.
        assert!(!unbalanced_single_quotes(r#"echo "the tenant's service""#));
    }

    #[test]
    fn every_generated_probe_script_has_balanced_quotes() {
        use crate::assessment::probe::ProbePod;

        // The real probes, not a stand-in. A guard that only checks a synthetic
        // script cannot catch the bug it exists for — which is exactly what
        // this test did until it was pointed at these.
        for (label, pod) in [
            (
                "dns probe",
                crate::assessment::network::create_dns_probe_pod("d", "svc.ns.svc.cluster.local"),
            ),
            (
                "reachability probe",
                crate::assessment::network::create_reachability_probe_pod("r", "10.0.0.1"),
            ),
            (
                "shell probe",
                ProbePod::new("p").shell("echo 'ok' && sleep 1").build(),
            ),
        ] {
            let command = pod.spec.as_ref().unwrap().containers[0]
                .command
                .as_ref()
                .expect("a shell probe puts its script in command");
            assert!(command.len() > 2, "{label}: expected sh -c <script>");
            assert!(
                !unbalanced_single_quotes(&command[2]),
                "{label}: script has unbalanced single quotes"
            );
        }
    }
}
