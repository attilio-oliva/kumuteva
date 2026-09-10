mod fairness;

pub use fairness::*;

use std::fmt::Display;

use async_trait::async_trait;
use k8s_openapi::api::{
    apps::v1::StatefulSet,
    core::v1::{PersistentVolume, PersistentVolumeClaim, Pod},
    storage::v1::StorageClass,
};
use serde::Serialize;
use tracing::info;

use crate::assessment::breach::{
    run_breach_experiment, BreachCondition, BreachExperiment, Intruder, Secret,
};
use crate::assessment::probe::{HostAccess, ProbePod};
use crate::assessment::Authorization;
use crate::assessment::TenantClusterConfig;
use crate::assessment::{
    run_assessment, AssessableResource, CrossTenantResult, IsolationLevel, MultitenancyAssessor,
    SubsystemReport,
};

// =============================================================================
// CONSTANTS
// =============================================================================

const POD_NAME: &str = "persistent-pod";
const PVC_NAME: &str = "kumuteva-pv-claim";
const HOSTPATH_PVC_NAME: &str = "kumuteva-hostpath-claim";
const FILE_NAME: &str = "index.html";
const FILE_CONTENT: &str = "Hello, this is a tenant1 using Kumuteva!";
const MOUNT_PATH: &str = "/usr/share/nginx/html";
/// Where a hostPath probe mounts inside its container.
///
/// The same for both hostPath properties, which is harmless: a mount point is
/// private to the pod.
const HOSTPATH_MOUNT_PATH: &str = "/tmp/kumuteva-hostpath";

/// The node directory the *inline* hostPath property uses.
const HOSTPATH_INLINE_HOST_PATH: &str = "/tmp/kumuteva-hostpath/inline";

/// The node directory the *PersistentVolume-backed* hostPath property uses.
///
/// Distinct from the inline one, and that is the point. Both properties used
/// `/tmp/kumuteva-hostpath` directly: `Use HostPath in a Volume` plants a file
/// there and is torn down, and `Use HostPath through a PersistentVolume` runs
/// straight afterwards against the same directory. Two independent properties
/// sharing one piece of mutable state on the node made the second flaky —
/// measured twice on identical clusters, it reported `Hard` once and a breach
/// once, and a `Hard` that comes and goes is a false claim of isolation in the
/// table.
///
/// Within a property both tenants still share a directory, because that shared
/// directory *is* the thing being tested.
const HOSTPATH_PV_HOST_PATH: &str = "/tmp/kumuteva-hostpath/persistent";
/// Throwaway pod used only to ask whether a hostPath mount is admitted.
const HOSTPATH_AUTH_POD_NAME: &str = "kumuteva-hostpath-auth-probe";
const STORAGE_SIZE: &str = "1Gi";
const POD_CREATION_TIMEOUT: u32 = 60;

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

pub type StorageIsolationReport = SubsystemReport<StorageResource>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageResource {
    /// Logical storage unit. Involves the use of PersistentVolumes and PersistentVolumeClaims.
    Volume,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageOperation {
    /// Create a volume and mount it to a pod (without setting reclaim policy)
    CreateAndMountVolume,
    /// Create a volume and mount it to a pod with Retain reclaim policy
    CreateAndMountVolumeWithRetainPolicy,
    /// Mount the node filesystem with a `hostPath` volume declared inline in a
    /// pod spec.
    ///
    /// No PersistentVolume is involved, so RBAC on cluster-scoped resources does
    /// not apply. What governs it is admission control on the pod, typically
    /// PodSecurity.
    UseHostPath,
    /// Mount the node filesystem through a PersistentVolumeClaim bound to a
    /// PersistentVolume whose backing is a host path.
    ///
    /// The same destination by a different route, and gated differently: a
    /// PersistentVolume is cluster-scoped, so this one is governed by RBAC.
    ///
    /// Kept apart from `UseHostPath` because a platform can permit one and
    /// refuse the other. Capsule does exactly that — it blocks PersistentVolume
    /// creation while admitting pods that declare hostPath inline. Testing only
    /// the PersistentVolume route reports the node filesystem as unreachable
    /// while a tenant can in fact mount it at will, which is what the comparison
    /// against kubectl-mtb exposed.
    UsePersistentHostPath,
}

impl AssessableResource for StorageResource {
    type Operation = StorageOperation;

    fn all() -> Vec<Self> {
        vec![StorageResource::Volume]
    }

    fn applicable_operations(&self) -> Vec<StorageOperation> {
        match self {
            StorageResource::Volume => vec![
                StorageOperation::CreateAndMountVolume,
                StorageOperation::CreateAndMountVolumeWithRetainPolicy,
                StorageOperation::UseHostPath,
                StorageOperation::UsePersistentHostPath,
            ],
        }
    }
}

// =============================================================================
// ASSESSOR IMPLEMENTATION
// =============================================================================

pub struct StorageAssessor;

#[async_trait]
impl MultitenancyAssessor for StorageAssessor {
    type Resource = StorageResource;

    fn name(&self) -> &'static str {
        "Storage"
    }

    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &StorageResource,
        operation: &StorageOperation,
    ) -> anyhow::Result<Authorization> {
        match (resource, operation) {
            (StorageResource::Volume, StorageOperation::CreateAndMountVolume)
            | (StorageResource::Volume, StorageOperation::CreateAndMountVolumeWithRetainPolicy) => {
                let can_create_pv = test_pv_creation_authorization(tenant).await?;
                let can_mount_pv = test_pv_mount_authorization(tenant).await?;
                Ok(can_create_pv.and(can_mount_pv))
            }
            (StorageResource::Volume, StorageOperation::UseHostPath) => {
                // Only the pod matters here. An inline hostPath volume needs no
                // PersistentVolume, so requiring one to be creatable would gate
                // this route behind an unrelated permission — which is precisely
                // what used to happen: the two checks were ANDed, Capsule failed
                // the PersistentVolume half, and the operation was reported as
                // unauthorised while a tenant could mount the host filesystem
                // from any pod it liked.
                test_hostpath_mount_authorization(tenant).await
            }
            (StorageResource::Volume, StorageOperation::UsePersistentHostPath) => {
                // This route genuinely does need both: a cluster-scoped
                // PersistentVolume backed by a host path, and a pod able to
                // mount the claim that binds it.
                let can_create_pv = test_hostpath_creation_authorization(tenant).await?;
                let can_mount_pvc = test_pv_mount_authorization(tenant).await?;
                Ok(can_create_pv.and(can_mount_pvc))
            }
        }
    }

    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &StorageResource,
        operation: &StorageOperation,
    ) -> anyhow::Result<CrossTenantResult> {
        match (resource, operation) {
            (StorageResource::Volume, StorageOperation::CreateAndMountVolume) => {
                test_pv_cross_tenant_access(tenant1, tenant2, false).await
            }
            (StorageResource::Volume, StorageOperation::CreateAndMountVolumeWithRetainPolicy) => {
                test_pv_cross_tenant_access(tenant1, tenant2, true).await
            }
            (StorageResource::Volume, StorageOperation::UseHostPath) => {
                run_breach_experiment(&hostpath_data_experiment(), tenant2, tenant1).await
            }
            (StorageResource::Volume, StorageOperation::UsePersistentHostPath) => {
                test_persistent_hostpath_cross_tenant_access(tenant1, tenant2).await
            }
        }
    }
}

/// Public API - entry point for storage isolation assessment
#[allow(dead_code)]
pub async fn check_storage_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<StorageIsolationReport> {
    run_assessment(&StorageAssessor, tenant1, tenant2).await
}

// =============================================================================
// AUTHORIZATION TESTS
// =============================================================================

async fn test_pv_creation_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let result = tenant
        .cluster
        .is_authorized_to("create", "PersistentVolume", None)
        .await;

    info!("PV creation authorization test result: {:?}", result);
    Ok(Authorization::from_attempt(result))
}

async fn test_pv_mount_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let test_commands = vec!["sleep", "1"];
    let result = create_stateful_set(tenant, &test_commands, None, None, false).await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
        .await;

    Ok(Authorization::from_attempt(result))
}

async fn test_hostpath_creation_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let test_pv_name = "auth-test-hostpath-pv";
    let test_pv = create_test_hostpath_pv_manifest(test_pv_name);

    let result = tenant
        .cluster
        .create_cluster_resource::<PersistentVolume>(&test_pv)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_cluster_resource::<PersistentVolume>(test_pv_name)
        .await;

    Ok(Authorization::from_attempt(result))
}

/// Will the API server accept a pod that mounts a host directory?
///
/// A bare Pod, not a StatefulSet, because that is the question. PodSecurity
/// enforces at *Pod* admission; a controller's pod template is at most warned
/// about. So a StatefulSet carrying a forbidden hostPath is accepted, its
/// creation returns success, and the pods are rejected afterwards by the
/// controller — out of band, where a check on the create response cannot see it.
/// The gate would then report the operation as permitted on a cluster that
/// forbids it.
///
/// Creating a Pod puts the question to the same admission path the real thing
/// takes, and the answer arrives synchronously in the response. No wait is
/// needed: whether the pod then schedules or pulls its image is a different
/// matter, and not what authorization means here.
///
/// The pod declares CPU and memory like every other probe, and that is load
/// bearing rather than boilerplate. A tenant with a compute ResourceQuota makes
/// `limits.cpu` mandatory for every pod in the namespace, so a pod without them
/// is rejected by quota admission *before* the hostPath policy is consulted.
/// This probe would then report hostPath as forbidden on a cluster that permits
/// it, having never asked the question — the same masking that made kubectl-mtb
/// score a tenant well for refusing every pod. Declaring resources gets the pod
/// past the quota so the answer is about hostPath.
async fn test_hostpath_mount_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let pod = ProbePod::new(HOSTPATH_AUTH_POD_NAME)
        .image("nginx")
        .shell("sleep 1")
        .requests(HostAccess::HostPath {
            host: HOSTPATH_INLINE_HOST_PATH.to_string(),
            mount: HOSTPATH_MOUNT_PATH.to_string(),
        })
        .build();

    let result = tenant
        .cluster
        .create_namespaced_resource::<Pod>(&pod, &tenant.namespace)
        .await;

    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<Pod>(HOSTPATH_AUTH_POD_NAME, &tenant.namespace)
        .await;

    Ok(Authorization::from_attempt(result))
}

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

async fn test_pv_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    use_retain_policy: bool,
) -> anyhow::Result<CrossTenantResult> {
    // One translation for both tests. They previously had a match block each,
    // and the two disagreed: the same `AccessResult` produced different
    // autonomy and, for `PartialAutonomy`, a different isolation level
    // depending on which test you were in.
    match attempt_other_tenant_file_access(tenant1, tenant2, use_retain_policy).await {
        Ok(result) => Ok(result.into()),
        Err(e) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!("Could not determine isolation: {e}"),
        }),
    }
}

async fn test_persistent_hostpath_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // One translation for both tests. They previously had a match block each,
    // and the two disagreed: the same `AccessResult` produced different
    // autonomy and, for `PartialAutonomy`, a different isolation level
    // depending on which test you were in.
    match test_persistent_hostpath_data_isolation(tenant1, tenant2).await {
        Ok(result) => Ok(result.into()),
        Err(e) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!("Could not determine isolation: {e}"),
        }),
    }
}

/// Can tenant2 read what tenant1 wrote, when both reach the node filesystem
/// through a hostPath-backed PersistentVolume?
///
/// Each tenant provisions its *own* PersistentVolume pointing at the same host
/// directory, rather than tenant2 rebinding tenant1's. Both are realistic, but
/// this one isolates the question being asked: the concern is the node
/// filesystem as a shared channel, not PersistentVolume rebinding, which
/// `CreateAndMountVolume` already covers. It also keeps the result meaningful on
/// platforms that hide cluster-scoped objects from tenants, where tenant2 could
/// not name tenant1's volume even if it were permitted to bind it.
async fn test_persistent_hostpath_data_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<AccessResult> {
    let t1_pv = "kumuteva-hostpath-pv-tenant1";
    let t2_pv = "kumuteva-hostpath-pv-tenant2";

    // Cleanup runs on every exit path, including the early returns below, so a
    // refused run does not leave a cluster-scoped volume behind for the next one
    // to trip over.
    /// Take the StatefulSet, its generated claim, and the volume away again.
    ///
    /// The claim is the part that used to be left behind, and it is the part
    /// that matters: deleting a StatefulSet does not delete the PVCs its
    /// `volumeClaimTemplates` created. The stale claim still names the
    /// dynamically provisioned volume from the *previous* experiment, which is
    /// gone, so it can never bind — and the next experiment's pod sits Pending
    /// on it forever:
    ///
    ///   FailedScheduling: pod has unbound immediate PersistentVolumeClaims
    ///
    /// which surfaced as "Tenant2 hostPath PersistentVolume pod never became
    /// ready" and scored the property `Unknown`. Observed on the testbed with a
    /// 34-minute-old claim from an earlier property in the same run.
    async fn cleanup(tenant: &TenantClusterConfig, pv_name: &str) {
        let _ = tenant
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .delete_resource_in_namespace::<PersistentVolumeClaim>(
                &statefulset_pvc_name(),
                &tenant.namespace,
            )
            .await;
        let _ = tenant
            .cluster
            .delete_cluster_resource::<PersistentVolume>(pv_name)
            .await;
    }

    // A claim left by an earlier experiment — or by a run that died before its
    // cleanup — binds nothing and blocks everything. Clear it before starting
    // rather than discovering it as a pod that never becomes ready.
    for tenant in [tenant1, tenant2] {
        let _ = tenant
            .cluster
            .delete_resource_in_namespace::<PersistentVolumeClaim>(
                &statefulset_pvc_name(),
                &tenant.namespace,
            )
            .await;
    }

    // --- tenant1 writes through the PersistentVolume route ---
    if let Err(e) = tenant1
        .cluster
        .create_cluster_resource::<PersistentVolume>(&create_test_hostpath_pv_manifest(t1_pv))
        .await
    {
        return Ok(AccessResult::VictimBlocked(format!(
            "Tenant1 cannot create a hostPath PersistentVolume: {}",
            e
        )));
    }

    if let Err(e) =
        create_stateful_set(tenant1, &tenant1_commands(), Some(t1_pv), Some(""), false).await
    {
        cleanup(tenant1, t1_pv).await;
        return Ok(AccessResult::VictimBlocked(format!(
            "Tenant1 cannot mount a hostPath PersistentVolume: {}",
            e
        )));
    }
    if let Err(e) = wait_for_statefulset_ready(tenant1).await {
        let refusal = statefulset_refusal(tenant1).await;
        cleanup(tenant1, t1_pv).await;
        // The victim never wrote its marker, so there was never anything for
        // the intruder to find. Silence from the intruder after that means
        // nothing at all — unless the platform said why, in which case it is
        // the victim's own capability that is missing.
        return Ok(match refusal {
            Some(reason) => AccessResult::VictimBlocked(format!(
                "Tenant1 cannot mount a hostPath PersistentVolume: {reason}"
            )),
            None => AccessResult::Undetermined(format!(
                "Tenant1 hostPath PersistentVolume pod never became ready: {e}"
            )),
        });
    }
    let Some(victim_logs) = victim_planted_secret(tenant1).await else {
        cleanup(tenant1, t1_pv).await;
        return Ok(AccessResult::Undetermined(
            "tenant1 never confirmed writing its marker through the hostPath \
             PersistentVolume, so the intruder had nothing to find"
                .to_string(),
        ));
    };
    info!("Tenant1 wrote through a hostPath PersistentVolume.");

    // --- tenant2 attempts the same route to the same host directory ---
    if let Err(e) = tenant2
        .cluster
        .create_cluster_resource::<PersistentVolume>(&create_test_hostpath_pv_manifest(t2_pv))
        .await
    {
        cleanup(tenant1, t1_pv).await;
        return Ok(AccessResult::IntruderBlockedByPolicy(format!(
            "Tenant2 cannot create a hostPath PersistentVolume: {}",
            e
        )));
    }

    if let Err(e) =
        create_stateful_set(tenant2, &tenant2_commands(), Some(t2_pv), Some(""), false).await
    {
        cleanup(tenant1, t1_pv).await;
        cleanup(tenant2, t2_pv).await;
        return Ok(AccessResult::IntruderBlockedByPolicy(format!(
            "Tenant2 cannot mount a hostPath PersistentVolume: {}",
            e
        )));
    }
    if let Err(e) = wait_for_statefulset_ready(tenant2).await {
        let refusal = if refused_rather_than_unobserved(&e) {
            Some(e.to_string())
        } else {
            statefulset_refusal(tenant2).await
        };
        cleanup(tenant1, t1_pv).await;
        cleanup(tenant2, t2_pv).await;
        return Ok(match refusal {
            Some(reason) => AccessResult::IntruderBlockedByPolicy(format!(
                "Tenant2's hostPath PersistentVolume pod was refused: {reason}"
            )),
            None => AccessResult::Undetermined(format!(
                "Tenant2 hostPath PersistentVolume pod never became ready: {e}"
            )),
        });
    }

    let (can_access, evidence) = match check_cross_tenant_mount(tenant2).await {
        Ok(outcome) => outcome,
        Err(e) => {
            cleanup(tenant1, t1_pv).await;
            cleanup(tenant2, t2_pv).await;
            return Ok(AccessResult::Undetermined(e.to_string()));
        }
    };

    cleanup(tenant1, t1_pv).await;
    cleanup(tenant2, t2_pv).await;

    if can_access {
        Ok(AccessResult::Accessible)
    } else {
        // Both sides of the disagreement, in one string. The intruder saying
        // "not found" is only half an observation: what settles it is whether
        // the victim wrote to the same mount, and that is a fact about the
        // victim's pod which no amount of looking at the intruder can supply.
        let mut both = evidence;
        for line in victim_logs.lines() {
            if line.starts_with("VICTIM_CONTENTS:") || line.starts_with("VICTIM_SOURCE:") {
                both.push_str(" || ");
                both.push_str(line.trim());
            }
        }
        Ok(AccessResult::Isolated(both))
    }
}

/// Result of attempting cross-tenant access
#[derive(Debug, Clone)]
/// The outcome of one cross-tenant storage attempt.
///
/// The variants distinguish *who* was stopped, which is the distinction the
/// methodology turns on and which an earlier single `IsolatedByPolicy` variant
/// lost. Autonomy asks whether the tenant can do its own legitimate work;
/// isolation asks whether the other tenant's attack was stopped. A refusal
/// aimed at the victim answers the first question, a refusal aimed at the
/// intruder answers the second, and collapsing them meant the same value had
/// to be translated two different ways in two different tests.
enum AccessResult {
    /// The intruder reached nothing, and nothing revealed that there was
    /// anything to reach. Carries what the intruder actually reported, because
    /// "the file was not there" and "the file was there but differed" are very
    /// different observations to be told apart afterwards.
    Isolated(String),
    /// The victim could not perform the operation *in its own namespace*.
    ///
    /// Not an isolation finding: the experiment never ran. The tenant simply
    /// does not have this capability, so autonomy is false and the operation is
    /// as unavailable as it would be in a single-tenant cluster.
    VictimBlocked(String),
    /// The intruder's attempt was refused by policy.
    ///
    /// Soft rather than Hard: the refusal itself confirms there was something
    /// there to refuse. The victim's own use is unaffected, so its autonomy
    /// stands.
    IntruderBlockedByPolicy(String),
    /// The operation worked, but not fully — a restriction short of refusal.
    PartialAutonomy(String),
    /// The experiment could not be carried out, so nothing was learned.
    ///
    /// Distinct from every variant above, which are all *findings*. A pod that
    /// never started tells us nothing about whether the platform isolates
    /// anything — but it used to be recorded as `PartialAutonomy`, and so as
    /// `Hard`, which is the reassuring answer and the one most likely to be
    /// wrong. It reported `native`, a cluster with no isolation whatsoever, as
    /// isolated, and it is part of what `capsule-hardened`'s storage verdict
    /// rested on.
    Undetermined(String),
    /// Cross-tenant access is possible.
    Accessible,
}

/// Why is there no pod, when the StatefulSet itself was accepted?
///
/// A StatefulSet is admitted even when its pods are not. PodSecurity evaluates
/// pods, not controller templates, so on a tenant enforcing `restricted` the
/// object is created and the controller's own pod creation is then refused:
///
/// ```text
/// Warning  FailedCreate  statefulset/persistent-pod
///   create Pod persistent-pod-0 ... is forbidden:
///   violates PodSecurity "restricted:latest"
/// ```
///
/// That refusal never reaches the call this code made — it lands in an event.
/// Without reading it, a prohibition and a cluster that is merely slow are the
/// same observation: a wait that ran out. Returns the platform's own words when
/// it declined, and `None` when nothing declined anything.
async fn statefulset_refusal(tenant: &TenantClusterConfig) -> Option<String> {
    let events = tenant
        .cluster
        .list_namespaced_resources::<k8s_openapi::api::core::v1::Event>(&tenant.namespace)
        .await
        .ok()?;

    events.items.into_iter().find_map(|event| {
        let about_our_set = event
            .involved_object
            .name
            .as_deref()
            .is_some_and(|name| name.starts_with(POD_NAME));
        let message = event.message?;
        (about_our_set && refused_text(&message)).then_some(message)
    })
}

/// Does this text say the platform declined?
fn refused_text(text: &str) -> bool {
    let text = text.to_lowercase();
    [
        "forbidden",
        "not allowed",
        "unauthorized",
        "denied",
        "admission webhook",
        "podsecurity",
        "exceeded quota",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

/// Did this failure refuse the operation, or merely fail to observe it?
///
/// A refusal is a result: the platform declined, and that is the thing being
/// measured. A timeout is the absence of a result, and the two must not share a
/// verdict — the whole difficulty of this kind of probe is that both look like
/// "nothing happened".
fn refused_rather_than_unobserved(error: &anyhow::Error) -> bool {
    refused_text(&error.to_string())
}

impl From<AccessResult> for CrossTenantResult {
    /// The single translation, replacing two that disagreed with each other.
    fn from(result: AccessResult) -> Self {
        match result {
            AccessResult::Isolated(evidence) => CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: format!(
                    "Cross-tenant storage access is blocked — intruder reported: {evidence}"
                ),
            },
            AccessResult::VictimBlocked(reason) => CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: false,
                details: format!("The tenant cannot perform this operation at all: {reason}"),
            },
            AccessResult::IntruderBlockedByPolicy(reason) => CrossTenantResult {
                isolation: IsolationLevel::Soft(
                    "A policy forbade the cross-tenant operation".to_string(),
                ),
                autonomy: true,
                details: format!("Storage isolated by policy: {reason}"),
            },
            AccessResult::PartialAutonomy(reason) => CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: false,
                details: format!("Storage isolated but with restrictions: {reason}"),
            },
            AccessResult::Undetermined(reason) => CrossTenantResult {
                isolation: IsolationLevel::Unknown,
                autonomy: false,
                details: format!("Storage isolation could not be determined: {reason}"),
            },
            AccessResult::Accessible => CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: "Cross-tenant storage access detected".to_string(),
            },
        }
    }
}

/// tenant1 writes a file into a node directory via an inline hostPath volume;
/// tenant2 mounts the same node path and tries to read it back.
///
/// The node's filesystem is the shared thing here: hostPath bypasses every
/// per-tenant storage boundary by construction, so if both tenants may mount it
/// the data is simply shared.
///
/// Replaces a pair of StatefulSets. Nothing about a StatefulSet was being used
/// — `replicas: 1`, no `volumeClaimTemplates`, no ordinals — and a bare Pod is
/// also the more honest probe, since PodSecurity admission judges Pods rather
/// than controller templates.
fn hostpath_data_experiment() -> BreachExperiment {
    let mount = HostAccess::HostPath {
        host: HOSTPATH_INLINE_HOST_PATH.to_string(),
        mount: HOSTPATH_MOUNT_PATH.to_string(),
    };

    BreachExperiment {
        what: "hostPath volume",
        target: ProbePod::new("hostpath-target")
            .image("alpine:latest")
            .requests(mount.clone())
            // Echoes the marker to stdout as well as into the file. The old
            // version only redirected it into the file, so the target's logs
            // were empty and there was no way to tell "tenant1 wrote nothing"
            // from "tenant2 could not read it" — the second reads as isolation.
            .shell(format!(
                "echo '{FILE_CONTENT}' > {HOSTPATH_MOUNT_PATH}/hostpath-test.txt && \
                 echo 'PLANTED {FILE_CONTENT}' && sleep 5"
            ))
            .build(),
        target_service: None,
        secret: Secret::ConfirmedBy(format!("PLANTED {FILE_CONTENT}")),
        // Any node will do: a hostPath is per-node, so the intruder must land
        // on the same one to see the file at all.
        intruder: Intruder::OnTargetNode(|node| {
            ProbePod::new("hostpath-intruder")
                .image("alpine:latest")
                .on_node(node)
                .requests(HostAccess::HostPath {
                    host: HOSTPATH_INLINE_HOST_PATH.to_string(),
                    mount: HOSTPATH_MOUNT_PATH.to_string(),
                })
                .shell(format!(
                    "if [ \"$(cat {HOSTPATH_MOUNT_PATH}/hostpath-test.txt 2>/dev/null)\" \
                          = \"{FILE_CONTENT}\" ]; then \
                       echo 'HOSTPATH_ACCESS_SUCCESS: Found tenant1 hostpath data'; \
                     else \
                       echo 'HOSTPATH_ACCESS_FAILED: not readable'; \
                     fi"
                ))
                .build()
        }),
        breach: BreachCondition::IntruderReports("HOSTPATH_ACCESS_SUCCESS"),
    }
}

/// A StorageClass of this tenant's own with the given reclaim policy, if the
/// cluster offers one.
///
/// Asked with the *tenant's* own credentials, so a class it cannot see does
/// not count — the question is what this tenant can obtain, not what exists.
/// `None` on any error for the same reason: a cluster that will not answer is
/// a cluster without a usable class, and the caller falls back to the route
/// that needs no class at all.
async fn tenant_storage_class(
    tenant: &TenantClusterConfig,
    reclaim_policy: &str,
) -> Option<String> {
    let classes = tenant
        .cluster
        .list_cluster_resources::<StorageClass>()
        .await
        .ok()?;

    classes
        .items
        .into_iter()
        .find(|class| {
            class.reclaim_policy.as_deref() == Some(reclaim_policy)
                && class
                    .metadata
                    .name
                    .as_deref()
                    .is_some_and(|name| name.contains(&tenant.namespace))
        })
        .and_then(|class| class.metadata.name)
}

async fn attempt_other_tenant_file_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    use_retain_policy: bool,
) -> anyhow::Result<AccessResult> {
    let tenant1_commands = tenant1_commands();
    let tenant2_commands = tenant2_commands();

    // Step 0: for the Retain variant, get tenant1 a Retain volume.
    //
    // Two routes, and the first is the one a tenant should have. Reclaim
    // policy is a property of the PersistentVolume, and the documented way to
    // obtain one is a StorageClass that declares `reclaimPolicy: Retain` —
    // dynamic provisioning then gives a Retain volume with no cluster-scoped
    // object created by hand.
    //
    // Falling back to building a hostPath PersistentVolume is what this did
    // unconditionally, and it quietly changed the question: `Create And Mount
    // Volume with Retain Reclaim Policy` ended up measuring *hostPath*, which
    // no storage backend can isolate, rather than reclaim policy. Clusters
    // that offer no Retain class still take that route, so their results are
    // unchanged.
    //
    // If the tenant may not create a PersistentVolume and has no Retain class,
    // that is the answer: the operation is unavailable to it, so autonomy is
    // false and there is no isolation finding to make.
    //
    // The plain variant asks the same question of a Delete class. It used to
    // ask for nothing at all, which meant its claim carried no
    // `storageClassName`, fell through to whichever class the cluster marks
    // default — `standard`, shared by both tenants — and reported a verdict on
    // a per-tenant-StorageClass configuration that was never in its path.
    let retain_pv_name = "kumuteva-retain-pv-tenant1";
    let wanted_policy = if use_retain_policy {
        "Retain"
    } else {
        "Delete"
    };
    let retain_class = tenant_storage_class(tenant1, wanted_policy).await;

    if use_retain_policy && retain_class.is_none() {
        info!("No Retain StorageClass for tenant1; falling back to a hostPath PersistentVolume");
        if let Err(e) = tenant1
            .cluster
            .create_cluster_resource::<PersistentVolume>(&hostpath_pv_manifest(
                retain_pv_name,
                "Retain",
            ))
            .await
        {
            return Ok(AccessResult::VictimBlocked(format!(
                "Tenant1 cannot create a Retain PersistentVolume: {e}"
            )));
        }
    }

    // Step 1: Create StatefulSet in tenant1 with PVC
    info!("Creating a StatefulSet in tenant1");
    let bind_to = (use_retain_policy && retain_class.is_none()).then_some(retain_pv_name);
    let create_result = create_and_wait_stateful_set(
        tenant1,
        &tenant1_commands,
        bind_to,
        // Provision through the tenant's own class, or bind by name to the
        // hand-built volume when the cluster offers no such class. A solution
        // without per-tenant classes passes neither and gets whichever class
        // is default, which is what every existing row did and still does.
        retain_class.as_deref().or_else(|| bind_to.map(|_| "")),
    )
    .await;

    let (created_pvc_name, dynamic_pv_name) = match create_result {
        Ok(info) => info,
        Err(e) => {
            if bind_to.is_some() {
                let _ = tenant1
                    .cluster
                    .delete_cluster_resource::<PersistentVolume>(retain_pv_name)
                    .await;
            }
            // A refusal is a finding; a pod that never appeared is not. The
            // refusal may be in the error, or — when PodSecurity rejected the
            // controller's pod rather than our object — only in an event.
            let refusal = if refused_rather_than_unobserved(&e) {
                Some(e.to_string())
            } else {
                statefulset_refusal(tenant1).await
            };
            return Ok(match refusal {
                Some(reason) => {
                    AccessResult::VictimBlocked(format!("Cannot create PVC/PV: {reason}"))
                }
                None => AccessResult::Undetermined(format!("Cannot create PVC/PV: {e}")),
            });
        }
    };

    // Step 2: Release the PV from tenant1
    let release_pv = release_pv_from_tenant(tenant1, &dynamic_pv_name, &created_pvc_name).await;

    match release_pv {
        Ok(_) => info!("Released PV {} from tenant1", dynamic_pv_name),
        Err(e) => {
            let error_msg = e.to_string();
            // Check for various forms of access denial:
            // - "cannot patch resource" / "forbidden" - standard RBAC denial
            // - "not found" - Capsule proxy hides cluster-scoped resources from tenants
            // - "not allowed" - Capsule proxy explicit denial
            // - deserialization errors with "Status" - kube client failing to parse error response
            if error_msg.contains("cannot patch resource \"persistentvolumes\"")
                || error_msg.contains("forbidden")
                || error_msg.contains("not found")
                || error_msg.contains("not allowed")
                || (error_msg.contains("Status") && error_msg.contains("deserializ"))
            {
                info!(
                    "PV {} access is blocked for tenant1 (proxy or RBAC restriction). Storage is isolated.",
                    dynamic_pv_name
                );
                return Ok(AccessResult::IntruderBlockedByPolicy(
                    "Cannot access PersistentVolume - cluster-scoped resource blocked by RBAC policy or reverse proxy filtering".to_string(),
                ));
            }
            info!(
                "Could not release PV {} from tenant1: {}. Unable to continue test.",
                dynamic_pv_name, e
            );
            return Ok(AccessResult::PartialAutonomy(format!(
                "Cannot release PV: {}",
                e
            )));
        }
    }

    // Step 3: Try to create StatefulSet in tenant2 that uses the released PV
    //
    // The claim has to name the volume's own class. This volume was
    // dynamically provisioned, so it carries whatever the StorageClass was —
    // `standard` on kind — and a claim declaring anything else, the empty
    // string included, simply never binds. Reading it off the volume keeps
    // this correct whatever provisioner the cluster runs.
    let released_class = tenant2
        .cluster
        .get_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
        .await
        .ok()
        .and_then(|pv| pv.spec.and_then(|spec| spec.storage_class_name))
        .unwrap_or_default();

    info!("Creating a StatefulSet in tenant2");
    let mount_attempt = create_stateful_set(
        tenant2,
        &tenant2_commands,
        Some(&dynamic_pv_name),
        Some(&released_class),
        false,
    )
    .await;

    if let Err(e) = mount_attempt {
        info!(
            "Tenant2 cannot create StatefulSet with the PV from Tenant1, storage is isolated: {}",
            e
        );
        // Cleanup the released PV
        let _ = tenant1
            .cluster
            .delete_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
            .await;

        let error_msg = e.to_string();
        if error_msg.contains("forbidden") || error_msg.contains("denied") {
            return Ok(AccessResult::IntruderBlockedByPolicy(format!(
                "Tenant2 cannot bind to released PV: {}",
                e
            )));
        }
        return Ok(AccessResult::Isolated(format!(
            "tenant2 could not create the mounting workload: {e}"
        )));
    }

    // Step 4: Check if tenant2 can actually mount and access the volume
    info!("Checking if tenant2 can mount the pv created by tenant1");
    let mount_result = check_mount_attempt(tenant2).await;

    if mount_result.is_err() {
        info!("Tenant2 cannot mount the pv created by Tenant1, storage is isolated");

        // Ask *why* before calling this isolation. A StatefulSet is admitted
        // even when the claims it asks for are not: the object is created, the
        // controller's own PVC create is refused, and the refusal lands in a
        // `FailedCreate` event that never reaches the call this code made. The
        // wait then runs out, and a policy that forbade the claim is
        // indistinguishable from a volume the intruder genuinely could not
        // reach — the first is Soft, the second Hard, and reporting the
        // stronger one is the direction that flatters the platform.
        //
        // A per-tenant StorageClass row hits this on every run: the intruder
        // quotes the released volume's class, admission denies it by name, and
        // without this the property reported Hard for what is a 403.
        let refusal = statefulset_refusal(tenant2).await;

        // Cleanup
        let _ = tenant2
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
            .await;
        let _ = tenant1
            .cluster
            .delete_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
            .await;

        return Ok(match refusal {
            Some(reason) => AccessResult::IntruderBlockedByPolicy(format!(
                "Tenant2 was refused the released volume: {reason}"
            )),
            None => AccessResult::Isolated(
                "tenant2's pod never became ready on the released volume".to_string(),
            ),
        });
    }

    // Step 5: Check if tenant2 can access tenant1's data
    //
    // An error here means the intruder never reported an outcome, which is not
    // the same as reporting that it found nothing — collapsing the two would
    // turn a failed observation into a claim of isolation.
    let (can_access_tenant1_files, evidence) = match check_cross_tenant_mount(tenant2).await {
        Ok(outcome) => outcome,
        Err(e) => return Ok(AccessResult::Undetermined(e.to_string())),
    };
    info!("Intruder reported: {evidence}");

    // Step 6: Cleanup resources
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
        .await;

    // Get the PVC name from tenant2's StatefulSet before cleanup
    let tenant2_pvc_name = match get_pvc_and_pv_info(tenant2).await {
        Ok((pvc_name, _)) => pvc_name,
        // Was `{PVC_NAME}-{POD_NAME}`, which is not a name any StatefulSet
        // generates — the ordinal is part of it — so the fallback deleted
        // nothing.
        Err(_) => statefulset_pvc_name(),
    };

    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<PersistentVolumeClaim>(
            &tenant2_pvc_name,
            &tenant2.namespace,
        )
        .await;

    let _ = tenant1
        .cluster
        .delete_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
        .await;

    if can_access_tenant1_files {
        Ok(AccessResult::Accessible)
    } else {
        Ok(AccessResult::Isolated(evidence))
    }
}

// =============================================================================
// MANIFEST CREATION HELPERS
// =============================================================================

fn create_test_hostpath_pv_manifest(name: &str) -> PersistentVolume {
    hostpath_pv_manifest(name, "Delete")
}

/// A hostPath-backed PersistentVolume with an explicit reclaim policy.
///
/// The reclaim policy belongs here and nowhere else: it is a field of
/// PersistentVolume, and a PersistentVolumeClaim has no such field. Setting it
/// on a claim — which this subsystem used to do — is discarded silently by
/// k8s-openapi, so `Retain` never reached the cluster and the property named
/// after it measured the same thing as the one beside it.
fn hostpath_pv_manifest(name: &str, reclaim_policy: &str) -> PersistentVolume {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": { "name": name },
        "spec": {
            "capacity": { "storage": STORAGE_SIZE },
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": reclaim_policy,
            "hostPath": {
                "path": HOSTPATH_PV_HOST_PATH,
                "type": "DirectoryOrCreate"
            }
        },
    }))
    .unwrap()
}

async fn create_stateful_set<T: AsRef<str> + Serialize>(
    tenant: &TenantClusterConfig,
    commands: &[T],
    pv_name: Option<&str>,
    pv_storage_class: Option<&str>,
    use_hostpath: bool,
) -> anyhow::Result<()> {
    let tenant_set =
        create_tenant_statefulset_manifest(commands, pv_name, pv_storage_class, use_hostpath)?;

    tenant
        .cluster
        .create_namespaced_resource::<StatefulSet>(&tenant_set, &tenant.namespace)
        .await
        .map(|_| ())
}

fn create_tenant_statefulset_manifest<T: AsRef<str> + Serialize>(
    commands: &[T],
    pv_name: Option<&str>,
    pv_storage_class: Option<&str>,
    use_hostpath: bool,
) -> anyhow::Result<StatefulSet> {
    let pvc_name = if use_hostpath {
        HOSTPATH_PVC_NAME
    } else {
        PVC_NAME
    };
    let mount_path = if use_hostpath {
        HOSTPATH_MOUNT_PATH
    } else {
        MOUNT_PATH
    };

    let mut pod_manifest: StatefulSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": { "name": POD_NAME },
        "spec": {
            "selector": { "matchLabels": { "app": POD_NAME } },
            "template": {
                "metadata": { "labels": { "app": POD_NAME } },
                "spec": {
                    "containers": [{
                        "name": POD_NAME,
                        "image": "nginx",
                        "command": commands,
                        "volumeMounts": [{ "mountPath": mount_path, "name": pvc_name }],
                        "resources": {
                            "requests": {
                                "memory": "64Mi",
                                "cpu": "250m"
                            },
                            "limits": {
                                "memory": "128Mi",
                                "cpu": "500m"
                            }
                        }
                    }],
                },
            },
            "restartPolicy": "Never",
            "replicas": 1
        }
    }))?;

    if use_hostpath {
        if let Some(spec) = pod_manifest.spec.as_mut() {
            spec.volume_claim_templates = None;
            let mut pod_spec = spec.template.spec.clone().unwrap_or_default();
            pod_spec.volumes = Some(vec![serde_json::from_value(serde_json::json!({
                "name": pvc_name,
                "hostPath": { "path": HOSTPATH_INLINE_HOST_PATH, "type": "DirectoryOrCreate" }
            }))?]);
            spec.template.spec = Some(pod_spec);
        }
    } else if let Some(spec) = pod_manifest.spec.as_mut() {
        let pvc_spec = serde_json::json!({
            "accessModes": ["ReadWriteOnce"],
            "resources": { "requests": { "storage": STORAGE_SIZE } },
        });
        spec.volume_claim_templates = Some(vec![serde_json::from_value(serde_json::json!({
            "metadata": { "name": pvc_name },
            "spec": pvc_spec,
        }))?]);
    }

    // The class is applied whether or not a volume is named. It used to be set
    // only inside the `pv_name` branch, so a dynamically provisioned claim
    // carried no class however the caller was asked to provision it: the
    // per-tenant StorageClass the tenant had just been given was looked up,
    // passed in, and then dropped here, leaving the claim to the cluster
    // default that both tenants share.
    if let Some(spec) = pod_manifest.spec.as_mut() {
        if let Some(volume_claim_templates) = spec.volume_claim_templates.as_mut() {
            if !volume_claim_templates.is_empty() {
                if let Some(claim_spec) = volume_claim_templates[0].spec.as_mut() {
                    if let Some(pv_name) = pv_name {
                        claim_spec.volume_name = Some(pv_name.to_string());
                        // Naming a volume is not enough to bind to it: the
                        // claim's class must equal the volume's.
                        //
                        // A claim that says nothing gets the cluster default
                        // stamped on by admission — `standard` on kind. That
                        // matches a dynamically provisioned volume and can never
                        // match a hand-made one, which has no class at all. So
                        // the claim copies whatever the volume actually carries,
                        // with the empty string standing for "no class".
                        //
                        // Both halves are load-bearing, and getting either wrong
                        // fails in the reassuring direction: the claim stays
                        // Pending, the pod never starts, and an intruder that
                        // could not bind looks exactly like one that was stopped.
                        claim_spec.storage_class_name =
                            Some(pv_storage_class.unwrap_or_default().to_string());
                    } else if let Some(class) = pv_storage_class {
                        // Dynamic provisioning through a named class. Left unset
                        // when the caller names none, which is what every
                        // solution without per-tenant classes does.
                        claim_spec.storage_class_name = Some(class.to_string());
                    }
                }
            }
        }
    }

    Ok(pod_manifest)
}

// =============================================================================
// COMMAND HELPERS
// =============================================================================

fn file_path() -> String {
    format!("{}/{}", MOUNT_PATH, FILE_NAME)
}

/// The victim writes its marker, then confirms it can read it back.
///
/// The read-back is the positive control. Without it, "the intruder found
/// nothing" is ambiguous between isolation and the victim never having written
/// anything — and this experiment has been reporting the first while unable to
/// rule out the second. Every experiment in `breach.rs` requires this
/// confirmation before an intruder's silence is allowed to count; this one is
/// hand-written and did not.
fn tenant1_commands() -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            // Reports where it wrote, not only that it wrote. The intruder
            // reports the same two lines when it finds nothing, so a
            // disagreement between the two — different mount, different
            // device — is visible in the report instead of needing a live
            // cluster to diagnose.
            //
            // `sleep 3600` rather than 30: the pod used to exit and be
            // restarted by the StatefulSet, which re-ran `echo > file` while
            // the intruder was reading. Staying up removes a moving target
            // from an experiment that is about what is on disk.
            "echo '{}' > {} && cat {} && \
             echo \"VICTIM_CONTENTS: $(ls -la {} 2>&1 | tr '\\n' ' ')\" && \
             echo \"VICTIM_SOURCE: $(grep -F ' {} ' /proc/self/mounts 2>&1 | tr '\\n' ' ')\" && \
             echo '{}' && sleep 3600",
            FILE_CONTENT,
            file_path(),
            file_path(),
            MOUNT_PATH,
            MOUNT_PATH,
            VICTIM_WROTE_MARKER
        ),
    ]
}

/// Printed by the victim once its marker is on disk and readable.
const VICTIM_WROTE_MARKER: &str = "VICTIM_WROTE_SECRET";

/// Did the victim actually plant anything?
///
/// Returns the victim's confirmation, or `None` if it never appeared. `None`
/// makes the whole experiment undetermined: an intruder that finds nothing
/// where nothing was put has demonstrated precisely nothing.
async fn victim_planted_secret(tenant: &TenantClusterConfig) -> Option<String> {
    const ATTEMPTS: u32 = 30;
    let label = format!("app={}", POD_NAME);

    for attempt in 1..=ATTEMPTS {
        let pod_name = tenant
            .cluster
            .list_pods_with_label_in_namespace(&label, &tenant.namespace)
            .await
            .ok()
            .and_then(|pods| pods.items.into_iter().next())
            .and_then(|pod| pod.metadata.name);

        if let Some(pod_name) = pod_name {
            if let Ok(logs) = tenant
                .cluster
                .get_pod_logs(&pod_name, &tenant.namespace)
                .await
            {
                if logs.contains(VICTIM_WROTE_MARKER) {
                    return Some(logs);
                }
            }
        }

        if attempt == ATTEMPTS {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    None
}

fn tenant2_commands() -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            // Retried, not read once. Everything else in this experiment
            // polls — the victim's marker, the intruder's own log — but the
            // read itself had exactly one chance, so a file that landed a
            // moment late read as isolation. This property reported `Hard`
            // intermittently on identical clusters, which is a false claim of
            // isolation, and the safe direction is to look again: a tenant
            // that genuinely cannot see the file still reports failure after
            // the retries, just later.
            "echo 'Reading file content:' && \
             for attempt in $(seq 1 15); do \
               [ -f {} ] && break; \
               sleep 2; \
             done; \
             if cat {} 2>/dev/null; then \
               if [ \"$(cat {} 2>/dev/null)\" = \"{}\" ]; then \
                 echo 'CROSS_TENANT_ACCESS_SUCCESS: Found tenant1 file content'; \
               else \
                 echo 'CROSS_TENANT_ACCESS_FAILED: File exists but content differs'; \
               fi; \
             else \
               echo 'CROSS_TENANT_ACCESS_FAILED: File not found/accessible'; \
               echo \"MOUNT_CONTENTS: $(ls -la {} 2>&1 | tr '\\n' ' ')\"; \
               echo \"MOUNT_SOURCE: $(grep -F ' {} ' /proc/self/mounts 2>&1 | tr '\\n' ' ')\"; \
             fi && sleep 10",
            file_path(),
            file_path(),
            file_path(),
            FILE_CONTENT,
            MOUNT_PATH,
            MOUNT_PATH,
        ),
    ]
}

// =============================================================================
// STATEFULSET & PV MANAGEMENT HELPERS
// =============================================================================

async fn create_and_wait_stateful_set<T: AsRef<str> + Serialize>(
    tenant: &TenantClusterConfig,
    commands: &[T],
    pv_name: Option<&str>,
    pv_storage_class: Option<&str>,
) -> anyhow::Result<(String, String)> {
    create_stateful_set(tenant, commands, pv_name, pv_storage_class, false).await?;
    wait_and_get_volume_info(tenant).await
}

async fn wait_and_get_volume_info(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<(String, String)> {
    wait_for_statefulset_ready(tenant).await?;
    let (created_pvc_name, dynamic_pv_name) = get_pvc_and_pv_info(tenant).await?;
    info!("A dynamic PV was created: {}", dynamic_pv_name);
    Ok((created_pvc_name, dynamic_pv_name))
}

/// The PVC a StatefulSet's `volumeClaimTemplate` generates.
///
/// `<template>-<statefulset>-<ordinal>`, and the ordinal is not optional: built
/// without it the name matches nothing, the delete silently succeeds, and the
/// claim survives to poison the next experiment.
fn statefulset_pvc_name() -> String {
    format!("{PVC_NAME}-{POD_NAME}-0")
}

async fn release_pv_from_tenant(
    tenant: &TenantClusterConfig,
    pv_name: &str,
    pvc_name: &str,
) -> anyhow::Result<()> {
    tenant
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .delete_resource_in_namespace::<PersistentVolumeClaim>(pvc_name, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .patch_cluster_resource::<PersistentVolume, _>(
            pv_name,
            &kube::api::Patch::Strategic(serde_json::json!({ "spec": { "claimRef": null } })),
        )
        .await?;

    Ok(())
}

async fn wait_for_statefulset_ready(tenant: &TenantClusterConfig) -> anyhow::Result<()> {
    tenant
        .cluster
        .watch_namespaced_resource_until_condition::<StatefulSet, _, _>(
            POD_NAME,
            &tenant.namespace,
            POD_CREATION_TIMEOUT,
            |_event| async {
                let stateful_set = tenant
                    .cluster
                    .get_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
                    .await;

                if stateful_set.is_err() {
                    return false;
                }

                let stateful_set = stateful_set.unwrap();
                let replicas = stateful_set
                    .status
                    .as_ref()
                    .map(|status| status.replicas)
                    .unwrap_or(0);
                let ready_replicas = stateful_set
                    .status
                    .as_ref()
                    .and_then(|status| status.ready_replicas)
                    .unwrap_or(0);

                replicas > 0 && replicas == ready_replicas
            },
        )
        .await
}

async fn get_pvc_and_pv_info(tenant: &TenantClusterConfig) -> anyhow::Result<(String, String)> {
    let created_pvc = tenant
        .cluster
        .list_namespaced_resources::<PersistentVolumeClaim>(&tenant.namespace)
        .await?
        .items
        .into_iter()
        .find(|pvc| {
            pvc.metadata
                .labels
                .as_ref()
                .map(|labels| labels.get("app").map(|v| v == POD_NAME).unwrap_or(false))
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow::anyhow!("PersistentVolumeClaim not found"))?;

    let created_pvc_name = created_pvc.metadata.name.as_deref().unwrap_or_default();
    let dynamic_pv_name = created_pvc
        .spec
        .ok_or_else(|| anyhow::anyhow!("PVC spec not found"))?
        .volume_name
        .ok_or_else(|| anyhow::anyhow!("PVC volume_name not found"))?;

    Ok((created_pvc_name.to_string(), dynamic_pv_name))
}

async fn check_mount_attempt(tenant: &TenantClusterConfig) -> anyhow::Result<()> {
    let wait_operation = tenant
        .cluster
        .watch_namespaced_resource_until_condition::<StatefulSet, _, _>(
            POD_NAME,
            &tenant.namespace,
            POD_CREATION_TIMEOUT,
            |_event| async {
                let pod = tenant
                    .cluster
                    .list_pods_with_label_in_namespace(
                        &format!("app={}", POD_NAME),
                        &tenant.namespace,
                    )
                    .await
                    .map(|pods| pods.items.first().cloned());

                if pod.is_err() || pod.as_ref().unwrap().is_none() {
                    return false;
                }

                let pod = pod.unwrap().unwrap();
                pod.status
                    .and_then(|status| status.container_statuses)
                    .map(|container_statuses| {
                        container_statuses.iter().any(|cs| {
                            cs.state
                                .as_ref()
                                .and_then(|state| {
                                    state
                                        .terminated
                                        .as_ref()
                                        .map(|t| t.exit_code == 0 || t.exit_code == 1)
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            },
        )
        .await;

    if let Err(err) = &wait_operation {
        if err.to_string().contains("timed out") {
            return Err(anyhow::anyhow!(
                "Pod creation timed out, we assume a policy is blocking the cross-tenant mount"
            ));
        }
    }

    wait_operation
}

/// Did the intruder read the victim's file?
///
/// `Ok(true)` it did, `Ok(false)` it looked and found nothing, `Err` we never
/// managed to ask — and the three must stay distinct, because the last one is
/// not a finding.
///
/// Polls the pod's logs rather than watching for a container-state transition.
/// The probe container runs for a few seconds and a StatefulSet's restart
/// policy is always `Always`, so it exits and restarts: a watch started a
/// moment late sees no transition, times out, and the caller turned that into
/// `false`. That reported the intruder as blocked when it had in fact printed
/// the victim's file — confirmed on a live cluster, where the same manifests
/// logged `CROSS_TENANT_ACCESS_SUCCESS` while this function returned nothing.
async fn check_cross_tenant_mount(tenant: &TenantClusterConfig) -> anyhow::Result<(bool, String)> {
    const ATTEMPTS: u32 = 45;

    let label = format!("app={}", POD_NAME);

    for attempt in 1..=ATTEMPTS {
        let pod_name = tenant
            .cluster
            .list_pods_with_label_in_namespace(&label, &tenant.namespace)
            .await
            .ok()
            .and_then(|pods| pods.items.into_iter().next())
            .and_then(|pod| pod.metadata.name);

        if let Some(pod_name) = pod_name {
            if let Ok(logs) = tenant
                .cluster
                .get_pod_logs(&pod_name, &tenant.namespace)
                .await
            {
                // The probe prints exactly one of these, so either is an answer
                // and the absence of both means it has not spoken yet.
                if logs.contains("CROSS_TENANT_ACCESS_SUCCESS")
                    || logs.contains("HOSTPATH_ACCESS_SUCCESS")
                {
                    info!("Cross-tenant access detected in logs:\n{}", logs);
                    return Ok((true, marker_line(&logs)));
                }
                if logs.contains("CROSS_TENANT_ACCESS_FAILED")
                    || logs.contains("HOSTPATH_ACCESS_FAILED")
                {
                    info!("No cross-tenant access detected in logs:\n{}", logs);
                    // Carry what the intruder actually saw. "File not found"
                    // reads the same whether the directory was empty, held a
                    // different file, or was not the mount we meant — and this
                    // property reports `Hard` intermittently, which is a false
                    // claim of isolation that the marker alone cannot explain.
                    let mut evidence = marker_line(&logs);
                    for line in logs.lines() {
                        if line.starts_with("MOUNT_CONTENTS:") || line.starts_with("MOUNT_SOURCE:")
                        {
                            evidence.push_str(" | ");
                            evidence.push_str(line.trim());
                        }
                    }
                    return Ok((false, evidence));
                }
            }
        }

        if attempt == ATTEMPTS {
            return Err(anyhow::anyhow!(
                "the intruder pod never reported either outcome within {}s — \
                 nothing was observed, so nothing can be concluded",
                ATTEMPTS * 2
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    unreachable!("the loop returns on its final attempt")
}

/// The line the probe used to announce its outcome.
///
/// Carried into the verdict so a reader can see *why* the intruder reported
/// what it did — "File not found/accessible" and "File exists but content
/// differs" are very different failures, and a bare `Hard` distinguishes
/// neither. Diagnosing this previously meant reproducing the whole scenario by
/// hand.
fn marker_line(logs: &str) -> String {
    logs.lines()
        .find(|line| line.contains("ACCESS_SUCCESS") || line.contains("ACCESS_FAILED"))
        .unwrap_or("no marker line")
        .trim()
        .to_string()
}

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for StorageResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageResource::Volume => write!(f, "Volume"),
        }
    }
}

impl Display for StorageOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageOperation::CreateAndMountVolume => {
                write!(f, "Create And Mount Volume (unsetted Reclaim Policy)")
            }
            StorageOperation::CreateAndMountVolumeWithRetainPolicy => {
                write!(f, "Create And Mount Volume with Retain Reclaim Policy")
            }
            StorageOperation::UseHostPath => write!(f, "Use HostPath in a Volume"),
            StorageOperation::UsePersistentHostPath => {
                write!(f, "Use HostPath through a PersistentVolume")
            }
        }
    }
}

#[cfg(test)]
mod verdict_classification_tests {
    use super::*;

    /// The generated claim's name must carry the ordinal.
    ///
    /// Built without it the delete matches nothing and succeeds anyway, so the
    /// claim outlives its experiment and the next one's pod waits on a volume
    /// that no longer exists.
    #[test]
    fn the_statefulset_claim_name_includes_the_ordinal() {
        let name = statefulset_pvc_name();
        assert_eq!(name, format!("{PVC_NAME}-{POD_NAME}-0"));
        assert!(name.ends_with("-0"), "{name}");
    }

    /// The intruder must look more than once before reporting isolation.
    ///
    /// Reading a single time made this property report `Hard` intermittently
    /// on identical clusters — a file that landed a moment late read as
    /// isolation, which is a false claim in the safest-looking direction.
    /// Retrying cannot manufacture a breach: a tenant that genuinely cannot
    /// see the file still fails, only later.
    #[test]
    fn the_intruder_retries_before_concluding_it_cannot_see_the_file() {
        let script = tenant2_commands().join(" ");
        assert!(script.contains("for attempt in $(seq 1 15)"), "{script}");
        assert!(script.contains("CROSS_TENANT_ACCESS_FAILED"), "{script}");
    }

    /// And it says what it saw when it fails, so an intermittent `Hard` is
    /// diagnosable from the report rather than only from a live cluster.
    #[test]
    fn a_failed_read_reports_what_was_actually_mounted() {
        let script = tenant2_commands().join(" ");
        assert!(script.contains("MOUNT_CONTENTS:"), "{script}");
        assert!(script.contains("MOUNT_SOURCE:"), "{script}");
    }

    /// The two hostPath properties must not share a node directory.
    ///
    /// They did, and it made the PersistentVolume-backed one flaky: the inline
    /// property plants a file in the same place and is torn down immediately
    /// before it runs. Measured twice on identical clusters the second
    /// reported `Hard` once and a breach once — and an intermittent `Hard` is
    /// a false claim of isolation, the worst thing this table can contain.
    #[test]
    fn the_two_hostpath_properties_touch_different_node_directories() {
        assert_ne!(HOSTPATH_INLINE_HOST_PATH, HOSTPATH_PV_HOST_PATH);
        // Both still under one parent, so a single cleanup finds them.
        for path in [HOSTPATH_INLINE_HOST_PATH, HOSTPATH_PV_HOST_PATH] {
            assert!(path.starts_with(HOSTPATH_MOUNT_PATH), "{path}");
        }
    }

    /// Within one property both tenants must still share a directory — that
    /// shared directory is the thing being tested, and separating the tenants
    /// would turn every hostPath breach into a false `Hard`.
    #[test]
    fn both_tenants_of_a_property_share_its_directory() {
        let pv = hostpath_pv_manifest("kumuteva-pv", "Retain");
        assert_eq!(
            pv.spec
                .as_ref()
                .and_then(|spec| spec.host_path.as_ref())
                .map(|host| host.path.as_str()),
            Some(HOSTPATH_PV_HOST_PATH),
            "every tenant's PersistentVolume names the same node directory"
        );
    }

    /// A timeout must never be read as a refusal.
    ///
    /// This is the distinction the storage subsystem got wrong: both arrive as
    /// an `Err` from the same call, and both look like "the pod did not run".
    /// One is the platform declining — a finding — and the other is the probe
    /// failing to observe anything, which is not. Recording the second as the
    /// first reported `native`, a cluster with no isolation at all, as
    /// isolated.
    #[test]
    fn a_timeout_is_not_a_refusal() {
        for unobserved in [
            "Resource watch timed out",
            "Pod did not become ready in time",
            "deadline has elapsed",
        ] {
            assert!(
                !refused_rather_than_unobserved(&anyhow::anyhow!("{unobserved}")),
                "{unobserved} says nothing about isolation"
            );
        }

        for refusal in [
            "pods is forbidden: User \"tenant2-admin\" cannot create resource",
            "admission webhook \"pods.projectcapsule.dev\" denied the request",
            "persistentvolumes is not allowed for this tenant",
        ] {
            assert!(
                refused_rather_than_unobserved(&anyhow::anyhow!("{refusal}")),
                "{refusal} is the platform declining, which is a result"
            );
        }
    }

    /// The refusal PodSecurity produces is a controller event, not an error on
    /// the call we made — and it must still read as a refusal.
    ///
    /// Verified against a live cluster: applying the storage StatefulSet to a
    /// namespace labelled `pod-security.kubernetes.io/enforce=restricted`
    /// creates the object and then emits exactly this, with no pod ever
    /// appearing. Without matching it, a tenant that forbids the operation is
    /// indistinguishable from a cluster that is merely slow.
    #[test]
    fn a_podsecurity_rejection_in_an_event_reads_as_a_refusal() {
        let event = "create Pod persistent-pod-0 in StatefulSet persistent-pod failed error: \
                     pods \"persistent-pod-0\" is forbidden: violates PodSecurity \
                     \"restricted:latest\": allowPrivilegeEscalation != false";
        assert!(refused_text(event));

        // Quota is the other way a controller's pod creation is declined.
        assert!(refused_text("exceeded quota: compute-resources"));

        // And the ordinary progress messages are not refusals.
        for benign in [
            "waiting for first consumer to be created before binding",
            "create Claim kumuteva-pv-claim-persistent-pod-0 ... success",
            "Successfully assigned tenant1/persistent-pod-0 to node",
        ] {
            assert!(!refused_text(benign), "{benign}");
        }
    }

    /// An undetermined result must not reach the table as a level.
    #[test]
    fn undetermined_reports_unknown_rather_than_hard() {
        let verdict: CrossTenantResult =
            AccessResult::Undetermined("Resource watch timed out".to_string()).into();
        assert_eq!(verdict.isolation, IsolationLevel::Unknown);
    }
}

#[cfg(test)]
mod reclaim_policy_tests {
    use super::*;

    /// A claim that names a volume must also opt out of the default class.
    ///
    /// Verified against a live cluster: with the class left unset the claim is
    /// stamped `standard` by admission, the hand-made PersistentVolume has no
    /// class, and the two never bind — the pod sits Pending until the probe
    /// times out. Setting it to the empty string, the pod reaches Running in
    /// about twenty seconds.
    ///
    /// This is why `Use HostPath through a PersistentVolume` never once ran:
    /// every verdict it has produced was an authorization refusal or a timeout,
    /// never an observation of the route it names.
    #[test]
    fn a_claim_naming_a_volume_copies_that_volumes_class() {
        // A hand-made volume has no class, and the claim must say so too.
        let manifest =
            create_tenant_statefulset_manifest(&["true"], Some("some-pv"), Some(""), false)
                .expect("the manifest must build");
        let claim_spec = manifest
            .spec
            .as_ref()
            .unwrap()
            .volume_claim_templates
            .as_ref()
            .unwrap()[0]
            .spec
            .as_ref()
            .unwrap();

        assert_eq!(claim_spec.volume_name.as_deref(), Some("some-pv"));
        assert_eq!(
            claim_spec.storage_class_name.as_deref(),
            Some(""),
            "an unset class becomes the cluster default, which cannot bind to a classless volume"
        );

        // A dynamically provisioned volume carries a class, and the claim must
        // match *that* — forcing the empty string here was a regression that
        // made an intruder unable to bind look like an intruder held back.
        let dynamic_pv =
            create_tenant_statefulset_manifest(&["true"], Some("pvc-abc"), Some("standard"), false)
                .expect("the manifest must build");
        let dynamic_claim = dynamic_pv
            .spec
            .as_ref()
            .unwrap()
            .volume_claim_templates
            .as_ref()
            .unwrap()[0]
            .spec
            .as_ref()
            .unwrap();
        assert_eq!(
            dynamic_claim.storage_class_name.as_deref(),
            Some("standard")
        );

        // A claim that wants dynamic provisioning must NOT opt out, or it would
        // never be provisioned at all.
        let dynamic = create_tenant_statefulset_manifest(&["true"], None, None, false)
            .expect("the manifest must build");
        let dynamic_spec = dynamic
            .spec
            .as_ref()
            .unwrap()
            .volume_claim_templates
            .as_ref()
            .unwrap()[0]
            .spec
            .as_ref()
            .unwrap();
        assert!(dynamic_spec.storage_class_name.is_none());
        assert!(dynamic_spec.volume_name.is_none());
    }

    /// The Retain variant must actually retain.
    ///
    /// `persistentVolumeReclaimPolicy` is a field of PersistentVolume, not of
    /// PersistentVolumeClaim. This subsystem used to set it inside a
    /// `volumeClaimTemplates` entry, where k8s-openapi discarded it silently —
    /// so the property named after Retain measured the same thing as the
    /// `unsetted` one beside it, and the two reported identical verdicts on
    /// every solution ever measured.
    ///
    /// The policy now travels on a PersistentVolume the tenant creates itself,
    /// which is the only way a tenant obtains a Retain volume: dynamic
    /// provisioning gives whatever the StorageClass says.
    #[test]
    fn the_reclaim_policy_lives_on_the_volume_not_the_claim() {
        let retained = serde_json::to_value(hostpath_pv_manifest("pv", "Retain"))
            .expect("the volume must serialise");
        assert_eq!(retained["spec"]["persistentVolumeReclaimPolicy"], "Retain");

        let deleted = serde_json::to_value(hostpath_pv_manifest("pv", "Delete"))
            .expect("the volume must serialise");
        assert_eq!(deleted["spec"]["persistentVolumeReclaimPolicy"], "Delete");

        // And nothing tries to say it on the claim, where it would vanish.
        let manifest = create_tenant_statefulset_manifest(&["true"], None, None, false)
            .expect("the manifest must build");
        let claim = &manifest
            .spec
            .as_ref()
            .unwrap()
            .volume_claim_templates
            .as_ref()
            .unwrap()[0];
        let serialised = serde_json::to_value(claim).expect("a claim must serialise");
        assert!(
            serialised["spec"]
                .get("persistentVolumeReclaimPolicy")
                .is_none(),
            "a claim has no reclaim policy; setting one is discarded in silence: {serialised}"
        );
    }
}

#[cfg(test)]
mod hostpath_probe_tests {
    use super::*;

    /// The hostPath authorization probe must declare resources.
    ///
    /// Regression guard for a conflation found during the builder conversion:
    /// the probe used to omit CPU and memory, and on a tenant with a compute
    /// ResourceQuota — `capsule-hardened` — quota admission rejects a pod
    /// without limits before the hostPath policy is consulted. The probe then
    /// reported hostPath as forbidden without ever asking, indistinguishable
    /// from a cluster that genuinely forbids it.
    #[test]
    fn the_hostpath_probe_declares_resources_so_a_quota_cannot_mask_the_answer() {
        let pod = ProbePod::new(HOSTPATH_AUTH_POD_NAME)
            .image("nginx")
            .shell("sleep 1")
            .requests(HostAccess::HostPath {
                host: HOSTPATH_INLINE_HOST_PATH.to_string(),
                mount: HOSTPATH_MOUNT_PATH.to_string(),
            })
            .build();

        let resources = pod.spec.as_ref().unwrap().containers[0]
            .resources
            .as_ref()
            .expect("a probe without resources is refused by quota before it is judged");
        let limits = resources.limits.as_ref().expect("limits");
        assert!(limits.contains_key("cpu"));
        assert!(limits.contains_key("memory"));
        assert!(resources
            .requests
            .as_ref()
            .expect("requests")
            .contains_key("cpu"));

        // And it must still actually ask for the hostPath.
        let volume = &pod.spec.as_ref().unwrap().volumes.as_ref().expect("volume")[0];
        assert_eq!(
            volume.host_path.as_ref().unwrap().path,
            HOSTPATH_INLINE_HOST_PATH
        );
    }
}
