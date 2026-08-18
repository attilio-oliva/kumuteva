mod fairness;

pub use fairness::*;

use std::fmt::Display;

use async_trait::async_trait;
use k8s_openapi::api::{
    apps::v1::StatefulSet,
    core::v1::{PersistentVolume, PersistentVolumeClaim, Pod},
};
use serde::Serialize;
use tracing::info;

use crate::assessment::probe::{HostAccess, ProbePod};
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
const HOSTPATH_MOUNT_PATH: &str = "/tmp/kumuteva-hostpath";
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
    ) -> anyhow::Result<bool> {
        match (resource, operation) {
            (StorageResource::Volume, StorageOperation::CreateAndMountVolume)
            | (StorageResource::Volume, StorageOperation::CreateAndMountVolumeWithRetainPolicy) => {
                let can_create_pv = test_pv_creation_authorization(tenant).await;
                let can_mount_pv = test_pv_mount_authorization(tenant).await;
                Ok(can_create_pv.unwrap_or(false) && can_mount_pv.unwrap_or(false))
            }
            (StorageResource::Volume, StorageOperation::UseHostPath) => {
                // Only the pod matters here. An inline hostPath volume needs no
                // PersistentVolume, so requiring one to be creatable would gate
                // this route behind an unrelated permission — which is precisely
                // what used to happen: the two checks were ANDed, Capsule failed
                // the PersistentVolume half, and the operation was reported as
                // unauthorised while a tenant could mount the host filesystem
                // from any pod it liked.
                Ok(test_hostpath_mount_authorization(tenant)
                    .await
                    .unwrap_or(false))
            }
            (StorageResource::Volume, StorageOperation::UsePersistentHostPath) => {
                // This route genuinely does need both: a cluster-scoped
                // PersistentVolume backed by a host path, and a pod able to
                // mount the claim that binds it.
                let can_create_pv = test_hostpath_creation_authorization(tenant).await;
                let can_mount_pvc = test_pv_mount_authorization(tenant).await;
                Ok(can_create_pv.unwrap_or(false) && can_mount_pvc.unwrap_or(false))
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
                test_hostpath_cross_tenant_access(tenant1, tenant2).await
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

async fn test_pv_creation_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let result = tenant
        .cluster
        .is_authorized_to("create", "PersistentVolume", None)
        .await;

    info!("PV creation authorization test result: {:?}", result);
    Ok(result.is_ok())
}

async fn test_pv_mount_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_commands = vec!["sleep", "1"];
    let result = create_stateful_set(tenant, &test_commands, None, false, false).await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_hostpath_creation_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<bool> {
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

    Ok(result.is_ok())
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
async fn test_hostpath_mount_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let pod = ProbePod::new(HOSTPATH_AUTH_POD_NAME)
        .image("nginx")
        .shell("sleep 1")
        .requests(HostAccess::HostPath {
            host: HOSTPATH_MOUNT_PATH.to_string(),
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

    Ok(result.is_ok())
}

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

async fn test_pv_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    use_retain_policy: bool,
) -> anyhow::Result<CrossTenantResult> {
    match attempt_other_tenant_file_access(tenant1, tenant2, use_retain_policy).await {
        Ok(AccessResult::Isolated) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "Cross-tenant PV access is properly blocked".to_string(),
        }),
        Ok(AccessResult::IsolatedByPolicy(reason)) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(
                "A policy forbid the operation for this resource".to_string(),
            ),
            autonomy: true,
            details: format!("Storage isolated by policy: {}", reason),
        }),
        Ok(AccessResult::PartialAutonomy(reason)) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false, // Partial autonomy means not full autonomy
            details: format!("Storage isolated but with restrictions: {}", reason),
        }),
        Ok(AccessResult::Accessible) => Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "Cross-tenant PV access detected - tenant2 can access tenant1's data"
                .to_string(),
        }),
        Err(e) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!("Could not determine isolation: {}", e),
        }),
    }
}

async fn test_hostpath_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    match test_hostpath_data_isolation(tenant1, tenant2).await {
        Ok(AccessResult::Isolated) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "HostPath volumes are properly isolated between tenants".to_string(),
        }),
        Ok(AccessResult::IsolatedByPolicy(reason)) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(
                "A policy explicitly forbid the operation for this resource".to_string(),
            ),
            autonomy: false, // Policy blocked it, so no autonomy for this operation
            details: format!("HostPath isolated by policy: {}", reason),
        }),
        Ok(AccessResult::PartialAutonomy(reason)) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(reason.clone()),
            autonomy: false,
            details: format!("HostPath partially restricted: {}", reason),
        }),
        Ok(AccessResult::Accessible) => Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "HostPath volume data is accessible across tenants".to_string(),
        }),
        Err(e) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!("Could not determine HostPath isolation: {}", e),
        }),
    }
}

async fn test_persistent_hostpath_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    match test_persistent_hostpath_data_isolation(tenant1, tenant2).await {
        Ok(AccessResult::Isolated) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "HostPath PersistentVolumes are properly isolated between tenants".to_string(),
        }),
        Ok(AccessResult::IsolatedByPolicy(reason)) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(
                "A policy explicitly forbid the operation for this resource".to_string(),
            ),
            autonomy: false,
            details: format!("HostPath PersistentVolume isolated by policy: {}", reason),
        }),
        Ok(AccessResult::PartialAutonomy(reason)) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(reason.clone()),
            autonomy: false,
            details: format!("HostPath PersistentVolume partially restricted: {}", reason),
        }),
        Ok(AccessResult::Accessible) => Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "Node filesystem reachable across tenants through a hostPath \
                      PersistentVolume"
                .to_string(),
        }),
        Err(e) => Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "Could not determine HostPath PersistentVolume isolation: {}",
                e
            ),
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
    async fn cleanup(tenant: &TenantClusterConfig, pv_name: &str) {
        let _ = tenant
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .delete_cluster_resource::<PersistentVolume>(pv_name)
            .await;
    }

    // --- tenant1 writes through the PersistentVolume route ---
    if let Err(e) = tenant1
        .cluster
        .create_cluster_resource::<PersistentVolume>(&create_test_hostpath_pv_manifest(t1_pv))
        .await
    {
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Tenant1 cannot create a hostPath PersistentVolume: {}",
            e
        )));
    }

    if let Err(e) =
        create_stateful_set(tenant1, &tenant1_commands(), Some(t1_pv), false, false).await
    {
        cleanup(tenant1, t1_pv).await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Tenant1 cannot mount a hostPath PersistentVolume: {}",
            e
        )));
    }
    if let Err(e) = wait_for_statefulset_ready(tenant1).await {
        cleanup(tenant1, t1_pv).await;
        return Ok(AccessResult::PartialAutonomy(format!(
            "Tenant1 hostPath PersistentVolume pod never became ready: {}",
            e
        )));
    }
    info!("Tenant1 wrote through a hostPath PersistentVolume.");

    // --- tenant2 attempts the same route to the same host directory ---
    if let Err(e) = tenant2
        .cluster
        .create_cluster_resource::<PersistentVolume>(&create_test_hostpath_pv_manifest(t2_pv))
        .await
    {
        cleanup(tenant1, t1_pv).await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Tenant2 cannot create a hostPath PersistentVolume: {}",
            e
        )));
    }

    if let Err(e) =
        create_stateful_set(tenant2, &tenant2_commands(), Some(t2_pv), false, false).await
    {
        cleanup(tenant1, t1_pv).await;
        cleanup(tenant2, t2_pv).await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Tenant2 cannot mount a hostPath PersistentVolume: {}",
            e
        )));
    }
    if let Err(e) = wait_for_statefulset_ready(tenant2).await {
        cleanup(tenant1, t1_pv).await;
        cleanup(tenant2, t2_pv).await;
        return Ok(AccessResult::PartialAutonomy(format!(
            "Tenant2 hostPath PersistentVolume pod never became ready: {}",
            e
        )));
    }

    let can_access = check_cross_tenant_mount(tenant2).await.unwrap_or(false);

    cleanup(tenant1, t1_pv).await;
    cleanup(tenant2, t2_pv).await;

    if can_access {
        Ok(AccessResult::Accessible)
    } else {
        Ok(AccessResult::Isolated)
    }
}

/// Result of attempting cross-tenant access
#[derive(Debug, Clone)]
enum AccessResult {
    /// Fully isolated - no cross-tenant access possible
    Isolated,
    /// Isolated due to a policy (e.g., RBAC denied patch on PV)
    IsolatedByPolicy(String),
    /// Operation works but with restrictions (partial autonomy)
    PartialAutonomy(String),
    /// Cross-tenant access is possible
    Accessible,
}

async fn test_hostpath_data_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<AccessResult> {
    let tenant1_commands = hostpath_write_commands();
    let tenant2_commands = hostpath_read_commands();

    // Create hostPath volume and write data in tenant1
    let create_result = create_stateful_set(tenant1, &tenant1_commands, None, true, false).await;
    if let Err(e) = create_result {
        // Cleanup attempt
        let _ = tenant1
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
            .await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Cannot create hostPath StatefulSet: {}",
            e
        )));
    }

    if let Err(e) = wait_for_statefulset_ready(tenant1).await {
        let _ = tenant1
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
            .await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "HostPath StatefulSet failed to become ready: {}",
            e
        )));
    }
    info!("Tenant1 has written data to hostPath volume.");

    // Try to read data from tenant2
    let create_result2 = create_stateful_set(tenant2, &tenant2_commands, None, true, false).await;
    if let Err(e) = create_result2 {
        // Cleanup tenant1
        let _ = tenant1
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
            .await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Tenant2 cannot create hostPath StatefulSet: {}",
            e
        )));
    }

    if let Err(e) = wait_for_statefulset_ready(tenant2).await {
        let _ = tenant1
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
            .await;
        let _ = tenant2
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
            .await;
        return Ok(AccessResult::IsolatedByPolicy(format!(
            "Tenant2 HostPath StatefulSet failed: {}",
            e
        )));
    }
    info!("Tenant2 has attempted to read data from hostPath volume.");

    let can_access_data = check_cross_tenant_mount(tenant2).await.unwrap_or(false);

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
        .await;

    if can_access_data {
        Ok(AccessResult::Accessible)
    } else {
        Ok(AccessResult::Isolated)
    }
}

async fn attempt_other_tenant_file_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    use_retain_policy: bool,
) -> anyhow::Result<AccessResult> {
    let tenant1_commands = tenant1_commands();
    let tenant2_commands = tenant2_commands();

    // Step 1: Create StatefulSet in tenant1 with PVC
    info!("Creating a StatefulSet in tenant1");
    let create_result =
        create_and_wait_stateful_set(tenant1, &tenant1_commands, None, use_retain_policy).await;

    let (created_pvc_name, dynamic_pv_name) = match create_result {
        Ok(info) => info,
        Err(e) => {
            return Ok(AccessResult::PartialAutonomy(format!(
                "Cannot create PVC/PV: {}",
                e
            )));
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
                return Ok(AccessResult::IsolatedByPolicy(
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
    info!("Creating a StatefulSet in tenant2");
    let mount_attempt = create_stateful_set(
        tenant2,
        &tenant2_commands,
        Some(&dynamic_pv_name),
        false,
        use_retain_policy,
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
            return Ok(AccessResult::IsolatedByPolicy(format!(
                "Tenant2 cannot bind to released PV: {}",
                e
            )));
        }
        return Ok(AccessResult::Isolated);
    }

    // Step 4: Check if tenant2 can actually mount and access the volume
    info!("Checking if tenant2 can mount the pv created by tenant1");
    let mount_result = check_mount_attempt(tenant2).await;

    if mount_result.is_err() {
        info!("Tenant2 cannot mount the pv created by Tenant1, storage is isolated");
        // Cleanup
        let _ = tenant2
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
            .await;
        let _ = tenant1
            .cluster
            .delete_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
            .await;
        return Ok(AccessResult::Isolated);
    }

    // Step 5: Check if tenant2 can access tenant1's data
    let can_access_tenant1_files = check_cross_tenant_mount(tenant2).await.unwrap_or(false);

    // Step 6: Cleanup resources
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
        .await;

    // Get the PVC name from tenant2's StatefulSet before cleanup
    let tenant2_pvc_name = match get_pvc_and_pv_info(tenant2).await {
        Ok((pvc_name, _)) => pvc_name,
        Err(_) => format!("{}-{}", PVC_NAME, POD_NAME), // Fallback name pattern
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
        Ok(AccessResult::Isolated)
    }
}

// =============================================================================
// MANIFEST CREATION HELPERS
// =============================================================================

fn create_test_hostpath_pv_manifest(name: &str) -> PersistentVolume {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": { "name": name },
        "spec": {
            "capacity": { "storage": STORAGE_SIZE },
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Delete",
            "hostPath": {
                "path": HOSTPATH_MOUNT_PATH,
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
    use_hostpath: bool,
    use_retain_policy: bool,
) -> anyhow::Result<()> {
    let tenant_set =
        create_tenant_statefulset_manifest(commands, pv_name, use_hostpath, use_retain_policy)?;

    tenant
        .cluster
        .create_namespaced_resource::<StatefulSet>(&tenant_set, &tenant.namespace)
        .await
        .map(|_| ())
}

fn create_tenant_statefulset_manifest<T: AsRef<str> + Serialize>(
    commands: &[T],
    pv_name: Option<&str>,
    use_hostpath: bool,
    use_retain_policy: bool,
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
                "hostPath": { "path": HOSTPATH_MOUNT_PATH, "type": "DirectoryOrCreate" }
            }))?]);
            spec.template.spec = Some(pod_spec);
        }
    } else if let Some(spec) = pod_manifest.spec.as_mut() {
        let mut pvc_spec = serde_json::json!({
            "accessModes": ["ReadWriteOnce"],
            "resources": { "requests": { "storage": STORAGE_SIZE } },
        });
        if use_retain_policy {
            pvc_spec["persistentVolumeReclaimPolicy"] = serde_json::json!("Retain");
        }
        spec.volume_claim_templates = Some(vec![serde_json::from_value(serde_json::json!({
            "metadata": { "name": pvc_name },
            "spec": pvc_spec,
        }))?]);
    }

    if let Some(pv_name) = pv_name {
        if let Some(spec) = pod_manifest.spec.as_mut() {
            if let Some(volume_claim_templates) = spec.volume_claim_templates.as_mut() {
                if !volume_claim_templates.is_empty() {
                    if let Some(claim_spec) = volume_claim_templates[0].spec.as_mut() {
                        claim_spec.volume_name = Some(pv_name.to_string());
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

fn tenant1_commands() -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("echo '{}' > {} && sleep 2", FILE_CONTENT, file_path()),
    ]
}

fn tenant2_commands() -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "echo 'Reading file content:' && \
             if cat {} 2>/dev/null; then \
               if [ \"$(cat {} 2>/dev/null)\" = \"{}\" ]; then \
                 echo 'CROSS_TENANT_ACCESS_SUCCESS: Found tenant1 file content'; \
               else \
                 echo 'CROSS_TENANT_ACCESS_FAILED: File exists but content differs'; \
               fi; \
             else \
               echo 'CROSS_TENANT_ACCESS_FAILED: File not found/accessible'; \
             fi && sleep 10",
            file_path(),
            file_path(),
            FILE_CONTENT
        ),
    ]
}

fn hostpath_write_commands() -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "echo '{}' > {}/hostpath-test.txt && sleep 2",
            FILE_CONTENT, HOSTPATH_MOUNT_PATH
        ),
    ]
}

fn hostpath_read_commands() -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "if cat {}/hostpath-test.txt 2>/dev/null; then \
               if [ \"$(cat {}/hostpath-test.txt 2>/dev/null)\" = \"{}\" ]; then \
                 echo 'HOSTPATH_ACCESS_SUCCESS: Found tenant1 hostpath data'; \
               else \
                 echo 'HOSTPATH_ACCESS_FAILED: File exists but content differs'; \
               fi; \
             else \
               echo 'HOSTPATH_ACCESS_FAILED: File not found/accessible'; \
             fi && sleep 10",
            HOSTPATH_MOUNT_PATH, HOSTPATH_MOUNT_PATH, FILE_CONTENT
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
    use_retain_policy: bool,
) -> anyhow::Result<(String, String)> {
    create_stateful_set(tenant, commands, pv_name, false, use_retain_policy).await?;
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

async fn check_cross_tenant_mount(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let label = format!("app={}", POD_NAME);
    let pod = tenant
        .cluster
        .list_pods_with_label_in_namespace(&label, &tenant.namespace)
        .await?
        .items
        .first()
        .ok_or(anyhow::anyhow!("Pod in tenant2 not found"))?
        .to_owned();

    tenant
        .cluster
        .watch_pod_until_condition(
            pod.metadata.name.as_deref().unwrap_or_default(),
            &tenant.namespace,
            |pod_event| async {
                match pod_event {
                    kube::api::WatchEvent::Modified(pod) => {
                        if let Some(status) = &pod.status {
                            if let Some(container_statuses) = &status.container_statuses {
                                for cs in container_statuses {
                                    if cs
                                        .state
                                        .as_ref()
                                        .and_then(|s| s.terminated.as_ref())
                                        .is_some()
                                    {
                                        if let Ok(logs) = tenant
                                            .cluster
                                            .get_pod_logs(
                                                pod.metadata.name.as_deref().unwrap_or_default(),
                                                &tenant.namespace,
                                            )
                                            .await
                                        {
                                            if logs.contains("CROSS_TENANT_ACCESS_SUCCESS")
                                                || logs.contains("HOSTPATH_ACCESS_SUCCESS")
                                                || logs.contains("CROSS_TENANT_ACCESS_FAILED")
                                                || logs.contains("HOSTPATH_ACCESS_FAILED")
                                            {
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        false
                    }
                    _ => false,
                }
            },
        )
        .await?;

    let logs = tenant
        .cluster
        .get_pod_logs(
            pod.metadata.name.as_deref().unwrap_or_default(),
            &tenant.namespace,
        )
        .await?;

    if logs.contains("CROSS_TENANT_ACCESS_SUCCESS") || logs.contains("HOSTPATH_ACCESS_SUCCESS") {
        info!("Cross-tenant access detected in logs:\n{}", logs);
        return Ok(true);
    }

    if logs.contains("CROSS_TENANT_ACCESS_FAILED") || logs.contains("HOSTPATH_ACCESS_FAILED") {
        info!("No cross-tenant access detected in logs:\n{}", logs);
        return Ok(false);
    }

    Ok(false)
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
                host: HOSTPATH_MOUNT_PATH.to_string(),
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
        assert_eq!(volume.host_path.as_ref().unwrap().path, HOSTPATH_MOUNT_PATH);
    }
}
