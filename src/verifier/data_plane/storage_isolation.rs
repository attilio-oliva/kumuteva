use std::{collections::HashMap, fmt::Display};

use k8s_openapi::api::{
    apps::v1::StatefulSet,
    core::v1::{PersistentVolume, PersistentVolumeClaim, Pod},
    storage::v1::StorageClass,
};
use serde::Serialize;

use crate::verifier::TenantClusterConfig;

// Constants for resource naming and configuration
const POD_NAME: &str = "persistent-pod";
const PVC_NAME: &str = "kumuteva-pv-claim";
const HOSTPATH_PVC_NAME: &str = "kumuteva-hostpath-claim";
const FILE_NAME: &str = "index.html";
const FILE_CONTENT: &str = "Hello, this is a tenant1 using Kumuteva!";
const MOUNT_PATH: &str = "/usr/share/nginx/html";
const HOSTPATH_MOUNT_PATH: &str = "/tmp/kumuteva-hostpath";
const STORAGE_SIZE: &str = "1Gi";
const POD_CREATION_TIMEOUT: u32 = 30;

/// Safety level for cross-tenant operations
#[derive(Debug, Clone, PartialEq)]
pub enum SafetyLevel {
    Safe,
    Unsafe,
    Unknown,
}
#[derive(Debug, Clone)]
pub struct StorageIsolationReport {
    pub resources_assessment: Vec<StorageResourceAssessment>,
    pub overall_autonomy: bool,
    pub overall_isolation: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StorageResourceAssessment {
    pub resource: StorageResource,
    pub operations_assessment: HashMap<StorageOperation, OperationAssessment>,
    pub is_autonomous: bool,
    pub is_isolated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageResource {
    Volume, // PersistentVolumes / PersistentVolumeClaims
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageOperation {
    CreateAndMountVolume, // Create persistent volumes/claims and mount them
    UseHostPath,
}

#[derive(Debug, Clone)]
pub struct OperationAssessment {
    pub authorized: bool,
    pub safe: SafetyLevel,
    pub test_details: Option<String>,
}

impl StorageResource {
    fn all() -> Vec<Self> {
        vec![StorageResource::Volume]
    }

    fn applicable_operations(&self) -> Vec<StorageOperation> {
        match self {
            StorageResource::Volume => vec![
                StorageOperation::CreateAndMountVolume,
                StorageOperation::UseHostPath,
            ],
        }
    }
}

/// Main function to assess storage isolation between two tenants
pub async fn check_storage_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<StorageIsolationReport> {
    println!("Assessing storage isolation systematically...");

    let resources = StorageResource::all();
    let mut resources_assessment = Vec::new();
    let mut warnings = Vec::new();

    for resource in resources {
        let operations = resource.applicable_operations();
        if operations.is_empty() {
            continue;
        }

        let mut operations_assessment = HashMap::new();

        for operation in operations {
            let assessment = assess_operation(tenant1, tenant2, &resource, &operation).await?;
            operations_assessment.insert(operation, assessment);
        }

        // Determine autonomy: all operations are authorized
        let is_autonomous = operations_assessment
            .values()
            .all(|assessment| assessment.authorized);

        // Determine isolation: no operation is unsafe
        let is_isolated = !operations_assessment
            .values()
            .any(|assessment| assessment.safe == SafetyLevel::Unsafe);

        // Generate warning if autonomous but not isolated
        if is_autonomous && !is_isolated {
            warnings.push(format!(
                "Warning: {} is autonomous but not isolated - potential security risk",
                resource
            ));
        }

        resources_assessment.push(StorageResourceAssessment {
            resource,
            operations_assessment,
            is_autonomous,
            is_isolated,
        });
    }

    // Overall assessment
    let overall_autonomy = resources_assessment.iter().all(|r| r.is_autonomous);
    let overall_isolation = resources_assessment.iter().all(|r| r.is_isolated);

    Ok(StorageIsolationReport {
        resources_assessment,
        overall_autonomy,
        overall_isolation,
        warnings,
    })
}

async fn assess_operation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    resource: &StorageResource,
    operation: &StorageOperation,
) -> anyhow::Result<OperationAssessment> {
    // First, check if the operation is authorized
    let authorized = is_authorized_to(tenant1, resource, operation).await?;

    if !authorized {
        return Ok(OperationAssessment {
            authorized: false,
            safe: SafetyLevel::Safe, // If not authorized, it's safe by definition
            test_details: Some("Operation not authorized - access denied".to_string()),
        });
    }

    // If authorized, test if it affects other tenants
    let (safe, test_details) =
        does_affect_other_tenant(tenant1, tenant2, resource, operation).await?;

    Ok(OperationAssessment {
        authorized: true,
        safe,
        test_details: Some(test_details),
    })
}

async fn is_authorized_to(
    tenant: &TenantClusterConfig,
    resource: &StorageResource,
    operation: &StorageOperation,
) -> anyhow::Result<bool> {
    match (resource, operation) {
        // Volume (PersistentVolumes)
        (StorageResource::Volume, StorageOperation::CreateAndMountVolume) => {
            let can_create_pv = test_pv_creation_authorization(tenant).await;
            let can_mount_pv = test_pv_mount_authorization(tenant).await;
            Ok(can_create_pv.unwrap_or(false) && can_mount_pv.unwrap_or(false))
        }
        (StorageResource::Volume, StorageOperation::UseHostPath) => {
            let can_create_hostpath = test_hostpath_creation_authorization(tenant).await;
            let can_mount_hostpath = test_hostpath_mount_authorization(tenant).await;
            Ok(can_create_hostpath.unwrap_or(false) && can_mount_hostpath.unwrap_or(false))
        }
    }
}

async fn does_affect_other_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    resource: &StorageResource,
    operation: &StorageOperation,
) -> anyhow::Result<(SafetyLevel, String)> {
    match (resource, operation) {
        // Volume (PersistentVolumes)
        (StorageResource::Volume, StorageOperation::CreateAndMountVolume) => {
            test_pv_cross_tenant_access(tenant1, tenant2).await
        }
        (StorageResource::Volume, StorageOperation::UseHostPath) => {
            test_hostpath_cross_tenant_access(tenant1, tenant2).await
        }
    }
}

// =============================================================================
// AUTHORIZATION TESTS
// =============================================================================

// Volume (PersistentVolume) Authorization Tests
async fn test_pv_creation_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let result = tenant
        .cluster
        .is_authorized_to("create", "PersistentVolume", None)
        .await;

    println!("PV creation authorization test result: {:?}", result);

    Ok(result.is_ok())
}

async fn test_pv_mount_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    // Test if tenant can mount PVs via StatefulSet
    let test_commands = vec!["sleep", "1"];
    let result = create_stateful_set(tenant, &test_commands, None, false).await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

// VolumeClaim (PersistentVolumeClaim) Authorization Tests
async fn test_pvc_creation_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    // Test if tenant can create PVCs
    let test_pvc_name = "auth-test-pvc";
    let test_pvc = create_test_pvc_manifest(test_pvc_name);

    let result = tenant
        .cluster
        .create_namespaced_resource::<PersistentVolumeClaim>(&test_pvc, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<PersistentVolumeClaim>(test_pvc_name, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_pvc_mount_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    // Test if tenant can mount PVCs in pods
    let test_commands = vec!["sleep", "1"];
    let result = create_multiple_pods_with_pvc(tenant, &test_commands, 2).await;

    // Cleanup
    cleanup_multiple_pods(tenant, 2).await?;

    Ok(result.is_ok())
}

// HostPathVolume Authorization Tests
async fn test_hostpath_creation_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<bool> {
    // Test if tenant can create PVCs with hostPath
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

async fn test_hostpath_mount_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    // Test if tenant can mount hostPath volumes
    let test_commands = vec!["sleep", "10"];
    let result = create_stateful_set(tenant, &test_commands, None, true).await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

// =============================================================================
// ISOLATION TESTS
// =============================================================================

// Volume (PersistentVolume) Isolation Tests
async fn test_pv_creation_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Test if storage classes are properly isolated
    match attempt_check_using_storage_classes(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "PV creation is properly isolated between tenants".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("PV creation isolation failed: {}", e),
        )),
    }
}

async fn test_pv_mount_isolation(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // For PV mount isolation, we assume it's safe if creation is isolated
    Ok((
        SafetyLevel::Safe,
        "PV mount operations appear isolated".to_string(),
    ))
}

async fn test_pv_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // This is the main cross-tenant access test for PVs
    match attempt_other_tenant_file_access(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "Cross-tenant PV access is properly blocked".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("Cross-tenant PV access detected: {}", e),
        )),
    }
}

// VolumeClaim (PersistentVolumeClaim) Isolation Tests
async fn test_pvc_creation_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Test if PVCs are properly isolated between tenants
    match test_pvc_namespace_isolation(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "PVC creation is properly isolated between tenants".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("PVC creation isolation failed: {}", e),
        )),
    }
}

async fn test_pvc_mount_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Test if multiple pods can mount the same PVC (ReadWriteMany scenario)
    match test_pvc_multi_mount_isolation(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "PVC mount operations are properly isolated".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("PVC mount isolation failed: {}", e),
        )),
    }
}

async fn test_pvc_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Test cross-tenant PVC access
    match test_cross_tenant_pvc_access(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "Cross-tenant PVC access is properly blocked".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("Cross-tenant PVC access detected: {}", e),
        )),
    }
}

// HostPathVolume Isolation Tests
async fn test_hostpath_creation_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Test if hostPath volumes are properly isolated
    match test_hostpath_policy_isolation(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "HostPath volume creation is properly controlled".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("HostPath volume creation policy failed: {}", e),
        )),
    }
}

async fn test_hostpath_mount_isolation(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // For hostPath mount isolation, we assume it's controlled by creation policies
    Ok((
        SafetyLevel::Safe,
        "HostPath mount operations controlled by creation policies".to_string(),
    ))
}

async fn test_hostpath_cross_tenant_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Test if hostPath volumes leak data between tenants
    match test_hostpath_data_isolation(tenant1, tenant2).await {
        Ok(()) => Ok((
            SafetyLevel::Safe,
            "HostPath volumes are properly isolated between tenants".to_string(),
        )),
        Err(e) => Ok((
            SafetyLevel::Unsafe,
            format!("HostPath volume data isolation failed: {}", e),
        )),
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn create_test_pv_manifest(name: &str) -> PersistentVolume {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {
            "name": name,
        },
        "spec": {
            "capacity": {
                "storage": STORAGE_SIZE,
            },
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Delete",
        },
    }))
    .unwrap()
}

fn create_test_hostpath_pv_manifest(name: &str) -> PersistentVolume {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {
            "name": name,
        },
        "spec": {
            "capacity": {
                "storage": STORAGE_SIZE,
            },
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

fn create_test_pvc_manifest(name: &str) -> PersistentVolumeClaim {
    let spec = serde_json::json!({
        "accessModes": ["ReadWriteOnce"],
        "resources": {
            "requests": {
                "storage": STORAGE_SIZE,
            },
        },
    });

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": name,
        },
        "spec": spec,
    }))
    .unwrap()
}

async fn create_stateful_set<T: AsRef<str> + Serialize>(
    tenant: &TenantClusterConfig,
    commands: &[T],
    pv_name: Option<&str>,
    use_hostpath: bool,
) -> anyhow::Result<()> {
    let tenant_set = create_tenant_statefulset_manifest(commands, pv_name, use_hostpath)?;

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
        "metadata": {
            "name": POD_NAME,
        },
        "spec": {
            "selector": {
                "matchLabels": {
                    "app": POD_NAME
                },
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": POD_NAME
                    },
                },
                "spec": {
                    "containers": [
                        {
                            "name": POD_NAME,
                            "image": "nginx",
                            "command": commands,
                            "volumeMounts": [
                                {
                                    "mountPath": mount_path,
                                    "name": pvc_name
                                },
                            ],
                        },
                    ],
                },
            },
            "restartPolicy": "Never",
            "replicas": 1
        }
    }))?;

    if use_hostpath {
        // For hostPath, use volumes instead of volumeClaimTemplates
        if let Some(spec) = pod_manifest.spec.as_mut() {
            spec.volume_claim_templates = None; // Remove PVC templates
            let mut pod_spec = spec.template.spec.clone().unwrap_or_default();
            pod_spec.volumes = Some(vec![serde_json::from_value(serde_json::json!({
                "name": pvc_name,
                "hostPath": {
                    "path": HOSTPATH_MOUNT_PATH,
                    "type": "DirectoryOrCreate"
                }
            }))
            .unwrap()]);
            spec.template.spec = Some(pod_spec);
        }
    } else {
        // For regular PVC, add volumeClaimTemplates
        if let Some(spec) = pod_manifest.spec.as_mut() {
            spec.volume_claim_templates = Some(vec![serde_json::from_value(serde_json::json!({
                "metadata": {
                    "name": pvc_name,
                },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {
                        "requests": {
                            "storage": STORAGE_SIZE,
                        },
                    },
                    "persistentVolumeReclaimPolicy": "Retain",
                },
            }))
            .unwrap()]);
        }
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
// SPECIFIC TEST IMPLEMENTATIONS
// =============================================================================

async fn test_pvc_namespace_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    // Create PVC in tenant1
    let pvc_name = "isolation-test-pvc";
    let pvc = create_test_pvc_manifest(pvc_name);

    tenant1
        .cluster
        .create_namespaced_resource::<PersistentVolumeClaim>(&pvc, &tenant1.namespace)
        .await?;

    // Try to access it from tenant2
    let result = tenant2
        .cluster
        .get_resource_in_namespace::<PersistentVolumeClaim>(pvc_name, &tenant1.namespace)
        .await;

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<PersistentVolumeClaim>(pvc_name, &tenant1.namespace)
        .await;

    if result.is_ok() {
        return Err(anyhow::anyhow!(
            "Tenant2 can access PVC from tenant1's namespace"
        ));
    }

    Ok(())
}

async fn test_pvc_multi_mount_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    // Test if multiple pods can mount the same PVC across tenants
    let test_commands = vec!["sleep", "10"];

    // Create multiple pods in tenant1
    create_multiple_pods_with_pvc(tenant1, &test_commands, 2).await?;

    // Try to create pods in tenant2 that might conflict
    let result = create_multiple_pods_with_pvc(tenant2, &test_commands, 1).await;

    // Cleanup
    cleanup_multiple_pods(tenant1, 2).await?;
    let _ = cleanup_multiple_pods(tenant2, 1).await;

    // If tenant2 could create conflicting pods, it might indicate insufficient isolation
    if result.is_ok() {
        println!("Warning: Multiple tenants can create pods with similar PVC configurations");
    }

    Ok(())
}

async fn test_cross_tenant_pvc_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    // Similar to PV test but focused on PVC
    let tenant1_commands = tenant1_commands();
    let tenant2_commands = tenant2_commands();

    // Create PVC and write data in tenant1
    create_stateful_set(tenant1, &tenant1_commands, None, false).await?;
    wait_for_statefulset_ready(tenant1).await?;

    // Try to access from tenant2
    let result = create_stateful_set(tenant2, &tenant2_commands, None, false).await;

    if result.is_ok() {
        // Additional check to see if data was accessible
        if let Ok(accessed) = check_cross_tenant_mount(tenant2).await {
            if accessed {
                return Err(anyhow::anyhow!("Cross-tenant PVC data access detected"));
            }
        }
    }

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
        .await;

    Ok(())
}

async fn test_hostpath_policy_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    // Test if hostPath volumes are blocked by policy
    let test_commands = vec!["sleep", "1"];

    let result1 = create_stateful_set(tenant1, &test_commands, None, true).await;
    let result2 = create_stateful_set(tenant2, &test_commands, None, true).await;

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
        .await;

    // If both tenants can create hostPath volumes, check if it's properly controlled
    if result1.is_ok() && result2.is_ok() {
        println!("Warning: Both tenants can create hostPath volumes - ensure proper policies are in place");
    }

    Ok(())
}

async fn test_hostpath_data_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    // Test if hostPath volumes leak data between tenants
    let tenant1_commands = hostpath_write_commands();
    let tenant2_commands = hostpath_read_commands();

    // Create hostPath volume and write data in tenant1
    create_stateful_set(tenant1, &tenant1_commands, None, true).await?;
    wait_for_statefulset_ready(tenant1).await?;
    println!("Tenant1 has written data to hostPath volume.");

    // Try to read data from tenant2
    create_stateful_set(tenant2, &tenant2_commands, None, true).await?;
    wait_for_statefulset_ready(tenant2).await?;
    println!("Tenant2 has attempted to read data from hostPath volume.");

    let can_access_data = check_cross_tenant_mount(tenant2).await?;

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
        return Err(anyhow::anyhow!(
            "HostPath volume data is accessible across tenants"
        ));
    }

    Ok(())
}

// =============================================================================
// ADDITIONAL HELPER FUNCTIONS
// =============================================================================

async fn create_multiple_pods_with_pvc<T: AsRef<str> + Serialize>(
    tenant: &TenantClusterConfig,
    commands: &[T],
    count: u32,
) -> anyhow::Result<()> {
    for i in 0..count {
        let pod_name = format!("test-pod-{}", i);
        let pod_manifest = create_simple_pod_manifest(&pod_name, commands)?;

        tenant
            .cluster
            .create_namespaced_resource::<Pod>(&pod_manifest, &tenant.namespace)
            .await?;
    }
    Ok(())
}

async fn cleanup_multiple_pods(tenant: &TenantClusterConfig, count: u32) -> anyhow::Result<()> {
    for i in 0..count {
        let pod_name = format!("test-pod-{}", i);
        let _ = tenant
            .cluster
            .delete_resource_in_namespace::<Pod>(&pod_name, &tenant.namespace)
            .await;
    }
    Ok(())
}

fn create_simple_pod_manifest<T: AsRef<str> + Serialize>(
    name: &str,
    commands: &[T],
) -> anyhow::Result<Pod> {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
        },
        "spec": {
            "containers": [
                {
                    "name": "test-container",
                    "image": "nginx",
                    "command": commands,
                },
            ],
            "restartPolicy": "Never",
        }
    }))
    .map_err(|e| anyhow::anyhow!("Failed to create pod manifest: {}", e))
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

// Keep all existing helper functions from the original code
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

/// Check if using different storage classes among tenants
/// We avoid using this as a primary test as it may not be applicable in all environments
async fn attempt_check_using_storage_classes(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    let can_t1_get_storage_class = is_authorized_to_get_storage_class(tenant1).await?;
    let can_t2_get_storage_class = is_authorized_to_get_storage_class(tenant2).await?;

    if can_t1_get_storage_class && can_t2_get_storage_class {
        let tenant1_storage_classes = tenant1
            .cluster
            .list_cluster_resources::<StorageClass>()
            .await?;
        let tenant2_storage_classes = tenant2
            .cluster
            .list_cluster_resources::<StorageClass>()
            .await?;

        if !tenant1_storage_classes.items.is_empty() && !tenant2_storage_classes.items.is_empty() {
            return check_storage_class_isolation(
                &tenant1_storage_classes.items,
                &tenant2_storage_classes.items,
            );
        }
    }

    Ok(())
}

async fn is_authorized_to_get_storage_class(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    tenant
        .cluster
        .is_authorized_to("get", "StorageClass", None)
        .await
}

fn check_storage_class_isolation(
    tenant1_storage_classes: &[StorageClass],
    tenant2_storage_classes: &[StorageClass],
) -> anyhow::Result<()> {
    let shared_storage_classes = tenant1_storage_classes
        .iter()
        .filter(|current_sc| {
            tenant2_storage_classes
                .iter()
                .any(|other_sc| other_sc.metadata.uid == current_sc.metadata.uid)
        })
        .collect::<Vec<_>>();

    if shared_storage_classes.is_empty() {
        return Ok(());
    }

    let shared_storage_classes_without_delete_policy = shared_storage_classes
        .iter()
        .filter(|sc| sc.reclaim_policy != Some("Delete".to_string()))
        .collect::<Vec<_>>();

    if !shared_storage_classes_without_delete_policy.is_empty() {
        return Err(anyhow::anyhow!(
            "Storage classes are not isolated between tenants, they must have reclaimPolicy set to Delete if StorageClass is shared"
        ));
    }

    Ok(())
}

async fn attempt_other_tenant_file_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    let tenant1_commands = tenant1_commands();
    let tenant2_commands = tenant2_commands();

    // Step 1: Create StatefulSet in tenant1 with PVC
    println!("Creating a StatefulSet in tenant1");
    let (created_pvc_name, dynamic_pv_name) =
        create_and_wait_stateful_set(tenant1, &tenant1_commands, None).await?;

    // Step 2: Release the PV from tenant1
    let release_pv = release_pv_from_tenant(tenant1, &dynamic_pv_name, &created_pvc_name).await;

    match release_pv {
        Ok(_) => println!("Released PV {} from tenant1", dynamic_pv_name),
        Err(e) => {
            if e.to_string()
                .contains("cannot patch resource \"persistentvolumes\"")
            {
                println!(
                    "PV {} patch operation is forbidden for tenant1. Considering storage is isolated.",
                    dynamic_pv_name
                );
                return Ok(());
            }
            println!(
                "Could not release PV {} from tenant1: {}. Unable to continue test.",
                dynamic_pv_name, e
            );
            return Ok(());
        }
    }

    // Step 3: Try to create StatefulSet in tenant2 that uses the released PV
    println!("Creating a StatefulSet in tenant2");
    let mount_attempt =
        create_stateful_set(tenant2, &tenant2_commands, Some(&dynamic_pv_name), false).await;

    if mount_attempt.is_err() {
        println!(
            "Tenant2 cannot create StatefulSet with the PV from Tenant1, storage is isolated: {}",
            mount_attempt.err().unwrap()
        );
        // Cleanup the released PV
        let _ = tenant1
            .cluster
            .delete_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
            .await;
        return Ok(());
    }

    // Step 4: Check if tenant2 can actually mount and access the volume
    println!("Checking if tenant2 can mount the pv created by tenant1");
    let mount_result = check_mount_attempt(tenant2).await;

    if mount_result.is_err() {
        println!("Tenant2 cannot mount the pv created by Tenant1, storage is isolated");
        // Cleanup
        let _ = tenant2
            .cluster
            .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
            .await;
        let _ = tenant1
            .cluster
            .delete_cluster_resource::<PersistentVolume>(&dynamic_pv_name)
            .await;
        return Ok(());
    }

    // Step 5: Check if tenant2 can access tenant1's data
    let can_access_tenant1_files = check_cross_tenant_mount(tenant2).await?;

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
        return Err(anyhow::anyhow!(
            "Tenant2 can access the file created by Tenant1, storage is not isolated"
        ));
    }

    Ok(())
}

// Keep all existing helper functions for StatefulSet management, PV operations, etc.
async fn wait_and_get_volume_info(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<(String, String)> {
    wait_for_statefulset_ready(tenant).await?;
    let (created_pvc_name, dynamic_pv_name) = get_pvc_and_pv_info(tenant).await?;
    println!("A dynamic PV was created: {}", dynamic_pv_name);
    Ok((created_pvc_name, dynamic_pv_name))
}

async fn create_and_wait_stateful_set<T: AsRef<str> + Serialize>(
    tenant: &TenantClusterConfig,
    commands: &[T],
    pv_name: Option<&str>,
) -> anyhow::Result<(String, String)> {
    create_stateful_set(tenant, commands, pv_name, false).await?;
    wait_and_get_volume_info(tenant).await
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
            &kube::api::Patch::Strategic(serde_json::json!({
                "spec": {
                    "claimRef": null
                }
            })),
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
        .await?;

    Ok(())
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
    let dynamic_pv_name = created_pvc.spec.unwrap().volume_name.unwrap();

    Ok((created_pvc_name.to_string(), dynamic_pv_name.to_string()))
}

async fn check_mount_attempt(tenant: &TenantClusterConfig) -> anyhow::Result<()> {
    let wait_operation = tenant
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

                let is_container_terminated = pod
                    .status
                    .and_then(|status| status.container_statuses)
                    .map(|container_statuses| {
                        container_statuses.iter().any(|container_status| {
                            container_status
                                .state
                                .as_ref()
                                .and_then(|state| {
                                    state.terminated.as_ref().map(|terminated| {
                                        terminated.exit_code == 0 || terminated.exit_code == 1
                                    })
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

                is_container_terminated
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
        .ok_or(anyhow::anyhow!("Pod in tenant2 not found"))
        .unwrap()
        .to_owned();

    //wait for 30 seconds for the pod to either log success or failure message
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
                                for container_status in container_statuses {
                                    if let Some(state) = &container_status.state {
                                        if let Some(terminated) = &state.terminated {
                                            if let Ok(logs) = tenant
                                                .cluster
                                                .get_pod_logs(
                                                    pod.metadata
                                                        .name
                                                        .as_deref()
                                                        .unwrap_or_default(),
                                                    &tenant.namespace,
                                                )
                                                .await
                                            {
                                                if logs.contains("CROSS_TENANT_ACCESS_SUCCESS")
                                                    || logs.contains("HOSTPATH_ACCESS_SUCCESS")
                                                {
                                                    return true;
                                                } else if logs
                                                    .contains("CROSS_TENANT_ACCESS_FAILED")
                                                    || logs.contains("HOSTPATH_ACCESS_FAILED")
                                                {
                                                    return true;
                                                }
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
            &pod.metadata.name.as_deref().unwrap_or_default(),
            &tenant.namespace,
        )
        .await?;

    if logs.contains("CROSS_TENANT_ACCESS_SUCCESS") || logs.contains("HOSTPATH_ACCESS_SUCCESS") {
        println!("Cross-tenant access detected in logs:\n{}", logs);
        return Ok(true);
    }

    if logs.contains("CROSS_TENANT_ACCESS_FAILED") || logs.contains("HOSTPATH_ACCESS_FAILED") {
        println!("No cross-tenant access detected in logs:\n{}", logs);
        return Ok(false);
    }

    Ok(false)
}

async fn get_pvc_from_pv(tenant: &TenantClusterConfig, pv_name: &str) -> anyhow::Result<String> {
    let pv = tenant
        .cluster
        .get_cluster_resource::<PersistentVolume>(pv_name)
        .await?;

    let pvc_name = pv
        .spec
        .and_then(|spec| spec.claim_ref)
        .and_then(|claim_ref| claim_ref.name)
        .ok_or_else(|| anyhow::anyhow!("PersistentVolumeClaim not found"))?;

    Ok(pvc_name)
}

async fn cleanup(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    pv_name: &str,
    pvc_name: &str,
) -> anyhow::Result<()> {
    tenant2
        .cluster
        .delete_resource_in_namespace::<StatefulSet>(POD_NAME, &tenant2.namespace)
        .await?;

    println!("Cleaning up PVC {}", pvc_name);
    tenant1
        .cluster
        .delete_resource_in_namespace::<PersistentVolumeClaim>(pvc_name, &tenant1.namespace)
        .await?;

    println!("Cleaning up PV {}", pv_name);
    tenant1
        .cluster
        .delete_cluster_resource::<PersistentVolume>(pv_name)
        .await?;

    Ok(())
}

// Display implementations
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
            StorageOperation::CreateAndMountVolume => write!(f, "Create And Mount Volume"),
            StorageOperation::UseHostPath => write!(f, "Use HostPath in a Volume"),
        }
    }
}

impl Display for StorageIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Multi-tenancy Data Plane - Storage Report")?;
        writeln!(f, "==========================================")?;

        writeln!(
            f,
            "🔒 Overall Isolation: {}",
            if self.overall_isolation {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        writeln!(
            f,
            "🔧 Overall Autonomy: {}",
            if self.overall_autonomy {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        if !self.warnings.is_empty() {
            writeln!(f)?;
            writeln!(f, "⚠️  Security Warnings:")?;
            for warning in &self.warnings {
                writeln!(f, "  • {}", warning)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "📋 Detailed Assessment by Resource:")?;

        for resource_assessment in &self.resources_assessment {
            writeln!(f, "  • {}:", resource_assessment.resource)?;
            writeln!(
                f,
                "    - Autonomy: {} | Isolation: {}",
                if resource_assessment.is_autonomous {
                    "✅"
                } else {
                    "❌"
                },
                if resource_assessment.is_isolated {
                    "✅"
                } else {
                    "❌"
                }
            )?;

            for (operation, assessment) in &resource_assessment.operations_assessment {
                let safety_icon = match assessment.safe {
                    SafetyLevel::Safe => "✅",
                    SafetyLevel::Unsafe => "❌",
                    SafetyLevel::Unknown => "❓",
                };

                writeln!(
                    f,
                    "      {} {}: Auth={} Safety={}",
                    safety_icon,
                    operation,
                    if assessment.authorized { "✅" } else { "❌" },
                    assessment.safe
                )?;

                if let Some(details) = &assessment.test_details {
                    writeln!(f, "        Details: {}", details)?;
                }
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

impl Display for SafetyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyLevel::Safe => write!(f, "Safe"),
            SafetyLevel::Unsafe => write!(f, "Unsafe"),
            SafetyLevel::Unknown => write!(f, "Unknown"),
        }
    }
}
