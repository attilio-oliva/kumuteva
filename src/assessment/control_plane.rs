use std::collections::HashMap;
use std::fmt::Display;

use async_trait::async_trait;
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};

use crate::assessment::{
    run_assessment, AssessableResource, MultitenancyAssessor, SafetyLevel, SubsystemReport,
};
use crate::verifier::TenantClusterConfig;
use crate::verifier::{create_minimal_object, KubernetesObject};

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

pub type ControlPlaneIsolationReport = SubsystemReport<ControlPlaneResource>;

/// Control plane resources map to Kubernetes object kinds
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ControlPlaneResource {
    // Core API (v1)
    Pod,
    Service,
    ConfigMap,
    Secret,
    PersistentVolume,
    PersistentVolumeClaim,
    Namespace,
    ServiceAccount,
    Endpoints,
    LimitRange,
    ResourceQuota,
    Node,

    // Apps API (apps/v1)
    Deployment,
    ReplicaSet,
    StatefulSet,
    DaemonSet,

    // Batch API (batch/v1)
    Job,
    CronJob,

    // Networking API (networking.k8s.io/v1)
    NetworkPolicy,
    Ingress,
    IngressClass,

    // RBAC API (rbac.authorization.k8s.io/v1)
    Role,
    RoleBinding,
    ClusterRole,
    ClusterRoleBinding,

    // Policy API (policy/v1)
    PodDisruptionBudget,

    // Autoscaling API (autoscaling/v2)
    HorizontalPodAutoscaler,

    // Storage API (storage.k8s.io/v1)
    StorageClass,
}

impl ControlPlaneResource {
    /// Convert to the existing KubernetesObject for reusing existing logic
    pub fn to_kubernetes_object(&self) -> KubernetesObject {
        match self {
            Self::Pod => KubernetesObject::Pod,
            Self::Service => KubernetesObject::Service,
            Self::ConfigMap => KubernetesObject::ConfigMap,
            Self::Secret => KubernetesObject::Secret,
            Self::PersistentVolume => KubernetesObject::PersistentVolume,
            Self::PersistentVolumeClaim => KubernetesObject::PersistentVolumeClaim,
            Self::Namespace => KubernetesObject::Namespace,
            Self::ServiceAccount => KubernetesObject::ServiceAccount,
            Self::Endpoints => KubernetesObject::Endpoints,
            Self::LimitRange => KubernetesObject::LimitRange,
            Self::ResourceQuota => KubernetesObject::ResourceQuota,
            Self::Node => KubernetesObject::Node,
            Self::Deployment => KubernetesObject::Deployment,
            Self::ReplicaSet => KubernetesObject::ReplicaSet,
            Self::StatefulSet => KubernetesObject::StatefulSet,
            Self::DaemonSet => KubernetesObject::DaemonSet,
            Self::Job => KubernetesObject::Job,
            Self::CronJob => KubernetesObject::CronJob,
            Self::NetworkPolicy => KubernetesObject::NetworkPolicy,
            Self::Ingress => KubernetesObject::Ingress,
            Self::IngressClass => KubernetesObject::IngressClass,
            Self::Role => KubernetesObject::Role,
            Self::RoleBinding => KubernetesObject::RoleBinding,
            Self::ClusterRole => KubernetesObject::ClusterRole,
            Self::ClusterRoleBinding => KubernetesObject::ClusterRoleBinding,
            Self::PodDisruptionBudget => KubernetesObject::PodDisruptionBudget,
            Self::HorizontalPodAutoscaler => KubernetesObject::HorizontalPodAutoscaler,
            Self::StorageClass => KubernetesObject::StorageClass,
        }
    }

    pub fn is_namespaced(&self) -> bool {
        self.to_kubernetes_object().is_namespaced()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ControlPlaneOperation {
    /// Kubernetes GET verb
    Get,
    /// Kubernetes LIST verb
    List,
    /// Kubernetes UPDATE verb
    Update,
    /// Kubernetes DELETE verb
    Delete,
}

impl AssessableResource for ControlPlaneResource {
    type Operation = ControlPlaneOperation;

    fn all() -> Vec<Self> {
        vec![
            // Core API
            Self::Pod,
            Self::Service,
            Self::ConfigMap,
            Self::Secret,
            Self::PersistentVolume,
            Self::PersistentVolumeClaim,
            Self::Namespace,
            Self::ServiceAccount,
            Self::Endpoints,
            Self::LimitRange,
            Self::ResourceQuota,
            Self::Node,
            // Apps API
            Self::Deployment,
            Self::ReplicaSet,
            Self::StatefulSet,
            Self::DaemonSet,
            // Batch API
            Self::Job,
            Self::CronJob,
            // Networking API
            Self::NetworkPolicy,
            Self::Ingress,
            Self::IngressClass,
            // RBAC API
            Self::Role,
            Self::RoleBinding,
            Self::ClusterRole,
            Self::ClusterRoleBinding,
            // Policy API
            Self::PodDisruptionBudget,
            // Autoscaling API
            Self::HorizontalPodAutoscaler,
            // Storage API
            Self::StorageClass,
        ]
    }

    fn applicable_operations(&self) -> Vec<Self::Operation> {
        vec![
            ControlPlaneOperation::Get,
            ControlPlaneOperation::List,
            ControlPlaneOperation::Update,
            ControlPlaneOperation::Delete,
        ]
    }
}

// =============================================================================
// ASSESSOR IMPLEMENTATION
// =============================================================================

pub struct ControlPlaneAssessor;

#[async_trait]
impl MultitenancyAssessor for ControlPlaneAssessor {
    type Resource = ControlPlaneResource;

    fn name(&self) -> &'static str {
        "Control Plane"
    }

    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &ControlPlaneResource,
        operation: &ControlPlaneOperation,
    ) -> anyhow::Result<bool> {
        let k8s_obj = resource.to_kubernetes_object();
        let verb = match operation {
            ControlPlaneOperation::Get => "get",
            ControlPlaneOperation::List => "list",
            ControlPlaneOperation::Update => "update",
            ControlPlaneOperation::Delete => "delete",
        };

        let namespace = if k8s_obj.is_namespaced() {
            Some(tenant.namespace.as_str())
        } else {
            None
        };

        let resource_name = k8s_obj.plural_kind();
        let result = tenant
            .cluster
            .is_authorized_to(verb, &resource_name, namespace)
            .await;

        Ok(result.is_ok())
    }

    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &ControlPlaneResource,
        operation: &ControlPlaneOperation,
    ) -> anyhow::Result<(SafetyLevel, String)> {
        let k8s_obj = resource.to_kubernetes_object();

        // First, try to create or find a test object in tenant1
        let object_name = match setup_test_object(tenant1, &k8s_obj).await {
            Ok(name) => name,
            Err(e) => {
                // If we can't create/find an object, we can't test isolation
                return Ok((
                    SafetyLevel::Unknown,
                    format!(
                        "Could not create test object for {}: {} - Cannot verify isolation",
                        k8s_obj.kind(),
                        e
                    ),
                ));
            }
        };

        // Test cross-tenant access based on operation
        let result = match operation {
            ControlPlaneOperation::Get => {
                test_cross_tenant_get(tenant1, tenant2, &k8s_obj, &object_name).await
            }
            ControlPlaneOperation::List => {
                test_cross_tenant_list(tenant1, tenant2, &k8s_obj, &object_name).await
            }
            ControlPlaneOperation::Update => {
                test_cross_tenant_update(tenant1, tenant2, &k8s_obj, &object_name).await
            }
            ControlPlaneOperation::Delete => {
                test_cross_tenant_delete(tenant1, tenant2, &k8s_obj, &object_name).await
            }
        };

        // Cleanup the test object (best effort)
        let _ = cleanup_test_object(tenant1, &k8s_obj, &object_name).await;

        result
    }
}

/// Public API - entry point for control plane isolation assessment
pub async fn check_control_plane_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<ControlPlaneIsolationReport> {
    run_assessment(&ControlPlaneAssessor, tenant1, tenant2).await
}

// =============================================================================
// TEST OBJECT MANAGEMENT
// =============================================================================

async fn setup_test_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<String> {
    let random_object_name = format!(
        "test-{}-{}",
        object_kind.kind().to_lowercase(),
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    // Try to create a new test object
    match create_test_object(tenant, object_kind, &random_object_name).await {
        Ok(_) => Ok(random_object_name),
        Err(creation_error) => {
            // If creation fails, try to find an existing object
            find_existing_object(tenant, object_kind, creation_error).await
        }
    }
}

async fn create_test_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> anyhow::Result<()> {
    let test_object = create_minimal_object(object_kind, object_name, &tenant.namespace)?;
    let dynamic_object = DynamicObject {
        types: Some(TypeMeta {
            api_version: object_kind.api_version().to_string(),
            kind: object_kind.kind().to_string(),
        }),
        metadata: ObjectMeta {
            name: Some(object_name.to_string()),
            ..Default::default()
        },
        data: test_object,
    };

    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    tenant
        .cluster
        .create_resource_dyn(object_kind, &dynamic_object, namespace)
        .await?;

    Ok(())
}

async fn find_existing_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    creation_error: anyhow::Error,
) -> anyhow::Result<String> {
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let resources = tenant
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await?;

    if resources.items.is_empty() {
        return Err(anyhow::anyhow!(
            "No existing objects found for isolation test on {}: {}",
            object_kind.kind(),
            creation_error
        ));
    }

    let first_resource = resources.items.first().unwrap();
    let object_name = first_resource.metadata.name.clone().unwrap_or_default();

    Ok(object_name)
}

async fn cleanup_test_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> anyhow::Result<()> {
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    tenant
        .cluster
        .delete_resource_dyn(object_kind, object_name, namespace)
        .await?;

    Ok(())
}

// =============================================================================
// CROSS-TENANT ISOLATION TESTS
// =============================================================================
/// Helper to get namespace parameter based on whether resource is namespaced
fn get_namespace_param<'a>(object_kind: &KubernetesObject, namespace: &'a str) -> Option<&'a str> {
    if object_kind.is_namespaced() {
        Some(namespace)
    } else {
        None
    }
}

async fn test_cross_tenant_get(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> anyhow::Result<(SafetyLevel, String)> {
    let namespace_param = get_namespace_param(object_kind, &tenant1.namespace);

    let resource = tenant2
        .cluster
        .get_resource_dyn(object_kind, object_name, namespace_param)
        .await;

    if resource.is_ok() {
        Ok((
            SafetyLevel::Unsafe,
            format!(
                "Cross-tenant GET access detected: {} {} readable by other tenant",
                object_kind.kind(),
                object_name
            ),
        ))
    } else {
        Ok((
            SafetyLevel::Safe,
            format!(
                "Cross-tenant GET blocked for {} {}",
                object_kind.kind(),
                object_name
            ),
        ))
    }
}

async fn test_cross_tenant_list(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> anyhow::Result<(SafetyLevel, String)> {
    let namespace_param = get_namespace_param(object_kind, &tenant1.namespace);

    let resources = tenant2
        .cluster
        .list_resources_dyn(object_kind, namespace_param)
        .await;

    if let Ok(resources) = resources {
        // Check if tenant1's object is visible in the list
        let can_see_tenant1_object = resources
            .items
            .iter()
            .any(|obj| obj.metadata.name.as_deref() == Some(object_name));

        if can_see_tenant1_object {
            return Ok((
                SafetyLevel::Unsafe,
                format!(
                    "Cross-tenant LIST access detected: {} {} visible to other tenant",
                    object_kind.kind(),
                    object_name
                ),
            ));
        }
    }

    Ok((
        SafetyLevel::Safe,
        format!("Cross-tenant LIST blocked for {}", object_kind.kind(),),
    ))
}

async fn test_cross_tenant_update(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> anyhow::Result<(SafetyLevel, String)> {
    let namespace_param = get_namespace_param(object_kind, &tenant1.namespace);

    // Verify the object exists first
    let resource = tenant1
        .cluster
        .get_resource_dyn(object_kind, object_name, namespace_param)
        .await;

    if resource.is_err() {
        return Ok((
            SafetyLevel::Unknown,
            format!(
                "Test object {} {} not found - Cannot verify UPDATE isolation",
                object_kind.kind(),
                object_name
            ),
        ));
    }

    // Create a minimal update patch
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "cross-tenant-test": "isolation-breach"
            }
        }
    }));

    // Attempt to update the object from tenant2
    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, object_name, &patch, namespace_param)
        .await;

    if update_result.is_ok() {
        // Verify the update actually took effect
        let updated_resource = tenant1
            .cluster
            .get_resource_dyn(object_kind, object_name, namespace_param)
            .await;

        if let Ok(updated_resource) = updated_resource {
            if updated_resource
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("cross-tenant-test"))
                == Some(&"isolation-breach".to_string())
            {
                return Ok((
                    SafetyLevel::Unsafe,
                    format!(
                        "Cross-tenant UPDATE access detected: {} {} modified by other tenant",
                        object_kind.kind(),
                        object_name
                    ),
                ));
            }
        }
    }

    Ok((
        SafetyLevel::Safe,
        format!(
            "Cross-tenant UPDATE blocked for {} {}",
            object_kind.kind(),
            object_name
        ),
    ))
}

async fn test_cross_tenant_delete(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> anyhow::Result<(SafetyLevel, String)> {
    let namespace_param = get_namespace_param(object_kind, &tenant1.namespace);

    // Attempt to delete the object from tenant2
    let delete_result = tenant2
        .cluster
        .delete_resource_dyn(object_kind, object_name, namespace_param)
        .await;

    if delete_result.is_ok() {
        Ok((
            SafetyLevel::Unsafe,
            format!(
                "Cross-tenant DELETE access detected: {} {} deleted by other tenant",
                object_kind.kind(),
                object_name
            ),
        ))
    } else {
        Ok((
            SafetyLevel::Safe,
            format!(
                "Cross-tenant DELETE blocked for {} {}",
                object_kind.kind(),
                object_name
            ),
        ))
    }
}

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for ControlPlaneResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let k8s_obj = self.to_kubernetes_object();
        write!(f, "{}/{}", k8s_obj.api_version(), k8s_obj.kind())
    }
}

impl Display for ControlPlaneOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlPlaneOperation::Get => write!(f, "GET"),
            ControlPlaneOperation::List => write!(f, "LIST"),
            ControlPlaneOperation::Update => write!(f, "UPDATE"),
            ControlPlaneOperation::Delete => write!(f, "DELETE"),
        }
    }
}
