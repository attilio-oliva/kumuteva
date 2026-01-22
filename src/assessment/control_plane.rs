use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};
use kube::ResourceExt;
use tokio::time::sleep;

use crate::assessment::{
    run_assessment, AssessableResource, AutonomyRatio, CrossTenantResult, IsolationLevel,
    MultitenancyAssessor, OperationAssessment, SubsystemReport,
};
use crate::verifier::TenantClusterConfig;
use crate::verifier::{create_minimal_object, KubernetesObject};

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

pub type ControlPlaneIsolationReport = SubsystemReport<ControlPlaneResource>;

/// Assessment of a single resource with all its operations
#[derive(Debug, Clone)]
pub struct ResourceAssessment<R: AssessableResource> {
    pub resource: R,
    pub operations: HashMap<R::Operation, OperationAssessment>,
    pub is_isolated: bool,
    pub has_hard_isolation: bool,
}

/// Autonomy category for control plane resources
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPlaneAutonomyCategory {
    /// Workload resources (Pods, Deployments, Jobs, etc.) - resources running inside namespace
    Workload,
    /// Scope resources (Namespace, ResourceQuota, LimitRange) - namespace-level configuration
    Scope,
    /// Infrastructure resources (Node, DaemonSet) - node-level access
    Infrastructure,
    /// Cluster-wide resources (ClusterRole, StorageClass, PersistentVolume, etc.)
    Cluster,
}

/// Autonomy level categories for control plane resources
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneAutonomyLevels {
    /// Workload resources (Pods, Deployments, etc.) - inside namespace
    pub workload: AutonomyRatio,
    /// Scope resources (Namespace itself, ResourceQuota, LimitRange)
    pub scope: AutonomyRatio,
    /// Infrastructure resources (Node, DaemonSet)
    pub infrastructure: AutonomyRatio,
    /// Cluster-wide resources (ClusterRole, StorageClass, etc.)
    pub cluster: AutonomyRatio,
}

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
    /// Returns the autonomy category for this resource
    pub fn autonomy_category(&self) -> ControlPlaneAutonomyCategory {
        match self {
            // Workload resources - run inside namespace
            Self::Pod
            | Self::Deployment
            | Self::ReplicaSet
            | Self::StatefulSet
            | Self::Job
            | Self::CronJob
            | Self::Service
            | Self::ConfigMap
            | Self::Secret
            | Self::ServiceAccount
            | Self::Endpoints
            | Self::NetworkPolicy
            | Self::Ingress
            | Self::Role
            | Self::RoleBinding
            | Self::PodDisruptionBudget
            | Self::HorizontalPodAutoscaler
            | Self::PersistentVolumeClaim => ControlPlaneAutonomyCategory::Workload,

            // Scope resources - namespace-level configuration
            Self::Namespace | Self::LimitRange | Self::ResourceQuota => {
                ControlPlaneAutonomyCategory::Scope
            }

            // Infrastructure resources - node-level
            Self::Node | Self::DaemonSet => ControlPlaneAutonomyCategory::Infrastructure,

            // Cluster-wide resources
            Self::PersistentVolume
            | Self::IngressClass
            | Self::ClusterRole
            | Self::ClusterRoleBinding
            | Self::StorageClass => ControlPlaneAutonomyCategory::Cluster,
        }
    }
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
    /// Kubernetes CREATE verb
    Create,
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
            ControlPlaneOperation::Create,
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

        // Actually try the operation instead of using is_authorized_to
        // This is necessary because some proxies (like Capsule) may allow operations
        // even when is_authorized_to returns false
        match operation {
            ControlPlaneOperation::Create => test_autonomy_create(tenant, &k8s_obj).await,
            ControlPlaneOperation::Get => test_autonomy_get(tenant, &k8s_obj).await,
            ControlPlaneOperation::List => test_autonomy_list(tenant, &k8s_obj).await,
            ControlPlaneOperation::Update => test_autonomy_update(tenant, &k8s_obj).await,
            ControlPlaneOperation::Delete => test_autonomy_delete(tenant, &k8s_obj).await,
        }
    }

    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &ControlPlaneResource,
        operation: &ControlPlaneOperation,
    ) -> anyhow::Result<CrossTenantResult> {
        let k8s_obj = resource.to_kubernetes_object();

        match operation {
            ControlPlaneOperation::Create => {
                test_cross_tenant_create(tenant1, tenant2, &k8s_obj).await
            }
            ControlPlaneOperation::Update => {
                test_cross_tenant_update(tenant1, tenant2, &k8s_obj).await
            }
            ControlPlaneOperation::Get => test_cross_tenant_get(tenant1, tenant2, &k8s_obj).await,
            ControlPlaneOperation::List => test_cross_tenant_list(tenant1, tenant2, &k8s_obj).await,
            ControlPlaneOperation::Delete => {
                test_cross_tenant_delete(tenant1, tenant2, &k8s_obj).await
            }
        }
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Check if an error indicates the operation is not authorized/allowed
/// This is conservative - only matches clear authorization failures
fn is_authorization_error(error_msg: &str) -> bool {
    // Standard Kubernetes Forbidden response (HTTP 403)
    error_msg.contains("Forbidden") || error_msg.contains("forbidden") ||
    // Unauthorized (HTTP 401)
    error_msg.contains("Unauthorized") || error_msg.contains("unauthorized") ||
    // Impossible errors triggered by some solution to filter requests (e.g. proxies like Capsule Proxy)
    error_msg.contains("BadRequest") || error_msg.contains("not allowed")
}

/// Infer isolation level from an error message during cross-tenant operation
fn infer_isolation_from_error(error_msg: &str) -> IsolationLevel {
    if error_msg.contains("NotFound") || error_msg.contains("not found") {
        // Resource not found in tenant2's scope - hard isolation
        // Intruder sees the same error as in a single-tenant system
        IsolationLevel::Hard
    } else if is_authorization_error(error_msg) {
        // Operation forbidden/not allowed - soft isolation
        // Intruder knows the resource exists but can't access it
        IsolationLevel::Soft("Access forbidden - reveals shared environment".to_string())
    } else if error_msg.contains("AlreadyExists") || error_msg.contains("already exists") {
        // Name collision - soft isolation
        // Intruder can infer another tenant is using this name
        IsolationLevel::Soft("Name collision - reveals resource exists".to_string())
    } else {
        // Other errors - treat as soft isolation with metadata leakage
        IsolationLevel::Soft(format!("Error reveals shared state: {}", error_msg))
    }
}

/// Helper to create a DynamicObject with proper metadata
fn create_dynamic_object(
    object_kind: &KubernetesObject,
    name: &str,
    data: serde_json::Value,
    created_by: &str,
) -> DynamicObject {
    DynamicObject {
        types: Some(TypeMeta {
            api_version: object_kind.api_version().to_string(),
            kind: object_kind.kind().to_string(),
        }),
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            annotations: Some(BTreeMap::from([(
                "kumuteva.io/created-by-tenant".to_string(),
                created_by.to_string(),
            )])),
            ..Default::default()
        },
        data,
    }
}

/// Helper to get namespace parameter based on whether resource is namespaced
fn get_namespace_param<'a>(object_kind: &KubernetesObject, namespace: &'a str) -> Option<&'a str> {
    if object_kind.is_namespaced() {
        Some(namespace)
    } else {
        None
    }
}

/// Validate that a GET result actually contains valid data
/// Some proxies (like Capsule) may return Ok with empty objects instead of errors
fn is_valid_get_result(obj: &DynamicObject, expected_name: &str) -> bool {
    // Check if the object has the expected name
    match &obj.metadata.name {
        Some(name) => name == expected_name,
        None => false,
    }
}

/// Validate that a GET result contains any valid object (for existing resources)
fn is_valid_object(obj: &DynamicObject) -> bool {
    obj.metadata.name.is_some()
}

// =============================================================================
// AUTONOMY TESTS (Actual operation attempts)
// =============================================================================

/// Test if tenant can actually CREATE a resource by attempting the operation
async fn test_autonomy_create(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        // For resources like Node, CREATE is never allowed by tenants
        return Ok(false);
    }

    let test_name = format!(
        "autonomy-create-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant.namespace);
    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    // Cleanup regardless of result
    if create_result.is_ok() {
        let _ = tenant
            .cluster
            .delete_resource_dyn(object_kind, &test_name, namespace)
            .await;
    }

    Ok(create_result.is_ok())
}

/// Test if tenant can actually GET a resource by attempting the operation
async fn test_autonomy_get(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        // Try to get an existing resource
        let existing_name = get_existing_object_for_testing(tenant, object_kind).await;
        if let Ok(name) = existing_name {
            let get_result = tenant
                .cluster
                .get_resource_dyn(object_kind, &name, None)
                .await;
            // Validate that the returned object is actually valid
            return Ok(get_result
                .map(|obj| is_valid_get_result(&obj, &name))
                .unwrap_or(false));
        }
        return Ok(false);
    }

    let namespace = get_namespace_param(object_kind, &tenant.namespace);

    // First, try to LIST to see if there are existing resources we can GET
    let list_result = tenant
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await;

    if let Ok(list) = list_result {
        // If there are existing resources, try to GET one of them
        if let Some(item) = list.items.first() {
            if let Some(name) = &item.metadata.name {
                let get_result = tenant
                    .cluster
                    .get_resource_dyn(object_kind, name, namespace)
                    .await;
                // Validate that the returned object is actually valid
                return Ok(get_result
                    .map(|obj| is_valid_get_result(&obj, name))
                    .unwrap_or(false));
            }
        }
    }

    // No existing resources - try to create one to test GET
    let test_name = format!(
        "autonomy-get-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        // Can't create and no existing resources to test with
        // Check if the LIST is authorized - if not, GET is also not allowed
        let list_check = tenant
            .cluster
            .list_resources_dyn(object_kind, namespace)
            .await;

        match list_check {
            Ok(_) => {
                // LIST works but is empty and can't create - assume GET would work
                // since LIST typically requires GET permissions
                return Ok(true);
            }
            Err(e) => {
                let err_str = e.to_string();
                // If LIST is forbidden/not allowed, GET is likely forbidden too
                return Ok(!is_authorization_error(&err_str));
            }
        }
    }

    // Try to GET the resource we created
    let get_result = tenant
        .cluster
        .get_resource_dyn(object_kind, &test_name, namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    // Validate that the returned object is actually valid
    Ok(get_result
        .map(|obj| is_valid_get_result(&obj, &test_name))
        .unwrap_or(false))
}

/// Test if tenant can actually LIST resources by attempting the operation
async fn test_autonomy_list(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    let namespace = get_namespace_param(object_kind, &tenant.namespace);

    let list_result = tenant
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await;

    Ok(list_result.is_ok())
}

/// Test if tenant can actually UPDATE a resource by attempting the operation
async fn test_autonomy_update(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        let existing_name = get_existing_object_for_testing(tenant, object_kind).await;
        if let Ok(name) = existing_name {
            let test_label_key = "kumuteva-autonomy-test";
            let test_label_value = "update-test";

            let patch = kube::api::Patch::Merge(serde_json::json!({
                "metadata": {
                    "labels": {
                        test_label_key: test_label_value
                    }
                }
            }));

            let update_result = tenant
                .cluster
                .patch_resource_dyn(object_kind, &name, &patch, None)
                .await;

            // Try to revert if successful
            if update_result.is_ok() {
                let revert_patch = kube::api::Patch::Merge(serde_json::json!({
                    "metadata": {
                        "labels": {
                            test_label_key: null
                        }
                    }
                }));
                let _ = tenant
                    .cluster
                    .patch_resource_dyn(object_kind, &name, &revert_patch, None)
                    .await;
            }

            return Ok(update_result.is_ok());
        }
        return Ok(false);
    }

    let namespace = get_namespace_param(object_kind, &tenant.namespace);

    // First, try to find an existing resource to update
    let list_result = tenant
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await;

    if let Ok(list) = list_result {
        if let Some(item) = list.items.first() {
            if let Some(name) = &item.metadata.name {
                // Try to update an existing resource
                let patch = kube::api::Patch::Merge(serde_json::json!({
                    "metadata": {
                        "labels": {
                            "kumuteva-autonomy-update-test": "true"
                        }
                    }
                }));

                let update_result = tenant
                    .cluster
                    .patch_resource_dyn(object_kind, name, &patch, namespace)
                    .await;

                // Try to revert if successful
                if update_result.is_ok() {
                    let revert_patch = kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": {
                                "kumuteva-autonomy-update-test": null
                            }
                        }
                    }));
                    let _ = tenant
                        .cluster
                        .patch_resource_dyn(object_kind, name, &revert_patch, namespace)
                        .await;
                }

                return Ok(update_result.is_ok());
            }
        }
    }

    // No existing resources - create one to test UPDATE
    let test_name = format!(
        "autonomy-update-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        // Can't create and no existing resources - cannot test UPDATE
        return Ok(false);
    }

    // Wait a moment for the resource to be ready
    let _ = tenant
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Try to UPDATE the resource
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "autonomy-update-test": "true"
            }
        }
    }));

    let update_result = tenant
        .cluster
        .patch_resource_dyn(object_kind, &test_name, &patch, namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    Ok(update_result.is_ok())
}

/// Test if tenant can actually DELETE a resource by attempting the operation
async fn test_autonomy_delete(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        // For resources like Node, DELETE is generally not allowed by tenants
        // We can't safely test this without potentially breaking the cluster
        return Ok(false);
    }

    // For DELETE, we MUST create a resource to delete - we can't delete existing resources
    // as that would be destructive to the user's environment
    let test_name = format!(
        "autonomy-delete-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant.namespace);
    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        // Can't create a resource to test DELETE with
        // If we can't create, we likely can't delete either
        return Ok(false);
    }

    // Wait a moment for the resource to be ready
    let _ = tenant
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Try to DELETE the resource
    let delete_result = tenant
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    Ok(delete_result.is_ok())
}

// =============================================================================
// CROSS-TENANT ISOLATION TESTS
// =============================================================================

/// Test cross-tenant CREATE isolation
async fn test_cross_tenant_create(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    let test_name = format!(
        "create-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let t1_namespace = get_namespace_param(object_kind, &tenant1.namespace);

    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;

    // Step 1: Tenant1 creates the resource
    let t1_create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj.clone(), "tenant1"),
            t1_namespace,
        )
        .await;

    if t1_create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Unknown,
            details: format!(
                "Cannot verify CREATE isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Step 2: Tenant2 attempts to create with the same name in tenant1's namespace
    let t2_create_result = tenant2
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant2"),
            t1_namespace, // Attempting in tenant1's namespace
        )
        .await;

    // Step 3: Analyze the result
    let result = match t2_create_result {
        Ok(_) => {
            // Tenant2 succeeded - check if it overwrote tenant1's object
            let current_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &test_name, t1_namespace)
                .await;

            if let Ok(obj) = current_obj {
                if obj.annotations().get("kumuteva.io/created-by-tenant")
                    == Some(&"tenant2".to_string())
                {
                    // Tenant2 overwrote tenant1's object - no isolation
                    CrossTenantResult {
                        autonomy: true,
                        isolation: IsolationLevel::None,
                        details: format!(
                            "Cross-tenant CREATE breach: {} overwritten by other tenant",
                            object_kind.kind()
                        ),
                    }
                } else {
                    // Object still belongs to tenant1 - tenant2 created in different scope
                    // This is hard isolation - each tenant has their own namespace
                    CrossTenantResult {
                        autonomy: true,
                        isolation: IsolationLevel::Hard,
                        details: format!(
                            "CREATE has hard isolation for {} - tenants have separate scopes",
                            object_kind.kind()
                        ),
                    }
                }
            } else {
                CrossTenantResult {
                    autonomy: false,
                    isolation: IsolationLevel::Unknown,
                    details: format!(
                        "Cannot verify CREATE isolation for {} - object state unclear",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant CREATE blocked for {}: {}",
                    object_kind.kind(),
                    error_msg
                ),
            }
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_dyn(object_kind, &test_name, t1_namespace)
        .await;

    Ok(result)
}

/// Test cross-tenant UPDATE isolation
async fn test_cross_tenant_update(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_update_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "update-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;

    // Step 1: Create object in tenant1 with a known marker label
    let initial_label_value = "tenant1-original";
    let mut dynamic_obj = create_dynamic_object(object_kind, &test_name, obj, "tenant1");
    dynamic_obj.metadata.labels = Some(BTreeMap::from([(
        "update-test-marker".to_string(),
        initial_label_value.to_string(),
    )]));

    let create_result = tenant1
        .cluster
        .create_resource_dyn(object_kind, &dynamic_obj, namespace)
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify UPDATE isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Wait for the resource to be created
    let _ = tenant1
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Step 2: Tenant2 attempts to update the object
    let malicious_label_value = "tenant2-modified";
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "update-test-marker": malicious_label_value
            }
        }
    }));

    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, &test_name, &patch, namespace)
        .await;

    // Step 3: Verify the actual state
    let result = match update_result {
        Ok(_) => {
            // Update call succeeded - verify if it actually modified the object
            let current_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &test_name, namespace)
                .await;

            match current_obj {
                Ok(obj) => {
                    let current_label = obj
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get("update-test-marker"));

                    if current_label == Some(&malicious_label_value.to_string()) {
                        // Update took effect - no isolation
                        CrossTenantResult {
                            autonomy: true,
                            isolation: IsolationLevel::None,
                            details: format!(
                                "Cross-tenant UPDATE breach: {} modified by other tenant",
                                object_kind.kind()
                            ),
                        }
                    } else if current_label == Some(&initial_label_value.to_string()) {
                        // Label unchanged - update was blocked but succeeded (soft isolation)
                        CrossTenantResult {
                            autonomy: true,
                            isolation: IsolationLevel::Soft(
                                "Update succeeded but did not modify resource".to_string(),
                            ),
                            details: format!(
                                "UPDATE has soft isolation for {} - modification blocked",
                                object_kind.kind()
                            ),
                        }
                    } else {
                        CrossTenantResult {
                            autonomy: true,
                            isolation: IsolationLevel::Soft(format!(
                                "Unexpected label value: {:?}",
                                current_label
                            )),
                            details: format!(
                                "UPDATE isolation unclear for {} - unexpected state",
                                object_kind.kind()
                            ),
                        }
                    }
                }
                Err(e) => CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(format!("Could not verify: {}", e)),
                    details: format!(
                        "Cannot verify UPDATE isolation for {} - read failed",
                        object_kind.kind()
                    ),
                },
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant UPDATE blocked for {}: {}",
                    object_kind.kind(),
                    error_msg
                ),
            }
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    Ok(result)
}

/// Test UPDATE for resources that can't be created (like Node)
async fn test_cross_tenant_update_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Get an existing object
    let existing_name = match get_existing_object_for_testing(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            return Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot test {} UPDATE - no existing object available: {}",
                    object_kind.kind(),
                    e
                ),
            });
        }
    };

    tracing::info!(
        "Testing UPDATE isolation for {} using existing object: {}",
        object_kind.kind(),
        existing_name
    );

    // Get the current state (to restore later if needed)
    let current_obj = tenant1
        .cluster
        .get_resource_dyn(object_kind, &existing_name, None)
        .await;

    let original_labels = current_obj
        .as_ref()
        .ok()
        .and_then(|obj| obj.metadata.labels.clone());

    // Tenant2 attempts to update the existing object
    let test_label_key = "kumuteva-update-test";
    let test_label_value = "tenant2-attempted-modification";

    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                test_label_key: test_label_value
            }
        }
    }));

    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, &existing_name, &patch, None)
        .await;

    let result = match update_result {
        Ok(_) => {
            // Update succeeded - verify if it took effect
            let updated_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &existing_name, None)
                .await;

            let was_modified = updated_obj
                .as_ref()
                .ok()
                .and_then(|obj| obj.metadata.labels.as_ref())
                .and_then(|labels| labels.get(test_label_key))
                == Some(&test_label_value.to_string());

            if was_modified {
                // Revert the modification
                let revert_patch = if let Some(ref orig) = original_labels {
                    kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": orig
                        }
                    }))
                } else {
                    kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": {
                                test_label_key: null
                            }
                        }
                    }))
                };

                let _ = tenant1
                    .cluster
                    .patch_resource_dyn(object_kind, &existing_name, &revert_patch, None)
                    .await;

                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant UPDATE breach: {} '{}' modified by other tenant",
                        object_kind.kind(),
                        existing_name
                    ),
                }
            } else {
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(
                        "Update succeeded but modification not visible".to_string(),
                    ),
                    details: format!(
                        "UPDATE has soft isolation for {} - modification not effective",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true, // Tenant1 can see the node, so there's autonomy
                isolation,
                details: format!(
                    "Cross-tenant UPDATE blocked for {} '{}': {}",
                    object_kind.kind(),
                    existing_name,
                    error_msg
                ),
            }
        }
    };

    Ok(result)
}

/// Test cross-tenant GET isolation
async fn test_cross_tenant_get(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_get_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "get-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    // Create test object in tenant1
    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;
    let create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant1"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify GET isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Tenant2 attempts to GET the object
    let get_result = tenant2
        .cluster
        .get_resource_dyn(object_kind, &test_name, namespace)
        .await;

    let result = match get_result {
        Ok(obj) => {
            // Check if the returned object is actually valid (has the expected name)
            // Some proxies return Ok with empty objects instead of errors
            if is_valid_get_result(&obj, &test_name) {
                // Tenant2 can actually read tenant1's object - no isolation
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant GET breach: {} readable by other tenant",
                        object_kind.kind()
                    ),
                }
            } else {
                // GET returned Ok but with empty/invalid object - this is hard isolation
                // The proxy is hiding the resource from tenant2
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "Cross-tenant GET blocked for {} - proxy returned empty object",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!("Cross-tenant GET blocked for {}", object_kind.kind()),
            }
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    Ok(result)
}

/// Test GET for resources that can't be created (like Node)
async fn test_cross_tenant_get_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Get an existing object visible to tenant1
    let existing_name = match get_existing_object_for_testing(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            return Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot test {} GET - no existing object available: {}",
                    object_kind.kind(),
                    e
                ),
            });
        }
    };

    tracing::info!(
        "Testing GET isolation for {} using existing object: {}",
        object_kind.kind(),
        existing_name
    );

    // Tenant2 attempts to GET the same object
    let t2_get_result = tenant2
        .cluster
        .get_resource_dyn(object_kind, &existing_name, None)
        .await;

    match t2_get_result {
        Ok(t2_obj) => {
            // Check if the returned object is actually valid
            // Some proxies return Ok with empty objects instead of errors
            if !is_valid_get_result(&t2_obj, &existing_name) {
                return Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "Cross-tenant GET blocked for {} - proxy returned empty object",
                        object_kind.kind()
                    ),
                });
            }

            // Both tenants can see the same resource
            // For cluster-scoped resources like nodes, this is expected
            // We need to check if it is the same object or not

            let t1_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &existing_name, None)
                .await?;

            if t1_obj.metadata == t2_obj.metadata {
                // Same view
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "{} GET retrieve the same object named '{}'",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            } else {
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "{} GET retrieve different objects named '{}'",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            Ok(CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant GET blocked for {} '{}': {}",
                    object_kind.kind(),
                    existing_name,
                    error_msg
                ),
            })
        }
    }
}

/// Test cross-tenant LIST isolation
async fn test_cross_tenant_list(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_list_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "list-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    // Create test object in tenant1 with unique annotation
    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;
    let create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant1"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify LIST isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Tenant2 attempts to LIST in tenant1's namespace
    let t2_list = tenant2
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await;

    let result = match t2_list {
        Ok(resources) => {
            // Check if tenant1's object is visible
            let can_see_tenant1_resource = resources
                .items
                .iter()
                .any(|item| item.metadata.name.as_deref() == Some(&test_name));

            if can_see_tenant1_resource {
                // Tenant2 can see tenant1's resources - no isolation
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant LIST breach: {} visible to other tenant",
                        object_kind.kind()
                    ),
                }
            } else {
                // Resources are filtered - hard isolation
                // Tenant2 sees an empty/filtered list as if resource doesn't exist
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "LIST has hard isolation for {} - tenant1's resources not visible",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!("Cross-tenant LIST blocked for {}", object_kind.kind()),
            }
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    Ok(result)
}

/// Test LIST for resources that can't be created (like Node)
async fn test_cross_tenant_list_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Ensure at least one object exists (trigger node sync in vCluster)
    let _ = get_existing_object_for_testing(tenant1, object_kind).await;

    // List from both tenants
    let tenant1_list = tenant1.cluster.list_resources_dyn(object_kind, None).await;

    let tenant2_list = tenant2.cluster.list_resources_dyn(object_kind, None).await;

    match (tenant1_list, tenant2_list) {
        (Ok(t1_items), Ok(t2_items)) => {
            let t1_names: std::collections::HashSet<_> = t1_items
                .items
                .iter()
                .filter_map(|n| n.metadata.name.clone())
                .collect();

            let t2_names: std::collections::HashSet<_> = t2_items
                .items
                .iter()
                .filter_map(|n| n.metadata.name.clone())
                .collect();

            // If both lists are empty, we cannot verify isolation
            // (can't tell if they share the same empty view or have separate empty views)
            if t1_names.is_empty() && t2_names.is_empty() {
                return Ok(CrossTenantResult {
                    autonomy: true, // Both can LIST (just returns empty)
                    isolation: IsolationLevel::Unknown,
                    details: format!(
                        "Cannot verify {} LIST isolation - both tenants see 0 items and cannot create test resources",
                        object_kind.kind()
                    ),
                });
            }

            if t1_names == t2_names {
                // Identical non-empty view - this is a shared view (no isolation)
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "LIST shows shared {} view - both tenants see same {} items",
                        object_kind.kind(),
                        t1_names.len()
                    ),
                })
            } else {
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "LIST has hard isolation for {} - different views (tenant1: {}, tenant2: {})",
                        object_kind.kind(),
                        t1_names.len(),
                        t2_names.len()
                    ),
                })
            }
        }
        (Ok(t1_items), Err(e)) => {
            // Tenant1 can list, tenant2 cannot
            Ok(CrossTenantResult {
                autonomy: true,
                isolation: IsolationLevel::Hard,
                details: format!(
                    "LIST has asymmetric isolation for {} - tenant1 sees {} items, tenant2 blocked: {}",
                    object_kind.kind(),
                    t1_items.items.len(),
                    e
                ),
            })
        }
        (Err(e), Ok(t2_items)) => {
            // Tenant2 can list, tenant1 cannot
            Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot verify {} LIST isolation - tenant1 blocked: {}, tenant2 sees {} items",
                    object_kind.kind(),
                    e,
                    t2_items.items.len()
                ),
            })
        }
        (Err(e1), Err(_e2)) => {
            // Neither can list
            Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot verify {} LIST isolation - both tenants blocked: {}",
                    object_kind.kind(),
                    e1
                ),
            })
        }
    }
}

/// Test cross-tenant DELETE isolation
async fn test_cross_tenant_delete(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_delete_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "delete-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    // Create test object in tenant1
    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;
    let create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant1"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify DELETE isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Wait for resource to be created
    let _ = tenant1
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Tenant2 attempts to DELETE the object
    let delete_result = tenant2
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    let result = match delete_result {
        Ok(_) => {
            // Delete succeeded - verify if object is actually gone
            let exists = tenant1
                .cluster
                .dyn_object_exists(object_kind, &test_name, namespace)
                .await
                .unwrap_or(true);

            if !exists {
                // Object was deleted - no isolation
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant DELETE breach: {} deleted by other tenant",
                        object_kind.kind()
                    ),
                }
            } else {
                // Object still exists - delete was silently ignored (soft isolation)
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(
                        "Delete succeeded but object still exists".to_string(),
                    ),
                    details: format!(
                        "DELETE has soft isolation for {} - object preserved",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            // Cleanup since delete failed
            let _ = tenant1
                .cluster
                .delete_resource_dyn(object_kind, &test_name, namespace)
                .await;

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!("Cross-tenant DELETE blocked for {}", object_kind.kind()),
            }
        }
    };

    Ok(result)
}

/// Test DELETE for resources that can't be created (like Node)
async fn test_cross_tenant_delete_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Get an existing object name
    let existing_name = match get_existing_object_for_testing(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            return Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot test {} DELETE - no existing object available: {}",
                    object_kind.kind(),
                    e
                ),
            });
        }
    };

    // Check if tenant2 is authorized to delete (don't actually delete!)
    let t2_can_delete = tenant2
        .cluster
        .is_authorized_to("delete", &object_kind.plural_kind(), None)
        .await
        .unwrap_or(false);

    if !t2_can_delete {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(
                "Tenant2 not authorized to delete resource".to_string(),
            ),
            details: format!(
                "Cannot verify DELETE isolation for {} - tenant2 lacks delete permission",
                object_kind.kind()
            ),
        });
    }

    // let's try deleting and chech if is still existing
    let delete_result = tenant2
        .cluster
        .delete_resource_dyn(object_kind, &existing_name, None)
        .await;

    match delete_result {
        Ok(_) => {
            // Delete succeeded - verify if object is actually gone
            let exists = tenant1
                .cluster
                .dyn_object_exists(object_kind, &existing_name, None)
                .await
                .unwrap_or(true);

            if !exists {
                // Object was deleted - no isolation
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant DELETE breach: {} '{}' deleted by other tenant",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            } else {
                // Object still exists - delete was silently ignored
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(
                        "Delete succeeded but object still exists".to_string(),
                    ),
                    details: format!(
                        "DELETE has soft isolation for {} - object '{}' preserved",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            Ok(CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant DELETE blocked for {} '{}': {}",
                    object_kind.kind(),
                    existing_name,
                    error_msg
                ),
            })
        }
    }
}

// =============================================================================
// SPECIAL RESOURCE HANDLING
// =============================================================================

/// Resources that cannot be created programmatically and require special handling
fn requires_existing_object(object_kind: &KubernetesObject) -> bool {
    matches!(object_kind, KubernetesObject::Node)
}

/// Get an existing node for testing, handling vCluster edge case where nodes
/// only appear after scheduling a pod
async fn get_existing_node(tenant: &TenantClusterConfig) -> anyhow::Result<String> {
    // First, try to list nodes directly
    let nodes = tenant
        .cluster
        .list_resources_dyn(&KubernetesObject::Node, None)
        .await;

    if let Ok(node_list) = nodes {
        if let Some(node) = node_list.items.first() {
            if let Some(name) = &node.metadata.name {
                return Ok(name.clone());
            }
        }
    }

    // No nodes found - this might be vCluster
    // Schedule a temporary pod to trigger node sync
    tracing::info!(
        "No nodes found, scheduling temporary pod to trigger node sync (vCluster edge case)..."
    );

    let temp_pod_name = format!(
        "node-sync-trigger-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let temp_pod: Pod = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": temp_pod_name,
            "namespace": tenant.namespace
        },
        "spec": {
            "containers": [{
                "name": "pause",
                "image": "registry.k8s.io/pause:3.9",
                "resources": {
                    "requests": {
                        "cpu": "10m",
                        "memory": "16Mi"
                    },
                    "limits": {
                        "cpu": "10m",
                        "memory": "16Mi"
                    }
                }
            }],
            "restartPolicy": "Never"
        }
    }))?;

    // Create the pod
    let pod_result = tenant
        .cluster
        .create_pod_in_namespace(&temp_pod, &tenant.namespace)
        .await;

    if pod_result.is_err() {
        return Err(anyhow::anyhow!(
            "Could not create temporary pod to trigger node sync: {}",
            pod_result.unwrap_err()
        ));
    }

    // Wait for pod to be scheduled (which should trigger node visibility)
    // Poll for nodes with exponential backoff
    let max_attempts = 10;
    let mut attempt = 0;
    let mut node_name: Option<String> = None;

    while attempt < max_attempts {
        sleep(Duration::from_millis(500 * (attempt + 1) as u64)).await;

        let nodes = tenant
            .cluster
            .list_resources_dyn(&KubernetesObject::Node, None)
            .await;

        if let Ok(node_list) = nodes {
            if let Some(node) = node_list.items.first() {
                if let Some(name) = &node.metadata.name {
                    node_name = Some(name.clone());
                    break;
                }
            }
        }

        attempt += 1;
        tracing::debug!(
            "Waiting for nodes to appear... attempt {}/{}",
            attempt,
            max_attempts
        );
    }

    // Cleanup the temporary pod
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(&temp_pod_name, &tenant.namespace)
        .await;

    node_name.ok_or_else(|| {
        anyhow::anyhow!(
            "No nodes became visible after scheduling pod - cluster may not expose nodes to tenants"
        )
    })
}

/// Get an existing object for resources that can't be created
async fn get_existing_object_for_testing(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<String> {
    match object_kind {
        KubernetesObject::Node => get_existing_node(tenant).await,
        _ => Err(anyhow::anyhow!(
            "No special handling for {} - should use create flow",
            object_kind.kind()
        )),
    }
}

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for IsolationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationLevel::Unknown => write!(f, "Unknown"),
            IsolationLevel::None => write!(f, "None"),
            IsolationLevel::Soft(reason) => write!(f, "Soft ({})", reason),
            IsolationLevel::Hard => write!(f, "Hard"),
        }
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
            Self::Create => write!(f, "CREATE"),
            Self::Get => write!(f, "GET"),
            Self::List => write!(f, "LIST"),
            Self::Update => write!(f, "UPDATE"),
            Self::Delete => write!(f, "DELETE"),
        }
    }
}

// =============================================================================
// MANUAL TESTING UTILITIES
// =============================================================================

/// Manual test helper for debugging cross-tenant isolation issues.
/// This function creates test objects and leaves them in place for manual inspection.
///
/// # Arguments
/// * `tenant1` - First tenant configuration (the "victim" tenant)
/// * `tenant2` - Second tenant configuration (the "attacker" tenant)  
/// * `resource` - The control plane resource to test
/// * `operation` - The operation to test
/// * `cleanup` - Whether to cleanup created resources after the test
///
/// # Returns
/// A tuple of (test_object_name, namespace) for manual inspection
pub async fn manual_test_cross_tenant_operation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    resource: &ControlPlaneResource,
    operation: &ControlPlaneOperation,
    cleanup: bool,
) -> anyhow::Result<()> {
    let k8s_obj = resource.to_kubernetes_object();

    println!("=======================================================");
    println!("MANUAL CROSS-TENANT TEST");
    println!("=======================================================");
    println!("Resource: {} ({})", k8s_obj.kind(), k8s_obj.api_version());
    println!("Operation: {:?}", operation);
    println!("Tenant1 namespace: {}", tenant1.namespace);
    println!("Tenant2 namespace: {}", tenant2.namespace);
    println!("Is namespaced: {}", k8s_obj.is_namespaced());
    println!("Cleanup: {}", cleanup);
    println!("-------------------------------------------------------");

    let test_name = format!(
        "manual-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(&k8s_obj, &tenant1.namespace);

    println!("\n[STEP 1] Creating test object as Tenant1...");
    println!("  Object name: {}", test_name);
    println!("  Namespace: {:?}", namespace);

    // Create minimal object
    let obj = match create_minimal_object(&k8s_obj, &test_name, &tenant1.namespace) {
        Ok(o) => o,
        Err(e) => {
            println!("  ERROR creating minimal object spec: {}", e);
            return Err(e);
        }
    };

    let dynamic_obj = create_dynamic_object(&k8s_obj, &test_name, obj.clone(), "tenant1");

    let create_result = tenant1
        .cluster
        .create_resource_dyn(&k8s_obj, &dynamic_obj, namespace)
        .await;

    match &create_result {
        Ok(_) => {
            println!("  SUCCESS: Object created by Tenant1");
        }
        Err(e) => {
            println!("  FAILED: {}", e);
            println!("\n[INFO] Cannot proceed with cross-tenant test - Tenant1 creation failed");
            return Ok(());
        }
    }

    println!("\n[STEP 2] Tenant2 attempting {} operation...", operation);

    match operation {
        ControlPlaneOperation::Create => {
            println!("  Tenant2 trying to CREATE with same name in tenant1's namespace...");
            let t2_obj = create_dynamic_object(&k8s_obj, &test_name, obj, "tenant2");
            let result = tenant2
                .cluster
                .create_resource_dyn(&k8s_obj, &t2_obj, namespace)
                .await;
            print_operation_result("CREATE", &result);
        }
        ControlPlaneOperation::Get => {
            println!("  Tenant2 trying to GET tenant1's object...");
            let result = tenant2
                .cluster
                .get_resource_dyn(&k8s_obj, &test_name, namespace)
                .await;

            match &result {
                Ok(obj) => {
                    println!("  [DETAILS] Object retrieved:");
                    println!("    Name: {:?}", obj.metadata.name);
                    println!("    Namespace: {:?}", obj.metadata.namespace);
                    println!("    Annotations: {:?}", obj.metadata.annotations);

                    // Validate if the object is actually valid
                    if is_valid_get_result(obj, &test_name) {
                        println!("  RESULT: GET SUCCEEDED with valid object - ISOLATION BREACH!");
                    } else {
                        println!("  RESULT: GET returned Ok but with EMPTY/INVALID object - GOOD ISOLATION");
                        println!("    (Proxy returned empty object instead of error - this is hard isolation)");
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if is_authorization_error(&err_str) {
                        println!("  RESULT: GET BLOCKED (Forbidden/NotAllowed) - GOOD ISOLATION");
                    } else if err_str.contains("NotFound") || err_str.contains("not found") {
                        println!("  RESULT: GET BLOCKED (NotFound) - HARD ISOLATION");
                    } else {
                        println!("  RESULT: GET FAILED: {}", err_str);
                    }
                }
            }
        }
        ControlPlaneOperation::List => {
            println!("  Tenant2 trying to LIST in tenant1's namespace...");
            let result = tenant2
                .cluster
                .list_resources_dyn(&k8s_obj, namespace)
                .await;

            match &result {
                Ok(list) => {
                    println!("  SUCCESS: LIST returned {} items", list.items.len());
                    for item in &list.items {
                        let name = item.metadata.name.as_deref().unwrap_or("<unnamed>");
                        let created_by = item
                            .metadata
                            .annotations
                            .as_ref()
                            .and_then(|a| a.get("kumuteva.io/created-by-tenant"))
                            .map(|s| s.as_str())
                            .unwrap_or("<unknown>");
                        println!("    - {} (created by: {})", name, created_by);

                        // Check if our test object is visible
                        if name == test_name {
                            println!("      ^^^ THIS IS TENANT1's TEST OBJECT - ISOLATION BREACH!");
                        }
                    }
                }
                Err(e) => {
                    println!("  BLOCKED: {}", e);
                }
            }
        }
        ControlPlaneOperation::Update => {
            println!("  Tenant2 trying to UPDATE tenant1's object...");
            let patch = kube::api::Patch::Merge(serde_json::json!({
                "metadata": {
                    "labels": {
                        "malicious-update": "tenant2-was-here"
                    }
                }
            }));
            let result = tenant2
                .cluster
                .patch_resource_dyn(&k8s_obj, &test_name, &patch, namespace)
                .await;
            print_operation_result("UPDATE", &result);

            // Verify if update took effect
            if result.is_ok() {
                println!("  [VERIFICATION] Checking if update was applied...");
                let verify = tenant1
                    .cluster
                    .get_resource_dyn(&k8s_obj, &test_name, namespace)
                    .await;
                if let Ok(obj) = verify {
                    let has_malicious_label = obj
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|l| l.get("malicious-update"))
                        .is_some();
                    if has_malicious_label {
                        println!("    ISOLATION BREACH: Update was applied!");
                    } else {
                        println!(
                            "    Update call succeeded but label not found (might be filtered)"
                        );
                    }
                }
            }
        }
        ControlPlaneOperation::Delete => {
            println!("  Tenant2 trying to DELETE tenant1's object...");
            let result = tenant2
                .cluster
                .delete_resource_dyn(&k8s_obj, &test_name, namespace)
                .await;
            print_operation_result("DELETE", &result);

            // Verify if delete took effect
            if result.is_ok() {
                println!("  [VERIFICATION] Checking if object still exists...");
                sleep(Duration::from_millis(500)).await;
                let verify = tenant1
                    .cluster
                    .get_resource_dyn(&k8s_obj, &test_name, namespace)
                    .await;
                match verify {
                    Ok(_) => println!("    Object still exists (delete might have been blocked)"),
                    Err(e) if e.to_string().contains("NotFound") => {
                        println!("    ISOLATION BREACH: Object was deleted!");
                    }
                    Err(e) => println!("    Verification error: {}", e),
                }
            }
        }
    }

    println!("\n-------------------------------------------------------");
    println!("MANUAL INSPECTION COMMANDS:");
    println!("-------------------------------------------------------");

    let kubectl_ns = namespace.map(|n| format!("-n {}", n)).unwrap_or_default();
    let resource_kind = k8s_obj.kind().to_lowercase();

    println!("# As Tenant1:");
    println!(
        "  kubectl get {} {} {} -o yaml",
        resource_kind, test_name, kubectl_ns
    );
    println!();
    println!("# As Tenant2 (to verify cross-tenant access):");
    println!(
        "  kubectl get {} {} {} -o yaml",
        resource_kind, test_name, kubectl_ns
    );
    println!();

    if !k8s_obj.is_namespaced() {
        println!("# NOTE: This is a cluster-scoped resource (no namespace)");
        println!("  kubectl get {} {} -o yaml", resource_kind, test_name);
    }

    if cleanup {
        println!("\n[CLEANUP] Deleting test object...");
        let del_result = tenant1
            .cluster
            .delete_resource_dyn(&k8s_obj, &test_name, namespace)
            .await;
        match del_result {
            Ok(_) => println!("  Cleanup successful"),
            Err(e) => println!("  Cleanup failed: {}", e),
        }
    } else {
        println!("\n[NO CLEANUP] Test object left in place for manual inspection:");
        println!("  Resource: {}", k8s_obj.kind());
        println!("  Name: {}", test_name);
        println!("  Namespace: {:?}", namespace);
        println!("\nTo cleanup manually:");
        println!(
            "  kubectl delete {} {} {}",
            resource_kind, test_name, kubectl_ns
        );
    }

    println!("=======================================================\n");

    Ok(())
}

/// Helper to print operation results consistently
fn print_operation_result<T: std::fmt::Debug, E: std::fmt::Display>(
    op: &str,
    result: &Result<T, E>,
) {
    match result {
        Ok(_) => {
            println!("  RESULT: {} SUCCEEDED (potential isolation breach!)", op);
        }
        Err(e) => {
            let err_str = e.to_string();
            if is_authorization_error(&err_str) {
                println!(
                    "  RESULT: {} BLOCKED (Forbidden/NotAllowed) - GOOD ISOLATION",
                    op
                );
            } else if err_str.contains("NotFound") || err_str.contains("not found") {
                println!("  RESULT: {} BLOCKED (NotFound) - HARD ISOLATION", op);
            } else {
                println!("  RESULT: {} FAILED: {}", op, err_str);
            }
        }
    }
}

/// Quick test for a specific resource - tests all operations
pub async fn manual_test_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    resource: &ControlPlaneResource,
) -> anyhow::Result<()> {
    for op in resource.applicable_operations() {
        manual_test_cross_tenant_operation(tenant1, tenant2, resource, &op, true).await?;
    }
    Ok(())
}

/// Manual test for autonomy (single tenant) - checks if tenant can perform operation
pub async fn manual_test_autonomy(
    tenant: &TenantClusterConfig,
    resource: &ControlPlaneResource,
    operation: &ControlPlaneOperation,
    cleanup: bool,
) -> anyhow::Result<()> {
    let k8s_obj = resource.to_kubernetes_object();

    println!("=======================================================");
    println!("MANUAL AUTONOMY TEST");
    println!("=======================================================");
    println!("Resource: {} ({})", k8s_obj.kind(), k8s_obj.api_version());
    println!("Operation: {:?}", operation);
    println!("Tenant namespace: {}", tenant.namespace);
    println!("Is namespaced: {}", k8s_obj.is_namespaced());
    println!("-------------------------------------------------------");

    let namespace = get_namespace_param(&k8s_obj, &tenant.namespace);

    match operation {
        ControlPlaneOperation::List => {
            println!("\n[TEST] Attempting LIST...");
            let result = tenant.cluster.list_resources_dyn(&k8s_obj, namespace).await;

            match &result {
                Ok(list) => {
                    println!("  SUCCESS: LIST returned {} items", list.items.len());
                    for item in list.items.iter().take(10) {
                        println!(
                            "    - {}",
                            item.metadata.name.as_deref().unwrap_or("<unnamed>")
                        );
                    }
                    if list.items.len() > 10 {
                        println!("    ... and {} more", list.items.len() - 10);
                    }
                }
                Err(e) => {
                    println!("  FAILED: {}", e);
                }
            }
        }
        _ => {
            let test_name = format!(
                "autonomy-test-{}",
                uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
            );

            println!("\n[SETUP] Creating test object...");
            println!("  Name: {}", test_name);

            let obj = create_minimal_object(&k8s_obj, &test_name, &tenant.namespace)?;
            let dynamic_obj = create_dynamic_object(&k8s_obj, &test_name, obj, "autonomy-test");

            match operation {
                ControlPlaneOperation::Create => {
                    println!("\n[TEST] Attempting CREATE...");
                    let result = tenant
                        .cluster
                        .create_resource_dyn(&k8s_obj, &dynamic_obj, namespace)
                        .await;
                    print_operation_result("CREATE", &result);

                    if result.is_ok() && cleanup {
                        let _ = tenant
                            .cluster
                            .delete_resource_dyn(&k8s_obj, &test_name, namespace)
                            .await;
                    }
                }
                ControlPlaneOperation::Get => {
                    // First create, then GET
                    let create_result = tenant
                        .cluster
                        .create_resource_dyn(&k8s_obj, &dynamic_obj, namespace)
                        .await;

                    if create_result.is_err() {
                        println!("  Cannot create test object, trying to GET existing...");
                        let list = tenant.cluster.list_resources_dyn(&k8s_obj, namespace).await;
                        if let Ok(l) = list {
                            if let Some(item) = l.items.first() {
                                if let Some(name) = &item.metadata.name {
                                    println!("\n[TEST] Attempting GET on existing '{}'...", name);
                                    let result = tenant
                                        .cluster
                                        .get_resource_dyn(&k8s_obj, name, namespace)
                                        .await;
                                    print_operation_result("GET", &result);
                                    return Ok(());
                                }
                            }
                        }
                        println!("  No existing resources to test GET");
                        return Ok(());
                    }

                    println!("\n[TEST] Attempting GET...");
                    let result = tenant
                        .cluster
                        .get_resource_dyn(&k8s_obj, &test_name, namespace)
                        .await;
                    print_operation_result("GET", &result);

                    if cleanup {
                        let _ = tenant
                            .cluster
                            .delete_resource_dyn(&k8s_obj, &test_name, namespace)
                            .await;
                    }
                }
                ControlPlaneOperation::Update => {
                    let create_result = tenant
                        .cluster
                        .create_resource_dyn(&k8s_obj, &dynamic_obj, namespace)
                        .await;

                    if create_result.is_err() {
                        println!("  Cannot create test object: {:?}", create_result.err());
                        return Ok(());
                    }

                    println!("\n[TEST] Attempting UPDATE...");
                    let patch = kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": {
                                "autonomy-test": "updated"
                            }
                        }
                    }));
                    let result = tenant
                        .cluster
                        .patch_resource_dyn(&k8s_obj, &test_name, &patch, namespace)
                        .await;
                    print_operation_result("UPDATE", &result);

                    if cleanup {
                        let _ = tenant
                            .cluster
                            .delete_resource_dyn(&k8s_obj, &test_name, namespace)
                            .await;
                    }
                }
                ControlPlaneOperation::Delete => {
                    let create_result = tenant
                        .cluster
                        .create_resource_dyn(&k8s_obj, &dynamic_obj, namespace)
                        .await;

                    if create_result.is_err() {
                        println!("  Cannot create test object: {:?}", create_result.err());
                        return Ok(());
                    }

                    println!("\n[TEST] Attempting DELETE...");
                    let result = tenant
                        .cluster
                        .delete_resource_dyn(&k8s_obj, &test_name, namespace)
                        .await;
                    print_operation_result("DELETE", &result);
                }
                ControlPlaneOperation::List => unreachable!(),
            }
        }
    }

    println!("=======================================================\n");
    Ok(())
}
