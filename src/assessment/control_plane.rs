use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;

use async_trait::async_trait;
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};
use kube::ResourceExt;

use crate::assessment::{
    run_assessment, AssessableResource, AutonomyRatio, CrossTenantResult, MultitenancyAssessor,
    OperationAssessment, SafetyLevel, SubsystemReport,
};
use crate::verifier::TenantClusterConfig;
use crate::verifier::{create_minimal_object, KubernetesObject};

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

pub type ControlPlaneIsolationReport = SubsystemReport<ControlPlaneResource>;

/// Isolation level for cross-tenant operations
#[derive(Debug, Clone, PartialEq)]
pub enum IsolationLevel {
    /// Isolation level could not be determined
    Unknown,
    /// No isolation - cross-tenant operation succeeded and affected other tenant's resources
    None,
    /// Soft isolation - operation blocked but reveals shared environment
    /// (e.g., Forbidden error, AlreadyExists indicating name collision)
    Soft(String),
    /// Hard isolation - operation fails as if system were single-tenant
    /// (e.g., NotFound error because resource doesn't exist in intruder's scope)
    Hard,
}

impl IsolationLevel {
    pub fn is_isolated(&self) -> bool {
        !matches!(self, IsolationLevel::None)
    }

    pub fn is_hard(&self) -> bool {
        matches!(self, IsolationLevel::Hard)
    }
}

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
        let verb = match operation {
            ControlPlaneOperation::Create => "create",
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
        tenant
            .cluster
            .is_authorized_to(verb, &resource_name, namespace)
            .await
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

/// Infer isolation level from an error message during cross-tenant operation
fn infer_isolation_from_error(error_msg: &str) -> IsolationLevel {
    if error_msg.contains("NotFound") || error_msg.contains("not found") {
        // Resource not found in tenant2's scope - hard isolation
        // Intruder sees the same error as in a single-tenant system
        IsolationLevel::Hard
    } else if error_msg.contains("Forbidden") || error_msg.contains("forbidden") {
        // Operation forbidden - soft isolation
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
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                t1_create_result.unwrap_err()
            )),
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
                    autonomy: true,
                    isolation: IsolationLevel::Soft("Could not verify object state".to_string()),
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

/// Test cross-tenant GET isolation
async fn test_cross_tenant_get(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
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
        Ok(_) => {
            // Tenant2 can read tenant1's object - no isolation
            CrossTenantResult {
                autonomy: true,
                isolation: IsolationLevel::None,
                details: format!(
                    "Cross-tenant GET breach: {} readable by other tenant",
                    object_kind.kind()
                ),
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

/// Test cross-tenant LIST isolation
async fn test_cross_tenant_list(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
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

/// Test cross-tenant DELETE isolation
async fn test_cross_tenant_delete(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
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
