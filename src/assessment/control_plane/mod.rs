mod autonomy;
mod fairness;
mod isolation;

mod objects;
mod utils;

use autonomy::*;
pub use fairness::*;
use isolation::*;
pub use objects::*;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use kube::api::{DeleteParams, DynamicObject, ObjectMeta, TypeMeta};
use kube::Api;
use tokio::time::sleep;

use crate::assessment::control_plane::utils::create_minimal_object;
use crate::assessment::{
    AssessableResource, CrossTenantResult, IsolationLevel, MultitenancyAssessor,
    OperationAssessment, SubsystemReport,
};

use crate::assessment::TenantClusterConfig;

#[allow(dead_code)]
pub type ControlPlaneIsolationReport = SubsystemReport<ControlPlaneResource>;

/// Assessment of a single resource with all its operations
#[allow(dead_code)]
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

    #[allow(dead_code)]
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

/// The HTTP status the API server returned, if the message carries one.
///
/// `kube`'s `ErrorResponse` renders as `... code: 403 })` when an error is
/// stringified, so the structured answer is usually still present in the text.
/// Reading it is worth the small parse: matching on words like "forbidden"
/// depends on message wording that upstream is free to change, and if it ever
/// does the classification degrades silently — a verdict flips and nothing
/// announces it.
fn status_code_in(error_msg: &str) -> Option<u16> {
    let rest = error_msg.rsplit_once("code: ")?.1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Infer isolation level from an error message during cross-tenant operation
fn infer_isolation_from_error(error_msg: &str) -> IsolationLevel {
    // Prefer the status code where the message carries one. Not every error
    // does — Pod Security Admission and quota rejections arrive as bare
    // messages — so the substring matching below remains the fallback rather
    // than being replaced.
    match status_code_in(error_msg) {
        // Absent from the intruder's scope: exactly what a single-tenant
        // cluster would say.
        Some(404) => return IsolationLevel::Hard,
        // Refused, but the refusal confirms there was something to refuse.
        Some(401) | Some(403) => {
            return IsolationLevel::Soft(
                "Access forbidden - reveals shared environment".to_string(),
            )
        }
        // The name is taken, which tells the intruder another tenant holds it.
        Some(409) => {
            return IsolationLevel::Soft("Name collision - reveals resource exists".to_string())
        }
        _ => {}
    }

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

/// Delete a test resource and clean up any associated resources (like PVCs for StatefulSets)
async fn cleanup_test_resource(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    test_name: &str,
    namespace: Option<&str>,
) {
    // Delete the main resource
    let _ = tenant
        .cluster
        .delete_resource_dyn(object_kind, test_name, namespace)
        .await;

    // For StatefulSets, also delete the PVCs created by volumeClaimTemplates
    // PVC naming pattern: <volumeClaimTemplate-name>-<statefulset-name>-<ordinal>
    // Since our volumeClaimTemplate name equals the StatefulSet name, pattern is: <name>-<name>-0
    if *object_kind == KubernetesObject::StatefulSet {
        if let Some(ns) = namespace {
            // The PVC name follows the pattern: <volumeClaimTemplate-name>-<statefulset-name>-<ordinal>
            // Our template uses the same name as the StatefulSet, so: <test_name>-<test_name>-0
            let pvc_name = format!("{}-{}-0", test_name, test_name);
            let _ = tenant
                .cluster
                .delete_resource_in_namespace::<PersistentVolumeClaim>(&pvc_name, ns)
                .await;
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
        // Also cleanup PVC for StatefulSets
        if k8s_obj.kind() == "StatefulSet" {
            if let Some(ns) = namespace {
                let pvc_name = format!("{}-{}-0", test_name, test_name);
                let _delete_operation = tenant1
                    .cluster
                    .delete_resource_in_namespace::<PersistentVolumeClaim>(&pvc_name, ns)
                    .await;
            }
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
                        // Also cleanup PVC for StatefulSets
                        if k8s_obj.kind() == "StatefulSet" {
                            if let Some(ns) = namespace {
                                let pvc_name = format!("{}-{}-0", test_name, test_name);
                                let pvc_api: Api<PersistentVolumeClaim> =
                                    Api::namespaced(tenant.cluster.client().clone(), ns);
                                let _ = pvc_api.delete(&pvc_name, &DeleteParams::default()).await;
                            }
                        }
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
                        // Also cleanup PVC for StatefulSets
                        if k8s_obj.kind() == "StatefulSet" {
                            if let Some(ns) = namespace {
                                let pvc_name = format!("{}-{}-0", test_name, test_name);
                                let pvc_api: Api<PersistentVolumeClaim> =
                                    Api::namespaced(tenant.cluster.client().clone(), ns);
                                let _ = pvc_api.delete(&pvc_name, &DeleteParams::default()).await;
                            }
                        }
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
                        // Also cleanup PVC for StatefulSets
                        if k8s_obj.kind() == "StatefulSet" {
                            if let Some(ns) = namespace {
                                let pvc_name = format!("{}-{}-0", test_name, test_name);
                                let pvc_api: Api<PersistentVolumeClaim> =
                                    Api::namespaced(tenant.cluster.client().clone(), ns);
                                let _ = pvc_api.delete(&pvc_name, &DeleteParams::default()).await;
                            }
                        }
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

                    // For DELETE test, also cleanup PVC for StatefulSets since the delete is the test
                    if k8s_obj.kind() == "StatefulSet" {
                        if let Some(ns) = namespace {
                            let pvc_name = format!("{}-{}-0", test_name, test_name);
                            let pvc_api: Api<PersistentVolumeClaim> =
                                Api::namespaced(tenant.cluster.client().clone(), ns);
                            let _ = pvc_api.delete(&pvc_name, &DeleteParams::default()).await;
                        }
                    }
                }
                ControlPlaneOperation::List => unreachable!(),
            }
        }
    }

    println!("=======================================================\n");
    Ok(())
}

#[cfg(test)]
mod error_classification_tests {
    //! Characterisation tests for the two functions that decide every
    //! control-plane verdict in the report.
    //!
    //! They had none, despite `infer_isolation_from_error` being called from
    //! seven places and mapping directly onto what the paper prints. The
    //! strings below are real messages from this project's own runs, not
    //! invented ones — the functions match on message text, so a test built
    //! from paraphrase would pass while the real thing failed.
    //!
    //! Their purpose is to pin current behaviour before the matching is moved
    //! onto structured status codes. Any change in these results after that
    //! move is a change in the published numbers.

    use super::*;

    /// Real 403 from a cross-tenant DaemonSet create, captured from a run.
    const FORBIDDEN_RBAC: &str = r#"ApiError: daemonsets.apps is forbidden: User "tenant2-admin" cannot create resource "daemonsets" in API group "apps" in the namespace "tenant1": Forbidden (ErrorResponse { status: "Failure", message: "daemonsets.apps is forbidden", reason: "Forbidden", code: 403 })"#;

    /// Real 403 from Pod Security Admission on a hardened tenant.
    const FORBIDDEN_POD_SECURITY: &str = r#"pods "network-multitool" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false"#;

    /// Real 403 from a ResourceQuota that requires limits.
    const FORBIDDEN_QUOTA: &str =
        r#"pods "probe" is forbidden: failed quota: capsule-tenant1-0: must specify limits.cpu"#;

    const NOT_FOUND: &str = r#"ApiError: configmaps "other-tenant-config" not found: NotFound (ErrorResponse { status: "Failure", message: "configmaps not found", reason: "NotFound", code: 404 })"#;

    const ALREADY_EXISTS: &str = r#"ApiError: configmaps "shared-name" already exists: AlreadyExists (ErrorResponse { reason: "AlreadyExists", code: 409 })"#;

    #[test]
    fn not_found_reads_as_hard_isolation() {
        // The intruder sees exactly what it would in a single-tenant cluster:
        // no evidence the resource exists at all.
        assert_eq!(infer_isolation_from_error(NOT_FOUND), IsolationLevel::Hard);
    }

    #[test]
    fn forbidden_reads_as_soft_isolation() {
        // Blocked, but the refusal itself confirms there is something there to
        // be refused — the environment is shared.
        for message in [FORBIDDEN_RBAC, FORBIDDEN_POD_SECURITY, FORBIDDEN_QUOTA] {
            assert!(
                matches!(infer_isolation_from_error(message), IsolationLevel::Soft(_)),
                "expected Soft for: {message}"
            );
        }
    }

    #[test]
    fn a_name_collision_reads_as_soft_isolation() {
        // The intruder learns another tenant holds that name.
        assert!(matches!(
            infer_isolation_from_error(ALREADY_EXISTS),
            IsolationLevel::Soft(_)
        ));
    }

    #[test]
    fn not_found_wins_over_forbidden_when_a_message_contains_both() {
        // Order matters and is not obvious: a NotFound message that also
        // carries the word "forbidden" must still read as Hard. Swapping the
        // branches would silently downgrade every such verdict to Soft.
        let both = r#"configmaps "x" not found; user is forbidden from listing"#;
        assert_eq!(infer_isolation_from_error(both), IsolationLevel::Hard);
    }

    #[test]
    fn an_unrecognised_error_is_soft_rather_than_hard() {
        // Deliberately conservative. An error we cannot classify might still
        // have leaked something, so it must not be reported as the strongest
        // isolation available.
        let level = infer_isolation_from_error("connection reset by peer");
        assert!(matches!(level, IsolationLevel::Soft(_)));
    }

    #[test]
    fn the_status_code_is_preferred_over_the_wording() {
        // The point of reading the code: classification stops depending on
        // upstream's choice of words. A 404 whose text says "forbidden" is
        // still Hard, and a 403 whose text says nothing recognisable is still
        // Soft — where substring matching alone would get the second one wrong
        // and file it under "unclassified".
        let misleading_404 =
            r#"something forbidden happened (ErrorResponse { reason: "NotFound", code: 404 })"#;
        assert_eq!(
            infer_isolation_from_error(misleading_404),
            IsolationLevel::Hard
        );

        let wordless_403 = r#"request rejected (ErrorResponse { reason: "Forbidden", code: 403 })"#;
        assert!(matches!(
            infer_isolation_from_error(wordless_403),
            IsolationLevel::Soft(_)
        ));

        let wordless_409 = r#"rejected (ErrorResponse { reason: "AlreadyExists", code: 409 })"#;
        assert!(matches!(
            infer_isolation_from_error(wordless_409),
            IsolationLevel::Soft(_)
        ));
    }

    #[test]
    fn messages_without_a_code_still_classify_by_wording() {
        // Pod Security Admission and quota rejections arrive as bare text, so
        // the substring path has to stay. Removing it would send every one of
        // them to the unclassified branch.
        assert_eq!(status_code_in(FORBIDDEN_POD_SECURITY), None);
        assert_eq!(status_code_in(FORBIDDEN_QUOTA), None);
        for message in [FORBIDDEN_POD_SECURITY, FORBIDDEN_QUOTA] {
            assert!(matches!(
                infer_isolation_from_error(message),
                IsolationLevel::Soft(_)
            ));
        }
    }

    #[test]
    fn the_code_parser_does_not_invent_one() {
        assert_eq!(status_code_in("no code here"), None);
        assert_eq!(status_code_in("code: notanumber"), None);
        assert_eq!(status_code_in("code: 403 })"), Some(403));
        // Several codes in one message: the last is the outermost wrapper,
        // which is the response actually returned.
        assert_eq!(
            status_code_in("inner code: 404 outer code: 403 })"),
            Some(403)
        );
    }

    #[test]
    fn authorization_errors_cover_the_forms_proxies_produce() {
        // capsule-proxy answers a filtered request with BadRequest rather than
        // Forbidden, and losing that mapping would make a proxy's refusal look
        // like an unclassified error.
        for message in [
            FORBIDDEN_RBAC,
            "Unauthorized",
            "BadRequest: filtered",
            "operation is not allowed",
        ] {
            assert!(is_authorization_error(message), "should match: {message}");
        }
        assert!(!is_authorization_error(NOT_FOUND));
    }
}
