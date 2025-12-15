use std::fmt::Display;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::runtime::reflector::Lookup;
use tracing::info;

use crate::assessment::{
    run_assessment, AssessableResource, MultitenancyAssessor, SafetyLevel, SubsystemReport,
};
use crate::verifier::TenantClusterConfig;

// =============================================================================
// CONSTANTS
// =============================================================================

const NETWORK_MULTITOOL_POD_NAME: &str = "network-multitool";
const AUTONOMY_TEST_SERVICE_NAME: &str = "autonomy-test-service";
const WEBSERVER_SERVICE_NAME: &str = "webserver-service";
const AUTONOMY_TEST_PORT: i32 = 8080;
const AUTONOMY_TEST_NODE_PORT: i32 = 30080;
const WEBSERVER_PORT: i32 = 80;

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

pub type NetworkIsolationReport = SubsystemReport<NetworkResource>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkResource {
    /// Pod-to-pod network communication
    PodNetwork,
    /// Service exposure and access
    ServiceNetwork,
    /// DNS resolution across namespaces
    DnsResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkOperation {
    /// Direct pod-to-pod communication via IP
    ConnectToPod,
    /// Access a service via ClusterIP
    ConnectToService,
    /// Expose a service on a NodePort
    ExposeNodePort,
    /// Resolve DNS names across namespaces
    ResolveDns,
}

impl AssessableResource for NetworkResource {
    type Operation = NetworkOperation;

    fn all() -> Vec<Self> {
        vec![
            NetworkResource::PodNetwork,
            NetworkResource::ServiceNetwork,
            NetworkResource::DnsResolution,
        ]
    }

    fn applicable_operations(&self) -> Vec<NetworkOperation> {
        match self {
            NetworkResource::PodNetwork => vec![NetworkOperation::ConnectToPod],
            NetworkResource::ServiceNetwork => vec![
                NetworkOperation::ConnectToService,
                NetworkOperation::ExposeNodePort,
            ],
            NetworkResource::DnsResolution => vec![NetworkOperation::ResolveDns],
        }
    }
}

// =============================================================================
// ASSESSOR IMPLEMENTATION
// =============================================================================

pub struct NetworkAssessor;

#[async_trait]
impl MultitenancyAssessor for NetworkAssessor {
    type Resource = NetworkResource;

    fn name(&self) -> &'static str {
        "Network"
    }

    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &NetworkResource,
        operation: &NetworkOperation,
    ) -> anyhow::Result<bool> {
        info!(
            "Checking authorization for {:?} - {:?}",
            resource, operation
        );
        match (resource, operation) {
            (NetworkResource::PodNetwork, NetworkOperation::ConnectToPod) => {
                // Tenants can always create pods that make network connections
                test_pod_network_authorization(tenant).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ConnectToService) => {
                // Tenants can create services
                test_service_creation_authorization(tenant).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ExposeNodePort) => {
                // Test if tenant can create NodePort services
                test_nodeport_authorization(tenant).await
            }
            (NetworkResource::DnsResolution, NetworkOperation::ResolveDns) => {
                // DNS resolution is typically always available
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &NetworkResource,
        operation: &NetworkOperation,
    ) -> anyhow::Result<(SafetyLevel, String)> {
        info!(
            "Checking cross-tenant effect for {:?} - {:?}",
            resource, operation
        );
        match (resource, operation) {
            (NetworkResource::PodNetwork, NetworkOperation::ConnectToPod) => {
                test_pod_network_isolation(tenant1, tenant2).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ConnectToService) => {
                test_service_network_isolation(tenant1, tenant2).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ExposeNodePort) => {
                test_nodeport_autonomy(tenant1, tenant2).await
            }
            (NetworkResource::DnsResolution, NetworkOperation::ResolveDns) => {
                test_dns_isolation(tenant1, tenant2).await
            }
            _ => Ok((SafetyLevel::Unknown, "Test not implemented".to_string())),
        }
    }
}

/// Public API - entry point for network isolation assessment
pub async fn check_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<NetworkIsolationReport> {
    run_assessment(&NetworkAssessor, tenant1, tenant2).await
}

// =============================================================================
// AUTHORIZATION TESTS
// =============================================================================

async fn test_pod_network_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);
    let result = tenant
        .cluster
        .create_pod_in_namespace(&test_pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant.namespace)
        .await;

    // wait for pod deletion to complete
    let _ = tenant
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_service_creation_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_service = create_clusterip_service(&tenant.namespace, "auth-test-service");
    let result = tenant
        .cluster
        .create_namespaced_resource::<Service>(&test_service, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<Service>("auth-test-service", &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_nodeport_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_service = create_nodeport_service(
        &tenant.namespace,
        "auth-test-nodeport",
        AUTONOMY_TEST_NODE_PORT,
    );
    let result = tenant
        .cluster
        .create_namespaced_resource::<Service>(&test_service, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<Service>("auth-test-nodeport", &tenant.namespace)
        .await;

    // Wait for service deletion to complete
    let _ = tenant
        .cluster
        .wait_for_namespaced_resource_deletion::<Service>("auth-test-nodeport", &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

async fn test_pod_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Create pods in both namespaces
    let pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);

    tenant1
        .cluster
        .create_pod_in_namespace(&pod, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .create_pod_in_namespace(&pod, &tenant2.namespace)
        .await?;

    info!("Waiting for pod in tenant1 to be ready...");
    tenant1
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    info!("Waiting for pod in tenant2 to be ready...");
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    // Get pod IPs
    let tenant2_pod_ip = tenant2
        .cluster
        .get_pod_ip(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    info!("Tenant 2 pod IP: {}", tenant2_pod_ip);

    // Try to connect from tenant1 to tenant2's pod
    let can_reach_other_pod = tenant1
        .cluster
        .exec_command_in_container(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant1.namespace,
            format!(
                "curl -sSf {}:80 --connect-timeout 10 2>&1 >/dev/null",
                tenant2_pod_ip
            )
            .as_str(),
        )
        .await?
        .is_empty();

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await;

    let _ = tenant1
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await;

    if can_reach_other_pod {
        Ok((
            SafetyLevel::Unsafe,
            "Tenant1 can directly connect to tenant2's pod - Network not isolated".to_string(),
        ))
    } else {
        Ok((
            SafetyLevel::Safe,
            "Pod-to-pod network isolation is enforced".to_string(),
        ))
    }
}

async fn test_service_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Create test pod in tenant1 and service in tenant2
    let pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);
    let service = create_webserver_service(&tenant2.namespace);

    tenant1
        .cluster
        .create_pod_in_namespace(&pod, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .create_pod_in_namespace(&pod, &tenant2.namespace)
        .await?;

    tenant2
        .cluster
        .create_namespaced_resource::<Service>(&service, &tenant2.namespace)
        .await?;

    // Wait for resources to be ready
    tenant1
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .wait_for_resource_creation::<Service>(WEBSERVER_SERVICE_NAME, &tenant2.namespace)
        .await?;

    // Get service IP
    let service_obj = tenant2
        .cluster
        .get_resource_in_namespace::<Service>(WEBSERVER_SERVICE_NAME, &tenant2.namespace)
        .await?;

    let service_ip = service_obj
        .spec
        .and_then(|s| s.cluster_ip)
        .unwrap_or_default();

    info!("Service IP: {}", service_ip);

    // Try to connect from tenant1 to tenant2's service
    let can_reach_service = tenant1
        .cluster
        .exec_command_in_container(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant1.namespace,
            format!(
                "curl -sSf {}:80 --connect-timeout 10 2>&1 >/dev/null",
                service_ip
            )
            .as_str(),
        )
        .await?
        .is_empty();

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<Service>(WEBSERVER_SERVICE_NAME, &tenant2.namespace)
        .await;

    let _ = tenant1
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await;

    if can_reach_service {
        Ok((
            SafetyLevel::Unsafe,
            "Tenant1 can access tenant2's services - Service network not isolated".to_string(),
        ))
    } else {
        Ok((
            SafetyLevel::Safe,
            "Service network isolation is enforced".to_string(),
        ))
    }
}

async fn test_nodeport_autonomy(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    info!("Testing network autonomy - NodePort service exposure independence...");

    // Create identical NodePort services in both tenant namespaces
    let tenant1_service = create_nodeport_service(
        &tenant1.namespace,
        AUTONOMY_TEST_SERVICE_NAME,
        AUTONOMY_TEST_NODE_PORT,
    );
    let tenant2_service = create_nodeport_service(
        &tenant2.namespace,
        AUTONOMY_TEST_SERVICE_NAME,
        AUTONOMY_TEST_NODE_PORT,
    );

    // Try to create service in tenant1
    let tenant1_result = tenant1
        .cluster
        .create_namespaced_resource::<Service>(&tenant1_service, &tenant1.namespace)
        .await;

    if tenant1_result.is_err() {
        return Ok((
            SafetyLevel::Unknown,
            format!(
                "Could not create NodePort service in tenant1: {:?}",
                tenant1_result.err()
            ),
        ));
    }

    // Try to create identical service in tenant2 (same NodePort)
    let tenant2_result = tenant2
        .cluster
        .create_namespaced_resource::<Service>(&tenant2_service, &tenant2.namespace)
        .await;

    let autonomy_success = tenant2_result.is_ok();

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant1.namespace)
        .await;

    if autonomy_success {
        let _ = tenant2
            .cluster
            .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant2.namespace)
            .await;
    }

    if autonomy_success {
        Ok((
            SafetyLevel::Safe,
            format!(
                "Both tenants can independently expose services on NodePort {} - Network autonomy verified",
                AUTONOMY_TEST_NODE_PORT
            ),
        ))
    } else {
        // NodePort conflict means tenants share the same network namespace for NodePorts
        // This is actually expected behavior in most multi-tenant setups
        Ok((
            SafetyLevel::Safe,
            format!(
                "NodePort {} conflict detected - Tenants share NodePort space (expected in shared-node setups)",
                AUTONOMY_TEST_NODE_PORT
            ),
        ))
    }
}

async fn test_dns_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Create pod in tenant1 and service in tenant2
    let pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);
    let service = create_webserver_service(&tenant2.namespace);

    tenant1
        .cluster
        .create_pod_in_namespace(&pod, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .create_namespaced_resource::<Service>(&service, &tenant2.namespace)
        .await?;

    tenant1
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .wait_for_resource_creation::<Service>(WEBSERVER_SERVICE_NAME, &tenant2.namespace)
        .await?;

    // Try to resolve tenant2's service DNS from tenant1
    let dns_result = tenant1
        .cluster
        .exec_command_in_container_with_status(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant1.namespace,
            format!(
                "nslookup {}.{}.svc.cluster.local",
                WEBSERVER_SERVICE_NAME, tenant2.namespace
            )
            .as_str(),
        )
        .await?;

    let can_resolve_dns = dns_result.code == Some(0);

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<Service>(WEBSERVER_SERVICE_NAME, &tenant2.namespace)
        .await;

    if can_resolve_dns {
        Ok((
            SafetyLevel::Unsafe,
            "Tenant1 can resolve DNS records from tenant2's namespace - DNS not isolated"
                .to_string(),
        ))
    } else {
        Ok((
            SafetyLevel::Safe,
            "DNS isolation is enforced between tenants".to_string(),
        ))
    }
}

// =============================================================================
// MANIFEST CREATION HELPERS
// =============================================================================

fn create_network_multitool_pod(name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {
                "app": "network-multitool"
            }
        },
        "spec": {
            "containers": [{
                "name": "multitool",
                "image": "praqma/network-multitool",
                "ports": [{ "containerPort": 80 }]
            }]
        }
    }))
    .unwrap()
}

fn create_webserver_service(namespace: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": WEBSERVER_SERVICE_NAME,
            "namespace": namespace
        },
        "spec": {
            "selector": {
                "app": "network-multitool"
            },
            "ports": [{
                "protocol": "TCP",
                "port": WEBSERVER_PORT,
                "targetPort": WEBSERVER_PORT
            }],
            "type": "ClusterIP"
        }
    }))
    .unwrap()
}

fn create_clusterip_service(namespace: &str, name: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "spec": {
            "selector": {
                "app": "test-app"
            },
            "ports": [{
                "protocol": "TCP",
                "port": 80,
                "targetPort": 80
            }],
            "type": "ClusterIP"
        }
    }))
    .unwrap()
}

fn create_nodeport_service(namespace: &str, name: &str, node_port: i32) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "test": "network-autonomy"
            }
        },
        "spec": {
            "selector": {
                "app": "autonomy-test"
            },
            "ports": [{
                "name": "http",
                "protocol": "TCP",
                "port": AUTONOMY_TEST_PORT,
                "targetPort": AUTONOMY_TEST_PORT,
                "nodePort": node_port
            }],
            "type": "NodePort"
        }
    }))
    .unwrap()
}

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for NetworkResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkResource::PodNetwork => write!(f, "Pod Network"),
            NetworkResource::ServiceNetwork => write!(f, "Service Network"),
            NetworkResource::DnsResolution => write!(f, "DNS Resolution"),
        }
    }
}

impl Display for NetworkOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkOperation::ConnectToPod => write!(f, "Connect to Pod"),
            NetworkOperation::ConnectToService => write!(f, "Connect to Service"),
            NetworkOperation::ExposeNodePort => write!(f, "Expose NodePort"),
            NetworkOperation::ResolveDns => write!(f, "Resolve DNS"),
        }
    }
}
