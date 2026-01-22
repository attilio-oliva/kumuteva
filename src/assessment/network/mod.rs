mod fairness;
pub use fairness::*;

use std::fmt::Display;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Pod, Service};
use tracing::info;

use crate::assessment::{
    run_assessment, AssessableResource, CrossTenantResult, IsolationLevel, MultitenancyAssessor,
    SubsystemReport,
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
    ) -> anyhow::Result<CrossTenantResult> {
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
            _ => Ok(CrossTenantResult {
                isolation: IsolationLevel::Unknown,
                autonomy: true,
                details: "Test not implemented".to_string(),
            }),
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
    // Use auto-assigned nodePort (0 or omit) to test if tenant can create NodePort services at all,
    // rather than testing if a specific port is available
    let test_service = create_nodeport_service_auto_port(&tenant.namespace, "auth-test-nodeport");
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
) -> anyhow::Result<CrossTenantResult> {
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
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "Tenant1 can directly connect to tenant2's pod - Network not isolated"
                .to_string(),
        })
    } else {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "Pod-to-pod network isolation is enforced".to_string(),
        })
    }
}

async fn test_service_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
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
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "Tenant1 can access tenant2's services - Service network not isolated"
                .to_string(),
        })
    } else {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "Service network isolation is enforced".to_string(),
        })
    }
}

async fn test_nodeport_autonomy(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
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
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Could not create NodePort service in tenant1: {:?}",
                tenant1_result.err()
            ),
        });
    }

    // Try to create identical service in tenant2 (same NodePort)
    let tenant2_result = tenant2
        .cluster
        .create_namespaced_resource::<Service>(&tenant2_service, &tenant2.namespace)
        .await;

    let hard_isolation = tenant2_result.is_ok();

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant1.namespace)
        .await;

    if hard_isolation {
        let _ = tenant2
            .cluster
            .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant2.namespace)
            .await;
    }

    // Wait for cleanup
    let _ = tenant1
        .cluster
        .wait_for_namespaced_resource_deletion::<Service>(
            AUTONOMY_TEST_SERVICE_NAME,
            &tenant1.namespace,
        )
        .await;

    if hard_isolation {
        let _ = tenant2
            .cluster
            .wait_for_namespaced_resource_deletion::<Service>(
                AUTONOMY_TEST_SERVICE_NAME,
                &tenant2.namespace,
            )
            .await;
    }

    if hard_isolation {
        // Both tenants can create NodePort on same port - full isolation (separate network namespaces)
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: format!(
                "Both tenants can independently expose services on NodePort {} - Full network autonomy",
                AUTONOMY_TEST_NODE_PORT
            ),
        })
    } else {
        // NodePort conflict - tenants share the NodePort space
        // Check if the error is due to port conflict
        let error_msg = tenant2_result
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();

        if error_msg.contains("already allocated")
            || error_msg.contains("port is already allocated")
            || error_msg.contains("nodePort")
        {
            // Port collision detected - partial autonomy
            Ok(CrossTenantResult {
                isolation: IsolationLevel::Soft(format!(
                    "NodePort {} shared across tenants",
                    AUTONOMY_TEST_NODE_PORT
                )),
                autonomy: true, // They can still create services, just not on the same port (soft isolation)
                details: format!(
                    "NodePort {} collision detected - Tenants share NodePort space, may conflict with each other",
                    AUTONOMY_TEST_NODE_PORT
                ),
            })
        } else {
            // Some other error
            Ok(CrossTenantResult {
                isolation: IsolationLevel::Unknown,
                autonomy: false,
                details: format!("NodePort creation failed for tenant2: {}", error_msg),
            })
        }
    }
}

async fn test_dns_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Create pod in tenant1 and service in tenant2
    let pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);
    let service = create_webserver_service(&tenant1.namespace);

    tenant1
        .cluster
        .create_namespaced_resource::<Service>(&service, &tenant1.namespace)
        .await?;
    tenant1
        .cluster
        .wait_for_resource_creation::<Service>(WEBSERVER_SERVICE_NAME, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .create_pod_in_namespace(&pod, &tenant2.namespace)
        .await?;
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    // Try to resolve tenant1's service DNS from tenant2
    let dns_query = format!(
        "nslookup {}.{}.svc.cluster.local",
        WEBSERVER_SERVICE_NAME, tenant1.namespace
    );
    info!("DNS isolation test: querying '{}' from tenant2", dns_query);

    // Capture the output and check if an IP address was resolved
    let dns_output = tenant2
        .cluster
        .exec_command_in_container(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant2.namespace,
            &format!("{} 2>&1 || true", dns_query),
        )
        .await
        .unwrap_or_else(|e| format!("Failed to get output: {}", e));

    info!("DNS query output: {}", dns_output);

    // Check if the output contains "Address:" after the "Name:" line (indicating successful resolution)
    // nslookup output format when successful:
    //   Server: ...
    //   Address: ... (DNS server address)
    //   Name: service.namespace.svc.cluster.local
    //   Address: ... (resolved IP - this is what we're looking for)
    let can_resolve_dns = dns_output.contains("Name:") && {
        // Find the part after "Name:" and check if there's an "Address:" line after it
        if let Some(name_pos) = dns_output.find("Name:") {
            dns_output[name_pos..].contains("Address:")
        } else {
            false
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<Service>(WEBSERVER_SERVICE_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await;

    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await;

    if can_resolve_dns {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "Tenant1 can resolve DNS records from tenant2's namespace - DNS not isolated"
                .to_string(),
        })
    } else {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "DNS isolation is enforced between tenants".to_string(),
        })
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

/// Creates a NodePort service with auto-assigned port (Kubernetes chooses the port).
/// This is useful for authorization tests where we only care if NodePort services
/// can be created, not whether a specific port is available.
fn create_nodeport_service_auto_port(namespace: &str, name: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "test": "network-authorization"
            }
        },
        "spec": {
            "selector": {
                "app": "auth-test"
            },
            "ports": [{
                "name": "http",
                "protocol": "TCP",
                "port": AUTONOMY_TEST_PORT,
                "targetPort": AUTONOMY_TEST_PORT
                // nodePort omitted - Kubernetes will auto-assign from available range
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
