mod fairness;

pub use fairness::*;

use std::fmt::Display;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Pod, Service};
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

const NETWORK_MULTITOOL_POD_NAME: &str = "network-multitool";
const AUTONOMY_TEST_SERVICE_NAME: &str = "autonomy-test-service";
const WEBSERVER_SERVICE_NAME: &str = "webserver-service";
const AUTONOMY_TEST_PORT: i32 = 8080;
const AUTONOMY_TEST_NODE_PORT: i32 = 30080;
/// Unprivileged, so the probe can serve without running as root.
///
/// A port below 1024 needs CAP_NET_BIND_SERVICE, which the `restricted` Pod
/// Security Standard forbids. A tenant configured to that standard — which is
/// the whole point of the `capsule-hardened` target — would refuse the probe
/// pod outright, and the reachability question would go unmeasured for the
/// solutions that are most interesting to measure.
///
/// The port number is not itself under test: the NetworkPolicies this
/// subsystem exercises select on pods and namespaces and carry no `ports`
/// block, so reachability on 8080 asks exactly the question reachability on 80
/// did.
const WEBSERVER_PORT: i32 = 8080;

/// How long a target is given to answer itself before the probe is declared
/// broken and the result Unknown.
///
/// This is a bound on the *whole* positive control, not on one attempt, because
/// the exec beneath it does its own retrying and nested budgets multiply.
const POSITIVE_CONTROL_BUDGET: tokio::time::Duration = tokio::time::Duration::from_secs(30);

// Infrastructure network test constants
const NODE_MARKER_POD_NAME: &str = "node-marker-service";
const NODE_MARKER_PORT: i32 = 31337;
const NODE_PROBE_POD_NAME: &str = "node-network-probe";

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

#[allow(dead_code)]
pub type NetworkIsolationReport = SubsystemReport<NetworkResource>;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkResource {
    /// Pod-to-pod network communication
    PodNetwork,
    /// Service exposure and access
    ServiceNetwork,
    /// Node-to-node network communication
    /// Currently not tested separately, as it overlaps with NodePort tests
    InfrastructureNetwork,
    /// DNS resolution across namespaces
    DnsResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkOperation {
    /// Direct pod-to-pod communication via IP
    ConnectToPod,
    /// Access a service via ClusterIP
    ConnectToService,
    /// Reach a node via its IP
    ConnectToNode,
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
            // Removed as it is redundant with NodePort tests
            // NetworkResource::InfrastructureNetwork,
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
            NetworkResource::InfrastructureNetwork => vec![NetworkOperation::ConnectToNode],
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
            (NetworkResource::InfrastructureNetwork, NetworkOperation::ConnectToNode) => {
                test_node_network_authorization(tenant).await
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
            (NetworkResource::InfrastructureNetwork, NetworkOperation::ConnectToNode) => {
                test_node_network_isolation(tenant1, tenant2).await
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
#[allow(dead_code)]
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

async fn test_node_network_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let pod_name = "auth-test-hostnetwork";
    let pod = create_host_network_pod(pod_name);

    let result = tenant
        .cluster
        .create_pod_in_namespace(&pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(pod_name, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

/// Puts a probe pod to a tenant's API server, separating "the cluster said no"
/// from "the run broke".
///
/// `Ok(None)` means the pod was admitted. `Ok(Some(result))` means it was
/// refused, and carries the finding to return in place of a measurement. Only a
/// genuine fault — the server unreachable, a malformed object — comes back as
/// `Err`.
///
/// The refusal is recorded as [`IsolationLevel::Hard`] because an operation the
/// tenant cannot perform at all is the strongest isolation this methodology
/// recognises, and `autonomy: false` because being unable to run a pod of one's
/// own is precisely a loss of autonomy. Both halves matter: reporting only the
/// isolation would make a tenant that can do nothing look ideal.
async fn admit_probe_pod(
    tenant: &TenantClusterConfig,
    pod: &Pod,
    what: &str,
) -> anyhow::Result<Option<CrossTenantResult>> {
    match tenant
        .cluster
        .create_pod_in_namespace(pod, &tenant.namespace)
        .await
    {
        Ok(_) => Ok(None),
        Err(error) => match crate::assessment::admission_refusal(&error) {
            Some(message) => {
                info!("{} refused in {}: {}", what, tenant.namespace, message);
                Ok(Some(CrossTenantResult {
                    isolation: IsolationLevel::Hard,
                    autonomy: false,
                    details: format!(
                        "{} could not be created in {}, so the effect could not be \
                         observed. The cluster refused it: {}",
                        what, tenant.namespace, message
                    ),
                }))
            }
            None => Err(error),
        },
    }
}

/// Delete these probe pods, whatever happened to the body.
///
/// Rust has no async `Drop`, so a guard cannot do this; the discipline is to
/// run the body to completion, clean up, and only then return its result.
///
/// Not merely tidy. Probe pods use fixed names, so one left behind makes the
/// next test's create fail with `AlreadyExists` — which is neither an admission
/// refusal nor a measurement, and aborts the whole assessment. The tests below
/// used to return early when a probe was refused, leaking any pod already
/// created in the *other* tenant, so a hardened tenant refusing one probe could
/// take out an unrelated subsystem several tests later.
async fn cleanup_probes(pods: &[(&TenantClusterConfig, &str)]) {
    for (tenant, name) in pods {
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(name, &tenant.namespace)
            .await;
    }
    for (tenant, name) in pods {
        let _ = tenant
            .cluster
            .wait_for_pod_deletion(name, &tenant.namespace)
            .await;
    }
}

async fn test_pod_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // The probes are cleaned up on every path out of the body — including the
    // early returns for a refused probe, which previously leaked whichever pod
    // had already been created in the other tenant.
    let outcome = pod_network_isolation_body(tenant1, tenant2).await;
    cleanup_probes(&[
        (tenant1, NETWORK_MULTITOOL_POD_NAME),
        (tenant2, NETWORK_MULTITOOL_POD_NAME),
    ])
    .await;
    outcome
}

async fn pod_network_isolation_body(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Create pods in both namespaces
    let pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);

    if let Some(refused) = admit_probe_pod(tenant1, &pod, "the tenant1 network probe").await? {
        return Ok(refused);
    }
    if let Some(refused) = admit_probe_pod(tenant2, &pod, "the tenant2 network probe").await? {
        return Ok(refused);
    }

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

    // Positive control, as in the service test. `Ready` is the kubelet
    // reporting that the container started, which is not the same as the
    // server inside it having bound its port. The window is narrower here than
    // for a Service — no endpoint controller is involved — but a refused
    // connection would be read as isolation just the same, so the target is
    // required to answer itself before its silence is allowed to mean
    // anything.
    if !service_answers(tenant2, &tenant2_pod_ip).await {
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "tenant2's own probe pod at {tenant2_pod_ip} never answered from \
                 inside {}, so there was nothing established to reach and a \
                 failure from tenant1 would prove nothing.",
                tenant2.namespace
            ),
        });
    }

    // Try to connect from tenant1 to tenant2's pod
    let can_reach_other_pod = tenant1
        .cluster
        .exec_command_in_container(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant1.namespace,
            format!(
                "curl -sSf {}:{WEBSERVER_PORT} --connect-timeout 10 2>&1 >/dev/null",
                tenant2_pod_ip
            )
            .as_str(),
        )
        .await?
        .is_empty();

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

/// Whether a tenant's own service answers from inside its own namespace.
///
/// The positive control for every cross-tenant service check. A pod being
/// `Ready` does not mean its Service has endpoints yet: readiness is reported
/// by the kubelet, while endpoint propagation is a separate controller writing
/// to a separate object, and the gap between them is exactly wide enough for a
/// curl to land in. Polling until the service answers closes that gap without
/// guessing at a fixed sleep.
///
/// Retries for roughly thirty seconds. A service that has not answered its own
/// namespace by then is not slow, it is broken.
async fn service_answers(tenant: &TenantClusterConfig, service_ip: &str) -> bool {
    let probe =
        format!("curl -sSf {service_ip}:{WEBSERVER_PORT} --connect-timeout 2 2>&1 >/dev/null");

    // A wall-clock deadline rather than a count of attempts.
    //
    // Counting attempts looks bounded and is not: each `exec_command_in_container`
    // retries internally three times with its own waits, so fifteen attempts here
    // multiply out to forty-five execs. Against a target that never answers —
    // exactly the case worth waiting on — that is minutes per probe, twice per
    // subsystem. A campaign spent them looking hung.
    //
    // Thirty seconds is what this is actually waiting for: the gap between the
    // kubelet reporting a pod Ready and the endpoint controller publishing it.
    // Longer than that is not slow propagation, it is a service that will not
    // answer.
    let deadline = tokio::time::Instant::now() + POSITIVE_CONTROL_BUDGET;
    let mut attempt = 0;

    while tokio::time::Instant::now() < deadline {
        attempt += 1;
        let answered = tenant
            .cluster
            .exec_command_in_container(NETWORK_MULTITOOL_POD_NAME, &tenant.namespace, &probe)
            .await
            .map(|output| output.is_empty())
            .unwrap_or(false);
        if answered {
            info!(
                "service {} answers from inside {} (attempt {})",
                service_ip, tenant.namespace, attempt
            );
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    info!(
        "service {} never answered from inside {} within {:?} ({} attempts)",
        service_ip, tenant.namespace, POSITIVE_CONTROL_BUDGET, attempt
    );
    false
}

async fn test_service_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Cleanup runs even when a probe is refused or the positive control fails.
    let outcome = test_service_network_isolation_body(tenant1, tenant2).await;
    cleanup_probes(&[
        (tenant1, NETWORK_MULTITOOL_POD_NAME),
        (tenant2, NETWORK_MULTITOOL_POD_NAME),
    ])
    .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<Service>(WEBSERVER_SERVICE_NAME, &tenant2.namespace)
        .await;
    outcome
}

async fn test_service_network_isolation_body(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Create test pod in tenant1 and service in tenant2
    let pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);
    let service = create_webserver_service(&tenant2.namespace);

    if let Some(refused) = admit_probe_pod(tenant1, &pod, "the tenant1 service probe").await? {
        return Ok(refused);
    }
    if let Some(refused) = admit_probe_pod(tenant2, &pod, "the tenant2 service backend").await? {
        return Ok(refused);
    }

    tenant2
        .cluster
        .create_namespaced_resource::<Service>(&service, &tenant2.namespace)
        .await?;

    // Wait for resources to be ready
    tenant1
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    // The backend, not just the client.
    //
    // Its absence was a real defect rather than an oversight: the test waited
    // for the *Service object* to exist, which says nothing about whether
    // anything is behind it. A curl issued before the backing pod was serving
    // got connection-refused, and the code below read that as proof of
    // isolation. The failure therefore appeared and disappeared between runs
    // and always in the reassuring direction.
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
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

    // Positive control, before the cross-tenant attempt means anything.
    //
    // "Nobody answered" and "the network refused me" look identical from the
    // client, and only one of them is isolation. So the service is first
    // required to answer from inside its own namespace. If it will not, the
    // probe is broken and the honest verdict is Unknown — reporting Hard there
    // would let every startup race, image pull and scheduling delay masquerade
    // as an isolation guarantee.
    let serving = service_answers(tenant2, &service_ip).await;
    if !serving {
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "tenant2's own service at {service_ip} never answered from inside \
                 {}, so it was never established that there was anything to reach. \
                 A failure from tenant1 would prove nothing.",
                tenant2.namespace
            ),
        });
    }

    // Try to connect from tenant1 to tenant2's service
    let can_reach_service = tenant1
        .cluster
        .exec_command_in_container(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant1.namespace,
            format!(
                "curl -sSf {}:{WEBSERVER_PORT} --connect-timeout 10 2>&1 >/dev/null",
                service_ip
            )
            .as_str(),
        )
        .await?
        .is_empty();

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
    info!("Testing NodePort isolation - can tenant2 reach tenant1's NodePort service?");

    // Generate a unique marker to identify tenant1's service
    let marker = format!("TENANT1_NODEPORT_MARKER_{}", uuid::Uuid::new_v4());
    info!("Generated NodePort marker for tenant1: {}", marker);

    // 1. Create a pod in tenant1 that serves the marker
    let marker_pod = create_nodeport_marker_pod("nodeport-marker-pod", &marker);

    let create_pod_result = tenant1
        .cluster
        .create_pod_in_namespace(&marker_pod, &tenant1.namespace)
        .await;

    if create_pod_result.is_err() {
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Could not create marker pod in tenant1: {:?}",
                create_pod_result.err()
            ),
        });
    }

    // Wait for pod to be ready
    if let Err(e) = tenant1
        .cluster
        .wait_for_pod_to_be_ready("nodeport-marker-pod", &tenant1.namespace)
        .await
    {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!("Tenant1 marker pod failed to start: {}", e),
        });
    }

    // 2. Create NodePort service pointing to the marker pod
    let tenant1_service = create_nodeport_service_with_selector(
        &tenant1.namespace,
        AUTONOMY_TEST_SERVICE_NAME,
        AUTONOMY_TEST_NODE_PORT,
        "nodeport-marker",
    );

    let create_svc_result = tenant1
        .cluster
        .create_namespaced_resource::<Service>(&tenant1_service, &tenant1.namespace)
        .await;

    if create_svc_result.is_err() {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Could not create NodePort service in tenant1: {:?}",
                create_svc_result.err()
            ),
        });
    }

    // 3. Try to get node IP - first try listing nodes, fall back to hostNetwork pod
    let node_ip = get_node_ip_for_nodeport_test(tenant1, tenant2).await?;

    if node_ip.is_empty() {
        cleanup_nodeport_test_resources(tenant1, tenant2).await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: "Could not determine node IP for NodePort test".to_string(),
        });
    }

    info!(
        "Probing tenant1's NodePort service at {}:{}",
        node_ip, AUTONOMY_TEST_NODE_PORT
    );

    // 4. Create probe pod in tenant2 (regular pod, not hostNetwork)
    let probe_pod = create_network_multitool_pod("nodeport-probe");

    let create_probe_result = tenant2
        .cluster
        .create_pod_in_namespace(&probe_pod, &tenant2.namespace)
        .await;

    if create_probe_result.is_err() {
        // Cleanup tenant1 resources
        let _ = tenant1
            .cluster
            .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant1.namespace)
            .await;
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
            .await;

        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Could not create probe pod in tenant2: {:?}",
                create_probe_result.err()
            ),
        });
    }

    // Wait for probe pod to be ready
    if let Err(e) = tenant2
        .cluster
        .wait_for_pod_to_be_ready("nodeport-probe", &tenant2.namespace)
        .await
    {
        // Cleanup
        cleanup_nodeport_test_resources(tenant1, tenant2).await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!("Tenant2 probe pod failed to start: {}", e),
        });
    }

    // 5. Probe tenant1's NodePort from tenant2
    let probe_cmd = format!(
        "curl -s --connect-timeout 5 http://{}:{} 2>/dev/null || wget -q -O - --timeout=5 http://{}:{} 2>/dev/null || echo 'CONNECTION_FAILED'",
        node_ip, AUTONOMY_TEST_NODE_PORT, node_ip, AUTONOMY_TEST_NODE_PORT
    );

    let probe_output = tenant2
        .cluster
        .exec_command_in_container("nodeport-probe", &tenant2.namespace, &probe_cmd)
        .await
        .unwrap_or_else(|e| format!("Exec failed: {}", e));

    info!("NodePort probe output from tenant2: {}", probe_output);

    let marker_found = probe_output.contains(&marker);
    let connection_failed =
        probe_output.contains("CONNECTION_FAILED") || probe_output.contains("Exec failed");

    // 6. Test autonomy: can tenant2 create a NodePort on the same port?
    let tenant2_service = create_nodeport_service(
        &tenant2.namespace,
        AUTONOMY_TEST_SERVICE_NAME,
        AUTONOMY_TEST_NODE_PORT,
    );

    let tenant2_svc_result = tenant2
        .cluster
        .create_namespaced_resource::<Service>(&tenant2_service, &tenant2.namespace)
        .await;

    let can_use_same_port = tenant2_svc_result.is_ok();

    // Cleanup all resources
    cleanup_nodeport_test_resources(tenant1, tenant2).await;

    let isolation = if can_use_same_port {
        IsolationLevel::Hard
    } else {
        IsolationLevel::Soft("NodePort unreachable but cannot use same port".to_string())
    };

    // Determine isolation level based on results
    // Note: autonomy is true as long as the test could be performed (tenant2 can create NodePort services)
    // The port collision only affects whether they can use the SAME port number, not overall capability
    if marker_found {
        // Tenant2 can reach tenant1's NodePort and read the marker - no isolation
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true, // Tenant2 was able to perform the operation
            details: format!(
                "Tenant2 successfully connected to tenant1 service via NodePort at {}:{} - \
                NodePort traffic not isolated between tenants. - {}",
                node_ip,
                AUTONOMY_TEST_NODE_PORT,
                if can_use_same_port {
                    "Both tenants can use same NodePort (separate port spaces)."
                } else {
                    "Tenants share NodePort space (port collision on same port number)."
                }
            ),
        })
    } else if connection_failed {
        // Tenant2 cannot reach the NodePort at all
        Ok(CrossTenantResult {
            isolation,
            autonomy: true, // Tenant2 can create NodePort services, traffic is just isolated
            details: format!(
                "Tenant2 cannot reach tenant1's NodePort at {}:{} - NodePort traffic isolated. {}",
                node_ip,
                AUTONOMY_TEST_NODE_PORT,
                if can_use_same_port {
                    "Both tenants can use same NodePort independently"
                } else {
                    "Tenants share NodePort space (cannot use same port) but traffic is isolated."
                }
            ),
        })
    } else {
        // Connection succeeded but marker not found - might be different service or proxy
        Ok(CrossTenantResult {
            isolation,
            autonomy: true,
            details: format!(
                "Tenant2 endpoint reached {}:{} but received unexpected response: '{}' - \
                We assume it is a different service or proxy - {}",
                node_ip,
                AUTONOMY_TEST_NODE_PORT,
                probe_output.chars().take(100).collect::<String>(),
                if can_use_same_port {
                    "Both tenants can use same NodePort."
                } else {
                    "Tenants share NodePort space."
                }
            ),
        })
    }
}

/// Helper to cleanup NodePort test resources
async fn cleanup_nodeport_test_resources(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) {
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant1.namespace)
        .await;
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant2.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace("nodeport-probe", &tenant2.namespace)
        .await;

    // Wait for cleanup
    let _ = tenant1
        .cluster
        .wait_for_namespaced_resource_deletion::<Service>(
            AUTONOMY_TEST_SERVICE_NAME,
            &tenant1.namespace,
        )
        .await;
    let _ = tenant1
        .cluster
        .wait_for_pod_deletion("nodeport-marker-pod", &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion("nodeport-probe", &tenant2.namespace)
        .await;
}

/// Helper to get a node IP for NodePort testing.
/// First tries to list nodes (preferred), falls back to pod status.hostIP if forbidden.
async fn get_node_ip_for_nodeport_test(
    tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<String> {
    // Try to list nodes first (preferred method)
    if let Ok(nodes) = tenant1.cluster.list_nodes().await {
        if let Some(node_ip) = nodes.iter().find_map(|n| {
            n.status.as_ref().and_then(|s| {
                s.addresses.as_ref().and_then(|addrs| {
                    addrs
                        .iter()
                        .find(|a| a.type_ == "InternalIP")
                        .map(|a| a.address.clone())
                })
            })
        }) {
            info!("Got node IP from node listing: {}", node_ip);
            return Ok(node_ip);
        }
    }

    // Fallback: get node IP from the marker pod's status.hostIP
    // This tells us which node the pod is running on
    info!("Node listing not available, getting node IP from pod status.hostIP...");
    if let Ok(pod) = tenant1
        .cluster
        .get_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
        .await
    {
        if let Some(host_ip) = pod.status.and_then(|s| s.host_ip) {
            info!("Got node IP from pod status.hostIP: {}", host_ip);
            return Ok(host_ip);
        }
    }

    // Last resort: try to get the default gateway from within the pod
    // This might work in some setups where hostIP is not populated
    info!("hostIP not available, trying to get default gateway from pod...");
    let get_gateway_cmd = "ip route | grep default | awk '{print $3}'";
    let gateway_ip = tenant1
        .cluster
        .exec_command_in_container("nodeport-marker-pod", &tenant1.namespace, get_gateway_cmd)
        .await
        .unwrap_or_default()
        .trim()
        .to_string();

    if !gateway_ip.is_empty() {
        info!("Got gateway IP from pod: {}", gateway_ip);
        return Ok(gateway_ip);
    }

    Ok(String::new())
}

/// Helper to get a node IP for infrastructure network testing.
/// First tries to list nodes (preferred), falls back to hostNetwork pod discovery if forbidden.
async fn get_node_ip_for_infra_test(
    tenant1: &TenantClusterConfig,
    marker_pod_name: &str,
) -> anyhow::Result<String> {
    // Try to list nodes first (preferred method)
    if let Ok(nodes) = tenant1.cluster.list_nodes().await {
        if let Some(node_ip) = nodes.iter().find_map(|n| {
            n.status.as_ref().and_then(|s| {
                s.addresses.as_ref().and_then(|addrs| {
                    addrs
                        .iter()
                        .find(|a| a.type_ == "InternalIP")
                        .map(|a| a.address.clone())
                })
            })
        }) {
            info!("Got node IP from node listing: {}", node_ip);
            return Ok(node_ip);
        }
    }

    // Fallback: discover node IP from within the hostNetwork marker pod
    info!("Node listing not available, discovering node IP from hostNetwork pod...");
    let get_node_ip_cmd =
        r#"ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'"#;
    let node_ip = tenant1
        .cluster
        .exec_command_in_container(marker_pod_name, &tenant1.namespace, get_node_ip_cmd)
        .await
        .unwrap_or_default()
        .trim()
        .to_string();

    if !node_ip.is_empty() {
        info!("Got node IP from hostNetwork pod: {}", node_ip);
    }

    Ok(node_ip)
}

async fn test_dns_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Cleanup runs even when the tenant2 probe is refused.
    let outcome = test_dns_isolation_body(tenant1, tenant2).await;
    cleanup_probes(&[(tenant2, NETWORK_MULTITOOL_POD_NAME)]).await;
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<Service>(WEBSERVER_SERVICE_NAME, &tenant1.namespace)
        .await;
    outcome
}

async fn test_dns_isolation_body(
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

    if let Some(refused) = admit_probe_pod(tenant2, &pod, "the tenant2 DNS probe").await? {
        return Ok(refused);
    }
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

/// Tests infrastructure network isolation using a marker-based approach.
///
/// This test verifies if tenant2 can bypass cluster network isolation by accessing
/// a tenant1 service through the underlying node network (using hostNetwork pods).
///
/// Methodology:
/// 1. Tenant1 creates a hostNetwork pod that listens on a specific port and responds
///    with a unique marker string - this is the "observable state" owned by tenant1
/// 2. Tenant2 creates a hostNetwork pod and attempts to reach tenant1's marker service
///    via the node's internal IP
/// 3. If tenant2 can read tenant1's marker, it proves:
///    a) They share the same underlying node infrastructure
///    b) Tenant2 can bypass cluster network isolation via the node network
///
/// This aligns with the assessment methodology: we create a tenant-owned observable
/// state (the marker) and verify if another tenant can observe/access it.
async fn test_node_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Generate a unique marker that identifies tenant1's service
    let marker = format!("TENANT1_NODE_MARKER_{}", uuid::Uuid::new_v4());
    info!("Generated marker for tenant1: {}", marker);

    // 1. Create marker service pod in tenant1 (hostNetwork to bind to node's port)
    let marker_pod = create_node_marker_pod(NODE_MARKER_POD_NAME, &marker, NODE_MARKER_PORT);

    let create_marker_result = tenant1
        .cluster
        .create_pod_in_namespace(&marker_pod, &tenant1.namespace)
        .await;

    if create_marker_result.is_err() {
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false,
            details:
                "Tenant1 cannot create hostNetwork pod - infrastructure network test not applicable"
                    .to_string(),
        });
    }

    // Wait for marker pod to be ready
    if let Err(e) = tenant1
        .cluster
        .wait_for_pod_to_be_ready(NODE_MARKER_POD_NAME, &tenant1.namespace)
        .await
    {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!("Tenant1 marker pod failed to start: {}", e),
        });
    }

    // Get node IP - try listing nodes first, fall back to discovering from hostNetwork pod
    let node_ip = get_node_ip_for_infra_test(tenant1, NODE_MARKER_POD_NAME).await?;

    if node_ip.is_empty() {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: "Could not determine node IP for infrastructure network test".to_string(),
        });
    }

    info!("Tenant1 marker service running on node IP: {}", node_ip);

    // 2. Create probe pod in tenant2 (hostNetwork to access node network)
    let probe_pod = create_host_network_pod(NODE_PROBE_POD_NAME);

    let create_probe_result = tenant2
        .cluster
        .create_pod_in_namespace(&probe_pod, &tenant2.namespace)
        .await;

    if create_probe_result.is_err() {
        // Cleanup tenant1's marker pod
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;

        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false,
            details: "Tenant2 cannot create hostNetwork pod - isolation enforced by policy"
                .to_string(),
        });
    }

    // Wait for probe pod to be ready
    if let Err(e) = tenant2
        .cluster
        .wait_for_pod_to_be_ready(NODE_PROBE_POD_NAME, &tenant2.namespace)
        .await
    {
        // Cleanup
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;
        let _ = tenant2
            .cluster
            .delete_pod_in_namespace(NODE_PROBE_POD_NAME, &tenant2.namespace)
            .await;

        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false,
            details: format!("Tenant2 probe pod failed to start: {}", e),
        });
    }

    // 3. Try to read tenant1's marker from tenant2's probe pod
    let probe_cmd = format!(
        "wget -q -O - --timeout=5 http://{}:{} 2>/dev/null || curl -s --connect-timeout 5 http://{}:{} 2>/dev/null || echo 'CONNECTION_FAILED'",
        node_ip, NODE_MARKER_PORT, node_ip, NODE_MARKER_PORT
    );

    let probe_output = tenant2
        .cluster
        .exec_command_in_container(NODE_PROBE_POD_NAME, &tenant2.namespace, &probe_cmd)
        .await
        .unwrap_or_else(|e| format!("Exec failed: {}", e));

    info!("Probe output from tenant2: {}", probe_output);

    // Check if tenant2 successfully read tenant1's marker
    let marker_found = probe_output.contains(&marker);

    // Cleanup both pods
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(NODE_PROBE_POD_NAME, &tenant2.namespace)
        .await;
    let _ = tenant1
        .cluster
        .wait_for_pod_deletion(NODE_MARKER_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(NODE_PROBE_POD_NAME, &tenant2.namespace)
        .await;

    if marker_found {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: format!(
                "Tenant2 successfully connected to tenant1 service via node network at {}:{} - \
                Infrastructure network is shared and can be used to bypass cluster network isolation",
                node_ip, NODE_MARKER_PORT
            ),
        })
    } else if probe_output.contains("CONNECTION_FAILED") || probe_output.contains("Exec failed") {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: format!(
                "Tenant2 cannot reach tenant1's node service at {}:{} - \
                Infrastructure network is isolated (different nodes or network policies in place)",
                node_ip, NODE_MARKER_PORT
            ),
        })
    } else {
        // Connection succeeded but marker not found - unexpected response
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft("Partial infrastructure sharing detected".to_string()),
            autonomy: true,
            details: format!(
                "Tenant2 reached {}:{} but received unexpected response: '{}' - \
                May indicate different service or NAT/proxy in between",
                node_ip,
                NODE_MARKER_PORT,
                probe_output.chars().take(100).collect::<String>()
            ),
        })
    }
}

// =============================================================================
// MANIFEST CREATION HELPERS
// =============================================================================

/// Serves `marker` over HTTP on [`WEBSERVER_PORT`], without needing root.
///
/// The image's own entrypoint cannot be used unprivileged: it rewrites
/// `/etc/nginx/nginx.conf` and `/usr/share/nginx/html/index.html` at startup and
/// dies on permission errors as a non-root user. Overriding the command skips
/// it entirely, and busybox `httpd` serves a directory under `/tmp`, which is
/// writable by any UID.
fn unprivileged_http_server_command(marker: &str) -> String {
    format!(
        "mkdir -p /tmp/www && printf '%s' '{}' > /tmp/www/index.html && \
         httpd -f -p {} -h /tmp/www",
        marker, WEBSERVER_PORT
    )
}

/// A restricted, unprivileged pod that both serves a marker and probes others.
fn create_network_multitool_pod(name: &str) -> Pod {
    ProbePod::new(name)
        .container("multitool")
        .image("praqma/network-multitool")
        .label("app", "network-multitool")
        .restricted()
        .port(WEBSERVER_PORT)
        .shell(unprivileged_http_server_command(name))
        .restart_on_failure_default()
        .build()
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
                "port": WEBSERVER_PORT,
                "targetPort": WEBSERVER_PORT
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

/// Creates a NodePort service with a custom selector.
/// Used for isolation testing where we need to point to a specific marker pod.
fn create_nodeport_service_with_selector(
    namespace: &str,
    name: &str,
    node_port: i32,
    app_selector: &str,
) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "test": "network-isolation"
            }
        },
        "spec": {
            "selector": {
                "app": app_selector
            },
            "ports": [{
                "name": "http",
                "protocol": "TCP",
                "port": WEBSERVER_PORT,
                "targetPort": WEBSERVER_PORT,
                "nodePort": node_port
            }],
            "type": "NodePort"
        }
    }))
    .unwrap()
}

/// Creates a pod that serves a unique marker on [`WEBSERVER_PORT`].
/// Used for NodePort isolation testing.
///
/// The pod itself asks for no privilege — what the NodePort test exercises is
/// the *Service*, and it is the Service that a confined tenant refuses. So this
/// runs unprivileged, and the refusal, when it comes, arrives at the Service
/// rather than here. That distinction is what lets the test report "NodePort
/// forbidden" instead of "the probe would not start".
/// Serves a marker behind a NodePort service the test then tries to reach.
///
/// The pod itself needs no privilege — the NodePort is the thing a confined
/// tenant should be unable to create — so it is restricted like any other
/// reachability probe.
fn create_nodeport_marker_pod(name: &str, marker: &str) -> Pod {
    ProbePod::new(name)
        .container("marker-server")
        .image("praqma/network-multitool")
        .label("app", "nodeport-marker")
        .restricted()
        .port_tcp(WEBSERVER_PORT)
        .shell(unprivileged_http_server_command(marker))
        .build()
}

/// Requests host networking. Its refusal on a confined tenant is the finding.
fn create_host_network_pod(name: &str) -> Pod {
    ProbePod::new(name)
        .image("praqma/network-multitool")
        .label("app", "host-network-test")
        .requests(HostAccess::Network)
        .shell("sleep 3600")
        .build()
}

/// Creates a hostNetwork pod that serves a unique marker on a specified port.
/// This is used to create an observable state that can be verified by another tenant.
/// A host-network pod serving a marker on a chosen node port.
///
/// Host networking is deliberate: the marker must be reachable from another
/// tenant via the node's address, which is exactly what should be isolated.
fn create_node_marker_pod(name: &str, marker: &str, port: i32) -> Pod {
    // praqma/network-multitool ships nginx; point it at a custom port and serve
    // the marker.
    let serve_cmd = format!(
        "echo '{}' > /usr/share/nginx/html/index.html && \
         sed -i 's/listen.*80/listen {}/g' /etc/nginx/nginx.conf && \
         nginx -g 'daemon off;'",
        marker, port
    );

    ProbePod::new(name)
        .container("marker-server")
        .image("praqma/network-multitool")
        .label("app", "node-marker-service")
        .requests(HostAccess::Network)
        .host_port(port)
        .shell(serve_cmd)
        .build()
}

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for NetworkResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkResource::PodNetwork => write!(f, "Pod Network"),
            NetworkResource::ServiceNetwork => write!(f, "Service Network"),
            NetworkResource::InfrastructureNetwork => write!(f, "Infrastructure Network"),
            NetworkResource::DnsResolution => write!(f, "DNS Resolution"),
        }
    }
}

impl Display for NetworkOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkOperation::ConnectToPod => write!(f, "Connect to Pod"),
            NetworkOperation::ConnectToService => write!(f, "Connect to Service"),
            NetworkOperation::ConnectToNode => write!(f, "Connect to Node"),
            NetworkOperation::ExposeNodePort => write!(f, "Expose NodePort"),
            NetworkOperation::ResolveDns => write!(f, "Resolve DNS"),
        }
    }
}

#[cfg(test)]
mod probe_requests_what_it_claims {
    //! The network counterpart of the workload guard of the same name.
    //!
    //! k8s-openapi silently drops keys it does not recognise, so a probe can
    //! fail to request the very thing it is testing and report isolation it
    //! never exercised. These assertions run against the typed struct, which is
    //! what the API server actually receives.
    //!
    //! The two directions matter equally here. The host-network probes must
    //! *keep* their privilege, because their rejection is the finding; the
    //! reachability probes must *keep* their restricted security context, or a
    //! hardened tenant refuses them and the measurement is lost rather than
    //! made.

    use super::*;

    fn spec(pod: &Pod) -> &k8s_openapi::api::core::v1::PodSpec {
        pod.spec.as_ref().expect("probe pod must have a spec")
    }

    #[test]
    fn the_host_network_probes_request_host_networking() {
        assert_eq!(
            spec(&create_host_network_pod("p")).host_network,
            Some(true),
            "without hostNetwork this probe tests nothing and reads as isolated"
        );

        let marker = create_node_marker_pod("m", "marker", NODE_MARKER_PORT);
        assert_eq!(spec(&marker).host_network, Some(true));
        assert_eq!(
            spec(&marker).containers[0].ports.as_ref().unwrap()[0].host_port,
            Some(NODE_MARKER_PORT),
            "the marker is only observable from another tenant via its hostPort"
        );
    }

    #[test]
    fn the_reachability_probes_stay_restricted_and_unprivileged() {
        // These need no privilege, and must satisfy the `restricted` Pod
        // Security Standard so they still run on a hardened tenant. If they
        // regress to requesting privilege, capsule-hardened refuses them and
        // the network columns go Unknown.
        for pod in [
            create_network_multitool_pod("p"),
            create_nodeport_marker_pod("p", "marker"),
        ] {
            let s = spec(&pod);
            assert_ne!(s.host_network, Some(true));
            assert_ne!(s.host_pid, Some(true));

            let pod_ctx = s.security_context.as_ref().expect("pod securityContext");
            assert_eq!(pod_ctx.run_as_non_root, Some(true));
            assert!(
                pod_ctx.seccomp_profile.is_some(),
                "restricted needs seccomp"
            );

            let container_ctx = s.containers[0]
                .security_context
                .as_ref()
                .expect("container securityContext");
            assert_eq!(container_ctx.allow_privilege_escalation, Some(false));
            assert_eq!(
                container_ctx.capabilities.as_ref().unwrap().drop,
                Some(vec!["ALL".to_string()])
            );
        }
    }

    #[test]
    fn the_reachability_probes_serve_on_an_unprivileged_port() {
        // Bound together: runAsNonRoot cannot bind below 1024, so the port and
        // the security context have to move as a pair. Splitting them yields a
        // probe that is admitted and then never answers.
        assert!(
            WEBSERVER_PORT >= 1024,
            "non-root cannot bind {WEBSERVER_PORT}"
        );
        assert_eq!(
            spec(&create_network_multitool_pod("p")).containers[0]
                .ports
                .as_ref()
                .unwrap()[0]
                .container_port,
            WEBSERVER_PORT
        );
    }
}
