use anyhow::{Ok, Result};
use k8s_openapi::api::core::v1::{Pod, Service, ServicePort, ServiceSpec};
use kube::{api::ObjectMeta, runtime::reflector::Lookup};
use std::sync::LazyLock;

use crate::verifier::{NetworkIsolationReport, TenantClusterConfig};

const NETWORK_MULTITOOL_IMAGE: &str = "wbitt/network-multitool";
const NETWORK_MULTITOOL_POD_NAME: &str = "network-multitool";
static NETWORK_MULTITOOL_POD: LazyLock<Pod> = LazyLock::new(|| {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": NETWORK_MULTITOOL_POD_NAME,
        },
        "spec": {
            "containers": [
                {
                    "name": NETWORK_MULTITOOL_POD_NAME,
                    "image": NETWORK_MULTITOOL_IMAGE,
                    "ports": [
                        {
                            "containerPort": 80,
                        }
                    ],
                }
            ]
        }
    }
    ))
    .unwrap()
});

static WEBSERVER_SERVICE: LazyLock<Service> = LazyLock::new(|| {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "tenant-service",
        },
        "spec": {
            "selector": {
                "app": "tenant-service",
            },
            "ports": [
                {
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 80,
                }
            ],
            "type": "ClusterIP",
        }
    }
    ))
    .unwrap()
});

/// Check if the network between two tenants is isolated.
///
/// Create a pod for each tenant and try to communicate between them.
/// If the communication is successful, the network is not isolated.
///
/// Additionally, create a service in the first tenant while the second tenant tries to access it.
/// If the second tenant can access the service, the network is not isolated.
pub async fn check_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<NetworkIsolationReport> {
    let _pod_tenant1 = tenant1
        .cluster
        .create_pod_in_namespace(&NETWORK_MULTITOOL_POD, &tenant1.namespace)
        .await?;

    let _pod_tenant2 = tenant2
        .cluster
        .create_pod_in_namespace(&NETWORK_MULTITOOL_POD, &tenant2.namespace)
        .await?;

    println!("Waiting for pod in tenant1 to be ready...");
    tenant1
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    println!("Waiting for pod in tenant2 to be ready...");
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    let tenant1_pod_ip = tenant1
        .cluster
        .get_pod_ip(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    println!("Tenant 1 pod IP: {}", tenant1_pod_ip);

    let tenant2_pod_ip = tenant2
        .cluster
        .get_pod_ip(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    println!("Tenant 2 pod IP: {}", tenant2_pod_ip);

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

    println!("Tenant1 can connect to tenant2: {}", can_reach_other_pod);

    // push a service to tenant2
    tenant2
        .cluster
        .create_namespaced_resource::<Service>(&WEBSERVER_SERVICE, &tenant2.namespace)
        .await?;

    tenant2
        .cluster
        .wait_for_resource_creation::<Service>(
            &WEBSERVER_SERVICE.name().unwrap(),
            &tenant2.namespace,
        )
        .await?;

    // get service ip
    let service_name = WEBSERVER_SERVICE.metadata.name.clone().unwrap();
    let service = tenant2
        .cluster
        .get_resource_in_namespace::<Service>(&service_name, &tenant2.namespace);
    let service_ip = service
        .await?
        .spec
        .unwrap()
        .cluster_ip
        .unwrap_or_else(|| "".to_string());

    println!("Service IP: {}", service_ip);

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

    println!(
        "Tenant1 pods can connect to services in tenant2: {}",
        can_reach_service
    );

    // Add the check on DNS isolation too
    // The tenant1 should not be able to resolve any DNS record from tenant2
    let can_resolve_dns = tenant1
        .cluster
        .exec_command_in_container_with_status(
            NETWORK_MULTITOOL_POD_NAME,
            &tenant1.namespace,
            format!(
                "nslookup {}.{}.svc.cluster.local",
                service_name, tenant2.namespace
            )
            .as_str(),
        )
        .await?
        .code
        == Some(0); // nslookup returns 0 if the domain is resolved (no error)

    if can_resolve_dns {
        println!("Tenant1 can resolve DNS records from tenant2");
    } else {
        println!("Tenant1 cannot resolve DNS records from tenant2");
    }

    // cleanup
    tenant2
        .cluster
        .delete_resource_in_namespace::<Service>(&service_name, &tenant2.namespace)
        .await?;

    tenant1
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    Ok(NetworkIsolationReport {
        pod_isolation: !can_reach_other_pod,
        service_isolation: !can_reach_service,
        dns_isolation: !can_resolve_dns,
        success: !can_reach_other_pod && !can_reach_service && !can_resolve_dns,
    })
}

const AUTONOMY_TEST_SERVICE_NAME: &str = "autonomy-test-service";
const AUTONOMY_TEST_PORT: i32 = 8080;
const AUTONOMY_TEST_NODE_PORT: i32 = 30080;

/// Create a test service for autonomy testing
fn create_autonomy_test_service(namespace: &str, service_name: &str) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(service_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some([("test".to_string(), "network-autonomy".to_string())].into()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some([("app".to_string(), "autonomy-test".to_string())].into()),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: AUTONOMY_TEST_PORT,
                target_port: Some(
                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                        AUTONOMY_TEST_PORT,
                    ),
                ),
                node_port: Some(AUTONOMY_TEST_NODE_PORT),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("NodePort".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Check network autonomy - can tenants independently expose services on the same ports?
/// This tests service-exposure autonomy by having both tenants create services on the same port.
/// If both succeed, the cluster has network autonomy (tenants have independent network namespaces).
pub async fn check_network_autonomy(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<bool> {
    println!("Testing network autonomy - service exposure independence...");

    // Create identical services in both tenant namespaces
    let tenant1_service =
        create_autonomy_test_service(&tenant1.namespace, AUTONOMY_TEST_SERVICE_NAME);
    let tenant2_service =
        create_autonomy_test_service(&tenant2.namespace, AUTONOMY_TEST_SERVICE_NAME);

    // Try to create service in tenant1
    let tenant1_service_created = tenant1
        .cluster
        .create_namespaced_resource::<Service>(&tenant1_service, &tenant1.namespace)
        .await;

    if tenant1_service_created.is_err() {
        println!(
            "Failed to create service in tenant1: {:?}",
            tenant1_service_created.err()
        );
        return Ok(false);
    }

    println!("Successfully created service in tenant1 namespace");

    // Try to create identical service in tenant2 (same port, same name)
    let tenant2_service_created = tenant2
        .cluster
        .create_namespaced_resource::<Service>(&tenant2_service, &tenant2.namespace)
        .await;

    let autonomy_success = tenant2_service_created.is_ok();

    if autonomy_success {
        println!("Successfully created identical service in tenant2 namespace");
        println!("✅ Network autonomy verified: Both tenants can independently expose services on port {}", AUTONOMY_TEST_PORT);
    } else {
        println!(
            "Failed to create identical service in tenant2: {:?}",
            tenant2_service_created.err()
        );
        println!("❌ Network autonomy failed: Tenants cannot independently expose services");
    }

    // Cleanup services
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

    Ok(autonomy_success)
}

// Comprehensive network multi-tenancy check including both isolation and autonomy
// pub async fn check_network_multitenancy(
//     tenant1: &TenantClusterConfig,
//     tenant2: &TenantClusterConfig,
// ) -> Result<ExtendedNetworkIsolationReport> {
//     // First check autonomy (less disruptive)
//     let autonomy = check_network_autonomy(tenant1, tenant2).await?;

//     // Then check isolation
//     let isolation = check_network_isolation(tenant1, tenant2).await?;

//     let overall_success = isolation.success && autonomy;

//     Ok(ExtendedNetworkIsolationReport {
//         isolation,
//         autonomy,
//         overall_success,
//     })
// }
