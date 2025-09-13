use anyhow::Result;
use k8s_openapi::api::core::v1::Service;

use crate::verifier::TenantClusterConfig;

const AUTONOMY_TEST_SERVICE_NAME: &str = "autonomy-test-service";
const AUTONOMY_TEST_PORT: i32 = 8080;
const AUTONOMY_TEST_NODE_PORT: i32 = 30080;

/// Check network autonomy - can tenants independently expose services on the same ports?
/// This tests service-exposure autonomy by having both tenants create services on the same port and expose using NodePort.
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

/// Create a test service for autonomy testing - builds fresh each time
fn create_autonomy_test_service(namespace: &str, service_name: &str) -> Service {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": service_name,
            "namespace": namespace,
            "labels": {
                "test": "network-autonomy"
            }
        },
        "spec": {
            "selector": {
                "app": "autonomy-test"
            },
            "ports": [
                {
                    "name": "http",
                    "protocol": "TCP",
                    "port": AUTONOMY_TEST_PORT,
                    "targetPort": AUTONOMY_TEST_PORT,
                    "nodePort": AUTONOMY_TEST_NODE_PORT
                }
            ],
            "type": "NodePort"
        }
    }
    ))
    .unwrap()
}
