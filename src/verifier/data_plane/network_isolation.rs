use super::TenantClusterConfig;
use anyhow::{Ok, Result};
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::runtime::reflector::Lookup;
use std::sync::LazyLock;

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
) -> Result<bool> {
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
        .wait_for_resource_to_be_created::<Service>(
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

    // cleanup
    tenant2
        .cluster
        .delete_resouce_in_namespace::<Service>(&service_name, &tenant2.namespace)
        .await?;

    tenant1
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant2.namespace)
        .await?;

    Ok(!can_reach_other_pod && !can_reach_service)
}
