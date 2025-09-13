use anyhow::{Ok, Result};
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector::Lookup;

use crate::verifier::{
    data_plane::network::{NETWORK_MULTITOOL_POD, NETWORK_MULTITOOL_POD_NAME, WEBSERVER_SERVICE},
    NetworkIsolationReport, TenantClusterConfig,
};

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
