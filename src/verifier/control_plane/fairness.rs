use std::sync::Arc;
use std::thread;

use crate::cluster::NGINX_POD;
use crate::verifier::TenantClusterConfig;
use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;

use super::get_example_pod_name;

/// Check if one tenant will not be starved by the other tenant control plane
///
/// Tenant1 will flood its control plane with requests
/// and tenant2 will monitor the average response time of its control plane
/// if the average response time of tenant2 control plane is greater than the threshold
/// then the tenant2 is starved by tenant1
pub async fn check_fairness(
    tenant1: TenantClusterConfig,
    tenant2: TenantClusterConfig,
) -> Result<bool> {
    let tenant1_config = Arc::new(tenant1);
    let tenant1_config_clone = Arc::clone(&tenant1_config);

    thread::spawn(move || {
        let tenant1_config = tenant1_config_clone;
        async move {
            flood_control_plane(&tenant1_config).await;
        }
    });

    // Check if tenant2 is starved by tenant1
    monitor_control_plane_response_time(&tenant2).await?;

    Ok(true)
}

/// Flood the control plane of the tenant by sending a lot of requests.
///
/// The requests are a cycle of pod creation, deletion, and update.
/// The requests are sent in parallel.
pub async fn flood_control_plane(tenant: &TenantClusterConfig) -> Result<()> {
    let pod_name = get_example_pod_name();
    loop {
        // Create a pod
        tenant
            .cluster
            .create_pod_in_namespace(&NGINX_POD, &tenant.namespace)
            .await?;
        // Update a pod
        // tenant
        //     .cluster
        //     .update_pod_in_namespace(&NGINX_POD, &tenant.namespace)
        //     .await?;
        // Delete a pod
        tenant
            .cluster
            .delete_pod_in_namespace(&pod_name, &tenant.namespace)
            .await?;
        // Sleep for a while

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

/// Monitor the control plane response time of the tenant by sending periodic requests
///
/// The requests are mad of pods list requests for now
pub async fn monitor_control_plane_response_time(tenant: &TenantClusterConfig) -> Result<bool> {
    loop {
        // List pods
        tenant
            .cluster
            .list_resource_in_namespace::<Pod>(&tenant.namespace)
            .await?;

        // Sleep for a while
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
