use crate::{
    cluster::{KubernetesClient, NGINX_POD},
    verifier::TenantClusterConfig,
};

use super::get_example_pod_name;

use anyhow::{Context, Result};

/// Verifies that object isolation works between two tenant clusters
pub async fn check_object_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<bool> {
    let pod_name = get_example_pod_name();

    // Deploy and verify pod for tenant1
    deploy_tenant_pod(&tenant1.cluster, &pod_name, &tenant1.namespace).await?;

    // Verify tenant2 cannot access tenant1's pod
    let is_isolated = assert_pod_isolation(&tenant2.cluster, &pod_name, &tenant1.namespace).await;

    // Cleanup
    cleanup_tenant_pod(&tenant1.cluster, &pod_name, &tenant1.namespace).await?;

    Ok(is_isolated)
}

async fn deploy_tenant_pod(
    cluster: &KubernetesClient,
    pod_name: &str,
    namespace: &str,
) -> Result<()> {
    cluster
        .create_pod_in_namespace(&NGINX_POD, namespace)
        .await
        .context("Failed to create tenant pod")?;

    cluster
        .get_pod_in_namespace(pod_name, namespace)
        .await
        .context("Failed to verify tenant pod creation")?;

    Ok(())
}

async fn assert_pod_isolation(
    other_cluster: &KubernetesClient,
    pod_name: &str,
    namespace: &str,
) -> bool {
    other_cluster
        .get_pod_in_namespace(pod_name, namespace)
        .await
        .is_err() // Expect an error if the pod is not found, meaning isolation is working
}

async fn cleanup_tenant_pod(
    cluster: &KubernetesClient,
    pod_name: &str,
    namespace: &str,
) -> Result<()> {
    cluster
        .delete_pod_in_namespace(pod_name, namespace)
        .await
        .context("Failed to cleanup tenant pod")
}
