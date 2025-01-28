use crate::cluster::{KubernetesCluster, NGINX_POD};

pub async fn check_object_isolation(
    first_tenant_cluster: &KubernetesCluster,
    second_tenant_cluster: &KubernetesCluster,
) -> anyhow::Result<()> {
    // deploy nginx pod in first cluster
    first_tenant_cluster
        .create_pod_in_namespace(&NGINX_POD, "t1")
        .await?;

    let pod_name = NGINX_POD
        .metadata
        .name
        .clone()
        .unwrap_or(String::from("nginx"));

    let first_tenant_namespace = "t1";

    // deploy nginx pod in first cluster
    first_tenant_cluster
        .create_pod_in_namespace(&NGINX_POD, first_tenant_namespace)
        .await?;
    // check if pod is available in first cluster by the first tenant
    let _pod_seen_by_tenant1 = first_tenant_cluster
        .get_pod_in_namespace(&pod_name, first_tenant_namespace)
        .await?;

    // Check pod visibility for tenant2
    let first_tenant_pod_access_by_others = match second_tenant_cluster
        .get_pod_in_namespace(&pod_name, first_tenant_namespace)
        .await
    {
        Ok(_) => Err(anyhow::anyhow!(
            "First tenant's pod is visible by the second tenant"
        )),
        // Pod should not be visible by the second tenant
        Err(_) => Ok(()),
    };

    // clean up
    first_tenant_cluster
        .delete_pod_in_namespace(&pod_name, "t1")
        .await?;

    first_tenant_pod_access_by_others
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::KindCluster;
    use std::path::PathBuf;

    const FIRST_CLUSTER_NAME_PREFIX: &str = "first-tenant";
    const SECOND_CLUSTER_NAME_PREFIX: &str = "second-tenant";

    fn temp_kubeconfig_path(cluster_name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("{}.kubeconfig", cluster_name));
        path
    }

    #[tokio::test]
    async fn test_object_isolation() {
        let first_cluster_name = format!("{}-obj-isolation", FIRST_CLUSTER_NAME_PREFIX);
        let second_cluster_name = format!("{}-obj-isolation", SECOND_CLUSTER_NAME_PREFIX);

        let first_cluster = KindCluster::create(&first_cluster_name).unwrap();
        let second_cluster = KindCluster::create(&second_cluster_name).unwrap();

        let first_kubeconfig_path = temp_kubeconfig_path(&first_cluster_name);
        let second_kubeconfig_path = temp_kubeconfig_path(&second_cluster_name);

        first_cluster
            .export_kubeconfig(&first_kubeconfig_path)
            .unwrap();
        second_cluster
            .export_kubeconfig(&second_kubeconfig_path)
            .unwrap();

        let first_kubernetes_cluster = KubernetesCluster::load(&first_kubeconfig_path)
            .await
            .unwrap();
        let second_kubernetes_cluster = KubernetesCluster::load(&second_kubeconfig_path)
            .await
            .unwrap();
        first_kubernetes_cluster
            .ensure_cluster_is_ready()
            .await
            .unwrap();
        second_kubernetes_cluster
            .ensure_cluster_is_ready()
            .await
            .unwrap();

        let result =
            check_object_isolation(&first_kubernetes_cluster, &second_kubernetes_cluster).await;
        assert!(
            result.is_err(),
            "A cluster without any isolation mechanism should fail"
        );

        // TODO: Add a test case where the object isolation is enabled

        // cleanup
        first_cluster.delete().unwrap();
        second_cluster.delete().unwrap();
    }
}
