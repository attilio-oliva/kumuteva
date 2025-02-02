use crate::cluster::{KubernetesCluster, NGINX_POD};
use anyhow::{Context, Result};

use super::TransparentIsolationLevel;

const TENANT1_NS: &str = "t1";
const POD_DEFAULT_NAME: &str = "nginx";

/// Verifies that object isolation works between two tenant clusters
pub async fn check_object_isolation(
    tenant1_cluster: &KubernetesCluster,
    tenant2_cluster: &KubernetesCluster,
) -> Result<()> {
    let pod_name = get_pod_name();

    // Deploy and verify pod for tenant1
    deploy_tenant_pod(tenant1_cluster, &pod_name, TENANT1_NS).await?;

    // Verify tenant2 cannot access tenant1's pod
    assert_pod_isolation(tenant2_cluster, &pod_name).await?;

    // Cleanup
    cleanup_tenant_pod(tenant1_cluster, &pod_name).await
}

pub async fn check_transparent_isolation_level(
    tenant1_cluster: &KubernetesCluster,
    tenant2_cluster: &KubernetesCluster,
    level: TransparentIsolationLevel,
) -> Result<()> {
    match level {
        TransparentIsolationLevel::Namespace => {
            check_namespace_isolation(tenant1_cluster, tenant2_cluster).await
        }
        TransparentIsolationLevel::Node => {
            check_node_isolation(tenant1_cluster, tenant2_cluster).await
        }
        TransparentIsolationLevel::Cluster => {
            check_cluster_isolation(tenant1_cluster, tenant2_cluster).await
        }
    }
}

async fn check_namespace_isolation(
    tenant1_cluster: &KubernetesCluster,
    tenant2_cluster: &KubernetesCluster,
) -> Result<()> {
    unimplemented!("Namespace isolation test is not implemented")
}

async fn check_node_isolation(
    tenant1_cluster: &KubernetesCluster,
    tenant2_cluster: &KubernetesCluster,
) -> Result<()> {
    unimplemented!("Node isolation test is not implemented")
}

async fn check_cluster_isolation(
    tenant1_cluster: &KubernetesCluster,
    tenant2_cluster: &KubernetesCluster,
) -> Result<()> {
    // attempt to create a CRD in tenant1
    // attempt to get the CRD in tenant2
    // attempt to create the same
    // ensure no name collision happens in tenant2

    let crd_name = "mycrd";
    let crd = r#"
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: mycrd
spec:
    group: example.com
    names:
        kind: MyCRD
        listKind: MyCRDList
        plural: mycrds
        singular: mycrd
    scope: Namespaced
    versions:
    - name: v1
        served: true
        storage: true
        schema:
        openAPIV3Schema:
            type: object
            properties:
            spec:
                type: object
                properties:
                foo:
                    type: string
            required:
            - spec
    "#;

    anyhow::Ok(())
}

fn get_pod_name() -> String {
    NGINX_POD
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| POD_DEFAULT_NAME.to_string())
}

async fn deploy_tenant_pod(
    cluster: &KubernetesCluster,
    pod_name: &str,
    namespace: &str,
) -> Result<()> {
    cluster.create_namespace_if_not_exists(namespace).await?;
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

async fn assert_pod_isolation(other_cluster: &KubernetesCluster, pod_name: &str) -> Result<()> {
    match other_cluster
        .get_pod_in_namespace(pod_name, TENANT1_NS)
        .await
    {
        Ok(_) => Err(anyhow::anyhow!(
            "Pod isolation failed: tenant2 can see tenant1's pod"
        )),
        Err(_) => Ok(()),
    }
}

async fn cleanup_tenant_pod(cluster: &KubernetesCluster, pod_name: &str) -> Result<()> {
    cluster
        .delete_pod_in_namespace(pod_name, TENANT1_NS)
        .await
        .context("Failed to cleanup tenant pod")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{
        ControlPlaneIsolation, IsolationTechnology, KindCluster, KubernetesClusterBuilder,
    };
    use std::path::PathBuf;

    const CLUSTER_NAME_PREFIX: &str = "cp";

    struct TestClusterConfig {
        name: String,
        kubeconfig_path: PathBuf,
    }

    impl TestClusterConfig {
        fn new(name: &str) -> Self {
            let name = name.to_string();
            let kubeconfig_path = temp_kubeconfig_path(&name);
            Self {
                name,
                kubeconfig_path,
            }
        }
    }

    fn temp_kubeconfig_path(cluster_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}.kubeconfig", cluster_name))
    }

    async fn setup_test_cluster(config: &TestClusterConfig) -> Result<KubernetesCluster> {
        let cluster = KubernetesCluster::load(&config.kubeconfig_path).await?;
        cluster.ensure_cluster_is_ready().await?;
        Ok(cluster)
    }

    #[tokio::test]
    async fn test_native_object_isolation() {
        let config =
            TestClusterConfig::new(&format!("{}-obj-isolation-native", CLUSTER_NAME_PREFIX));

        let kind_cluster = KindCluster::create(
            &config.name,
            config.kubeconfig_path.clone(),
            Default::default(),
        )
        .unwrap();

        let tenant1_cluster = setup_test_cluster(&config).await.unwrap();
        let tenant2_cluster = setup_test_cluster(&config).await.unwrap();

        let result = check_object_isolation(&tenant1_cluster, &tenant2_cluster).await;
        assert!(result.is_err(), "Native cluster should fail isolation test");

        kind_cluster.delete().unwrap();
    }

    #[tokio::test]
    async fn test_vcluster_object_isolation() {
        let base_config =
            TestClusterConfig::new(&format!("{}-obj-isolation-vcluster", CLUSTER_NAME_PREFIX));
        let kind_cluster = KindCluster::create(
            &base_config.name,
            base_config.kubeconfig_path.clone(),
            Default::default(),
        )
        .unwrap();

        let tenant1_config = TestClusterConfig::new(&format!("tenant1-{}", base_config.name));
        let tenant2_config = TestClusterConfig::new(&format!("tenant2-{}", base_config.name));

        let tenant1_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
            .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant1_config.name.clone()))
            .with_kubeconfig_path(tenant1_config.kubeconfig_path)
            .build()
            .await
            .unwrap();

        tenant1_cluster.ensure_cluster_is_ready().await.unwrap();

        let tenant2_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
            .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant2_config.name.clone()))
            .with_kubeconfig_path(tenant2_config.kubeconfig_path)
            .build()
            .await
            .unwrap();

        tenant2_cluster.ensure_cluster_is_ready().await.unwrap();

        let result = check_object_isolation(&tenant1_cluster, &tenant2_cluster).await;
        assert!(result.is_ok(), "VCluster should pass isolation test");

        kind_cluster.delete().unwrap();
    }
}
