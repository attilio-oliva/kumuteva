mod fairness;
mod obj_isolation;
mod transparent_isolation;

pub use fairness::*;
pub use obj_isolation::*;
pub use transparent_isolation::*;

use crate::cluster::NGINX_POD;

const POD_DEFAULT_NAME: &str = "nginx";

fn get_example_pod_name() -> String {
    NGINX_POD
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| POD_DEFAULT_NAME.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{
        ControlPlaneIsolation, HostClusterType, KindCluster, KubernetesClient,
        KubernetesClusterBuilder,
    };
    use crate::verifier::TenantClusterConfig;
    use anyhow::Result;
    use std::path::PathBuf;

    const TENANT1_NS: &str = "t1";
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

    async fn setup_test_cluster(config: &TestClusterConfig) -> Result<KubernetesClient> {
        let cluster = KubernetesClient::load(&config.kubeconfig_path).await?;
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
        .await
        .unwrap();

        let tenant1_cluster = setup_test_cluster(&config).await.unwrap();
        let tenant2_cluster = setup_test_cluster(&config).await.unwrap();

        let tenant1_config = TenantClusterConfig {
            cluster: tenant1_cluster,
            namespace: TENANT1_NS.to_string(),
        };

        let tenant2_config = TenantClusterConfig {
            cluster: tenant2_cluster,
            namespace: "t2".to_string(),
        };

        let result = check_object_isolation(&tenant1_config, &tenant2_config).await;
        assert!(result.is_err(), "Native cluster should fail isolation test");

        kind_cluster.delete().await.unwrap();
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
        .await
        .unwrap();

        let tenant1_config = TestClusterConfig::new(&format!("tenant1-{}", base_config.name));
        let tenant2_config = TestClusterConfig::new(&format!("tenant2-{}", base_config.name));

        let tenant1_cluster =
            KubernetesClusterBuilder::new(HostClusterType::Kind(kind_cluster.clone()))
                .with_isolation_technology(ControlPlaneIsolation::VCluster(
                    tenant1_config.name.clone(),
                ))
                .with_kubeconfig_path(tenant1_config.kubeconfig_path)
                .build()
                .await
                .unwrap();

        tenant1_cluster.ensure_cluster_is_ready().await.unwrap();

        let tenant2_cluster =
            KubernetesClusterBuilder::new(HostClusterType::Kind(kind_cluster.clone()))
                .with_isolation_technology(ControlPlaneIsolation::VCluster(
                    tenant2_config.name.clone(),
                ))
                .with_kubeconfig_path(tenant2_config.kubeconfig_path)
                .build()
                .await
                .unwrap();

        tenant2_cluster.ensure_cluster_is_ready().await.unwrap();

        let tenant1_config = TenantClusterConfig {
            cluster: tenant1_cluster,
            namespace: TENANT1_NS.to_string(),
        };

        let tenant2_config = TenantClusterConfig {
            cluster: tenant2_cluster,
            namespace: "t2".to_string(),
        };

        let result = check_object_isolation(&tenant1_config, &tenant2_config).await;
        assert!(result.is_ok(), "VCluster should pass isolation test");

        kind_cluster.delete().await.unwrap();
    }
}
