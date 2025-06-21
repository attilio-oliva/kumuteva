mod fairness;
mod isolation;
mod objects;
mod transparent_isolation;

use std::fmt::Display;

pub use fairness::*;
pub use isolation::*;
pub use objects::*;
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

#[derive(Debug, Clone)]
pub struct ObjectKind {
    pub api_version: String,
    pub kind: String,
    pub namespaced: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum KubernetesVerb {
    Create,
    Get,
    List,
    Update,
    Patch,
    Delete,
    Watch,
}

impl Display for KubernetesVerb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verb_str = match self {
            KubernetesVerb::Create => "CREATE",
            KubernetesVerb::Get => "GET",
            KubernetesVerb::List => "LIST",
            KubernetesVerb::Update => "UPDATE",
            KubernetesVerb::Patch => "PATCH",
            KubernetesVerb::Delete => "DELETE",
            KubernetesVerb::Watch => "WATCH",
        };
        write!(f, "{}", verb_str)
    }
}

#[derive(Debug, Clone)]
pub struct OperationResult {
    pub verb: KubernetesVerb,
    pub success: bool,
    pub error_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectKindTestResult {
    pub kind: KubernetesObject,
    pub autonomy_results: Vec<OperationResult>,
    pub isolation_results: Vec<OperationResult>,
    pub has_autonomy: bool,
    pub has_isolation: bool,
}

#[derive(Debug, Clone)]
pub struct EnhancedObjectIsolationReport {
    pub overall_isolation_success: bool,
    pub overall_autonomy_success: bool,
    pub object_results: Vec<ObjectKindTestResult>,
    pub isolation_failures: Vec<String>,
    pub autonomy_failures: Vec<String>,
}

impl std::fmt::Display for EnhancedObjectIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Enhanced Object Isolation Report")?;
        writeln!(f, "=================================")?;
        writeln!(
            f,
            "Overall Isolation: {}",
            if self.overall_isolation_success {
                "✅ PASS"
            } else {
                "❌ FAIL"
            }
        )?;
        writeln!(
            f,
            "Overall Autonomy: {}",
            if self.overall_autonomy_success {
                "✅ PASS"
            } else {
                "❌ FAIL"
            }
        )?;

        if !self.isolation_failures.is_empty() {
            writeln!(f, "\nIsolation Failures:")?;
            for failure in &self.isolation_failures {
                writeln!(f, "  - {}", failure)?;
            }
        }

        if !self.autonomy_failures.is_empty() {
            writeln!(f, "\nAutonomy Failures:")?;
            for failure in &self.autonomy_failures {
                writeln!(f, "  - {}", failure)?;
            }
        }

        writeln!(f, "\nDetailed Results by Object Kind:")?;
        for result in &self.object_results {
            writeln!(f, "  {} ({})", result.kind, result.kind.api_version())?;
            writeln!(
                f,
                "    Autonomy: {}",
                if result.has_autonomy { "✅" } else { "❌" }
            )?;
            writeln!(
                f,
                "    Isolation: {}",
                if result.has_isolation { "✅" } else { "❌" }
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

        let result = crate::verifier::control_plane::isolation::check_object_isolation(
            &tenant1_config,
            &tenant2_config,
        )
        .await;
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

        let result = crate::verifier::control_plane::isolation::check_object_isolation(
            &tenant1_config,
            &tenant2_config,
        )
        .await;
        assert!(result.is_ok(), "VCluster should pass isolation test");

        kind_cluster.delete().await.unwrap();
    }
}
