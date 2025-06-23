mod autonomy;
mod fairness;
mod isolation;
mod objects;
mod transparent_isolation;

use std::fmt::Display;

pub use autonomy::*;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssessmentResult {
    Success,
    NotEvaluated(String),
    Unsuccessful(String),
}

#[derive(Debug, Clone)]
pub struct ObjectPropertyAssessment {
    pub kind: KubernetesObject,
    pub issued_operations: Vec<OperationResult>,
    pub result: AssessmentResult,
}
impl ObjectPropertyAssessment {
    pub fn is_valid(&self) -> bool {
        match self.result {
            AssessmentResult::Success => true,
            AssessmentResult::NotEvaluated(_) => true,
            AssessmentResult::Unsuccessful(_) => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObjectAutonomyReport {
    pub kind: KubernetesObject,
    pub isolation_results: Vec<OperationResult>,
    pub has_isolation: bool,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneIsolationReport {
    pub overall_isolation_success: bool,
    pub objects_assessment: Vec<ObjectPropertyAssessment>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneAutonomyReport {
    pub autonomy_level: ControlPlaneAutonomy,
    pub objects_assessment: Vec<ObjectPropertyAssessment>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneAutonomy {
    pub namespace_level: bool,
    pub node_level: bool,
    pub cluster_level: bool,
}

impl Display for ControlPlaneAutonomy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Control Plane Autonomy:")?;
        writeln!(
            f,
            "  Namespace Level: {}",
            if self.namespace_level { "✅" } else { "❌" }
        )?;
        writeln!(
            f,
            "  Node Level: {}",
            if self.node_level { "✅" } else { "❌" }
        )?;
        writeln!(
            f,
            "  Cluster Level: {}",
            if self.cluster_level { "✅" } else { "❌" }
        )?;
        Ok(())
    }
}

impl From<&[ObjectPropertyAssessment]> for ControlPlaneAutonomy {
    fn from(assessments: &[ObjectPropertyAssessment]) -> Self {
        let namespace_level = assessments
            .iter()
            .filter(|assessment| {
                assessment.kind.is_namespaced() || assessment.kind == KubernetesObject::Namespace
            })
            .all(|autonomy| autonomy.is_valid());

        let node_level = assessments
            .iter()
            .filter(|assessment| assessment.kind == KubernetesObject::Node)
            .all(|autonomy| autonomy.is_valid());

        let cluster_level = assessments
            .iter()
            .filter(|assessment| {
                assessment.kind.is_cluster_wide()
                    && assessment.kind != KubernetesObject::Namespace
                    && assessment.kind != KubernetesObject::Node
            })
            .all(|autonomy| autonomy.is_valid());

        Self {
            namespace_level,
            node_level,
            cluster_level,
        }
    }
}

impl Display for ControlPlaneAutonomyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Control Plane Autonomy Report")?;
        writeln!(f, "==============================")?;
        writeln!(f, "{}", self.autonomy_level)?;

        if !self.failures.is_empty() {
            writeln!(f, "\nAutonomy Failures:")?;
            for failure in &self.failures {
                writeln!(f, "  - {}", failure)?;
            }
        }

        writeln!(f, "\nDetailed Results by Object Kind:")?;
        for assessment in &self.objects_assessment {
            writeln!(
                f,
                "  {} ({})",
                assessment.kind,
                assessment.kind.api_version()
            )?;
            writeln!(
                f,
                "    Autonomy: {}",
                match assessment.result {
                    AssessmentResult::Success => "✅",
                    AssessmentResult::NotEvaluated(_) => "⚠️",
                    AssessmentResult::Unsuccessful(_) => "❌",
                }
            )?;
            for operation in &assessment.issued_operations {
                writeln!(f, "      - {}: {}", operation.verb, operation.success)?;
                if let Some(reason) = &operation.error_reason {
                    writeln!(f, "        Reason: {}", reason)?;
                }
            }
        }
        Ok(())
    }
}

impl Display for ControlPlaneIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Control Plane Isolation Report")?;
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

        // Also display the untested objects  as warning
        if self
            .objects_assessment
            .iter()
            .any(|assessment| matches!(assessment.result, AssessmentResult::NotEvaluated(_)))
        {
            writeln!(f, "⚠️ Some objects were not evaluated properly.")?;
            writeln!(
                f,
                "Probably CREATE is disallowed and no existing object of a kind exists for tenant1."
            )?;
            writeln!(
                f,
                "Please check the detailed results below for more information."
            )?;
        }

        if !self.failures.is_empty() {
            writeln!(f, "\nIsolation Failures:")?;
            for failure in &self.failures {
                writeln!(f, "  - {}", failure)?;
            }
        }

        writeln!(f, "\nDetailed Results by Object Kind:")?;
        for assessment in &self.objects_assessment {
            writeln!(
                f,
                "  {} ({})",
                assessment.kind,
                assessment.kind.api_version()
            )?;
            writeln!(
                f,
                "    Isolation: {}",
                match assessment.result {
                    AssessmentResult::Success => "✅",
                    AssessmentResult::NotEvaluated(_) => "⚠️",
                    AssessmentResult::Unsuccessful(_) => "❌",
                }
            )?;

            writeln!(f, "    Operations:")?;
            for op in &assessment.issued_operations {
                let result_status = if op.success && op.error_reason.is_none() {
                    "true"
                } else if !op.success && op.error_reason.is_some() {
                    "false"
                } else {
                    "unknown"
                };
                let error_info = match &op.error_reason {
                    Some(reason) => format!("({})", reason),
                    None => {
                        if op.success {
                            //"(Success)".to_string()
                            "".to_string()
                        } else {
                            "(Failed)".to_string()
                        }
                    }
                };
                writeln!(f, "      {}: {} {}", op.verb, result_status, error_info)?;
            }
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
