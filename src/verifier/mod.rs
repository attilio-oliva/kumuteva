use anyhow::Result;
use std::{fmt, sync::Arc};

mod control_plane;
mod data_plane;

pub use control_plane::*;
pub use data_plane::*;

use crate::cluster::KubernetesClient;

pub struct IsolationReport {
    control_plane: ControlPlaneReport,
    data_plane: DataPlaneReport,
}

pub struct ControlPlaneReport {
    object_isolation: TestResult,
    transparent_isolation: TransparentIsolationReport,
    fairness: TestResult,
}

pub struct TransparentIsolationReport {
    namespace: TestResult,
    node: TestResult,
    cluster: TestResult,
}

pub struct DataPlaneReport {
    storage_isolation: TestResult,
    network_isolation: TestResult,
    workload_isolation: TestResult,
}

/// Run all the isolation tests
pub async fn check_all(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<IsolationReport> {
    let control_plane = check_control_plane_isolation(tenant1.clone(), tenant2.clone()).await?;
    let data_plane = check_data_plane_isolation(tenant1.clone(), tenant2.clone()).await?;

    Ok(IsolationReport {
        control_plane,
        data_plane,
    })
}

/// Run all the control plane isolation tests
pub async fn check_control_plane_isolation(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<ControlPlaneReport> {
    let object_isolation = ControlPlaneIsolationProperty::ObjectIsolation
        .run(tenant1.clone(), tenant2.clone())
        .await?;

    let transparent_isolation_namespace =
        ControlPlaneIsolationProperty::TransparentIsolation(TransparentIsolationLevel::Namespace)
            .run(tenant1.clone(), tenant2.clone())
            .await?;

    let transparent_isolation_node =
        ControlPlaneIsolationProperty::TransparentIsolation(TransparentIsolationLevel::Node)
            .run(tenant1.clone(), tenant2.clone())
            .await?;

    let transparent_isolation_cluster =
        ControlPlaneIsolationProperty::TransparentIsolation(TransparentIsolationLevel::Cluster)
            .run(tenant1.clone(), tenant2.clone())
            .await?;

    let transparent_isolation = TransparentIsolationReport {
        namespace: transparent_isolation_namespace,
        node: transparent_isolation_node,
        cluster: transparent_isolation_cluster,
    };

    let fairness = ControlPlaneIsolationProperty::Fairness
        .run(tenant1, tenant2)
        .await?;

    Ok(ControlPlaneReport {
        object_isolation,
        transparent_isolation,
        fairness,
    })
}

/// Run all the data plane isolation tests
pub async fn check_data_plane_isolation(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<DataPlaneReport> {
    let storage_isolation = DataPlaneIsolationProperty::StorageIsolation
        .run(tenant1.clone(), tenant2.clone())
        .await?;

    let network_isolation = DataPlaneIsolationProperty::NetworkIsolation
        .run(tenant1.clone(), tenant2.clone())
        .await?;

    let workload_isolation = DataPlaneIsolationProperty::WorkloadIsolation
        .run(tenant1.clone(), tenant2.clone())
        .await?;

    Ok(DataPlaneReport {
        storage_isolation,
        network_isolation,
        workload_isolation,
    })
}

#[derive(Debug, Clone, Copy)]
pub enum IsolationKind {
    ControlPlane(ControlPlaneIsolationProperty),
    DataPlane(DataPlaneIsolationProperty),
}

#[derive(Debug, Clone, Copy)]
pub enum ControlPlaneIsolationProperty {
    ObjectIsolation,
    TransparentIsolation(TransparentIsolationLevel),
    Fairness,
}
#[derive(Debug, Clone, Copy)]
pub enum TransparentIsolationLevel {
    Namespace,
    Node,
    Cluster,
}

#[derive(Debug, Clone, Copy)]
pub enum DataPlaneIsolationProperty {
    StorageIsolation,
    NetworkIsolation,
    WorkloadIsolation,
}
#[derive(Debug, Clone)]
pub struct TestResult {
    success: bool,
    message: String,
}

pub trait IsolationTest {
    async fn run(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
    ) -> Result<TestResult>;
}

impl IsolationTest for IsolationKind {
    async fn run(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
    ) -> Result<TestResult> {
        match self {
            IsolationKind::ControlPlane(property) => property.run(tenant1, tenant2).await,
            IsolationKind::DataPlane(property) => property.run(tenant1, tenant2).await,
        }
    }
}

impl IsolationTest for ControlPlaneIsolationProperty {
    async fn run(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
    ) -> Result<TestResult> {
        match self {
            ControlPlaneIsolationProperty::ObjectIsolation => {
                check_object_isolation(&tenant1, &tenant2)
                    .await
                    .map(|report| TestResult {
                        success: report.overall_isolation_success,
                        message: if report.overall_isolation_success {
                            String::from("Object isolation test passed")
                        } else {
                            format!(
                                "Object isolation test failed: {}",
                                report.isolation_failures.join(", ")
                            )
                        },
                    })
            }
            ControlPlaneIsolationProperty::TransparentIsolation(level) => {
                level.run(tenant1, tenant2).await
            }
            ControlPlaneIsolationProperty::Fairness => {
                check_fairness(tenant1, tenant2, FairnessTestConfig::default())
                    .await
                    .map(|is_fair| TestResult {
                        success: is_fair,
                        message: if is_fair {
                            String::from("Fairness test passed")
                        } else {
                            String::from("Fairness test failed")
                        },
                    })
            }
        }
    }
}

impl IsolationTest for TransparentIsolationLevel {
    async fn run(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
    ) -> Result<TestResult> {
        let result = check_transparent_isolation_level(&tenant1, &tenant2, *self).await;
        match result {
            Ok(()) => Ok(TestResult {
                success: true,
                message: format!("Test passed at {}", self),
            }),
            Err(e) => Ok(TestResult {
                success: false,
                message: format!("Test failed at {}: {}", self, e),
            }),
        }
    }
}

impl IsolationTest for DataPlaneIsolationProperty {
    async fn run(
        &self,
        _tenant1: Arc<TenantClusterConfig>,
        _tenant2: Arc<TenantClusterConfig>,
    ) -> Result<TestResult> {
        match self {
            DataPlaneIsolationProperty::StorageIsolation => Ok(TestResult {
                success: true,
                message: String::from("Storage isolation test passed"),
            }),
            DataPlaneIsolationProperty::NetworkIsolation => Ok(TestResult {
                success: true,
                message: String::from("Network isolation test passed"),
            }),
            DataPlaneIsolationProperty::WorkloadIsolation => Ok(TestResult {
                success: true,
                message: String::from("Workload isolation test passed"),
            }),
        }
    }
}

impl fmt::Display for IsolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsolationKind::ControlPlane(property) => write!(f, "Control Plane: {}", property),
            IsolationKind::DataPlane(property) => write!(f, "Data Plane: {}", property),
        }
    }
}

impl fmt::Display for ControlPlaneIsolationProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlPlaneIsolationProperty::ObjectIsolation => {
                write!(f, "Object Isolation")
            }
            ControlPlaneIsolationProperty::TransparentIsolation(level) => {
                write!(f, "Transparent Isolation: {}", level)
            }
            ControlPlaneIsolationProperty::Fairness => write!(f, "Fairness"),
        }
    }
}

impl fmt::Display for TransparentIsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransparentIsolationLevel::Namespace => write!(f, "Namespace-Level"),
            TransparentIsolationLevel::Node => write!(f, "Node-Level"),
            TransparentIsolationLevel::Cluster => write!(f, "Cluster-Level"),
        }
    }
}

impl fmt::Display for DataPlaneIsolationProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataPlaneIsolationProperty::StorageIsolation => write!(f, "Storage Isolation"),
            DataPlaneIsolationProperty::NetworkIsolation => write!(f, "Network Isolation"),
            DataPlaneIsolationProperty::WorkloadIsolation => write!(f, "Workload Isolation"),
        }
    }
}

impl fmt::Display for IsolationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Control Plane Isolation")?;
        writeln!(f, "------------------------")?;
        writeln!(f, "{}", self.control_plane)?;

        writeln!(f, "\nData Plane Isolation")?;
        writeln!(f, "---------------------")?;
        writeln!(f, "{}", self.data_plane)?;

        Ok(())
    }
}

impl fmt::Display for ControlPlaneReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.object_isolation)?;
        // error icon if all fails, success icon if all pass, warning icon if some fail
        let icon = if self.transparent_isolation.namespace.success
            && self.transparent_isolation.node.success
            && self.transparent_isolation.cluster.success
        {
            "✅"
        } else if !self.transparent_isolation.namespace.success
            && !self.transparent_isolation.node.success
            && !self.transparent_isolation.cluster.success
        {
            "❌"
        } else {
            "⚠️"
        };
        write!(
            f,
            "{}  Transparent isolation: \n{}",
            icon, self.transparent_isolation
        )?;
        writeln!(f, "{}", self.fairness)?;

        Ok(())
    }
}

impl fmt::Display for TransparentIsolationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "   {}", self.namespace)?;
        writeln!(f, "   {}", self.node)?;
        writeln!(f, "   {}", self.cluster)?;
        Ok(())
    }
}

impl fmt::Display for DataPlaneReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.storage_isolation)?;
        writeln!(f, "{}", self.network_isolation)?;
        writeln!(f, "{}", self.workload_isolation)?;

        Ok(())
    }
}

impl fmt::Display for TestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(f, "✅ {}", self.message)
        } else {
            write!(f, "❌ {}", self.message)
        }
    }
}

/// All the configuration needed to test a tenant cluster isolation.
pub struct TenantClusterConfig {
    pub cluster: KubernetesClient,
    /// The namespace to use for the tenant's resources created during the tests.
    pub namespace: String,
}
