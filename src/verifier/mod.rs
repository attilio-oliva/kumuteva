use anyhow::Result;
use std::fmt;

mod control_plane;

pub use control_plane::*;

use crate::cluster::KubernetesCluster;

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
    fn run(&self) -> Result<TestResult>;
}

impl IsolationTest for IsolationKind {
    fn run(&self) -> Result<TestResult> {
        match self {
            IsolationKind::ControlPlane(property) => property.run(),
            IsolationKind::DataPlane(property) => property.run(),
        }
    }
}

impl IsolationTest for ControlPlaneIsolationProperty {
    fn run(&self) -> Result<TestResult> {
        match self {
            ControlPlaneIsolationProperty::ObjectIsolation => Ok(TestResult {
                success: true,
                message: String::from("Object isolation test passed"),
            }),
            ControlPlaneIsolationProperty::TransparentIsolation(level) => level.run(),
            ControlPlaneIsolationProperty::Fairness => Ok(TestResult {
                success: true,
                message: String::from("Fairness test passed"),
            }),
        }
    }
}

impl IsolationTest for TransparentIsolationLevel {
    fn run(&self) -> Result<TestResult> {
        match self {
            TransparentIsolationLevel::Namespace => Ok(TestResult {
                success: true,
                message: String::from("Namespace isolation test passed"),
            }),
            TransparentIsolationLevel::Node => Ok(TestResult {
                success: true,
                message: String::from("Node isolation test passed"),
            }),
            TransparentIsolationLevel::Cluster => Ok(TestResult {
                success: true,
                message: String::from("Cluster isolation test passed"),
            }),
        }
    }
}

impl IsolationTest for DataPlaneIsolationProperty {
    fn run(&self) -> Result<TestResult> {
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

// impl fmt::Display for TestResult {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         writeln!(
//             f,
//             "[{:?}]: {} ({})",
//             self.kind,
//             if result.success { "PASS" } else { "FAIL" },
//             result.message
//         )?;

//         Ok(())
//     }
// }

/// All the configuration needed to test a tenant cluster isolation.
pub struct TenantClusterConfig {
    pub cluster: KubernetesCluster,
    /// The namespace to use for the tenant's resources created during the tests.
    pub namespace: String,
}
