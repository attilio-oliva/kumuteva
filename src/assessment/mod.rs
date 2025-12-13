mod storage;
mod workload;

pub use storage::*;
pub use workload::*;

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;

use async_trait::async_trait;

use crate::verifier::TenantClusterConfig;

/// Safety level for cross-tenant operations
#[derive(Debug, Clone, PartialEq)]
pub enum SafetyLevel {
    Safe,
    Unsafe,
    Unknown,
}

/// Result of assessing a single operation
#[derive(Debug, Clone)]
pub struct OperationAssessment {
    pub authorized: bool,
    pub safe: SafetyLevel,
    pub details: Option<String>,
}

/// Assessment of a single resource with all its operations
#[derive(Debug, Clone)]
pub struct ResourceAssessment<R: AssessableResource> {
    pub resource: R,
    pub operations: HashMap<R::Operation, OperationAssessment>,
    pub is_autonomous: bool,
    pub is_isolated: bool,
}

/// Final report for a subsystem
#[derive(Debug, Clone)]
pub struct SubsystemReport<R: AssessableResource> {
    pub name: String,
    pub assessments: Vec<ResourceAssessment<R>>,
    pub overall_autonomy: bool,
    pub overall_isolation: bool,
    pub warnings: Vec<String>,
}

/// A resource that can be assessed for multi-tenancy properties
pub trait AssessableResource: Clone + Display + std::fmt::Debug + Send + Sync + 'static {
    type Operation: Clone + Display + std::fmt::Debug + Eq + Hash + Send + Sync + 'static;

    fn all() -> Vec<Self>;
    fn applicable_operations(&self) -> Vec<Self::Operation>;
}

/// The core assessment logic each subsystem implements
#[async_trait]
pub trait MultitenancyAssessor: Send + Sync {
    type Resource: AssessableResource;

    fn name(&self) -> &'static str;

    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &Self::Resource,
        operation: &<Self::Resource as AssessableResource>::Operation,
    ) -> anyhow::Result<bool>;

    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &Self::Resource,
        operation: &<Self::Resource as AssessableResource>::Operation,
    ) -> anyhow::Result<(SafetyLevel, String)>;
}

/// Generic runner that works with any assessor
pub async fn run_assessment<A: MultitenancyAssessor>(
    assessor: &A,
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<SubsystemReport<A::Resource>> {
    println!("Assessing {} isolation...", assessor.name());

    let resources = A::Resource::all();
    let mut assessments = Vec::new();
    let mut warnings = Vec::new();

    for resource in resources {
        let operations = resource.applicable_operations();
        if operations.is_empty() {
            continue;
        }

        let mut ops_map = HashMap::new();

        for operation in operations {
            let authorized = assessor
                .is_authorized(tenant1, &resource, &operation)
                .await?;

            let assessment = if !authorized {
                OperationAssessment {
                    authorized: false,
                    safe: SafetyLevel::Safe,
                    details: Some("Operation not authorized - access denied".to_string()),
                }
            } else {
                let (safe, details) = assessor
                    .check_cross_tenant_effect(tenant1, tenant2, &resource, &operation)
                    .await?;

                OperationAssessment {
                    authorized: true,
                    safe,
                    details: Some(details),
                }
            };

            ops_map.insert(operation, assessment);
        }

        let is_autonomous = ops_map.values().all(|a| a.authorized);
        let is_isolated = !ops_map.values().any(|a| a.safe == SafetyLevel::Unsafe);

        if is_autonomous && !is_isolated {
            warnings.push(format!(
                "Warning: {} is usable but not isolated - potential security risk",
                resource
            ));
        }

        assessments.push(ResourceAssessment {
            resource,
            operations: ops_map,
            is_autonomous,
            is_isolated,
        });
    }

    let overall_autonomy = assessments.iter().all(|a| a.is_autonomous);
    let overall_isolation = assessments.iter().all(|a| a.is_isolated);

    Ok(SubsystemReport {
        name: assessor.name().to_string(),
        assessments,
        overall_autonomy,
        overall_isolation,
        warnings,
    })
}

impl Display for SafetyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyLevel::Safe => write!(f, "Safe"),
            SafetyLevel::Unsafe => write!(f, "Unsafe"),
            SafetyLevel::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Display for OperationAssessment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth_emoji = if self.authorized { "✅" } else { "❌" };
        let safe_emoji = match self.safe {
            SafetyLevel::Safe => "🛡️",
            SafetyLevel::Unsafe => "⚠️",
            SafetyLevel::Unknown => "❓",
        };
        write!(f, "Auth: {} | Safety: {}", auth_emoji, safe_emoji)
    }
}

impl<R: AssessableResource> Display for SubsystemReport<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let iso_emoji = if self.overall_isolation { "✅" } else { "❌" };
        let auto_emoji = if self.overall_autonomy { "✅" } else { "❌" };

        writeln!(
            f,
            "⚙️  {} (Isolation: {} | Autonomy: {})",
            self.name, iso_emoji, auto_emoji
        )?;

        if !self.warnings.is_empty() {
            for warning in &self.warnings {
                writeln!(f, "   ⚠️  {}", warning)?;
            }
        }

        let total = self.assessments.len();
        for (i, assessment) in self.assessments.iter().enumerate() {
            let is_last_resource = i == total - 1;
            let res_prefix = if is_last_resource {
                "└──"
            } else {
                "├──"
            };
            let child_prefix = if is_last_resource { "    " } else { "│   " };

            let res_iso = if assessment.is_isolated { "✅" } else { "❌" };
            let res_auto = if assessment.is_autonomous {
                "✅"
            } else {
                "❌"
            };

            writeln!(
                f,
                "{} 📦 {} (Isolation: {} | Autonomy: {})",
                res_prefix, assessment.resource, res_iso, res_auto
            )?;

            let ops: Vec<_> = assessment.operations.iter().collect();
            let ops_total = ops.len();
            for (j, (operation, op_assessment)) in ops.iter().enumerate() {
                let is_last_op = j == ops_total - 1;
                let op_prefix = if is_last_op { "└──" } else { "├──" };
                let detail_prefix = if is_last_op { "    " } else { "│   " };

                writeln!(
                    f,
                    "{}{} {} → {}",
                    child_prefix, op_prefix, operation, op_assessment
                )?;

                if let Some(details) = &op_assessment.details {
                    writeln!(f, "{}{}    💬 {}", child_prefix, detail_prefix, details)?;
                }
            }
        }
        Ok(())
    }
}

/* TODO: use when the refactor is complete

pub struct MultitenancyReport {
    pub control_plane: SubsystemReport<ControlPlaneResource>,
    pub storage: SubsystemReport<StorageResource>,
    pub network: SubsystemReport<NetworkResource>,
    pub workload: SubsystemReport<WorkloadResource>,
    pub fairness: FairnessReport, // Separate since it's different
}

impl MultitenancyReport {
    pub fn overall_isolation(&self) -> bool {
        self.control_plane.overall_isolation
            && self.storage.overall_isolation
            && self.network.overall_isolation
            && self.workload.overall_isolation
    }
}
*/

/*  TODO: use in main
pub async fn assess_multitenancy(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<MultitenancyReport> {
    let control_plane = run_assessment(&ControlPlaneAssessor, &tenant1, &tenant2).await?;
    let storage = run_assessment(&StorageAssessor, &tenant1, &tenant2).await?;
    let network = run_assessment(&NetworkAssessor, &tenant1, &tenant2).await?;
    let workload = run_assessment(&WorkloadAssessor, &tenant1, &tenant2).await?;

    // Fairness is special - run separately
    let fairness = check_fairness(tenant1, tenant2, FairnessTestConfig::default()).await?;

    Ok(MultitenancyReport {
        control_plane,
        storage,
        network,
        workload,
        fairness,
    })
}

*/
