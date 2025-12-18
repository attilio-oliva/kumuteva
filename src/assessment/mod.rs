mod control_plane;
mod network;
mod storage;
mod workload;

pub use control_plane::*;
pub use network::*;
pub use storage::*;
use tabled::settings::object::{Columns, Rows};
use tabled::settings::{Alignment, Border, Modify, Span, Style};
use tabled::{Table, Tabled};
pub use workload::*;

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use colored::Colorize;

use crate::verifier::TenantClusterConfig;

/// Safety level for cross-tenant operations
#[derive(Debug, Clone, PartialEq)]
pub enum SafetyLevel {
    Safe,
    Unsafe,
    Unknown,
}

/// Authorization level for operations
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizationLevel {
    /// Fully authorized - can always perform the operation
    Full,
    /// Partially authorized - can perform only if no collision with other tenants
    /// Contains description of what causes the collision
    Partial(String),
    /// Not authorized - operation is denied
    Denied,
}

impl AuthorizationLevel {
    pub fn is_authorized(&self) -> bool {
        matches!(
            self,
            AuthorizationLevel::Full | AuthorizationLevel::Partial(_)
        )
    }

    pub fn is_full(&self) -> bool {
        matches!(self, AuthorizationLevel::Full)
    }

    pub fn is_partial(&self) -> bool {
        matches!(self, AuthorizationLevel::Partial(_))
    }
}

impl Display for AuthorizationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationLevel::Full => write!(f, "✅ Full"),
            AuthorizationLevel::Partial(reason) => write!(f, "⚠️ Partial ({})", reason),
            AuthorizationLevel::Denied => write!(f, "❌ Denied"),
        }
    }
}

/// Result of assessing a single operation
#[derive(Debug, Clone)]
pub struct OperationAssessment {
    pub authorization: AuthorizationLevel,
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

/// Autonomy level categories for control plane resources
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneAutonomyLevels {
    /// Workload resources (Pods, Deployments, etc.) - inside namespace
    pub workload: AutonomyRatio,
    /// Scope resources (Namespace itself, ResourceQuota, LimitRange)
    pub scope: AutonomyRatio,
    /// Infrastructure resources (Node, DaemonSet)
    pub infrastructure: AutonomyRatio,
    /// Cluster-wide resources (ClusterRole, StorageClass, etc.)
    pub cluster: AutonomyRatio,
}

/// Represents an autonomy ratio with full/partial/denied counts
#[derive(Debug, Clone, Default)]
pub struct AutonomyRatio {
    pub full: usize,
    pub partial: usize,
    pub denied: usize,
}

impl AutonomyRatio {
    pub fn new(full: usize, partial: usize, denied: usize) -> Self {
        Self {
            full,
            partial,
            denied,
        }
    }

    pub fn total(&self) -> usize {
        self.full + self.partial + self.denied
    }

    /// Ratio of fully authorized operations
    pub fn full_ratio(&self) -> f64 {
        if self.total() == 0 {
            0.0
        } else {
            self.full as f64 / self.total() as f64
        }
    }

    /// Ratio of at least partially authorized operations
    pub fn authorized_ratio(&self) -> f64 {
        if self.total() == 0 {
            0.0
        } else {
            (self.full + self.partial) as f64 / self.total() as f64
        }
    }

    pub fn is_full_autonomy(&self) -> bool {
        self.total() > 0 && self.denied == 0 && self.partial == 0
    }

    pub fn has_any_autonomy(&self) -> bool {
        self.full > 0 || self.partial > 0
    }

    pub fn add(&mut self, other: &AutonomyRatio) {
        self.full += other.full;
        self.partial += other.partial;
        self.denied += other.denied;
    }
}

impl Display for AutonomyRatio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{} (full/partial/denied)",
            self.full, self.partial, self.denied
        )
    }
}

/// Final report for a subsystem
#[derive(Debug, Clone)]
pub struct SubsystemReport<R: AssessableResource> {
    pub name: String,
    pub assessments: Vec<ResourceAssessment<R>>,
    pub overall_autonomy: bool,
    pub overall_isolation: bool,
    pub autonomy_ratio: AutonomyRatio,
    pub warnings: Vec<String>,
}

impl<R: AssessableResource> SubsystemReport<R> {
    /// Calculate the autonomy ratio from assessments
    pub fn calculate_autonomy_ratio(assessments: &[ResourceAssessment<R>]) -> AutonomyRatio {
        let mut ratio = AutonomyRatio::default();

        for assessment in assessments {
            for op_assessment in assessment.operations.values() {
                match &op_assessment.authorization {
                    AuthorizationLevel::Full => ratio.full += 1,
                    AuthorizationLevel::Partial(_) => ratio.partial += 1,
                    AuthorizationLevel::Denied => ratio.denied += 1,
                }
            }
        }

        ratio
    }
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

    /// Check authorization level - now returns Full, Partial, or Denied
    async fn check_authorization(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &Self::Resource,
        operation: &<Self::Resource as AssessableResource>::Operation,
    ) -> anyhow::Result<AuthorizationLevel>;

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
            let authorization = assessor
                .check_authorization(tenant1, tenant2, &resource, &operation)
                .await?;

            let assessment = match &authorization {
                AuthorizationLevel::Denied => OperationAssessment {
                    authorization,
                    safe: SafetyLevel::Safe,
                    details: Some("Operation not authorized - access denied".to_string()),
                },
                AuthorizationLevel::Full | AuthorizationLevel::Partial(_) => {
                    let (safe, details) = assessor
                        .check_cross_tenant_effect(tenant1, tenant2, &resource, &operation)
                        .await?;

                    OperationAssessment {
                        authorization,
                        safe,
                        details: Some(details),
                    }
                }
            };

            ops_map.insert(operation, assessment);
        }

        let is_fully_autonomous = ops_map.values().all(|a| a.authorization.is_full());
        let is_partially_autonomous = ops_map.values().all(|a| a.authorization.is_authorized());
        let is_isolated = !ops_map.values().any(|a| a.safe == SafetyLevel::Unsafe);

        if is_partially_autonomous && !is_fully_autonomous {
            let partial_ops: Vec<_> = ops_map
                .iter()
                .filter(|(_, a)| a.authorization.is_partial())
                .map(|(op, _)| op.to_string())
                .collect();
            warnings.push(format!(
                "⚠️ {} has partial autonomy for: {}",
                resource,
                partial_ops.join(", ")
            ));
        }

        if is_partially_autonomous && !is_isolated {
            warnings.push(format!(
                "Warning: {} is usable but not isolated - potential security risk",
                resource
            ));
        }

        assessments.push(ResourceAssessment {
            resource,
            operations: ops_map,
            is_autonomous: is_fully_autonomous,
            is_isolated,
        });
    }

    let overall_autonomy = assessments.iter().all(|a| a.is_autonomous);
    let overall_isolation = assessments.iter().all(|a| a.is_isolated);
    let autonomy_ratio = SubsystemReport::calculate_autonomy_ratio(&assessments);

    Ok(SubsystemReport {
        name: assessor.name().to_string(),
        assessments,
        overall_autonomy,
        overall_isolation,
        autonomy_ratio,
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
        let auth_emoji = match self.authorization {
            AuthorizationLevel::Full => "✅",
            AuthorizationLevel::Partial(_) => "⚠️",
            AuthorizationLevel::Denied => "❌",
        };
        let safe_emoji = match self.safe {
            SafetyLevel::Safe => "🛡️",
            SafetyLevel::Unsafe => "⚠️",
            SafetyLevel::Unknown => "❓",
        };
        write!(
            f,
            "{} {}  {}{}",
            safe_emoji,
            "Safe".dimmed(),
            auth_emoji,
            "Authorization".dimmed()
        )
    }
}

/// Wraps text to fit within a maximum width, adding a prefix to continuation lines.
/// Also breaks on special separators (e.g., " - ") to improve readability.
/// Returns a vector of (prefix, content) pairs for each line.
fn wrap_text_lines(
    text: &str,
    max_width: usize,
    first_prefix: &str,
    continuation_prefix: &str,
) -> Vec<(String, String)> {
    const SEPARATOR: &str = " - ";
    const BULLET: &str = "• ";

    // First, split by the special separator
    let segments: Vec<&str> = text.split(SEPARATOR).collect();

    let mut lines: Vec<(String, String)> = Vec::new();
    let mut is_first_line = true;

    for (seg_idx, segment) in segments.iter().enumerate() {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        // Add bullet for non-first segments
        let segment_text = if seg_idx > 0 {
            format!("{}{}", BULLET, segment)
        } else {
            segment.to_string()
        };

        // Now wrap this segment by words if needed
        let prefix = if is_first_line {
            first_prefix.to_string()
        } else {
            continuation_prefix.to_string()
        };
        let available_width = max_width.saturating_sub(prefix.chars().count());

        // If segment fits in one line, just add it
        if segment_text.len() <= available_width {
            lines.push((prefix, segment_text));
            is_first_line = false;
        } else {
            // Word-wrap this segment
            let mut current_line = String::new();

            for word in segment_text.split_whitespace() {
                let line_prefix = if is_first_line {
                    first_prefix.to_string()
                } else {
                    continuation_prefix.to_string()
                };
                let width = max_width.saturating_sub(line_prefix.chars().count());

                if current_line.is_empty() {
                    current_line = word.to_string();
                } else if current_line.len() + 1 + word.len() <= width {
                    current_line.push(' ');
                    current_line.push_str(word);
                } else {
                    // Flush current line
                    lines.push((line_prefix, current_line));
                    current_line = word.to_string();
                    is_first_line = false;
                }
            }

            // Flush remaining words
            if !current_line.is_empty() {
                let line_prefix = if is_first_line {
                    first_prefix.to_string()
                } else {
                    continuation_prefix.to_string()
                };
                lines.push((line_prefix, current_line));
                is_first_line = false;
            }
        }
    }

    lines
}

/// Get terminal width, defaulting to 80 if unavailable.
/// Leaves some margin (2 characters), hence does not return the full width.
fn get_terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize - 2) // Leave some margin
        .unwrap_or(80)
}

impl<R: AssessableResource> Display for SubsystemReport<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let term_width = get_terminal_width();

        let iso_emoji = if self.overall_isolation { "✅" } else { "❌" };
        let auto_emoji = if self.overall_autonomy { "✅" } else { "❌" };

        writeln!(
            f,
            "⚙️  {} → {}{}  {}{}",
            self.name.bold(),
            iso_emoji,
            "Isolation".dimmed(),
            auto_emoji,
            "Autonomy".dimmed()
        )?;

        let has_warnings = !self.warnings.is_empty();
        let has_assessments = !self.assessments.is_empty();

        // Print warnings as part of the tree under "Findings"
        if has_warnings {
            let findings_prefix = if has_assessments {
                "├──"
            } else {
                "└──"
            };
            let findings_child_prefix = if has_assessments { "│   " } else { "    " };

            writeln!(
                f,
                "{} 📌 {}",
                findings_prefix.dimmed(),
                "Findings".yellow().bold()
            )?;

            let warnings_total = self.warnings.len();
            for (i, warning) in self.warnings.iter().enumerate() {
                let is_last_warning = i == warnings_total - 1;
                let warning_prefix = if is_last_warning {
                    "└──"
                } else {
                    "├──"
                };
                let first = format!("{}{} ⚠️  ", findings_child_prefix, warning_prefix);
                let cont = format!("{}       ", findings_child_prefix);
                let lines = wrap_text_lines(warning, term_width, &first, &cont);
                for (prefix, content) in lines {
                    writeln!(f, "{}{}", prefix.dimmed(), content.yellow())?;
                }
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
                "{} 📦 {} → {}{}  {}{}",
                res_prefix.dimmed(),
                assessment.resource.to_string().bold(),
                res_iso,
                "Isolation".dimmed(),
                res_auto,
                "Autonomy".dimmed()
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
                    child_prefix.dimmed(),
                    op_prefix.dimmed(),
                    operation.to_string().cyan(),
                    op_assessment
                )?;

                if let Some(details) = &op_assessment.details {
                    let first = format!("{}{}└── 💬 ", child_prefix, detail_prefix);
                    let cont = format!("{}{}       ", child_prefix, detail_prefix);
                    let lines = wrap_text_lines(details, term_width, &first, &cont);
                    for (prefix, content) in lines {
                        let colored_content = match op_assessment.safe {
                            SafetyLevel::Safe => content.green(),
                            SafetyLevel::Unsafe => content.red(),
                            SafetyLevel::Unknown => content.yellow(),
                        };
                        writeln!(f, "{}{}", prefix.dimmed(), colored_content)?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct MultitenancyReport {
    pub control_plane: SubsystemReport<ControlPlaneResource>,
    pub control_plane_autonomy_levels: ControlPlaneAutonomyLevels,
    pub storage: SubsystemReport<StorageResource>,
    pub network: SubsystemReport<NetworkResource>,
    pub workload: SubsystemReport<WorkloadResource>,
}

impl MultitenancyReport {
    pub fn overall_isolation(&self) -> bool {
        self.control_plane.overall_isolation
            && self.storage.overall_isolation
            && self.network.overall_isolation
            && self.workload.overall_isolation
    }

    pub fn overall_autonomy_ratio(&self) -> AutonomyRatio {
        let mut total = AutonomyRatio::default();
        total.add(&self.control_plane.autonomy_ratio);
        total.add(&self.storage.autonomy_ratio);
        total.add(&self.network.autonomy_ratio);
        total.add(&self.workload.autonomy_ratio);
        total
    }
}

/// Calculate control plane autonomy levels from assessments
fn calculate_control_plane_autonomy_levels(
    assessments: &[ResourceAssessment<ControlPlaneResource>],
) -> ControlPlaneAutonomyLevels {
    let mut levels = ControlPlaneAutonomyLevels::default();

    for assessment in assessments {
        let category = assessment.resource.autonomy_category();
        let ratio = match category {
            ControlPlaneAutonomyCategory::Workload => &mut levels.workload,
            ControlPlaneAutonomyCategory::Scope => &mut levels.scope,
            ControlPlaneAutonomyCategory::Infrastructure => &mut levels.infrastructure,
            ControlPlaneAutonomyCategory::Cluster => &mut levels.cluster,
        };

        for op_assessment in assessment.operations.values() {
            if op_assessment.authorization.is_full() {
                ratio.full += 1;
            } else if op_assessment.authorization.is_partial() {
                ratio.partial += 1;
            } else {
                ratio.denied += 1;
            }
        }
    }

    levels
}

pub async fn assess_multitenancy(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<MultitenancyReport> {
    let control_plane = run_assessment(&ControlPlaneAssessor, &tenant1, &tenant2).await?;
    let control_plane_autonomy_levels =
        calculate_control_plane_autonomy_levels(&control_plane.assessments);
    // sleep after every major assessment to allow resources to settle
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let storage = run_assessment(&StorageAssessor, &tenant1, &tenant2).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let network = run_assessment(&NetworkAssessor, &tenant1, &tenant2).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let workload = run_assessment(&WorkloadAssessor, &tenant1, &tenant2).await?;

    Ok(MultitenancyReport {
        control_plane,
        control_plane_autonomy_levels,
        storage,
        network,
        workload,
    })
}

#[derive(Tabled)]
struct ReportRow {
    #[tabled(rename = "System")]
    system: String,
    #[tabled(rename = "Property")]
    property: String,
    #[tabled(rename = "Value")]
    value: String,
}

fn format_ratio_with_icon(ratio: &AutonomyRatio) -> String {
    let icon = if ratio.is_full_autonomy() {
        "✅"
    } else if ratio.authorized_ratio() >= 0.5 {
        "🟡"
    } else if ratio.has_any_autonomy() {
        "🟠"
    } else {
        "❌"
    };
    format!("{} {}", icon, ratio)
}

fn format_isolation(isolated: bool) -> String {
    if isolated {
        "✅".to_string()
    } else {
        "❌".to_string()
    }
}

impl Display for MultitenancyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rows = Vec::new();

        // Control Plane section
        rows.push(ReportRow {
            system: "Control Plane".to_string(),
            property: "Isolation".to_string(),
            value: format_isolation(self.control_plane.overall_isolation),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "Autonomy".to_string(),
            value: format_ratio_with_icon(&self.control_plane.autonomy_ratio),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "  ├─ Workload".to_string(),
            value: format_ratio_with_icon(&self.control_plane_autonomy_levels.workload),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "  ├─ Scope".to_string(),
            value: format_ratio_with_icon(&self.control_plane_autonomy_levels.scope),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "  ├─ Infrastructure".to_string(),
            value: format_ratio_with_icon(&self.control_plane_autonomy_levels.infrastructure),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "  └─ Cluster".to_string(),
            value: format_ratio_with_icon(&self.control_plane_autonomy_levels.cluster),
        });

        // Separator row
        rows.push(ReportRow {
            system: "─────────────".to_string(),
            property: "─────────────────".to_string(),
            value: "─────────────────".to_string(),
        });

        // Storage section
        rows.push(ReportRow {
            system: "Storage".to_string(),
            property: "Isolation".to_string(),
            value: format_isolation(self.storage.overall_isolation),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "Autonomy".to_string(),
            value: format_ratio_with_icon(&self.storage.autonomy_ratio),
        });

        // Separator row
        rows.push(ReportRow {
            system: "─────────────".to_string(),
            property: "─────────────────".to_string(),
            value: "─────────────────".to_string(),
        });

        // Network section
        rows.push(ReportRow {
            system: "Network".to_string(),
            property: "Isolation".to_string(),
            value: format_isolation(self.network.overall_isolation),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "Autonomy".to_string(),
            value: format_ratio_with_icon(&self.network.autonomy_ratio),
        });

        // Separator row
        rows.push(ReportRow {
            system: "─────────────".to_string(),
            property: "─────────────────".to_string(),
            value: "─────────────────".to_string(),
        });

        // Workload section
        rows.push(ReportRow {
            system: "Workload".to_string(),
            property: "Isolation".to_string(),
            value: format_isolation(self.workload.overall_isolation),
        });
        rows.push(ReportRow {
            system: "".to_string(),
            property: "Autonomy".to_string(),
            value: format_ratio_with_icon(&self.workload.autonomy_ratio),
        });

        let table = Table::new(rows)
            .with(Style::rounded())
            .with(Modify::new(Rows::first()).with(Alignment::center()))
            .with(Modify::new(Rows::new(1..)).with(Alignment::left()))
            .to_string();

        writeln!(f, "\n📊 Multi-Tenancy Assessment Report")?;
        writeln!(f, "══════════════════════════════════\n")?;
        write!(f, "{}", table)?;

        // Overall summary
        let overall_iso = self.overall_isolation();
        let overall_auto = self.overall_autonomy_ratio();

        writeln!(f, "\n📋 Summary:")?;
        writeln!(f, "   Overall Isolation: {}", format_isolation(overall_iso))?;
        writeln!(
            f,
            "   Overall Autonomy:  {}",
            format_ratio_with_icon(&overall_auto)
        )?;

        if self.overall_autonomy_ratio().partial > 0 {
            writeln!(f, "\n⚠️  Partial autonomy detected - some operations may be forbidden when another tenant is active")?;
        }

        Ok(())
    }
}
