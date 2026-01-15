mod control_plane;
mod network;
mod storage;
mod workload;

pub use control_plane::*;

pub use network::*;
pub use storage::*;
pub use workload::*;

use tabled::settings::object::{Columns, Rows};
use tabled::settings::{Alignment, Border, Modify, Span, Style};
use tabled::{Table, Tabled};

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use colored::Colorize;

use crate::verifier::TenantClusterConfig;

/// Isolation level for cross-tenant operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Isolation level could not be determined
    Unknown,
    /// No isolation - cross-tenant operation succeeded and affected other tenant's resources
    None,
    /// Soft isolation - operation blocked but reveals shared environment
    /// (e.g., Forbidden error, AlreadyExists indicating name collision)
    Soft(String),
    /// Hard isolation - operation fails as if system were single-tenant
    /// (e.g., NotFound error because resource doesn't exist in intruder's scope)
    Hard,
}

impl IsolationLevel {
    pub fn is_isolated(&self) -> bool {
        !matches!(self, IsolationLevel::None)
    }

    pub fn is_hard(&self) -> bool {
        matches!(self, IsolationLevel::Hard)
    }
}

impl PartialOrd for IsolationLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IsolationLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(level: &IsolationLevel) -> u8 {
            match level {
                IsolationLevel::None => 0, // Worst
                IsolationLevel::Unknown => 1,
                IsolationLevel::Soft(_) => 2,
                IsolationLevel::Hard => 3, // Best
            }
        }
        rank(self).cmp(&rank(other))
    }
}

fn compute_overall_isolation_level(assessments: &[IsolationLevel]) -> IsolationLevel {
    assessments
        .iter()
        .min()
        .cloned()
        .unwrap_or(IsolationLevel::Hard)
}

/// Result of assessing a single operation
#[derive(Debug, Clone)]
pub struct OperationAssessment {
    pub isolation: IsolationLevel,
    pub autonomy: bool,
    pub details: Option<String>,
}

/// Assessment of a single resource with all its operations
#[derive(Debug, Clone)]
pub struct ResourceAssessment<R: AssessableResource> {
    pub resource: R,
    pub operations: HashMap<R::Operation, OperationAssessment>,
    pub overall_isolation: IsolationLevel,
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

/// Represents an autonomy ratio with allowed/total counts
#[derive(Debug, Clone, Default)]
pub struct AutonomyRatio {
    pub allowed: usize,
    pub total: usize,
}

impl AutonomyRatio {
    pub fn new(allowed: usize, total: usize) -> Self {
        Self { allowed, total }
    }

    pub fn add(&mut self, other: &Self) {
        self.allowed += other.allowed;
        self.total += other.total;
    }

    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.allowed as f64 / self.total as f64) * 100.0
        }
    }

    pub fn is_perfect(&self) -> bool {
        self.total > 0 && self.allowed == self.total
    }
}

impl Display for AutonomyRatio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} ({:.1}%)",
            self.allowed,
            self.total,
            self.percentage(),
        )
    }
}

/// Final report for a subsystem
#[derive(Debug, Clone)]
pub struct SubsystemReport<R: AssessableResource> {
    pub name: String,
    pub assessments: Vec<ResourceAssessment<R>>,
    pub isolation_level: IsolationLevel,
    pub autonomy_ratio: AutonomyRatio,
    pub warnings: Vec<String>,
}

impl<R: AssessableResource> SubsystemReport<R> {
    /// Calculate the autonomy ratio from assessments
    pub fn calculate_autonomy_ratio(assessments: &[ResourceAssessment<R>]) -> AutonomyRatio {
        let mut ratio = AutonomyRatio::default();

        for assessment in assessments {
            for op_assessment in assessment.operations.values() {
                ratio.total += 1;
                if op_assessment.autonomy {
                    ratio.allowed += 1;
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

/// Result from a cross-tenant operation attempt
#[derive(Debug, Clone)]
pub struct CrossTenantResult {
    /// The isolation level determined from the operation
    pub isolation: IsolationLevel,
    /// Whether the operation had autonomy (i.e., was permitted)
    pub autonomy: bool,
    /// Detailed description of what happened
    pub details: String,
}

/// The core assessment logic each subsystem implements
#[async_trait]
pub trait MultitenancyAssessor: Send + Sync {
    type Resource: AssessableResource;

    fn name(&self) -> &'static str;

    /// Check if the tenant has basic authorization to perform the operation.
    /// This is used only to determine if there's ZERO autonomy.
    /// Returns true if the operation is permitted at all.
    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &Self::Resource,
        operation: &<Self::Resource as AssessableResource>::Operation,
    ) -> anyhow::Result<bool>;

    /// Perform the cross-tenant effect check by actually attempting the operation.
    /// This returns both isolation AND autonomy levels based on the actual results.
    ///
    /// The function should:
    /// 1. Have tenant1 create/setup a resource
    /// 2. Have tenant2 attempt to operate on it (or create with same name for CREATE)
    /// 3. Infer isolation from whether tenant2 affected tenant1's resource
    /// 4. Infer autonomy from the operation result
    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &Self::Resource,
        operation: &<Self::Resource as AssessableResource>::Operation,
    ) -> anyhow::Result<CrossTenantResult>;
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
            // First, check if tenant1 has basic authorization
            let authorized = assessor
                .is_authorized(tenant1, &resource, &operation)
                .await?;

            let assessment = if !authorized {
                // Zero autonomy - operation not permitted at all
                OperationAssessment {
                    autonomy: false,
                    isolation: IsolationLevel::Hard, // If not authorized, it's safe by definition
                    details: Some("Operation not authorized - no autonomy".to_string()),
                }
            } else {
                // Authorized - proceed with cross-tenant effect check
                // This will determine both isolation AND autonomy
                let result = assessor
                    .check_cross_tenant_effect(tenant1, tenant2, &resource, &operation)
                    .await?;

                OperationAssessment {
                    autonomy: result.autonomy,
                    isolation: result.isolation,
                    details: Some(result.details),
                }
            };

            ops_map.insert(operation, assessment);
        }

        // Determine overall autonomy for resource: all operations have Full autonomy
        let is_autonomous = ops_map.values().all(|a| a.autonomy);

        // Determine isolation
        let overall_isolation = compute_overall_isolation_level(
            ops_map
                .values()
                .map(|a| a.isolation.clone())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        // Generate warnings for partial isolation
        if overall_isolation == IsolationLevel::None {
            warnings.push(format!(
                "Resource {} has unsafe cross-tenant operations",
                resource
            ));

        // Generate warnings for unknown isolation
        } else if ops_map
            .values()
            .any(|a| a.isolation == IsolationLevel::Unknown)
        {
            warnings.push(format!(
                "Resource {} has unknown isolation for some operations",
                resource
            ));
        }

        assessments.push(ResourceAssessment {
            resource,
            operations: ops_map,
            overall_isolation,
        });
    }

    let overall_isolation = compute_overall_isolation_level(
        assessments
            .iter()
            .map(|a| a.overall_isolation.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let autonomy_ratio = SubsystemReport::calculate_autonomy_ratio(&assessments);

    Ok(SubsystemReport {
        name: assessor.name().to_string(),
        assessments,
        isolation_level: overall_isolation,
        autonomy_ratio,
        warnings,
    })
}

impl Display for OperationAssessment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth_emoji = match self.autonomy {
            true => "🟢",
            false => "🔴",
        };
        let safe_emoji = match self.isolation {
            IsolationLevel::Hard => "🟢",
            IsolationLevel::Soft(_) => "🟠",
            IsolationLevel::None => "⚠️",
            IsolationLevel::Unknown => "❓",
        };
        write!(
            f,
            "{} {}  {}{}",
            safe_emoji,
            "Isolation".dimmed(),
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

        let iso_emoji = match self.isolation_level {
            IsolationLevel::Hard => "✅",
            IsolationLevel::Soft(_) => "🟠",
            IsolationLevel::None => "❌",
            IsolationLevel::Unknown => "❓",
        };
        let auto_emoji = if self.autonomy_ratio.is_perfect() {
            "✅"
        } else if self.autonomy_ratio.percentage() >= 50.0 {
            "🟡"
        } else if self.autonomy_ratio.allowed > 0 {
            "🟠"
        } else {
            "❌"
        };

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

            let res_iso = match assessment.overall_isolation {
                IsolationLevel::Hard => "✅",
                IsolationLevel::Soft(_) => "🟠",
                IsolationLevel::None => "❌",
                IsolationLevel::Unknown => "❓",
            };
            let res_auto =
                match SubsystemReport::<R>::calculate_autonomy_ratio(&[assessment.clone()]) {
                    ratio if ratio.is_perfect() => "✅",
                    ratio if ratio.percentage() >= 50.0 => "🟡",
                    ratio if ratio.allowed > 0 => "🟠",
                    _ => "❌",
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

            let mut ops: Vec<_> = assessment.operations.iter().collect::<Vec<_>>();
            ops.sort_by_key(|(op, _)| op.to_string());
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
                        let colored_content = match op_assessment.isolation {
                            IsolationLevel::Hard => content.green(),
                            IsolationLevel::Soft(_) => content.yellow(),
                            IsolationLevel::None => content.red(),
                            IsolationLevel::Unknown => content.dimmed(),
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
    pub fn overall_isolation(&self) -> IsolationLevel {
        compute_overall_isolation_level(&[
            self.control_plane.isolation_level.clone(),
            self.storage.isolation_level.clone(),
            self.network.isolation_level.clone(),
            self.workload.isolation_level.clone(),
        ])
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
            ratio.total += 1;
            if op_assessment.autonomy {
                ratio.allowed += 1;
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
    let icon = if ratio.is_perfect() {
        "✅"
    } else if ratio.percentage() >= 50.0 {
        "🟡"
    } else if ratio.allowed > 0 {
        "🟠"
    } else {
        "❌"
    };
    format!("{} {}", icon, ratio)
}

fn format_isolation(level: &IsolationLevel) -> String {
    match level {
        IsolationLevel::Hard => "✅ Hard".to_string(),
        IsolationLevel::Soft(_reason) => format!("🟠 Soft"),
        IsolationLevel::None => "❌ None".to_string(),
        IsolationLevel::Unknown => "❓ Unknown".to_string(),
    }
}

impl Display for MultitenancyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rows = vec![
            // Control Plane section
            ReportRow {
                system: "Control Plane".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation(&self.control_plane.isolation_level),
            },
            ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&self.control_plane.autonomy_ratio),
            },
            ReportRow {
                system: "".to_string(),
                property: "  ├─ Workload".to_string(),
                value: format_ratio_with_icon(&self.control_plane_autonomy_levels.workload),
            },
            ReportRow {
                system: "".to_string(),
                property: "  ├─ Scope".to_string(),
                value: format_ratio_with_icon(&self.control_plane_autonomy_levels.scope),
            },
            ReportRow {
                system: "".to_string(),
                property: "  ├─ Infrastructure".to_string(),
                value: format_ratio_with_icon(&self.control_plane_autonomy_levels.infrastructure),
            },
            ReportRow {
                system: "".to_string(),
                property: "  └─ Cluster".to_string(),
                value: format_ratio_with_icon(&self.control_plane_autonomy_levels.cluster),
            },
            // Separator row
            ReportRow {
                system: "─────────────".to_string(),
                property: "─────────────────".to_string(),
                value: "─────────────────".to_string(),
            },
            // Storage section
            ReportRow {
                system: "Storage".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation(&self.storage.isolation_level),
            },
            ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&self.storage.autonomy_ratio),
            },
            // Separator row
            ReportRow {
                system: "─────────────".to_string(),
                property: "─────────────────".to_string(),
                value: "─────────────────".to_string(),
            },
            // Network section
            ReportRow {
                system: "Network".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation(&self.network.isolation_level),
            },
            ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&self.network.autonomy_ratio),
            },
            // Separator row
            ReportRow {
                system: "─────────────".to_string(),
                property: "─────────────────".to_string(),
                value: "─────────────────".to_string(),
            },
            // Workload section
            ReportRow {
                system: "Workload".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation(&self.workload.isolation_level),
            },
            ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&self.workload.autonomy_ratio),
            },
        ];

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
        writeln!(
            f,
            "   Overall Isolation: {}",
            format_isolation(&overall_iso)
        )?;
        writeln!(
            f,
            "   Overall Autonomy:  {}",
            format_ratio_with_icon(&overall_auto)
        )?;

        Ok(())
    }
}
