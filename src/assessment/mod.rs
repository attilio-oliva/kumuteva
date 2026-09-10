// Isolation assessment modules (for multi-tenancy isolation checks)
mod breach;
mod control_plane;
mod network;
pub mod probe;
pub mod storage;
mod workload;

pub mod fairness_assessor;
pub mod report_json;

// Re-export isolation assessment types
pub use control_plane::*;
pub use network::*;
pub use storage::*;
pub use workload::*;

use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Style};
use tabled::{Table, Tabled};

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use colored::Colorize;

use crate::cluster::KubernetesClient;

/// All the configuration needed to test a tenant cluster isolation.
#[derive(Clone)]
pub struct TenantClusterConfig {
    pub cluster: KubernetesClient,
    /// The namespace to use for the tenant's resources created during the tests.
    pub namespace: String,
}
/// Configuration for which assessment systems to run.
/// By default, all systems are enabled. If any flag is explicitly set,
/// only the specified systems will be assessed.
#[derive(Debug, Clone, Default)]
pub struct AssessmentConfig {
    pub control_plane: bool,
    pub storage: bool,
    pub network: bool,
    pub workload: bool,
}

impl AssessmentConfig {
    /// Create a new config with all systems enabled
    pub fn all() -> Self {
        Self {
            control_plane: true,
            storage: true,
            network: true,
            workload: true,
        }
    }

    /// Create config from CLI flags.
    /// If no flags are set, all systems are enabled (default behavior).
    /// If any flag is set, only those systems are enabled (exclusive mode).
    pub fn from_flags(control_plane: bool, storage: bool, network: bool, workload: bool) -> Self {
        let any_specified = control_plane || storage || network || workload;

        if any_specified {
            // Exclusive mode: only run what was explicitly specified
            Self {
                control_plane,
                storage,
                network,
                workload,
            }
        } else {
            // Default mode: run all assessments
            Self::all()
        }
    }

    /// Get a list of enabled system names
    pub fn enabled_systems(&self) -> Vec<&'static str> {
        let mut systems = Vec::new();
        if self.control_plane {
            systems.push("control-plane");
        }
        if self.storage {
            systems.push("storage");
        }
        if self.network {
            systems.push("network");
        }
        if self.workload {
            systems.push("workload");
        }
        systems
    }
}

impl Display for AssessmentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let systems = self.enabled_systems();
        if systems.is_empty() {
            write!(f, "No systems enabled")
        } else {
            write!(f, "Assessing {}", systems.join(", "))
        }
    }
}

/// The message from an API server that refused a request on policy grounds,
/// or `None` if the error was something else.
///
/// A probe pod can be turned away by Pod Security Admission, a validating
/// webhook, or a quota. That is a fact about the tenant being assessed, not a
/// malfunction, and it must not be allowed to end the run: a single refused
/// pod used to propagate out of the network subsystem and take the whole
/// report with it, so a `capsule-hardened` tenant produced no control-plane,
/// storage or workload results either.
///
/// 403 is admission or RBAC saying no. 422 is a webhook rejecting the object as
/// invalid, which is how several policy engines express a denial.
pub fn admission_refusal(error: &anyhow::Error) -> Option<String> {
    error
        .chain()
        .find_map(|cause| match cause.downcast_ref::<kube::Error>() {
            Some(kube::Error::Api(response)) if response.code == 403 || response.code == 422 => {
                Some(response.message.clone())
            }
            _ => None,
        })
}

/// What an authorization probe established about an operation on its own,
/// before any cross-tenant question is asked.
///
/// Replaces a `bool`, and the missing third case is why. The probes attempt
/// the operation and used to report `result.is_ok()`, which makes a policy
/// saying no indistinguishable from a name collision, a timeout, or an API
/// hiccup. Both read as "not authorized", and the runner scored that as `Hard`
/// — so a flaky create produced the most reassuring verdict in the table.
///
/// Observed: `native+gvisor` reported `Use Privileged Syscalls` as authorized
/// on one run and not on the next, with no configuration change between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// The tenant may perform the operation in its own namespace.
    Allowed,
    /// A policy refused it. The tenant learns a restriction exists.
    Forbidden(String),
    /// The API accepted the operation and it had no effect: nothing was
    /// refused, and nothing happened either.
    ///
    /// A virtual cluster does this with the kinds it synthesises. vCluster
    /// admits a `Node` create — the tenant is admin of its own API server, so
    /// RBAC has no objection — and its syncer then discards the object, which
    /// never appears. The tenant has no autonomy over the kind, yet it was told
    /// no restriction: what it observes afterwards is a cluster in which the
    /// object simply does not exist, which is what a lone tenant observes too.
    /// So autonomy is false and isolation is `Hard`.
    ///
    /// Distinct from [`Authorization::Forbidden`], which is `Soft` precisely
    /// because a refusal discloses that a restriction exists. Nothing is
    /// disclosed here.
    Ineffective(String),
    /// The probe failed for a reason that is not a policy decision, so
    /// nothing was established either way.
    Undetermined(String),
}

impl Authorization {
    /// Classify the outcome of a probe attempted purely to see whether the
    /// tenant is allowed to do something.
    pub fn from_attempt<T>(outcome: anyhow::Result<T>) -> Self {
        match outcome {
            Ok(_) => Authorization::Allowed,
            Err(error) => match admission_refusal(&error) {
                Some(message) => Authorization::Forbidden(message),
                None => Authorization::Undetermined(error.to_string()),
            },
        }
    }

    /// Both halves must be allowed for the whole to be.
    ///
    /// A policy refusal is decisive and outranks an undetermined half: the
    /// operation is forbidden whatever the other probe did. An ineffective half
    /// ranks below a refusal — a refusal that did happen is the stronger
    /// finding — and above an undetermined one, which established nothing.
    pub fn and(self, other: Authorization) -> Self {
        match (self, other) {
            (Authorization::Forbidden(why), _) | (_, Authorization::Forbidden(why)) => {
                Authorization::Forbidden(why)
            }
            (Authorization::Ineffective(why), _) | (_, Authorization::Ineffective(why)) => {
                Authorization::Ineffective(why)
            }
            (Authorization::Undetermined(why), _) | (_, Authorization::Undetermined(why)) => {
                Authorization::Undetermined(why)
            }
            (Authorization::Allowed, Authorization::Allowed) => Authorization::Allowed,
        }
    }
}

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

/// Computes the minimum isolation level from known assessments only (excluding Unknown).
/// Returns None if all assessments are Unknown or the list is empty.
fn compute_min_known_isolation_level(assessments: &[IsolationLevel]) -> Option<IsolationLevel> {
    assessments
        .iter()
        .filter(|l| !matches!(l, IsolationLevel::Unknown))
        .min()
        .cloned()
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

    /// Returns the minimum known isolation level (excluding Unknown values) from this subsystem's assessments.
    /// Returns None if all assessments have Unknown isolation.
    pub fn min_known_isolation(&self) -> Option<IsolationLevel> {
        let levels: Vec<IsolationLevel> = self
            .assessments
            .iter()
            .map(|a| a.overall_isolation.clone())
            .collect();
        compute_min_known_isolation_level(&levels)
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

    /// Check whether the tenant may perform the operation in its own
    /// namespace, before any cross-tenant question is asked.
    ///
    /// Three outcomes, not two: see [`Authorization`]. A probe that fails for
    /// a reason other than policy must say so rather than reporting the
    /// operation forbidden.
    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &Self::Resource,
        operation: &<Self::Resource as AssessableResource>::Operation,
    ) -> anyhow::Result<Authorization>;

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

            let assessment = match authorized {
                // A policy refused the operation outright. That is soft, not
                // hard: the tenant is told it may not do this, which is
                // exactly the "forbidden error you can infer a policy from"
                // case. Hard is reserved for an operation that *runs* and
                // returns what a lone tenant would have got anyway — and this
                // one never ran, so it cannot have earned that.
                //
                // This read `Hard` with the comment "if not authorized, it's
                // safe by definition", which contradicted `IsolationLevel`'s
                // own documentation and scored every prohibition as the
                // strongest possible isolation.
                Authorization::Forbidden(why) => OperationAssessment {
                    autonomy: false,
                    isolation: IsolationLevel::Soft(format!("Operation forbidden: {why}")),
                    details: Some(format!("Operation not authorized — {why}")),
                },
                // Accepted and inert. No autonomy, because the tenant cannot
                // make the operation do anything; `Hard` isolation, because
                // what it is left looking at is a cluster where the object does
                // not exist — indistinguishable from single tenancy, and
                // nothing about another tenant leaked to produce it.
                //
                // This is the verdict `test_cross_tenant_create` already
                // reaches for the same situation; routing it through the
                // authorization gate keeps DELETE from calling it a refusal.
                Authorization::Ineffective(why) => OperationAssessment {
                    autonomy: false,
                    isolation: IsolationLevel::Hard,
                    details: Some(format!(
                        "Operation accepted but ineffective — {why}, so the tenant \
                         is left with the view a single tenant would have"
                    )),
                },
                // Neither allowed nor refused: the probe itself did not work,
                // so there is nothing to report but that.
                Authorization::Undetermined(why) => OperationAssessment {
                    autonomy: true,
                    isolation: IsolationLevel::Unknown,
                    details: Some(format!(
                        "The authorization probe failed for a reason that is not a \
                         policy decision, so neither autonomy nor isolation was \
                         measured — {why}"
                    )),
                },
                // Permitted, so the cross-tenant question is worth asking.
                // That check determines both isolation and autonomy.
                Authorization::Allowed => {
                    let result = assessor
                        .check_cross_tenant_effect(tenant1, tenant2, &resource, &operation)
                        .await?;

                    OperationAssessment {
                        autonomy: result.autonomy,
                        isolation: result.isolation,
                        details: Some(result.details),
                    }
                }
            };

            ops_map.insert(operation, assessment);
        }

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
            "{}{}  {}{}",
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
    pub control_plane: Option<SubsystemReport<ControlPlaneResource>>,
    pub control_plane_autonomy_levels: Option<ControlPlaneAutonomyLevels>,
    pub storage: Option<SubsystemReport<StorageResource>>,
    pub network: Option<SubsystemReport<NetworkResource>>,
    pub workload: Option<SubsystemReport<WorkloadResource>>,
}

impl MultitenancyReport {
    pub fn overall_isolation(&self) -> IsolationLevel {
        let levels: Vec<IsolationLevel> = [
            self.control_plane
                .as_ref()
                .map(|r| r.isolation_level.clone()),
            self.storage.as_ref().map(|r| r.isolation_level.clone()),
            self.network.as_ref().map(|r| r.isolation_level.clone()),
            self.workload.as_ref().map(|r| r.isolation_level.clone()),
        ]
        .into_iter()
        .flatten()
        .collect();

        if levels.is_empty() {
            return IsolationLevel::Unknown;
        }
        compute_overall_isolation_level(&levels)
    }

    /// Returns the minimum known isolation level (excluding Unknown values).
    /// This digs into subsystem assessments to find the minimum known level.
    /// Returns None if all levels are Unknown.
    pub fn min_known_isolation(&self) -> Option<IsolationLevel> {
        // Collect min_known from each subsystem (which looks at individual resource assessments)
        let min_known_levels: Vec<IsolationLevel> = [
            self.control_plane
                .as_ref()
                .and_then(|r| r.min_known_isolation()),
            self.storage.as_ref().and_then(|r| r.min_known_isolation()),
            self.network.as_ref().and_then(|r| r.min_known_isolation()),
            self.workload.as_ref().and_then(|r| r.min_known_isolation()),
        ]
        .into_iter()
        .flatten()
        .collect();

        // Return the minimum of the min_known levels
        min_known_levels.into_iter().min()
    }

    pub fn overall_autonomy_ratio(&self) -> AutonomyRatio {
        let mut total = AutonomyRatio::default();
        if let Some(cp) = &self.control_plane {
            total.add(&cp.autonomy_ratio);
        }
        if let Some(s) = &self.storage {
            total.add(&s.autonomy_ratio);
        }
        if let Some(n) = &self.network {
            total.add(&n.autonomy_ratio);
        }
        if let Some(w) = &self.workload {
            total.add(&w.autonomy_ratio);
        }
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
    config: &AssessmentConfig,
) -> Result<MultitenancyReport> {
    let (control_plane, control_plane_autonomy_levels) = if config.control_plane {
        let cp = run_assessment(&ControlPlaneAssessor, &tenant1, &tenant2).await?;
        let levels = calculate_control_plane_autonomy_levels(&cp.assessments);
        // Allow cluster to recover after intensive control plane tests
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        (Some(cp), Some(levels))
    } else {
        (None, None)
    };

    let storage = if config.storage {
        let s = run_assessment(&StorageAssessor, &tenant1, &tenant2).await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Some(s)
    } else {
        None
    };

    let network = if config.network {
        let n = run_assessment(&NetworkAssessor, &tenant1, &tenant2).await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Some(n)
    } else {
        None
    };

    let workload = if config.workload {
        Some(run_assessment(&WorkloadAssessor, &tenant1, &tenant2).await?)
    } else {
        None
    };

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

/// Formats an isolation level, optionally showing the upper bound when Unknown.
/// When level is Unknown and min_known is provided, shows "❓/🟠 Unknown/Soft" format.
fn format_isolation_with_bound(
    level: &IsolationLevel,
    min_known: Option<&IsolationLevel>,
) -> String {
    match level {
        IsolationLevel::Hard => "✅ Hard".to_string(),
        IsolationLevel::Soft(_reason) => "🟠 Soft".to_string(),
        IsolationLevel::None => "❌ None".to_string(),
        IsolationLevel::Unknown => match min_known {
            Some(bound) => {
                let bound_str = match bound {
                    IsolationLevel::Hard => "❓/✅ Unknown/Hard",
                    IsolationLevel::Soft(_) => "❓/🟠 Unknown/Soft",
                    IsolationLevel::None => "❓/❌ Unknown/None",
                    IsolationLevel::Unknown => "❓ Unknown",
                };
                bound_str.to_string()
            }
            None => "❓ Unknown".to_string(),
        },
    }
}

/// Formats isolation for the summary with a more verbose description.
fn format_isolation_summary(level: &IsolationLevel, min_known: Option<&IsolationLevel>) -> String {
    match level {
        IsolationLevel::Hard => "✅ Hard".to_string(),
        IsolationLevel::Soft(_reason) => "🟠 Soft".to_string(),
        IsolationLevel::None => "❌ None".to_string(),
        IsolationLevel::Unknown => match min_known {
            Some(bound) => {
                let bound_str = match bound {
                    IsolationLevel::Hard => "❓ Unknown but no more than ✅ Hard",
                    IsolationLevel::Soft(_) => "❓ Unknown but no more than 🟠 Soft",
                    IsolationLevel::None => "❓ Unknown but no more than ❌ None",
                    IsolationLevel::Unknown => "❓ Unknown",
                };
                bound_str.to_string()
            }
            None => "❓ Unknown".to_string(),
        },
    }
}

impl Display for MultitenancyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rows = Vec::new();
        let mut first_section = true;

        // Helper to add separator if not first section
        let add_separator = |rows: &mut Vec<ReportRow>, is_first: &mut bool| {
            if !*is_first {
                rows.push(ReportRow {
                    system: "─────────────".to_string(),
                    property: "─────────────────".to_string(),
                    value: "─────────────────".to_string(),
                });
            }
            *is_first = false;
        };

        // Control Plane section
        if let Some(control_plane) = &self.control_plane {
            add_separator(&mut rows, &mut first_section);
            let cp_min_known = control_plane.min_known_isolation();
            rows.push(ReportRow {
                system: "Control Plane".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation_with_bound(
                    &control_plane.isolation_level,
                    cp_min_known.as_ref(),
                ),
            });
            rows.push(ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&control_plane.autonomy_ratio),
            });

            if let Some(levels) = &self.control_plane_autonomy_levels {
                rows.push(ReportRow {
                    system: "".to_string(),
                    property: "  ├─ Workload".to_string(),
                    value: format_ratio_with_icon(&levels.workload),
                });
                rows.push(ReportRow {
                    system: "".to_string(),
                    property: "  ├─ Scope".to_string(),
                    value: format_ratio_with_icon(&levels.scope),
                });
                rows.push(ReportRow {
                    system: "".to_string(),
                    property: "  ├─ Infrastructure".to_string(),
                    value: format_ratio_with_icon(&levels.infrastructure),
                });
                rows.push(ReportRow {
                    system: "".to_string(),
                    property: "  └─ Cluster".to_string(),
                    value: format_ratio_with_icon(&levels.cluster),
                });
            }
        }

        // Storage section
        if let Some(storage) = &self.storage {
            add_separator(&mut rows, &mut first_section);
            let storage_min_known = storage.min_known_isolation();
            rows.push(ReportRow {
                system: "Storage".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation_with_bound(
                    &storage.isolation_level,
                    storage_min_known.as_ref(),
                ),
            });
            rows.push(ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&storage.autonomy_ratio),
            });
        }

        // Network section
        if let Some(network) = &self.network {
            add_separator(&mut rows, &mut first_section);
            let network_min_known = network.min_known_isolation();
            rows.push(ReportRow {
                system: "Network".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation_with_bound(
                    &network.isolation_level,
                    network_min_known.as_ref(),
                ),
            });
            rows.push(ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&network.autonomy_ratio),
            });
        }

        // Workload section
        if let Some(workload) = &self.workload {
            add_separator(&mut rows, &mut first_section);
            let workload_min_known = workload.min_known_isolation();
            rows.push(ReportRow {
                system: "Workload".to_string(),
                property: "Isolation".to_string(),
                value: format_isolation_with_bound(
                    &workload.isolation_level,
                    workload_min_known.as_ref(),
                ),
            });
            rows.push(ReportRow {
                system: "".to_string(),
                property: "Autonomy".to_string(),
                value: format_ratio_with_icon(&workload.autonomy_ratio),
            });
        }

        if rows.is_empty() {
            writeln!(f, "\n📊 Multi-Tenancy Assessment Report")?;
            writeln!(f, "══════════════════════════════════\n")?;
            writeln!(f, "No assessments were run.")?;
            return Ok(());
        }

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
        let min_known_iso = self.min_known_isolation();
        let overall_auto = self.overall_autonomy_ratio();

        writeln!(f, "\n📋 Summary:")?;
        writeln!(
            f,
            "   Overall Isolation: {}",
            format_isolation_summary(&overall_iso, min_known_iso.as_ref())
        )?;
        writeln!(
            f,
            "   Overall Autonomy:  {}",
            format_ratio_with_icon(&overall_auto)
        )?;

        Ok(())
    }
}

/// A policy refusing an operation and a probe simply failing are different
/// facts and must not collapse into one.
///
/// The `bool` these replace made them the same, and the runner then scored
/// "not authorized" as `Hard` — the strongest isolation in the vocabulary —
/// so an intermittent API error produced the most reassuring possible result.
#[cfg(test)]
mod authorization_tests {
    use super::{admission_refusal_tests::api_error, Authorization};

    #[test]
    fn a_successful_attempt_means_the_tenant_may_do_it() {
        assert_eq!(
            Authorization::from_attempt(Ok::<_, anyhow::Error>(())),
            Authorization::Allowed
        );
    }

    #[test]
    fn a_policy_refusal_is_recognised_as_a_policy_refusal() {
        let outcome: anyhow::Result<()> = Err(api_error(403, "violates PodSecurity"));
        assert!(matches!(
            Authorization::from_attempt(outcome),
            Authorization::Forbidden(why) if why.contains("PodSecurity")
        ));
    }

    /// The case that made `native+gvisor` report `Use Privileged Syscalls`
    /// authorized on one run and forbidden on the next, with no configuration
    /// change in between.
    #[test]
    fn a_transient_failure_is_not_a_policy_refusal() {
        let outcome: anyhow::Result<()> = Err(api_error(409, "object is being deleted"));
        assert!(matches!(
            Authorization::from_attempt(outcome),
            Authorization::Undetermined(_)
        ));
    }

    #[test]
    fn a_refusal_of_either_half_forbids_the_whole() {
        let forbidden = Authorization::Forbidden("no PersistentVolumes for you".to_string());
        assert!(matches!(
            forbidden.clone().and(Authorization::Allowed),
            Authorization::Forbidden(_)
        ));
        assert!(matches!(
            Authorization::Allowed.and(forbidden.clone()),
            Authorization::Forbidden(_)
        ));
        // Decisive over a half that established nothing.
        assert!(matches!(
            Authorization::Undetermined("timed out".to_string()).and(forbidden),
            Authorization::Forbidden(_)
        ));
    }

    /// An operation that was accepted and did nothing is not one that was
    /// refused.
    ///
    /// vCluster admits a `Node` create — the tenant owns its own API server —
    /// and its syncer discards the object. The DELETE probe then found nothing
    /// to delete, and "could not perform the operation" scored that as a policy
    /// refusal, which is `Soft`: `v1/Node` came out at soft isolation for a
    /// virtual cluster whose node view is entirely its own, where nothing was
    /// refused and nothing was disclosed.
    #[test]
    fn an_ineffective_operation_outranks_an_undetermined_one_but_not_a_refusal() {
        let ineffective = Authorization::Ineffective("the Node never appeared".to_string());

        assert!(matches!(
            ineffective.clone().and(Authorization::Allowed),
            Authorization::Ineffective(_)
        ));
        assert!(matches!(
            Authorization::Undetermined("timed out".to_string()).and(ineffective.clone()),
            Authorization::Ineffective(_)
        ));
        // A refusal that actually happened is the stronger finding.
        assert!(matches!(
            ineffective.and(Authorization::Forbidden("no".to_string())),
            Authorization::Forbidden(_)
        ));
    }

    #[test]
    fn both_halves_must_be_allowed_for_the_whole_to_be() {
        assert_eq!(
            Authorization::Allowed.and(Authorization::Allowed),
            Authorization::Allowed
        );
        assert!(matches!(
            Authorization::Allowed.and(Authorization::Undetermined("timed out".to_string())),
            Authorization::Undetermined(_)
        ));
    }
}

#[cfg(test)]
mod admission_refusal_tests {
    use super::admission_refusal;

    pub(super) fn api_error(code: u16, message: &str) -> anyhow::Error {
        anyhow::Error::new(kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: message.to_string(),
            reason: "Forbidden".to_string(),
            code,
        }))
    }

    #[test]
    fn pod_security_admission_is_a_refusal_not_a_fault() {
        // The exact shape that used to end a whole run: a probe pod turned away
        // by the `restricted` standard on a hardened tenant.
        let error = api_error(
            403,
            "pods \"network-multitool\" is forbidden: violates PodSecurity \
             \"restricted:latest\": allowPrivilegeEscalation != false",
        );
        let message = admission_refusal(&error).expect("403 must be recognised");
        assert!(message.contains("violates PodSecurity"));
    }

    #[test]
    fn a_webhook_rejection_is_also_a_refusal() {
        // Several policy engines deny by declaring the object invalid rather
        // than forbidden, so 422 has to count too.
        assert!(admission_refusal(&api_error(422, "denied by webhook")).is_some());
    }

    #[test]
    fn other_api_errors_are_still_faults() {
        // A missing namespace or an unreachable server is a broken run, and
        // must keep propagating. Swallowing these would turn a botched setup
        // into a page of confident "Hard isolation" findings.
        assert_eq!(admission_refusal(&api_error(404, "not found")), None);
        assert_eq!(admission_refusal(&api_error(500, "server error")), None);
        assert_eq!(
            admission_refusal(&anyhow::anyhow!("connection refused")),
            None
        );
    }

    #[test]
    fn a_refusal_is_found_through_context_layers() {
        // Callers add context with `.context(...)`, which buries the kube error
        // further down the chain; the search has to walk it.
        use anyhow::Context;
        let error = Err::<(), _>(api_error(403, "forbidden by policy"))
            .context("creating the tenant1 network probe")
            .unwrap_err();
        assert!(admission_refusal(&error).is_some());
    }
}
