//! Fairness Assessment Module
//!
//! This module provides a unified framework for assessing performance fairness
//! across different subsystems (control plane, network, storage).
//!
//! Performance fairness is measured as a continuous quantity representing the
//! degradation experienced by a "regular" tenant when a "malicious"
//! tenant increases their resource usage significantly.
//!
//! A degradation of 0 means perfect fairness (no impact from other tenants).
//! Higher degradation values indicate worse fairness guarantees.
#![allow(dead_code)] // Framework code - will be used by subsystem implementations

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use colored::Colorize;

use crate::verifier::TenantClusterConfig;

// =============================================================================
// CORE DATA STRUCTURES
// =============================================================================

/// Configuration for fairness tests - common across all subsystems
#[derive(Debug, Clone)]
pub struct FairnessTestConfig {
    /// Duration for baseline measurement (both tenants under equal load)
    pub baseline_duration: Duration,
    /// Duration for unbalanced measurement (malicious tenant under heavy load)
    pub test_duration: Duration,
    /// Load multiplier for the malicious tenant during unbalanced phase
    /// (e.g., 10.0 means 10x the normal load)
    pub malicious_load_multiplier: f64,
}

impl Default for FairnessTestConfig {
    fn default() -> Self {
        Self {
            baseline_duration: Duration::from_secs(30),
            test_duration: Duration::from_secs(60),
            malicious_load_multiplier: 10.0,
        }
    }
}

/// Metrics collected from a single tenant during a test phase
#[derive(Debug, Clone)]
pub struct TenantMetrics {
    /// Average operation latency in milliseconds
    pub avg_latency_ms: f64,
    /// Standard deviation of latency in milliseconds
    pub std_deviation_ms: f64,
    /// Total number of operations performed
    pub total_operations: u64,
    /// Error rate as a percentage (0.0 - 100.0)
    pub error_rate: f64,
}

/// Results from a fairness test phase (baseline or unbalanced)
#[derive(Debug, Clone)]
pub struct PhaseResults {
    /// Metrics for tenant 1 (regular tenant in unbalanced phase)
    pub tenant1: TenantMetrics,
    /// Metrics for tenant 2 (malicious tenant in unbalanced phase)
    pub tenant2: TenantMetrics,
}

/// Complete result of a fairness assessment
#[derive(Debug, Clone)]
pub struct FairnessResult {
    /// Name of the subsystem tested
    pub subsystem: String,
    /// Results from the baseline phase
    pub baseline: PhaseResults,
    /// Results from the unbalanced phase
    pub unbalanced: PhaseResults,
    /// Performance degradation as ratio of unbalanced to baseline latency
    /// 1.0 = no change, 1.5 = 50% increase, 2.0 = doubled latency
    pub latency_degradation: f64,
    /// Optional detailed description
    pub details: Option<String>,
}

impl FairnessResult {
    /// Calculate latency degradation as ratio of unbalanced to baseline
    /// Returns the degradation ratio (1.0 = no change, higher = worse)
    ///
    /// Formula: unbalanced_latency / baseline_latency
    /// 1.0 = no degradation, 1.5 = 50% increase, 2.0 = doubled
    pub fn calculate_latency_degradation(
        baseline_latency_ms: f64,
        unbalanced_latency_ms: f64,
    ) -> f64 {
        if baseline_latency_ms == 0.0 {
            return 1.0;
        }
        unbalanced_latency_ms / baseline_latency_ms
    }

    /// Returns a qualitative assessment of the fairness level
    pub fn fairness_level(&self) -> FairnessLevel {
        let ratio = self.latency_degradation;
        if ratio <= 1.05 {
            FairnessLevel::Excellent
        } else if ratio <= 1.15 {
            FairnessLevel::Good
        } else if ratio <= 1.30 {
            FairnessLevel::Moderate
        } else if ratio <= 1.50 {
            FairnessLevel::Poor
        } else {
            FairnessLevel::Critical
        }
    }
}

/// Qualitative fairness levels for display purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairnessLevel {
    /// ratio <= 1.05 (≤5% increase)
    Excellent,
    /// ratio <= 1.15 (≤15% increase)
    Good,
    /// ratio <= 1.30 (≤30% increase)
    Moderate,
    /// ratio <= 1.50 (≤50% increase)
    Poor,
    /// ratio > 1.50 (>50% increase)
    Critical,
}

impl Display for FairnessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FairnessLevel::Excellent => write!(f, "Excellent"),
            FairnessLevel::Good => write!(f, "Good"),
            FairnessLevel::Moderate => write!(f, "Moderate"),
            FairnessLevel::Poor => write!(f, "Poor"),
            FairnessLevel::Critical => write!(f, "Critical"),
        }
    }
}

impl Display for FairnessResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = self.fairness_level();
        let level_icon = match level {
            FairnessLevel::Excellent => "🟢",
            FairnessLevel::Good => "🟢",
            FairnessLevel::Moderate => "🟡",
            FairnessLevel::Poor => "🟠",
            FairnessLevel::Critical => "🔴",
        };

        writeln!(f, "\n{} {} Fairness Assessment", level_icon, self.subsystem)?;
        writeln!(f, "{}", "─".repeat(40))?;

        writeln!(f, "\n{}", "Baseline Phase:".bold())?;
        writeln!(
            f,
            "  Tenant 1: {:.2} ms ± {:.2} ms ({} ops, {:.1}% errors)",
            self.baseline.tenant1.avg_latency_ms,
            self.baseline.tenant1.std_deviation_ms,
            self.baseline.tenant1.total_operations,
            self.baseline.tenant1.error_rate
        )?;
        writeln!(
            f,
            "  Tenant 2: {:.2} ms ± {:.2} ms ({} ops, {:.1}% errors)",
            self.baseline.tenant2.avg_latency_ms,
            self.baseline.tenant2.std_deviation_ms,
            self.baseline.tenant2.total_operations,
            self.baseline.tenant2.error_rate
        )?;

        writeln!(f, "\n{}", "Unbalanced Phase:".bold())?;
        writeln!(
            f,
            "  Regular:   {:.2} ms ± {:.2} ms ({} ops, {:.1}% errors)",
            self.unbalanced.tenant1.avg_latency_ms,
            self.unbalanced.tenant1.std_deviation_ms,
            self.unbalanced.tenant1.total_operations,
            self.unbalanced.tenant1.error_rate
        )?;
        writeln!(
            f,
            "  Malicious: {:.2} ms ± {:.2} ms ({} ops, {:.1}% errors)",
            self.unbalanced.tenant2.avg_latency_ms,
            self.unbalanced.tenant2.std_deviation_ms,
            self.unbalanced.tenant2.total_operations,
            self.unbalanced.tenant2.error_rate
        )?;

        writeln!(f, "\n{}", "Latency Fairness:".bold())?;
        let ratio = self.latency_degradation;
        let deg_str = if ratio >= 1.0 {
            format!("{:.2}x latency multiplier", ratio)
        } else {
            format!("{:.2}x latency multiplier (improved)", ratio)
        };
        writeln!(f, "  {} - {} ({})", level_icon, level, deg_str)?;

        if let Some(ref details) = self.details {
            writeln!(f, "\n{}", "Details:".dimmed())?;
            writeln!(f, "  {}", details)?;
        }

        Ok(())
    }
}

// =============================================================================
// FAIRNESS ASSESSOR TRAIT
// =============================================================================

/// Trait for subsystem-specific fairness assessors
///
/// All assessors measure operation latency as the primary metric.
/// Implementors provide the subsystem-specific logic for:
/// - Running baseline measurements with equal load on both tenants
/// - Running unbalanced measurements with increased load on tenant2
/// - Measuring and reporting operation latencies
#[async_trait]
pub trait FairnessAssessor: Send + Sync {
    /// Name of the subsystem being assessed
    fn name(&self) -> &'static str;

    /// Description of what operation latency is being measured
    /// (e.g., "API request latency", "I/O operation latency", "Network RTT")
    fn operation_description(&self) -> &'static str;

    /// Run baseline phase with both tenants under equal, normal load
    ///
    /// This establishes the expected performance when resources are fairly shared.
    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults>;

    /// Run unbalanced phase with tenant2 acting as "malicious"
    ///
    /// Tenant2 increases load by `config.malicious_load_multiplier` while
    /// tenant1 maintains normal load. This tests if tenant1 is protected
    /// from noisy neighbor effects.
    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults>;
}

// =============================================================================
// GENERIC ASSESSMENT RUNNER
// =============================================================================

/// Run a fairness assessment using the provided assessor
///
/// This function orchestrates the two-phase fairness test:
/// 1. Baseline phase: Both tenants under equal load
/// 2. Unbalanced phase: Tenant2 under heavy load, tenant1 normal
///
/// Returns a `FairnessResult` with the calculated latency degradation.
pub async fn run_fairness_assessment<A: FairnessAssessor>(
    assessor: &A,
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: &FairnessTestConfig,
) -> Result<FairnessResult> {
    println!(
        "\n{} Running {} fairness assessment ({})...",
        "▶".blue(),
        assessor.name(),
        assessor.operation_description()
    );

    // Phase 1: Baseline measurement
    println!(
        "  {} Phase 1: Baseline ({} seconds)...",
        "→".dimmed(),
        config.baseline_duration.as_secs()
    );
    let baseline = assessor
        .run_baseline(tenant1.clone(), tenant2.clone(), config)
        .await?;

    println!(
        "    Tenant 1: {:.2} ms, Tenant 2: {:.2} ms",
        baseline.tenant1.avg_latency_ms, baseline.tenant2.avg_latency_ms
    );

    // Phase 2: Unbalanced measurement
    println!(
        "  {} Phase 2: Unbalanced ({} seconds, {}x load on tenant2)...",
        "→".dimmed(),
        config.test_duration.as_secs(),
        config.malicious_load_multiplier
    );
    let unbalanced = assessor.run_unbalanced(tenant1, tenant2, config).await?;

    println!(
        "    Regular: {:.2} ms, Malicious: {:.2} ms",
        unbalanced.tenant1.avg_latency_ms, unbalanced.tenant2.avg_latency_ms
    );

    // Calculate latency degradation for regular tenant
    let degradation = FairnessResult::calculate_latency_degradation(
        baseline.tenant1.avg_latency_ms,
        unbalanced.tenant1.avg_latency_ms,
    );

    let result = FairnessResult {
        subsystem: assessor.name().to_string(),
        baseline,
        unbalanced,
        latency_degradation: degradation,
        details: None,
    };

    println!(
        "  {} Latency fairness: {:.2}x multiplier ({})",
        "✓".green(),
        degradation,
        result.fairness_level()
    );

    Ok(result)
}

// =============================================================================
// AGGREGATE FAIRNESS REPORT
// =============================================================================

/// Aggregated fairness results across all subsystems
#[derive(Debug, Clone, Default)]
pub struct FairnessReport {
    pub control_plane: Option<FairnessResult>,
    pub network: Option<FairnessResult>,
    pub storage: Option<FairnessResult>,
}

impl FairnessReport {
    /// Calculate the overall latency fairness as average degradation
    pub fn overall_degradation(&self) -> Option<f64> {
        let results: Vec<f64> = [
            self.control_plane.as_ref(),
            self.network.as_ref(),
            self.storage.as_ref(),
        ]
        .iter()
        .filter_map(|r| r.map(|res| res.latency_degradation))
        .collect();

        if results.is_empty() {
            None
        } else {
            Some(results.iter().sum::<f64>() / results.len() as f64)
        }
    }

    /// Get the worst fairness result (highest degradation)
    pub fn worst_fairness(&self) -> Option<&FairnessResult> {
        [
            self.control_plane.as_ref(),
            self.network.as_ref(),
            self.storage.as_ref(),
        ]
        .iter()
        .filter_map(|r| *r)
        .max_by(|a, b| {
            a.latency_degradation
                .partial_cmp(&b.latency_degradation)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

impl Display for FairnessReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n{}", "═".repeat(50))?;
        writeln!(f, "📊 FAIRNESS ASSESSMENT REPORT")?;
        writeln!(f, "{}", "═".repeat(50))?;

        if let Some(ref cp) = self.control_plane {
            write!(f, "{}", cp)?;
        }

        if let Some(ref net) = self.network {
            write!(f, "{}", net)?;
        }

        if let Some(ref storage) = self.storage {
            write!(f, "{}", storage)?;
        }

        if let Some(overall) = self.overall_degradation() {
            writeln!(f, "\n{}", "═".repeat(50))?;
            writeln!(f, "{}", "OVERALL SUMMARY".bold())?;
            writeln!(f, "{}", "─".repeat(50))?;
            writeln!(f, "Average Latency Degradation: {:.2}x", overall)?;

            if let Some(worst) = self.worst_fairness() {
                writeln!(
                    f,
                    "Worst Subsystem: {} ({:.2}x degradation)",
                    worst.subsystem, worst.latency_degradation
                )?;
            }
        } else {
            writeln!(f, "\nNo fairness assessments completed.")?;
        }

        Ok(())
    }
}

// =============================================================================
// CSV EXPORT DATA STRUCTURES
// =============================================================================

/// Raw metric data point for CSV export
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricDataPoint {
    /// Timestamp relative to test start (seconds)
    pub timestamp_secs: f64,
    /// Latency of this operation in milliseconds
    pub latency_ms: f64,
    /// Whether this operation resulted in an error
    pub is_error: bool,
    /// Optional operation type description
    pub operation: Option<String>,
}

/// Extended phase results that include raw data for CSV export
#[derive(Debug, Clone)]
pub struct DetailedPhaseResults {
    /// Aggregated metrics for tenant 1
    pub tenant1: TenantMetrics,
    /// Aggregated metrics for tenant 2
    pub tenant2: TenantMetrics,
    /// Raw data points for tenant 1 (for CSV export)
    pub tenant1_raw: Vec<MetricDataPoint>,
    /// Raw data points for tenant 2 (for CSV export)
    pub tenant2_raw: Vec<MetricDataPoint>,
}

impl From<DetailedPhaseResults> for PhaseResults {
    fn from(detailed: DetailedPhaseResults) -> Self {
        PhaseResults {
            tenant1: detailed.tenant1,
            tenant2: detailed.tenant2,
        }
    }
}

/// Extended fairness result with raw data for export
#[derive(Debug, Clone)]
pub struct DetailedFairnessResult {
    /// The standard fairness result
    pub result: FairnessResult,
    /// Raw baseline data for CSV export (tenant1, tenant2)
    pub baseline_raw: Option<(Vec<MetricDataPoint>, Vec<MetricDataPoint>)>,
    /// Raw unbalanced data for CSV export (tenant1, tenant2)
    pub unbalanced_raw: Option<(Vec<MetricDataPoint>, Vec<MetricDataPoint>)>,
}

// =============================================================================
// DETAILED FAIRNESS ASSESSOR TRAIT
// =============================================================================

/// Extended trait for assessors that can provide raw data for CSV export
#[async_trait]
pub trait DetailedFairnessAssessor: FairnessAssessor {
    /// Run baseline phase and return detailed results with raw data
    async fn run_baseline_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<DetailedPhaseResults>;

    /// Run unbalanced phase and return detailed results with raw data
    async fn run_unbalanced_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<DetailedPhaseResults>;
}

// =============================================================================
// DETAILED ASSESSMENT RUNNER WITH CSV EXPORT
// =============================================================================

/// Run a detailed fairness assessment with CSV export support
pub async fn run_detailed_fairness_assessment<A: DetailedFairnessAssessor>(
    assessor: &A,
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: &FairnessTestConfig,
    export_csv: bool,
    output_dir: Option<&str>,
) -> Result<DetailedFairnessResult> {
    println!(
        "\n{} Running {} fairness assessment ({})...",
        "▶".blue(),
        assessor.name(),
        assessor.operation_description()
    );

    // Phase 1: Baseline measurement
    println!(
        "  {} Phase 1: Baseline ({} seconds)...",
        "→".dimmed(),
        config.baseline_duration.as_secs()
    );
    let baseline_detailed = assessor
        .run_baseline_detailed(tenant1.clone(), tenant2.clone(), config)
        .await?;

    println!(
        "    Tenant 1: {:.2} ms ± {:.2} ms ({} ops)",
        baseline_detailed.tenant1.avg_latency_ms,
        baseline_detailed.tenant1.std_deviation_ms,
        baseline_detailed.tenant1.total_operations
    );
    println!(
        "    Tenant 2: {:.2} ms ± {:.2} ms ({} ops)",
        baseline_detailed.tenant2.avg_latency_ms,
        baseline_detailed.tenant2.std_deviation_ms,
        baseline_detailed.tenant2.total_operations
    );

    // Phase 2: Unbalanced measurement
    println!(
        "  {} Phase 2: Unbalanced ({} seconds, {}x load on tenant2)...",
        "→".dimmed(),
        config.test_duration.as_secs(),
        config.malicious_load_multiplier
    );
    let unbalanced_detailed = assessor
        .run_unbalanced_detailed(tenant1, tenant2, config)
        .await?;

    println!(
        "    Regular:   {:.2} ms ± {:.2} ms ({} ops, {:.1}% errors)",
        unbalanced_detailed.tenant1.avg_latency_ms,
        unbalanced_detailed.tenant1.std_deviation_ms,
        unbalanced_detailed.tenant1.total_operations,
        unbalanced_detailed.tenant1.error_rate
    );
    println!(
        "    Malicious: {:.2} ms ± {:.2} ms ({} ops, {:.1}% errors)",
        unbalanced_detailed.tenant2.avg_latency_ms,
        unbalanced_detailed.tenant2.std_deviation_ms,
        unbalanced_detailed.tenant2.total_operations,
        unbalanced_detailed.tenant2.error_rate
    );

    // Calculate latency degradation for regular tenant
    let latency_degradation = FairnessResult::calculate_latency_degradation(
        baseline_detailed.tenant1.avg_latency_ms,
        unbalanced_detailed.tenant1.avg_latency_ms,
    );

    let result = FairnessResult {
        subsystem: assessor.name().to_string(),
        baseline: PhaseResults {
            tenant1: baseline_detailed.tenant1.clone(),
            tenant2: baseline_detailed.tenant2.clone(),
        },
        unbalanced: PhaseResults {
            tenant1: unbalanced_detailed.tenant1.clone(),
            tenant2: unbalanced_detailed.tenant2.clone(),
        },
        latency_degradation,
        details: None,
    };

    println!(
        "  {} Latency fairness: {:.2}x degradation ({})",
        "✓".green(),
        latency_degradation,
        result.fairness_level()
    );

    let detailed_result = DetailedFairnessResult {
        result,
        baseline_raw: Some((baseline_detailed.tenant1_raw, baseline_detailed.tenant2_raw)),
        unbalanced_raw: Some((
            unbalanced_detailed.tenant1_raw,
            unbalanced_detailed.tenant2_raw,
        )),
    };

    // Export CSV if requested
    if export_csv {
        let dir = output_dir.unwrap_or("fairness_results");
        export_fairness_csv(&detailed_result, dir).await?;
    }

    Ok(detailed_result)
}

// =============================================================================
// CSV EXPORT FUNCTIONALITY
// =============================================================================

/// Export fairness test results to CSV files
pub async fn export_fairness_csv(result: &DetailedFairnessResult, output_dir: &str) -> Result<()> {
    use tokio::fs;

    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir).await?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let subsystem = result.result.subsystem.to_lowercase().replace(' ', "_");

    // Export baseline data if available
    if let Some((tenant1_raw, tenant2_raw)) = &result.baseline_raw {
        let baseline_t1_file = format!(
            "{}/fairness_{}_baseline_tenant1_{}.csv",
            output_dir, subsystem, timestamp
        );
        let baseline_t2_file = format!(
            "{}/fairness_{}_baseline_tenant2_{}.csv",
            output_dir, subsystem, timestamp
        );

        write_metrics_csv(&baseline_t1_file, tenant1_raw).await?;
        write_metrics_csv(&baseline_t2_file, tenant2_raw).await?;

        println!("    📁 Baseline CSV: {}", baseline_t1_file);
        println!("    📁 Baseline CSV: {}", baseline_t2_file);
    }

    // Export unbalanced data if available
    if let Some((tenant1_raw, tenant2_raw)) = &result.unbalanced_raw {
        let unbalanced_t1_file = format!(
            "{}/fairness_{}_unbalanced_regular_{}.csv",
            output_dir, subsystem, timestamp
        );
        let unbalanced_t2_file = format!(
            "{}/fairness_{}_unbalanced_malicious_{}.csv",
            output_dir, subsystem, timestamp
        );

        write_metrics_csv(&unbalanced_t1_file, tenant1_raw).await?;
        write_metrics_csv(&unbalanced_t2_file, tenant2_raw).await?;

        println!("    📁 Unbalanced CSV: {}", unbalanced_t1_file);
        println!("    📁 Unbalanced CSV: {}", unbalanced_t2_file);
    }

    // Export metadata as JSON
    let metadata_file = format!(
        "{}/fairness_{}_metadata_{}.json",
        output_dir, subsystem, timestamp
    );

    let metadata = serde_json::json!({
        "subsystem": result.result.subsystem,
        "latency_degradation": result.result.latency_degradation,
        "fairness_level": result.result.fairness_level().to_string(),
        "baseline": {
            "tenant1": {
                "avg_latency_ms": result.result.baseline.tenant1.avg_latency_ms,
                "std_deviation_ms": result.result.baseline.tenant1.std_deviation_ms,
                "total_operations": result.result.baseline.tenant1.total_operations,
                "error_rate": result.result.baseline.tenant1.error_rate
            },
            "tenant2": {
                "avg_latency_ms": result.result.baseline.tenant2.avg_latency_ms,
                "std_deviation_ms": result.result.baseline.tenant2.std_deviation_ms,
                "total_operations": result.result.baseline.tenant2.total_operations,
                "error_rate": result.result.baseline.tenant2.error_rate
            }
        },
        "unbalanced": {
            "regular": {
                "avg_latency_ms": result.result.unbalanced.tenant1.avg_latency_ms,
                "std_deviation_ms": result.result.unbalanced.tenant1.std_deviation_ms,
                "total_operations": result.result.unbalanced.tenant1.total_operations,
                "error_rate": result.result.unbalanced.tenant1.error_rate
            },
            "malicious": {
                "avg_latency_ms": result.result.unbalanced.tenant2.avg_latency_ms,
                "std_deviation_ms": result.result.unbalanced.tenant2.std_deviation_ms,
                "total_operations": result.result.unbalanced.tenant2.total_operations,
                "error_rate": result.result.unbalanced.tenant2.error_rate
            }
        }
    });

    fs::write(&metadata_file, serde_json::to_string_pretty(&metadata)?).await?;
    println!("    📁 Metadata JSON: {}", metadata_file);

    Ok(())
}

/// Helper function to write metric data points to a CSV file
async fn write_metrics_csv(filename: &str, data: &[MetricDataPoint]) -> Result<()> {
    use tokio::fs;

    let mut csv_content = String::from("timestamp_secs,latency_ms,is_error,operation\n");

    for point in data {
        csv_content.push_str(&format!(
            "{},{},{},{}\n",
            point.timestamp_secs,
            point.latency_ms,
            point.is_error,
            point.operation.as_deref().unwrap_or("")
        ));
    }

    fs::write(filename, csv_content).await?;
    Ok(())
}

/// Calculate TenantMetrics from raw data points
pub fn calculate_tenant_metrics(data: &[MetricDataPoint]) -> TenantMetrics {
    if data.is_empty() {
        return TenantMetrics {
            avg_latency_ms: 0.0,
            std_deviation_ms: 0.0,
            total_operations: 0,
            error_rate: 0.0,
        };
    }

    let total_operations = data.len() as u64;
    let error_count = data.iter().filter(|p| p.is_error).count();
    let error_rate = (error_count as f64 / total_operations as f64) * 100.0;

    let latencies: Vec<f64> = data.iter().map(|p| p.latency_ms).collect();
    let avg_latency_ms: f64 = latencies.iter().sum::<f64>() / latencies.len() as f64;

    let variance: f64 = latencies
        .iter()
        .map(|l| (l - avg_latency_ms).powi(2))
        .sum::<f64>()
        / latencies.len() as f64;
    let std_deviation_ms = variance.sqrt();

    TenantMetrics {
        avg_latency_ms,
        std_deviation_ms,
        total_operations,
        error_rate,
    }
}
