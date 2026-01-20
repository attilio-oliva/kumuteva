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
    /// Performance fairness as latency degradation ratio for the regular tenant
    /// 0.0 = perfect fairness (no latency increase), higher = worse fairness
    pub latency_degradation: f64,
    /// Optional detailed description
    pub details: Option<String>,
}

impl FairnessResult {
    /// Calculate latency degradation from baseline and unbalanced metrics
    /// Returns the degradation ratio (0.0 = perfect fairness)
    ///
    /// Formula: (unbalanced_latency - baseline_latency) / baseline_latency
    /// Positive means latency increased (worse), negative means improved
    pub fn calculate_latency_degradation(baseline_latency_ms: f64, unbalanced_latency_ms: f64) -> f64 {
        if baseline_latency_ms == 0.0 {
            return 0.0;
        }
        (unbalanced_latency_ms - baseline_latency_ms) / baseline_latency_ms
    }

    /// Returns a qualitative assessment of the fairness level
    pub fn fairness_level(&self) -> FairnessLevel {
        let deg = self.latency_degradation;
        if deg <= 0.05 {
            FairnessLevel::Excellent
        } else if deg <= 0.15 {
            FairnessLevel::Good
        } else if deg <= 0.30 {
            FairnessLevel::Moderate
        } else if deg <= 0.50 {
            FairnessLevel::Poor
        } else {
            FairnessLevel::Critical
        }
    }
}

/// Qualitative fairness levels for display purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairnessLevel {
    /// <= 5% degradation
    Excellent,
    /// <= 15% degradation
    Good,
    /// <= 30% degradation
    Moderate,
    /// <= 50% degradation
    Poor,
    /// > 50% degradation
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
        let deg_pct = self.latency_degradation * 100.0;
        let deg_str = if self.latency_degradation >= 0.0 {
            format!("+{:.1}% latency increase", deg_pct)
        } else {
            format!("{:.1}% latency decrease", deg_pct)
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
        baseline.tenant1.avg_latency_ms,
        baseline.tenant2.avg_latency_ms
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
        unbalanced.tenant1.avg_latency_ms,
        unbalanced.tenant2.avg_latency_ms
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
        "  {} Latency fairness: {:.1}% degradation ({})",
        "✓".green(),
        degradation * 100.0,
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
            writeln!(f, "Average Latency Degradation: {:.1}%", overall * 100.0)?;

            if let Some(worst) = self.worst_fairness() {
                writeln!(
                    f,
                    "Worst Subsystem: {} ({:.1}% degradation)",
                    worst.subsystem, worst.latency_degradation * 100.0
                )?;
            }
        } else {
            writeln!(f, "\nNo fairness assessments completed.")?;
        }

        Ok(())
    }
}
