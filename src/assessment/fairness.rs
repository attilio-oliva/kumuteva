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
    /// Primary performance metric (latency in ms, throughput in Mbps, etc.)
    pub primary_metric: f64,
    /// Optional secondary metrics for detailed analysis
    pub secondary_metrics: Vec<(String, f64)>,
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
    /// Unit of the primary metric (e.g., "ms", "Mbps", "IOPS")
    pub metric_unit: String,
    /// Whether higher metric values are better (true for throughput, false for latency)
    pub higher_is_better: bool,
    /// Results from the baseline phase
    pub baseline: PhaseResults,
    /// Results from the unbalanced phase
    pub unbalanced: PhaseResults,
    /// Performance fairness as degradation ratio for the regular tenant
    /// 0.0 = perfect fairness, higher = worse fairness
    pub performance_fairness_degradation: f64,
    /// Optional detailed description
    pub details: Option<String>,
}

impl FairnessResult {
    /// Calculate performance fairness from baseline and unbalanced metrics
    /// Returns the degradation ratio (0.0 = perfect fairness)
    pub fn calculate_degradation(baseline: f64, unbalanced: f64, higher_is_better: bool) -> f64 {
        if baseline == 0.0 {
            return 0.0;
        }

        let degradation = if higher_is_better {
            // For throughput: degradation = (baseline - unbalanced) / baseline
            // Positive means worse performance
            (baseline - unbalanced) / baseline
        } else {
            // For latency: degradation = (unbalanced - baseline) / baseline
            // Positive means higher latency (worse)
            (unbalanced - baseline) / baseline
        };

        // Clamp to reasonable range (can be negative if performance improved)
        degradation.max(-1.0)
    }

    /// Returns a qualitative assessment of the fairness level
    pub fn fairness_level(&self) -> FairnessLevel {
        let deg = self.performance_fairness_degradation;
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
            "  Tenant 1: {:.2} {} (error rate: {:.1}%)",
            self.baseline.tenant1.primary_metric,
            self.metric_unit,
            self.baseline.tenant1.error_rate
        )?;
        writeln!(
            f,
            "  Tenant 2: {:.2} {} (error rate: {:.1}%)",
            self.baseline.tenant2.primary_metric,
            self.metric_unit,
            self.baseline.tenant2.error_rate
        )?;

        writeln!(f, "\n{}", "Unbalanced Phase:".bold())?;
        writeln!(
            f,
            "  Regular Tenant:   {:.2} {} (error rate: {:.1}%)",
            self.unbalanced.tenant1.primary_metric,
            self.metric_unit,
            self.unbalanced.tenant1.error_rate
        )?;
        writeln!(
            f,
            "  Malicious Tenant: {:.2} {} (error rate: {:.1}%)",
            self.unbalanced.tenant2.primary_metric,
            self.metric_unit,
            self.unbalanced.tenant2.error_rate
        )?;

        writeln!(f, "\n{}", "Performance Fairness:".bold())?;
        let deg_str = if self.performance_fairness_degradation >= 0.0 {
            format!("{:.2} degradation", self.performance_fairness_degradation)
        } else {
            format!(
                "{:.2} improvement",
                self.performance_fairness_degradation.abs()
            )
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
/// Implementors provide the subsystem-specific logic for:
/// - Running baseline measurements with equal load on both tenants
/// - Running unbalanced measurements with increased load on tenant2
/// - Parsing and interpreting benchmark results
#[async_trait]
pub trait FairnessAssessor: Send + Sync {
    /// Name of the subsystem being assessed
    fn name(&self) -> &'static str;

    /// Unit of the primary metric (e.g., "ms", "Mbps", "IOPS")
    fn metric_unit(&self) -> &'static str;

    /// Whether higher metric values indicate better performance
    /// - `true` for throughput-based metrics (bandwidth, IOPS)
    /// - `false` for latency-based metrics (response time)
    fn higher_is_better(&self) -> bool;

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
/// Returns a `FairnessResult` with the calculated performance fairness degradation.
pub async fn run_fairness_assessment<A: FairnessAssessor>(
    assessor: &A,
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: &FairnessTestConfig,
) -> Result<FairnessResult> {
    println!(
        "\n{} Running {} fairness assessment...",
        "▶".blue(),
        assessor.name()
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
        "    Tenant 1: {:.2} {}, Tenant 2: {:.2} {}",
        baseline.tenant1.primary_metric,
        assessor.metric_unit(),
        baseline.tenant2.primary_metric,
        assessor.metric_unit()
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
        "    Regular: {:.2} {}, Malicious: {:.2} {}",
        unbalanced.tenant1.primary_metric,
        assessor.metric_unit(),
        unbalanced.tenant2.primary_metric,
        assessor.metric_unit()
    );

    // Calculate performance fairness degradation
    let degradation = FairnessResult::calculate_degradation(
        baseline.tenant1.primary_metric,
        unbalanced.tenant1.primary_metric,
        assessor.higher_is_better(),
    );

    let result = FairnessResult {
        subsystem: assessor.name().to_string(),
        metric_unit: assessor.metric_unit().to_string(),
        higher_is_better: assessor.higher_is_better(),
        baseline,
        unbalanced,
        performance_fairness_degradation: degradation,
        details: None,
    };

    println!(
        "  {} Performance fairness: {:.2} degradation ({})",
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
    /// Calculate the overall performance fairness as average degradation
    pub fn overall_degradation(&self) -> Option<f64> {
        let results: Vec<f64> = [
            self.control_plane.as_ref(),
            self.network.as_ref(),
            self.storage.as_ref(),
        ]
        .iter()
        .filter_map(|r| r.map(|res| res.performance_fairness_degradation))
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
            a.performance_fairness_degradation
                .partial_cmp(&b.performance_fairness_degradation)
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
            writeln!(f, "Average Performance Degradation: {:.2}", overall)?;

            if let Some(worst) = self.worst_fairness() {
                writeln!(
                    f,
                    "Worst Subsystem: {} ({:.2} degradation)",
                    worst.subsystem, worst.performance_fairness_degradation
                )?;
            }
        } else {
            writeln!(f, "\nNo fairness assessments completed.")?;
        }

        Ok(())
    }
}
