//! Fairness Assessment Framework
//!
//! A unified framework for measuring performance fairness across subsystems.
//! Fairness is measured by comparing a "regular" tenant's latency when a
//! "malicious" tenant increases their resource usage.
//!
//! ## Design Principles
//!
//! 1. **Single Trait**: One `FairnessAssessor` trait for all subsystems
//! 2. **Rate Limiting Built-in**: Rate is part of the config, strategies are pluggable
//! 3. **Always Detailed**: Raw metrics are always collected (no separate "Detailed" traits)
//! 4. **Simple Runner**: One `run()` method that handles everything

#![allow(dead_code)]

use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use colored::Colorize;
use tokio::sync::Mutex;

use crate::assessment::TenantClusterConfig;

// =============================================================================
// RATE LIMITING
// =============================================================================

/// Rate limiting strategy
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RateLimitStrategy {
    /// No rate limiting - run as fast as possible
    #[default]
    Unlimited,
    /// Fixed delay between operations (1/rate seconds)
    FixedDelay,
    /// Adaptive rate adjustment based on feedback (future)
    Adaptive,
}

impl Display for RateLimitStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitStrategy::Unlimited => write!(f, "Unlimited"),
            RateLimitStrategy::FixedDelay => write!(f, "Fixed Delay"),
            RateLimitStrategy::Adaptive => write!(f, "Adaptive"),
        }
    }
}

/// A stateful rate limiter instance
///
/// Create one per concurrent operation stream (e.g., per tenant).
/// Call `wait()` before each operation to enforce the rate.
pub struct RateLimiter {
    pub strategy: RateLimitStrategy,
    interval: Duration,
    last_request: Mutex<Option<Instant>>,
}

impl RateLimiter {
    /// Create a rate limiter with the given strategy and target rate (ops/sec)
    pub fn new(strategy: RateLimitStrategy, rate: f64) -> Self {
        let interval = if rate > 0.0 {
            Duration::from_secs_f64(1.0 / rate)
        } else {
            Duration::ZERO
        };

        Self {
            strategy,
            interval,
            last_request: Mutex::new(None),
        }
    }

    /// Create an unlimited rate limiter
    pub fn unlimited() -> Self {
        Self::new(RateLimitStrategy::Unlimited, 0.0)
    }

    /// Create a fixed-delay rate limiter
    pub fn fixed_delay(rate: f64) -> Self {
        Self::new(RateLimitStrategy::FixedDelay, rate)
    }

    /// Wait until the next operation is allowed
    ///
    /// Call this before each operation to enforce the rate limit.
    pub async fn wait(&self) {
        match self.strategy {
            RateLimitStrategy::Unlimited => {
                // No waiting
            }
            RateLimitStrategy::FixedDelay | RateLimitStrategy::Adaptive => {
                let mut last = self.last_request.lock().await;

                if let Some(last_time) = *last {
                    let elapsed = last_time.elapsed();
                    if elapsed < self.interval {
                        tokio::time::sleep(self.interval - elapsed).await;
                    }
                }

                *last = Some(Instant::now());
            }
        }
    }

    /// Get the target rate in ops/sec
    pub fn rate(&self) -> f64 {
        if self.interval.is_zero() {
            f64::INFINITY
        } else {
            1.0 / self.interval.as_secs_f64()
        }
    }
}

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Configuration for fairness tests
#[derive(Debug, Clone)]
pub struct FairnessConfig {
    /// Duration for baseline measurement (equal load on both tenants)
    pub baseline_duration: Duration,
    /// Duration for unbalanced test phase (malicious tenant under heavy load)
    pub test_duration: Duration,
    /// Load multiplier for malicious tenant (e.g., 10.0 = 10x load)
    pub malicious_load_multiplier: f64,
    /// Request rate for tenant1 (regular tenant) in ops/sec
    pub tenant1_rate: f64,
    /// Request rate for tenant2 (malicious tenant) in ops/sec
    pub tenant2_rate: f64,
    /// Rate limiting strategy
    pub strategy: RateLimitStrategy,
}

impl Default for FairnessConfig {
    fn default() -> Self {
        Self {
            baseline_duration: Duration::from_secs(30),
            test_duration: Duration::from_secs(60),
            malicious_load_multiplier: 10.0,
            tenant1_rate: 10.0,
            tenant2_rate: 10.0,
            strategy: RateLimitStrategy::Unlimited,
        }
    }
}

impl FairnessConfig {
    /// Get the malicious rate (tenant2 rate * multiplier)
    pub fn malicious_rate(&self) -> f64 {
        self.tenant2_rate * self.malicious_load_multiplier
    }

    /// Create a rate limiter for tenant1
    pub fn tenant1_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.strategy, self.tenant1_rate)
    }

    /// Create a rate limiter for tenant2 (baseline)
    pub fn tenant2_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.strategy, self.tenant2_rate)
    }

    /// Create a rate limiter for tenant2 during unbalanced phase
    pub fn tenant2_malicious_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.strategy, self.malicious_rate())
    }
}

// =============================================================================
// METRICS
// =============================================================================

/// Raw metric data point for detailed analysis and CSV export
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricPoint {
    /// Timestamp in seconds from test start
    pub timestamp_secs: f64,
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Whether this operation was an error
    pub is_error: bool,
    /// Optional operation label (e.g., "pod-0", "get-configmap")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Aggregated metrics for a tenant during a test phase
#[derive(Debug, Clone, Default)]
pub struct TenantMetrics {
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Standard deviation of latency
    pub std_deviation_ms: f64,
    /// Total operations performed
    pub operations: u64,
    /// Error rate (0.0 - 100.0)
    pub error_rate: f64,
    /// Raw data points
    pub raw: Vec<MetricPoint>,
}

impl TenantMetrics {
    /// Create from raw data points
    pub fn from_raw(points: Vec<MetricPoint>) -> Self {
        let latencies: Vec<f64> = points.iter().map(|p| p.latency_ms).collect();
        let errors = points.iter().filter(|p| p.is_error).count();

        let (avg, std) = if latencies.is_empty() {
            (0.0, 0.0)
        } else {
            let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
            let variance =
                latencies.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / latencies.len() as f64;
            (avg, variance.sqrt())
        };

        let error_rate = if points.is_empty() {
            0.0
        } else {
            (errors as f64 / points.len() as f64) * 100.0
        };

        Self {
            avg_latency_ms: avg,
            std_deviation_ms: std,
            operations: points.len() as u64,
            error_rate,
            raw: points,
        }
    }
}

/// Results from a single test phase
#[derive(Debug, Clone, Default)]
pub struct PhaseResult {
    pub tenant1: TenantMetrics,
    pub tenant2: TenantMetrics,
}

// =============================================================================
// FAIRNESS RESULT
// =============================================================================

/// Complete result of a fairness assessment
#[derive(Debug, Clone)]
pub struct FairnessResult {
    /// Name of the subsystem tested
    pub subsystem: String,
    /// Baseline phase results
    pub baseline: PhaseResult,
    /// Unbalanced phase results
    pub unbalanced: PhaseResult,
    /// Latency degradation ratio (1.0 = no change, 2.0 = doubled)
    pub latency_degradation: f64,
}

impl FairnessResult {
    /// Calculate degradation from baseline to unbalanced
    pub fn calculate_degradation(baseline_ms: f64, unbalanced_ms: f64) -> f64 {
        if baseline_ms <= 0.0 {
            1.0
        } else {
            (unbalanced_ms / baseline_ms).max(0.0)
        }
    }

    /// Get qualitative fairness level
    pub fn fairness_level(&self) -> FairnessLevel {
        match self.latency_degradation {
            r if r <= 1.05 => FairnessLevel::Excellent,
            r if r <= 1.15 => FairnessLevel::Good,
            r if r <= 1.30 => FairnessLevel::Moderate,
            r if r <= 1.50 => FairnessLevel::Poor,
            _ => FairnessLevel::Critical,
        }
    }
}

/// Qualitative fairness levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairnessLevel {
    Excellent, // ≤5% degradation
    Good,      // ≤15% degradation
    Moderate,  // ≤30% degradation
    Poor,      // ≤50% degradation
    Critical,  // >50% degradation
}

impl Display for FairnessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FairnessLevel::Excellent => write!(f, "Excellent (≤5%)"),
            FairnessLevel::Good => write!(f, "Good (≤15%)"),
            FairnessLevel::Moderate => write!(f, "Moderate (≤30%)"),
            FairnessLevel::Poor => write!(f, "Poor (≤50%)"),
            FairnessLevel::Critical => write!(f, "Critical (>50%)"),
        }
    }
}

impl Display for FairnessResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = self.fairness_level();
        let icon = match level {
            FairnessLevel::Excellent | FairnessLevel::Good => "🟢",
            FairnessLevel::Moderate => "🟡",
            FairnessLevel::Poor => "🟠",
            FairnessLevel::Critical => "🔴",
        };

        writeln!(f, "\n{} {} Fairness", icon, self.subsystem)?;
        writeln!(f, "{}", "─".repeat(50))?;

        writeln!(f, "\n{}", "Baseline:".bold())?;
        writeln!(
            f,
            "  Tenant1: {:>8.2}ms ± {:>6.2}ms  ({:>5} ops)",
            self.baseline.tenant1.avg_latency_ms,
            self.baseline.tenant1.std_deviation_ms,
            self.baseline.tenant1.operations
        )?;
        writeln!(
            f,
            "  Tenant2: {:>8.2}ms ± {:>6.2}ms  ({:>5} ops)",
            self.baseline.tenant2.avg_latency_ms,
            self.baseline.tenant2.std_deviation_ms,
            self.baseline.tenant2.operations
        )?;

        writeln!(f, "\n{}", "Unbalanced:".bold())?;
        writeln!(
            f,
            "  Regular:   {:>8.2}ms ± {:>6.2}ms  ({:>6} ops)",
            self.unbalanced.tenant1.avg_latency_ms,
            self.unbalanced.tenant1.std_deviation_ms,
            self.unbalanced.tenant1.operations
        )?;
        writeln!(
            f,
            "  Malicious: {:>8.2}ms ± {:>6.2}ms  ({:>6} ops)",
            self.unbalanced.tenant2.avg_latency_ms,
            self.unbalanced.tenant2.std_deviation_ms,
            self.unbalanced.tenant2.operations
        )?;

        writeln!(f, "\n{}", "Result:".bold())?;
        writeln!(
            f,
            "  {:.2}x degradation — {}",
            self.latency_degradation, level
        )?;

        Ok(())
    }
}

// =============================================================================
// FAIRNESS ASSESSOR TRAIT
// =============================================================================

/// Trait for subsystem-specific fairness assessors
///
/// Implement this trait to add fairness assessment for a new subsystem.
/// The assessor receives the full configuration including rate limiting
/// parameters and is responsible for using them appropriately.
///
/// ## Example Implementation
///
/// ```rust,ignore
/// #[async_trait]
/// impl FairnessAssessor for MyAssessor {
///     fn name(&self) -> &'static str { "My Subsystem" }
///     fn metric(&self) -> &'static str { "request latency" }
///
///     async fn run_baseline(
///         &self,
///         tenant1: Arc<TenantClusterConfig>,
///         tenant2: Arc<TenantClusterConfig>,
///         config: &FairnessConfig,
///     ) -> Result<PhaseResult> {
///         // Create rate limiters from config
///         let t1_limiter = config.tenant1_limiter();
///         let t2_limiter = config.tenant2_limiter();
///
///         // Run concurrent workloads with rate limiting
///         let (t1_points, t2_points) = tokio::try_join!(
///             self.run_tenant(&tenant1, config.baseline_duration, &t1_limiter),
///             self.run_tenant(&tenant2, config.baseline_duration, &t2_limiter),
///         )?;
///
///         Ok(PhaseResult {
///             tenant1: TenantMetrics::from_raw(t1_points),
///             tenant2: TenantMetrics::from_raw(t2_points),
///         })
///     }
///
///     async fn run_unbalanced(...) -> Result<PhaseResult> {
///         // Similar, but use config.tenant2_malicious_limiter() for tenant2
///     }
/// }
/// ```
#[async_trait]
pub trait FairnessAssessor: Send + Sync {
    /// Name of the subsystem (e.g., "Control Plane", "Network")
    fn name(&self) -> &'static str;

    /// Description of what metric is being measured (e.g., "API latency")
    fn metric(&self) -> &'static str;

    /// Run baseline phase - both tenants under equal load
    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult>;

    /// Run unbalanced phase - tenant2 under heavy load
    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult>;
}

// =============================================================================
// FAIRNESS RUNNER
// =============================================================================

/// Runner that orchestrates fairness assessments
pub struct FairnessRunner {
    config: FairnessConfig,
    export_csv: bool,
    output_dir: String,
}

impl FairnessRunner {
    /// Create a new runner with the given configuration
    pub fn new(config: FairnessConfig) -> Self {
        Self {
            config,
            export_csv: false,
            output_dir: "fairness_results".to_string(),
        }
    }

    /// Enable CSV export to the specified directory
    pub fn with_csv_export(mut self, dir: &str) -> Self {
        self.export_csv = true;
        self.output_dir = dir.to_string();
        self
    }

    /// Get the configuration
    pub fn config(&self) -> &FairnessConfig {
        &self.config
    }

    /// Run a fairness assessment
    pub async fn run<A: FairnessAssessor>(
        &self,
        assessor: &A,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
    ) -> Result<FairnessResult> {
        println!(
            "\n{} {} ({})...",
            "▶".blue(),
            assessor.name(),
            assessor.metric()
        );

        // Phase 1: Baseline
        println!(
            "  {} Baseline ({} sec)...",
            "→".dimmed(),
            self.config.baseline_duration.as_secs()
        );
        let baseline = assessor
            .run_baseline(tenant1.clone(), tenant2.clone(), &self.config)
            .await?;

        println!(
            "      Tenant1: {:.2}ms, Tenant2: {:.2}ms",
            baseline.tenant1.avg_latency_ms, baseline.tenant2.avg_latency_ms
        );

        // Phase 2: Unbalanced
        println!(
            "  {} Unbalanced ({} sec, {}x load on tenant2)...",
            "→".dimmed(),
            self.config.test_duration.as_secs(),
            self.config.malicious_load_multiplier
        );
        let unbalanced = assessor
            .run_unbalanced(tenant1, tenant2, &self.config)
            .await?;

        println!(
            "      Regular: {:.2}ms, Malicious: {:.2}ms",
            unbalanced.tenant1.avg_latency_ms, unbalanced.tenant2.avg_latency_ms
        );

        // Calculate degradation
        let degradation = FairnessResult::calculate_degradation(
            baseline.tenant1.avg_latency_ms,
            unbalanced.tenant1.avg_latency_ms,
        );

        let result = FairnessResult {
            subsystem: assessor.name().to_string(),
            baseline,
            unbalanced,
            latency_degradation: degradation,
        };

        println!(
            "  {} {:.2}x degradation ({})",
            "✓".green(),
            degradation,
            result.fairness_level()
        );

        // Export CSV if enabled
        if self.export_csv {
            self.export_to_csv(&result).await?;
        }

        Ok(result)
    }

    async fn export_to_csv(&self, result: &FairnessResult) -> Result<()> {
        use tokio::fs;
        use tokio::io::AsyncWriteExt;

        fs::create_dir_all(&self.output_dir).await?;

        let subsystem = result.subsystem.to_lowercase().replace(' ', "_");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Export baseline
        let path = format!(
            "{}/{}_baseline_{}.csv",
            self.output_dir, subsystem, timestamp
        );
        write_csv(&path, &result.baseline).await?;

        // Export unbalanced
        let path = format!(
            "{}/{}_unbalanced_{}.csv",
            self.output_dir, subsystem, timestamp
        );
        write_csv(&path, &result.unbalanced).await?;

        println!("  📁 Exported to {}/", self.output_dir);
        Ok(())
    }
}

async fn write_csv(path: &str, phase: &PhaseResult) -> Result<()> {
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    let mut file = File::create(path).await?;
    file.write_all(b"tenant,timestamp_secs,latency_ms,is_error,label\n")
        .await?;

    for point in &phase.tenant1.raw {
        file.write_all(
            format!(
                "tenant1,{:.3},{:.3},{},{}\n",
                point.timestamp_secs,
                point.latency_ms,
                point.is_error,
                point.label.as_deref().unwrap_or("")
            )
            .as_bytes(),
        )
        .await?;
    }

    for point in &phase.tenant2.raw {
        file.write_all(
            format!(
                "tenant2,{:.3},{:.3},{},{}\n",
                point.timestamp_secs,
                point.latency_ms,
                point.is_error,
                point.label.as_deref().unwrap_or("")
            )
            .as_bytes(),
        )
        .await?;
    }

    Ok(())
}

// =============================================================================
// BUILDER
// =============================================================================

/// Builder for creating a FairnessRunner with custom configuration
#[derive(Default)]
pub struct FairnessRunnerBuilder {
    baseline_duration: Option<Duration>,
    test_duration: Option<Duration>,
    malicious_multiplier: Option<f64>,
    rate: Option<f64>,
    strategy: Option<RateLimitStrategy>,
    export_csv: Option<String>,
}

impl FairnessRunnerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn baseline_duration(mut self, d: Duration) -> Self {
        self.baseline_duration = Some(d);
        self
    }

    pub fn test_duration(mut self, d: Duration) -> Self {
        self.test_duration = Some(d);
        self
    }

    pub fn malicious_multiplier(mut self, m: f64) -> Self {
        self.malicious_multiplier = Some(m);
        self
    }

    pub fn rate(mut self, r: f64) -> Self {
        self.rate = Some(r);
        self
    }

    pub fn strategy(mut self, s: RateLimitStrategy) -> Self {
        self.strategy = Some(s);
        self
    }

    pub fn export_csv(mut self, dir: &str) -> Self {
        self.export_csv = Some(dir.to_string());
        self
    }

    pub fn build(self) -> FairnessRunner {
        let config = FairnessConfig {
            baseline_duration: self.baseline_duration.unwrap_or(Duration::from_secs(30)),
            test_duration: self.test_duration.unwrap_or(Duration::from_secs(60)),
            malicious_load_multiplier: self.malicious_multiplier.unwrap_or(10.0),
            tenant1_rate: self.rate.unwrap_or(10.0),
            tenant2_rate: self.rate.unwrap_or(10.0),
            strategy: self.strategy.unwrap_or_default(),
        };

        let mut runner = FairnessRunner::new(config);
        if let Some(dir) = self.export_csv {
            runner = runner.with_csv_export(&dir);
        }
        runner
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Calculate mean and standard deviation from values
pub fn calculate_stats(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;

    (mean, variance.sqrt())
}
