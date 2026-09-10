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
use tracing::info;

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
    /// Create a rate limiter with the given strategy and target rate (ops/s)
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
// OPERATION SCHEDULING (COORDINATED-OMISSION CORRECTION)
// =============================================================================

/// A fixed dispatch schedule for a stream of operations.
///
/// A rate limiter that sleeps `1/rate` *after the previous request completed*
/// produces a closed-loop generator: when the system under test slows down, the
/// generator slows down with it, and the latency it records is the service time
/// of requests that were themselves delayed. The queueing those requests should
/// have experienced is never measured. This is coordinated omission, and it
/// biases the measured degradation factor **downwards** precisely under stress.
///
/// This type instead fixes the intended send time of operation `k` at
/// `start + k * interval`, independent of how long earlier operations took. The
/// difference between the intended time and completion is the *response time* —
/// what a client actually experiences — while dispatch-to-completion is the
/// *service time* the server sees. When the generator keeps up the two are equal.
///
/// In the reference campaign the regular tenant fell to 2.5% of its configured
/// rate under stress, so nearly every request was dispatched late and its
/// queueing delay went unrecorded.
pub struct OperationSchedule {
    start: Instant,
    interval: Duration,
    issued: u64,
}

impl OperationSchedule {
    /// Build a schedule issuing `rate` operations per second from `start`.
    ///
    /// A non-positive or non-finite rate means "as fast as possible": every slot
    /// is due immediately, and response time collapses onto service time.
    pub fn new(start: Instant, rate: f64) -> Self {
        let interval = if rate.is_finite() && rate > 0.0 {
            Duration::from_secs_f64(1.0 / rate)
        } else {
            Duration::ZERO
        };
        Self {
            start,
            interval,
            issued: 0,
        }
    }

    /// Time origin of the schedule. All workers in a phase share this instant, so
    /// their metric timestamps are directly comparable on one axis.
    pub fn start(&self) -> Instant {
        self.start
    }

    /// Intended dispatch time of the next operation, without consuming the slot.
    pub fn next_intended(&self) -> Instant {
        self.start + self.interval * self.issued as u32
    }

    /// Wait until the next slot is due and return the time it was *due*.
    ///
    /// The returned instant is the point latency must be measured from. It is in
    /// the past whenever the generator has fallen behind, and that gap is the
    /// queueing delay a closed-loop generator would otherwise discard.
    pub async fn next_slot(&mut self) -> Instant {
        let intended = self.next_intended();
        self.issued += 1;

        // Unpaced: there is no schedule to fall behind, so the slot is due the
        // moment it is asked for and response time equals service time.
        //
        // Returning `intended` here would return the phase start every time —
        // `next_intended` multiplies a zero interval by the operation count —
        // and every latency would come out as the time elapsed since the phase
        // began, growing linearly for the whole run.
        if self.interval.is_zero() {
            return Instant::now();
        }

        let now = Instant::now();
        if intended > now {
            tokio::time::sleep(intended - now).await;
        }
        intended
    }

    /// Operations dispatched so far.
    pub fn issued(&self) -> u64 {
        self.issued
    }
}

// =============================================================================
// POD QUALITY OF SERVICE
// =============================================================================

/// Kubernetes QoS class requested for a benchmark pod.
///
/// QoS is the mechanism that actually decides how a shared node arbitrates
/// between tenants, so it must be an explicit parameter of the experiment rather
/// than an accident of whichever resource block a pod happened to carry. The fio
/// pod, for instance, previously requested 100m and capped at 500m CPU, making it
/// Burstable *and* throttling the very I/O benchmark it was running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QosClass {
    /// requests == limits on every resource. The scheduler will not evict it and
    /// the cfs quota is fixed, which is what a measurement probe wants.
    #[default]
    Guaranteed,
    /// Requests below limits: may burst, may be throttled, evicted second.
    Burstable,
    /// No requests or limits: unconstrained, evicted first. The realistic shape
    /// for a misconfigured or adversarial neighbour.
    BestEffort,
}

impl Display for QosClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QosClass::Guaranteed => write!(f, "Guaranteed"),
            QosClass::Burstable => write!(f, "Burstable"),
            QosClass::BestEffort => write!(f, "BestEffort"),
        }
    }
}

/// CPU and memory a benchmark pod asks for and is capped at.
///
/// Requests and limits are kept separate because they govern different things
/// and the difference decides whether a run is possible at all. The *request*
/// is what the scheduler subtracts from node capacity; the *limit* is the cfs
/// quota that throttles the container. A KubeVirt tenant cluster is a pair of
/// small VMs, so ten intruder pods requesting a full core each simply do not
/// fit, however idle the underlying host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodResources {
    pub cpu_request_millis: u32,
    pub cpu_limit_millis: u32,
    pub memory_request_mi: u32,
    pub memory_limit_mi: u32,
}

impl PodResources {
    /// Requests equal to limits — the shape Guaranteed requires.
    pub fn uniform(cpu_millis: u32, memory_mi: u32) -> Self {
        Self {
            cpu_request_millis: cpu_millis,
            cpu_limit_millis: cpu_millis,
            memory_request_mi: memory_mi,
            memory_limit_mi: memory_mi,
        }
    }

    /// Modest requests with a generous ceiling.
    ///
    /// Schedulable on a node far smaller than the ceiling, while still free to
    /// use the whole limit when the node is idle. The cost is real and worth
    /// stating: under cgroup v2 a container's CPU weight derives from its
    /// *request*, so on a saturated node a 100m-request pod receives a tenth of
    /// the share of a 1000m one. Where that matters for a measurement, use
    /// `uniform` and Guaranteed instead.
    pub fn burstable(
        cpu_request_millis: u32,
        cpu_limit_millis: u32,
        memory_request_mi: u32,
        memory_limit_mi: u32,
    ) -> Self {
        Self {
            cpu_request_millis,
            cpu_limit_millis,
            memory_request_mi,
            memory_limit_mi,
        }
    }
}

impl QosClass {
    /// Build the container `resources` block that yields this QoS class.
    ///
    /// The class, not the caller, decides the final shape: Guaranteed pins
    /// requests to the limits regardless of what was passed, since anything
    /// else silently produces a Burstable pod. Returns `None` for BestEffort,
    /// where the block must be absent entirely — an empty `resources: {}` is
    /// not the same thing to the kubelet.
    pub fn resources_json(&self, resources: &PodResources) -> Option<serde_json::Value> {
        let cpu_limit = format!("{}m", resources.cpu_limit_millis);
        let memory_limit = format!("{}Mi", resources.memory_limit_mi);

        match self {
            QosClass::Guaranteed => Some(serde_json::json!({
                "requests": { "cpu": cpu_limit, "memory": memory_limit },
                "limits":   { "cpu": cpu_limit, "memory": memory_limit }
            })),
            QosClass::Burstable => {
                // Requests at or above the limits would be rejected, or would
                // quietly promote the pod to Guaranteed. Clamp rather than fail:
                // the caller asked for headroom, not for a specific ratio.
                let cpu_request = resources
                    .cpu_request_millis
                    .min(resources.cpu_limit_millis.saturating_sub(1).max(1));
                let memory_request = resources
                    .memory_request_mi
                    .min(resources.memory_limit_mi.saturating_sub(1).max(1));
                Some(serde_json::json!({
                    "requests": { "cpu": format!("{cpu_request}m"), "memory": format!("{memory_request}Mi") },
                    "limits":   { "cpu": cpu_limit, "memory": memory_limit }
                }))
            }
            QosClass::BestEffort => None,
        }
    }

    /// Stamp this QoS class, and an optional RuntimeClass, onto a pod spec.
    ///
    /// One helper rather than per-assessor resource blocks, so a change of
    /// sandbox runtime or QoS applies identically across every subsystem.
    pub fn apply_to_pod(
        &self,
        pod: &mut serde_json::Value,
        resources: &PodResources,
        runtime_class_name: Option<&str>,
    ) {
        match self.resources_json(resources) {
            Some(resources) => {
                if let Some(containers) = pod["spec"]["containers"].as_array_mut() {
                    for container in containers {
                        container["resources"] = resources.clone();
                    }
                }
            }
            None => {
                if let Some(containers) = pod["spec"]["containers"].as_array_mut() {
                    for container in containers {
                        if let Some(map) = container.as_object_mut() {
                            map.remove("resources");
                        }
                    }
                }
            }
        }

        if let Some(runtime_class) = runtime_class_name {
            pod["spec"]["runtimeClassName"] = serde_json::json!(runtime_class);
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
    /// Load multiplier for malicious tenant rate (e.g., 10.0 = 10x rate)
    pub malicious_load_multiplier: f64,
    /// Pod multiplier for malicious tenant (e.g., 2.0 = 2x pods)
    pub malicious_pod_multiplier: f64,
    /// Request rate for tenant1 (regular tenant) in ops/sec
    pub tenant1_rate: f64,
    /// Request rate for tenant2 (malicious tenant) in ops/sec
    pub tenant2_rate: f64,
    /// Rate limiting strategy
    pub strategy: RateLimitStrategy,
}

impl Default for FairnessConfig {
    fn default() -> Self {
        // Keep these in step with `main::defaults`, which is authoritative for the
        // CLI and always sets both multipliers explicitly. These values previously
        // had the two multipliers transposed relative to the CLI defaults; nothing
        // consumed them, but a future caller constructing a config directly would
        // have silently got a different experiment than the one the CLI runs.
        Self {
            baseline_duration: Duration::from_secs(30),
            test_duration: Duration::from_secs(60),
            malicious_load_multiplier: 1.0,
            malicious_pod_multiplier: 10.0,
            tenant1_rate: 10.0,
            tenant2_rate: 10.0,
            strategy: RateLimitStrategy::FixedDelay,
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
    /// When the operation was *dispatched*, in seconds from the phase start.
    ///
    /// A real clock. A time series drawn against it covers the phase it was
    /// measured in, and a rate computed from it is the rate the tenant actually
    /// got. Both of those stop being true if the schedule is used instead —
    /// see [`Self::slot_timestamp_secs`].
    ///
    /// For the pod-based subsystems the pod reports its own elapsed time, which
    /// is the same quantity measured inside the pod rather than at the caller.
    pub timestamp_secs: f64,
    /// How long the operation took, measured from when it was actually
    /// dispatched to when it completed.
    ///
    /// This is the reportable latency and the one the degradation factor is
    /// computed from. It is a measured quantity: it charges the operation only
    /// for time the system under test actually spent on it.
    pub latency_ms: f64,
    /// Time from the operation's *scheduled slot* to its completion, where the
    /// subsystem dispatches against an [`OperationSchedule`].
    ///
    /// Larger than `latency_ms` whenever the generator has fallen behind, since
    /// it also charges the operation for the wait between when it was due and
    /// when a worker was free to send it. That wait is modelled rather than
    /// observed — our workers are sequential loops, so a request that is not yet
    /// sent is not queued anywhere real — which is why this is a diagnostic and
    /// not the reported latency.
    ///
    /// Its use is as a validity check. Divided by `latency_ms` it gives the
    /// coordinated-omission factor: near 1.0 the probe kept up and its latency
    /// is trustworthy; far above 1.0 the probe was itself saturated, so the
    /// figure describes its own backlog more than the platform. Under sustained
    /// overload it grows with the phase duration and is not a stable metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_latency_ms: Option<f64>,
    /// The operation's *scheduled slot*, in seconds from the phase start, where
    /// the subsystem dispatches against an [`OperationSchedule`].
    ///
    /// Not a clock: [`OperationSchedule::next_intended`] is `issued / rate`, so
    /// this counts operations, not seconds. The two agree only while the
    /// generator keeps up. When it falls behind, the schedule runs slow — a
    /// phase that offered 300 ops/s and achieved 31 advances its schedule by
    /// about four seconds over thirty real ones.
    ///
    /// Which makes it the wrong axis for a time series and the wrong
    /// denominator for a rate. `ops / schedule_span` reduces to
    /// `ops / (ops / configured_rate)` — the configured rate, restated, whatever
    /// the run did. It is kept because paired with `scheduled_latency_ms` it is
    /// what the coordinated-omission correction is computed from, and because
    /// its divergence from `timestamp_secs` *is* the shortfall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_timestamp_secs: Option<f64>,
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
    /// Wall-clock span covered by the recorded operations, in seconds
    ///
    /// Derived from [`MetricPoint::timestamp_secs`] rather than the phase
    /// duration: the pod-based subsystems measure inside the pod, so the phase
    /// wall clock would include pod scheduling and startup and understate the
    /// rate.
    ///
    /// That only holds because `timestamp_secs` is a clock. Taken from
    /// [`MetricPoint::slot_timestamp_secs`] instead, this span is
    /// `operations / configured_rate` and the achieved rate derived from it is
    /// the configured rate by construction — a saturated phase would report
    /// full throughput. The distinction is the whole reason the two fields are
    /// separate.
    pub observed_span_secs: f64,
    /// Payload bytes moved per second, where the subsystem knows its payload size
    ///
    /// Only the network subsystem populates this. It makes the reported bandwidth
    /// a measurement rather than a restatement of the configured packet rate.
    pub achieved_bytes_per_sec: Option<f64>,
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

        let observed_span_secs = match (
            points
                .iter()
                .map(|p| p.timestamp_secs)
                .fold(f64::INFINITY, f64::min),
            points
                .iter()
                .map(|p| p.timestamp_secs)
                .fold(f64::NEG_INFINITY, f64::max),
        ) {
            (lo, hi) if lo.is_finite() && hi.is_finite() && hi > lo => hi - lo,
            _ => 0.0,
        };

        Self {
            avg_latency_ms: avg,
            std_deviation_ms: std,
            operations: points.len() as u64,
            error_rate,
            observed_span_secs,
            achieved_bytes_per_sec: None,
            raw: points,
        }
    }

    /// Record the payload size of one operation, deriving achieved bandwidth.
    ///
    /// For a request/response probe, pass the bytes that cross the wire per
    /// operation in *both* directions — an echo of an N-byte payload moves 2N.
    pub fn with_bytes_per_operation(mut self, bytes_per_operation: f64) -> Self {
        self.achieved_bytes_per_sec = Some(self.achieved_ops_per_sec() * bytes_per_operation);
        self
    }

    /// Operations actually issued per second over the observed window.
    ///
    /// This is the number the paper must report: the *configured* rate is an
    /// intent, and a closed-loop generator silently falls short of it whenever
    /// the system under test saturates.
    pub fn achieved_ops_per_sec(&self) -> f64 {
        if self.observed_span_secs > 0.0 {
            self.operations as f64 / self.observed_span_secs
        } else {
            0.0
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
    /// Throughput retention for the regular tenant (1.0 = rate held, 0.5 = halved)
    ///
    /// The companion to `latency_degradation`. Under a closed-loop generator a
    /// saturated system harms the victim twice: its requests get slower *and* it
    /// completes fewer of them. Latency alone therefore understates the damage —
    /// in the reference campaign the regular tenant retained as little as 2.5% of
    /// its baseline request rate while its mean latency rose 43x.
    pub throughput_retention: f64,
}

impl FairnessResult {
    /// Calculate degradation from baseline to unbalanced
    ///
    /// Returns NaN when either phase produced no usable latency, so an absent
    /// measurement cannot be mistaken for an excellent one. A phase whose owner
    /// contributed nothing has a mean of 0, and dividing that by the baseline
    /// gave 0.00 — which `fairness_level` then classified as "Excellent". Three
    /// of five runs in the first corrected campaign reported exactly that while
    /// the owner's fio pod had in fact produced no samples at all.
    pub fn calculate_degradation(baseline_ms: f64, unbalanced_ms: f64) -> f64 {
        if baseline_ms <= 0.0 || unbalanced_ms <= 0.0 {
            return f64::NAN;
        }
        unbalanced_ms / baseline_ms
    }

    /// Fraction of the baseline request rate the regular tenant sustained under stress.
    ///
    /// 1.0 means the Owner held R_base as the fairness model assumes; anything
    /// materially below that means the measured latency degradation is optimistic,
    /// because the victim was throttled rather than merely slowed.
    pub fn calculate_throughput_retention(baseline_ops: f64, unbalanced_ops: f64) -> f64 {
        if baseline_ops <= 0.0 {
            1.0
        } else {
            (unbalanced_ops / baseline_ops).max(0.0)
        }
    }

    /// Whether this result rests on actual measurements in both phases.
    ///
    /// False when a phase produced no samples; the degradation factor is then
    /// NaN and must not be reported or averaged.
    pub fn is_valid(&self) -> bool {
        self.latency_degradation.is_finite()
    }

    /// Get qualitative fairness level
    pub fn fairness_level(&self) -> FairnessLevel {
        if !self.latency_degradation.is_finite() {
            // NaN compares false against every bound, so without this it would
            // fall through to the last arm and be reported as Critical — a
            // definite-looking verdict derived from no data.
            return FairnessLevel::Unknown;
        }
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
    /// A phase produced no samples; there is no measurement to grade.
    Unknown,
    Excellent, // ≤5% degradation
    Good,      // ≤15% degradation
    Moderate,  // ≤30% degradation
    Poor,      // ≤50% degradation
    Critical,  // >50% degradation
}

impl Display for FairnessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FairnessLevel::Unknown => write!(f, "Unknown (no data)"),
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
            FairnessLevel::Unknown => "❔",
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
            "  Tenant1: {:>8.2}ms ± {:>6.2}ms  ({:>5} ops, {:>9.1} ops/s, {:>5.2}% err)",
            self.baseline.tenant1.avg_latency_ms,
            self.baseline.tenant1.std_deviation_ms,
            self.baseline.tenant1.operations,
            self.baseline.tenant1.achieved_ops_per_sec(),
            self.baseline.tenant1.error_rate
        )?;
        writeln!(
            f,
            "  Tenant2: {:>8.2}ms ± {:>6.2}ms  ({:>5} ops, {:>9.1} ops/s, {:>5.2}% err)",
            self.baseline.tenant2.avg_latency_ms,
            self.baseline.tenant2.std_deviation_ms,
            self.baseline.tenant2.operations,
            self.baseline.tenant2.achieved_ops_per_sec(),
            self.baseline.tenant2.error_rate
        )?;

        writeln!(f, "\n{}", "Unbalanced:".bold())?;
        writeln!(
            f,
            "  Regular:   {:>8.2}ms ± {:>6.2}ms  ({:>6} ops, {:>9.1} ops/s, {:>5.2}% err)",
            self.unbalanced.tenant1.avg_latency_ms,
            self.unbalanced.tenant1.std_deviation_ms,
            self.unbalanced.tenant1.operations,
            self.unbalanced.tenant1.achieved_ops_per_sec(),
            self.unbalanced.tenant1.error_rate
        )?;
        writeln!(
            f,
            "  Malicious: {:>8.2}ms ± {:>6.2}ms  ({:>6} ops, {:>9.1} ops/s, {:>5.2}% err)",
            self.unbalanced.tenant2.avg_latency_ms,
            self.unbalanced.tenant2.std_deviation_ms,
            self.unbalanced.tenant2.operations,
            self.unbalanced.tenant2.achieved_ops_per_sec(),
            self.unbalanced.tenant2.error_rate
        )?;
        // How hard the intruder actually pushed, in every subsystem. The
        // configured escalation is a request, not an outcome: a pod multiplier
        // silently dropped from the campaign file and a generator that could
        // not keep up both show here as an escalation below the configured
        // one, and neither is visible from the latency figures alone.
        let baseline_load = self.baseline.tenant2.achieved_ops_per_sec();
        let unbalanced_load = self.unbalanced.tenant2.achieved_ops_per_sec();
        if baseline_load > 0.0 {
            writeln!(
                f,
                "    ↳ {:.1}x the baseline load ({:.1} → {:.1} ops/s)",
                unbalanced_load / baseline_load,
                baseline_load,
                unbalanced_load
            )?;
        }

        // Only the network generator knows its payload size, so the other
        // subsystems leave this None and print no bandwidth at all.
        if let (Some(b), Some(u)) = (
            self.baseline.tenant1.achieved_bytes_per_sec,
            self.unbalanced.tenant1.achieved_bytes_per_sec,
        ) {
            let mbps = |bytes_per_sec: f64| bytes_per_sec * 8.0 / 1.0e6;
            writeln!(f, "\n{}", "Bandwidth (on the wire):".bold())?;
            writeln!(
                f,
                "  regular    baseline {:>9.1} Mbps   unbalanced {:>9.1} Mbps",
                mbps(b),
                mbps(u)
            )?;
            if let (Some(b2), Some(u2)) = (
                self.baseline.tenant2.achieved_bytes_per_sec,
                self.unbalanced.tenant2.achieved_bytes_per_sec,
            ) {
                writeln!(
                    f,
                    "  malicious  baseline {:>9.1} Mbps   unbalanced {:>9.1} Mbps",
                    mbps(b2),
                    mbps(u2)
                )?;
            }
        }

        writeln!(f, "\n{}", "Result:".bold())?;
        writeln!(
            f,
            "  {:.2}x latency degradation — {}",
            self.latency_degradation, level
        )?;
        writeln!(
            f,
            "  {:.1}% throughput retained by the regular tenant",
            self.throughput_retention * 100.0
        )?;
        if self.throughput_retention < 0.95 {
            writeln!(
                f,
                "  ⚠ regular tenant did not sustain its configured rate; the latency"
            )?;
            writeln!(
                f,
                "    degradation above is a LOWER BOUND on the true impact"
            )?;
        }

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

    /// Subsystem-specific settings, recorded in the run manifest.
    ///
    /// The manifest otherwise carries only the shared `FairnessConfig`, so the
    /// knobs that decide *what was actually measured* went unrecorded: nothing
    /// in a result set said whether storage exercised a PVC or a node-local
    /// `emptyDir`, which prime size the workload used, or how large the network
    /// packets were. Reconstructing that afterwards is guesswork.
    fn configuration(&self) -> Option<serde_json::Value> {
        None
    }

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

// =============================================================================
// RUN MANIFEST
// =============================================================================

/// Per-tenant, per-phase measurements as persisted alongside the CSVs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TenantManifest {
    pub operations: u64,
    pub observed_span_secs: f64,
    pub achieved_ops_per_sec: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub achieved_bytes_per_sec: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub achieved_mbps: Option<f64>,
    /// Mean dispatch-to-completion time — the reported latency.
    pub mean_latency_ms: f64,
    /// Population standard deviation (divides by n), matching `calculate_stats`.
    pub stddev_latency_ms_population: f64,
    pub p95_latency_ms: f64,
    pub error_rate_percent: f64,
    /// Mean slot-to-completion time, where the subsystem dispatches on a schedule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_scheduled_latency_ms: Option<f64>,
    /// `mean_scheduled_latency_ms / mean_latency_ms`.
    ///
    /// A validity check on the probe, not a result. 1.0 means the generator kept
    /// up, so the latency above measures the platform. Well above 1.0 means the
    /// probe fell behind and spent the phase working through its own backlog, at
    /// which point its latency says more about the probe than the system, and
    /// `throughput_retention` is the metric carrying the real signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinated_omission_factor: Option<f64>,
}

impl TenantManifest {
    fn from_metrics(m: &TenantMetrics) -> Self {
        let mut sorted: Vec<f64> = m.raw.iter().map(|p| p.latency_ms).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p95 = if sorted.is_empty() {
            0.0
        } else {
            let idx = (((sorted.len() as f64) * 0.95).ceil() as usize).saturating_sub(1);
            sorted[idx.min(sorted.len() - 1)]
        };

        // Only present where the subsystem dispatches against a schedule; the
        // pod-based assessors pace themselves inside the pod and record neither.
        let scheduled: Vec<f64> = m
            .raw
            .iter()
            .filter_map(|p| p.scheduled_latency_ms)
            .collect();
        let mean_scheduled_latency_ms =
            (!scheduled.is_empty()).then(|| scheduled.iter().sum::<f64>() / scheduled.len() as f64);
        let coordinated_omission_factor = mean_scheduled_latency_ms
            .filter(|_| m.avg_latency_ms > 0.0)
            .map(|scheduled| scheduled / m.avg_latency_ms);

        Self {
            operations: m.operations,
            observed_span_secs: m.observed_span_secs,
            achieved_ops_per_sec: m.achieved_ops_per_sec(),
            achieved_bytes_per_sec: m.achieved_bytes_per_sec,
            achieved_mbps: m.achieved_bytes_per_sec.map(|b| b * 8.0 / 1.0e6),
            mean_latency_ms: m.avg_latency_ms,
            stddev_latency_ms_population: m.std_deviation_ms,
            p95_latency_ms: p95,
            error_rate_percent: m.error_rate,
            mean_scheduled_latency_ms,
            coordinated_omission_factor,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PhaseManifest {
    pub tenant1: TenantManifest,
    pub tenant2: TenantManifest,
}

/// The configuration a run actually resolved to, after CLI/YAML/default layering.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigManifest {
    pub baseline_duration_secs: u64,
    pub test_duration_secs: u64,
    pub rate_strategy: String,
    pub tenant1_rate: f64,
    pub tenant2_rate: f64,
    pub malicious_load_multiplier: f64,
    pub malicious_pod_multiplier: f64,
    /// tenant2_rate * malicious_load_multiplier, i.e. the intruder's target rate.
    /// Total request rate the intruder is aimed at, in the subsystem's own
    /// units.
    ///
    /// `rate * loadMultiplier * podMultiplier`. The pod multiplier belongs in
    /// here: the control plane scales its tenant total by it, and the pod-based
    /// subsystems reach the same figure by running that many more pods. Recording
    /// only `rate * loadMultiplier` described a 1000 req/s control-plane intruder
    /// as 100.
    ///
    /// Assumes the subsystem's base pod, pair or worker-group count is 1, which
    /// is what the campaign config uses. Where it is not, this is the per-group
    /// target and the true total is that many times larger — so compare against
    /// `unbalanced.tenant2.achieved_ops_per_sec`, which is measured rather than
    /// derived.
    pub intruder_target_rate: f64,
    /// The combined stress factor applied to the intruder. Subsystems configured
    /// with different factors are NOT comparable to one another.
    pub effective_stress_factor: f64,
}

impl ConfigManifest {
    fn from_config(c: &FairnessConfig) -> Self {
        Self {
            baseline_duration_secs: c.baseline_duration.as_secs(),
            test_duration_secs: c.test_duration.as_secs(),
            rate_strategy: c.strategy.to_string(),
            tenant1_rate: c.tenant1_rate,
            tenant2_rate: c.tenant2_rate,
            malicious_load_multiplier: c.malicious_load_multiplier,
            malicious_pod_multiplier: c.malicious_pod_multiplier,
            intruder_target_rate: c.malicious_rate() * c.malicious_pod_multiplier,
            effective_stress_factor: c.malicious_load_multiplier * c.malicious_pod_multiplier,
        }
    }
}

/// Everything needed to interpret a pair of result CSVs without external notes.
///
/// The reference campaign recorded its configuration only as captured stdout,
/// which meant the offered load had to be reconstructed by arithmetic on op
/// counts long afterwards. This makes each run self-describing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunManifest {
    pub schema_version: u32,
    pub subsystem: String,
    pub metric: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution_label: Option<String>,
    pub tool_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub started_at_utc: String,
    pub run_timestamp: u64,
    pub baseline_csv: String,
    pub unbalanced_csv: String,
    pub config: ConfigManifest,
    /// Subsystem-specific settings; see `FairnessAssessor::configuration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem_config: Option<serde_json::Value>,
    pub baseline: PhaseManifest,
    pub unbalanced: PhaseManifest,
    pub latency_degradation: f64,
    pub throughput_retention: f64,
    pub fairness_level: String,
    /// Set when the regular tenant failed to sustain its configured rate, which
    /// makes `latency_degradation` a lower bound rather than a point estimate.
    pub owner_throttled: bool,
    /// Fraction of its configured rate the intruder actually delivered.
    ///
    /// The degradation factor only compares across solutions if each was put
    /// under the same load, and that is not something to assume. A KubeVirt
    /// tenant delivered 19.6k of a configured 156k packets/s — an eighth of what
    /// the namespace-based solutions managed — because the VM's virtual NIC
    /// could not carry it. Its degradation factor of 1.00 therefore says nothing
    /// about isolation: the stress was never applied.
    pub intruder_load_ratio: f64,
    /// Set when the intruder delivered materially less than its configured rate,
    /// so this run is not comparable with one where the load did arrive.
    pub intruder_underloaded: bool,
}

/// Below this share of its configured rate, the intruder did not apply the load
/// the experiment specifies and the run should not be compared with one that
/// did. Not a tight bound — a few percent of jitter is normal — but an eightfold
/// shortfall must never pass silently.
pub const INTRUDER_LOAD_THRESHOLD: f64 = 0.90;

/// Render a Unix timestamp as an ISO-8601 UTC string.
///
/// Hand-rolled rather than pulling in a date crate for one line of output;
/// uses the standard days-to-civil conversion (Howard Hinnant's algorithm).
pub fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = era * 400 + yoe + i64::from(m <= 2);

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Best-effort commit hash so a result set can be traced back to the code.
///
/// Suffixed with `-dirty` when the working tree has uncommitted changes. Without
/// that marker the field actively misleads: a campaign run from a modified tree
/// records the last commit, which does not describe the binary that produced the
/// numbers — and the whole point of the field is that it should.
pub fn git_commit_hash() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let hash = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if hash.is_empty() {
        return None;
    }

    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| !out.stdout.is_empty());

    Some(if dirty { format!("{hash}-dirty") } else { hash })
}

/// What share of its configured rate the intruder actually delivered.
///
/// `NaN` when no target is configured, so callers must not treat a missing value
/// as a pass.
fn intruder_load_ratio(config: &FairnessConfig, result: &FairnessResult) -> f64 {
    let target = config.malicious_rate() * config.malicious_pod_multiplier;
    if target <= 0.0 {
        return f64::NAN;
    }
    result.unbalanced.tenant2.achieved_ops_per_sec() / target
}

/// Runner that orchestrates fairness assessments
pub struct FairnessRunner {
    config: FairnessConfig,
    export_csv: bool,
    output_dir: String,
    solution_label: Option<String>,
}

impl FairnessRunner {
    /// Create a new runner with the given configuration
    pub fn new(config: FairnessConfig) -> Self {
        Self {
            config,
            export_csv: false,
            output_dir: "fairness_results".to_string(),
            solution_label: None,
        }
    }

    /// Enable CSV export to the specified directory
    pub fn with_csv_export(mut self, dir: &str) -> Self {
        self.export_csv = true;
        self.output_dir = dir.to_string();
        self
    }

    /// Record which multi-tenancy solution this run targeted (e.g. "vcluster")
    pub fn with_solution_label(mut self, label: Option<String>) -> Self {
        self.solution_label = label;
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

        // Taken before any measurement so the CSVs and the manifest share a key
        // that reflects when the run started, not when it happened to finish.
        let run_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let started_at_utc = format_unix_utc(run_timestamp);

        // Phase 1: Baseline
        println!(
            "  {} Baseline ({}s)...",
            "→".dimmed(),
            self.config.baseline_duration.as_secs()
        );
        let baseline = assessor
            .run_baseline(tenant1.clone(), tenant2.clone(), &self.config)
            .await?;

        println!(
            "      Tenant1: {:.2}ms @ {:.1} ops/s, Tenant2: {:.2}ms @ {:.1} ops/s",
            baseline.tenant1.avg_latency_ms,
            baseline.tenant1.achieved_ops_per_sec(),
            baseline.tenant2.avg_latency_ms,
            baseline.tenant2.achieved_ops_per_sec()
        );

        // Phase 2: Unbalanced
        println!(
            "  {} Unbalanced ({}s, {}x effective load on tenant2)...",
            "→".dimmed(),
            self.config.test_duration.as_secs(),
            self.config.malicious_load_multiplier * self.config.malicious_pod_multiplier
        );
        let unbalanced = assessor
            .run_unbalanced(tenant1, tenant2, &self.config)
            .await?;

        println!(
            "      Regular: {:.2}ms @ {:.1} ops/s, Malicious: {:.2}ms @ {:.1} ops/s",
            unbalanced.tenant1.avg_latency_ms,
            unbalanced.tenant1.achieved_ops_per_sec(),
            unbalanced.tenant2.avg_latency_ms,
            unbalanced.tenant2.achieved_ops_per_sec()
        );

        // Calculate degradation
        info!("Calculating degradation...");
        let degradation = FairnessResult::calculate_degradation(
            baseline.tenant1.avg_latency_ms,
            unbalanced.tenant1.avg_latency_ms,
        );
        let retention = FairnessResult::calculate_throughput_retention(
            baseline.tenant1.achieved_ops_per_sec(),
            unbalanced.tenant1.achieved_ops_per_sec(),
        );

        let result = FairnessResult {
            subsystem: assessor.name().to_string(),
            baseline,
            unbalanced,
            latency_degradation: degradation,
            throughput_retention: retention,
        };

        println!(
            "  {} {:.2}x latency degradation ({})",
            "✓".green(),
            degradation,
            result.fairness_level()
        );
        println!(
            "  {} {:.1}% throughput retained by the regular tenant",
            if retention >= 0.95 {
                "✓".green()
            } else {
                "⚠".yellow()
            },
            retention * 100.0
        );
        if retention < 0.95 {
            println!(
                "      {} the regular tenant could not sustain its configured rate, so the",
                "note:".dimmed()
            );
            println!(
                "      {} latency degradation above is a lower bound on the true impact",
                "     ".dimmed()
            );
        }

        // A degradation factor only compares across solutions if each was put
        // under the same load. Printed here rather than left in the manifest
        // because a run that never applied its stress should be visible while
        // the campaign is still running, not after the analysis.
        let load_ratio = intruder_load_ratio(&self.config, &result);
        if load_ratio.is_finite() && load_ratio < INTRUDER_LOAD_THRESHOLD {
            println!(
                "  {} intruder delivered {:.1}% of its configured load ({:.0} of {:.0} ops/s)",
                "⚠".yellow(),
                load_ratio * 100.0,
                result.unbalanced.tenant2.achieved_ops_per_sec(),
                self.config.malicious_rate() * self.config.malicious_pod_multiplier
            );
            println!(
                "      {} the specified stress was never applied, so this degradation factor",
                "note:".dimmed()
            );
            println!(
                "      {} is not comparable with a run where the intruder reached its target",
                "     ".dimmed()
            );
        }

        // Export CSV if enabled
        if self.export_csv {
            info!("Exporting results to CSV...");
            info!("  Output directory: {}", self.output_dir);
            self.export_to_csv(
                &result,
                assessor.metric(),
                assessor.configuration(),
                run_timestamp,
                started_at_utc,
            )
            .await?;
        }

        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    async fn export_to_csv(
        &self,
        result: &FairnessResult,
        metric: &str,
        subsystem_config: Option<serde_json::Value>,
        run_timestamp: u64,
        started_at_utc: String,
    ) -> Result<()> {
        use tokio::fs;

        fs::create_dir_all(&self.output_dir).await?;

        let subsystem = result.subsystem.to_lowercase().replace(' ', "_");

        info!("Exporting metrics to {}/", self.output_dir);

        // The timestamp is taken once at the start of the run and shared by the
        // CSVs and the manifest, so the three files join on a stable key.
        let baseline_path = format!(
            "{}/{}_baseline_{}.csv",
            self.output_dir, subsystem, run_timestamp
        );
        let unbalanced_path = format!(
            "{}/{}_unbalanced_{}.csv",
            self.output_dir, subsystem, run_timestamp
        );
        let manifest_path = format!(
            "{}/{}_manifest_{}.json",
            self.output_dir, subsystem, run_timestamp
        );

        // Run both writes concurrently
        let write_baseline = write_csv(&baseline_path, &result.baseline);
        let write_unbalanced = write_csv(&unbalanced_path, &result.unbalanced);

        tokio::try_join!(write_baseline, write_unbalanced)?;

        let manifest = RunManifest {
            schema_version: 1,
            subsystem: result.subsystem.clone(),
            metric: metric.to_string(),
            solution_label: self.solution_label.clone(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: git_commit_hash(),
            started_at_utc,
            run_timestamp,
            baseline_csv: baseline_path
                .rsplit('/')
                .next()
                .unwrap_or(&baseline_path)
                .to_string(),
            unbalanced_csv: unbalanced_path
                .rsplit('/')
                .next()
                .unwrap_or(&unbalanced_path)
                .to_string(),
            config: ConfigManifest::from_config(&self.config),
            subsystem_config,
            baseline: PhaseManifest {
                tenant1: TenantManifest::from_metrics(&result.baseline.tenant1),
                tenant2: TenantManifest::from_metrics(&result.baseline.tenant2),
            },
            unbalanced: PhaseManifest {
                tenant1: TenantManifest::from_metrics(&result.unbalanced.tenant1),
                tenant2: TenantManifest::from_metrics(&result.unbalanced.tenant2),
            },
            latency_degradation: result.latency_degradation,
            throughput_retention: result.throughput_retention,
            fairness_level: result.fairness_level().to_string(),
            owner_throttled: result.throughput_retention < 0.95,
            intruder_load_ratio: intruder_load_ratio(&self.config, result),
            intruder_underloaded: intruder_load_ratio(&self.config, result)
                < INTRUDER_LOAD_THRESHOLD,
        };
        fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).await?;

        println!("  📁 Exported to {}/", self.output_dir);
        println!("      - {}", baseline_path);
        println!("      - {}", unbalanced_path);
        println!("      - {}", manifest_path);
        Ok(())
    }
}

async fn write_csv(path: &str, phase: &PhaseResult) -> Result<()> {
    use std::fmt::Write;
    use tokio::fs::File;
    use tokio::io::{AsyncWriteExt, BufWriter}; // Needed for write! macro on String

    let file = File::create(path).await?;
    // Use a large buffer (e.g., 64KB) to minimize syscalls
    let mut writer = BufWriter::with_capacity(64 * 1024, file);

    // `scheduled_latency_ms` and `slot_timestamp_secs` are appended after the
    // original columns so that readers of the pre-existing five-column format
    // keep working unchanged. `latency_ms` holds dispatch-to-completion, the
    // reported latency; `timestamp_secs` holds the dispatch clock, so a reader
    // that knows nothing of the schedule still gets a correct time axis.
    writer
        .write_all(
            b"tenant,timestamp_secs,latency_ms,is_error,label,scheduled_latency_ms,slot_timestamp_secs\n",
        )
        .await?;

    // Reusable buffer to avoid allocating a new String for every row
    let mut line_buf = String::with_capacity(256);

    // Helper closure to write points (reduces code duplication)
    // Note: We use a macro-like approach or simple loop to avoid borrow checker complexity in async
    for (tenant, points) in [
        ("tenant1", &phase.tenant1.raw),
        ("tenant2", &phase.tenant2.raw),
    ] {
        for point in points {
            line_buf.clear();
            // Write formatting into memory buffer first
            write!(
                &mut line_buf,
                "{},{:.3},{:.3},{},{},",
                tenant,
                point.timestamp_secs,
                point.latency_ms,
                point.is_error,
                point.label.as_deref().unwrap_or("")
            )
            .unwrap();
            if let Some(scheduled) = point.scheduled_latency_ms {
                write!(&mut line_buf, "{scheduled:.3}").unwrap();
            }
            line_buf.push(',');
            match point.slot_timestamp_secs {
                Some(slot) => writeln!(&mut line_buf, "{slot:.3}").unwrap(),
                None => writeln!(&mut line_buf).unwrap(),
            }

            // Write memory buffer to BufWriter (fast)
            writer.write_all(line_buf.as_bytes()).await?;
        }
    }

    writer.flush().await?;
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
    pod_multiplier: Option<f64>,
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

    pub fn pod_multiplier(mut self, m: f64) -> Self {
        self.pod_multiplier = Some(m);
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
        // Unset fields fall back to FairnessConfig::default(), so the builder and a
        // directly-constructed config cannot disagree.
        let defaults = FairnessConfig::default();
        let config = FairnessConfig {
            baseline_duration: self.baseline_duration.unwrap_or(defaults.baseline_duration),
            test_duration: self.test_duration.unwrap_or(defaults.test_duration),
            malicious_load_multiplier: self
                .malicious_multiplier
                .unwrap_or(defaults.malicious_load_multiplier),
            malicious_pod_multiplier: self
                .pod_multiplier
                .unwrap_or(defaults.malicious_pod_multiplier),
            tenant1_rate: self.rate.unwrap_or(defaults.tenant1_rate),
            tenant2_rate: self.rate.unwrap_or(defaults.tenant2_rate),
            strategy: self.strategy.unwrap_or(defaults.strategy),
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
///
/// NOTE: this is the *population* standard deviation (divides by n), matching
/// `TenantMetrics::from_raw`. The Python analysis pipeline uses pandas `.std()`,
/// which is the *sample* standard deviation (ddof=1). Reported figures must state
/// which convention they use.
pub fn calculate_stats(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;

    (mean, variance.sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rate contract: N gated operations at rate R occupy (N-1)/R seconds.
    ///
    /// This is what makes "configured rate == achieved rate" true. The control
    /// plane assessor calls `wait()` once per API request, so a scenario issuing
    /// six requests and one issuing four both emit at the limiter's rate. The
    /// previous implementation gated once per CRUD *scenario* while dividing the
    /// rate by a hardcoded 3.0, which inflated the achieved rate by
    /// (2*4 + 3*6) / (5*3) = 1.733x at the campaign's 5-worker configuration.
    #[tokio::test]
    async fn fixed_delay_paces_each_operation() {
        let limiter = RateLimiter::fixed_delay(200.0); // 5 ms apart
        let started = Instant::now();
        for _ in 0..11 {
            limiter.wait().await;
        }
        // 11 waits => 10 intervals => >= 50 ms. Upper bound is loose because the
        // tokio timer only guarantees "at least" the requested sleep.
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(50),
            "11 waits at 200/s took {elapsed:?}, expected >= 50ms"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "11 waits at 200/s took {elapsed:?}, far above the 50ms target"
        );
    }

    /// Intended dispatch times must be fixed by the schedule, not by how long
    /// earlier operations took. This is the property that makes the recorded
    /// latency a response time rather than a service time.
    #[tokio::test]
    async fn schedule_slots_do_not_drift_with_slow_operations() {
        let start = Instant::now();
        let mut schedule = OperationSchedule::new(start, 100.0); // 10 ms apart

        let first = schedule.next_slot().await;
        assert_eq!(first, start, "slot 0 is due immediately");

        // Simulate an operation that overruns its slot by a wide margin.
        tokio::time::sleep(Duration::from_millis(80)).await;

        // The next slot was due at start+10ms and is now well in the past, so it
        // must be returned immediately and must NOT be pushed out by the overrun.
        let before = Instant::now();
        let second = schedule.next_slot().await;
        assert!(
            before.elapsed() < Duration::from_millis(5),
            "an overdue slot must not sleep"
        );
        assert_eq!(second, start + Duration::from_millis(10));

        // A request completing now would have a response time of ~80 ms measured
        // from its intended slot, versus a service time near zero. That gap is
        // exactly what closed-loop measurement discards.
        let response = Instant::now().saturating_duration_since(second);
        assert!(
            response >= Duration::from_millis(60),
            "response time should carry the queueing delay, got {response:?}"
        );

        assert_eq!(schedule.issued(), 2);
    }

    #[tokio::test]
    async fn schedule_with_zero_rate_never_sleeps() {
        let start = Instant::now();
        for rate in [0.0, -1.0, f64::INFINITY, f64::NAN] {
            let mut schedule = OperationSchedule::new(start, rate);
            let before = Instant::now();
            for _ in 0..100 {
                schedule.next_slot().await;
            }
            assert!(
                before.elapsed() < Duration::from_millis(50),
                "rate {rate} must not pace"
            );
        }
    }

    #[tokio::test]
    async fn unpaced_slots_are_due_when_asked_for_not_at_the_origin() {
        // The Unlimited strategy reports an infinite rate, which the control
        // plane turns into 0.0 before building the schedule. There is then no
        // grid to fall behind, so each slot is due the moment it is requested
        // and response time must collapse onto service time.
        //
        // The regression guarded here: a zero interval times the operation count
        // is still zero, so a slot taken from the grid stays pinned to the phase
        // start. Every recorded latency then becomes the time elapsed since the
        // phase began, climbing linearly for the whole run instead of measuring
        // how long each operation took.
        let start = Instant::now();
        let mut schedule = OperationSchedule::new(start, 0.0);

        let first = schedule.next_slot().await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let second = schedule.next_slot().await;

        assert!(second > first, "each unpaced slot tracks real time");

        // What the metric actually depends on: no queueing delay is attributed
        // to an operation that was never made to wait.
        let response = Instant::now().saturating_duration_since(second);
        assert!(
            response < Duration::from_millis(5),
            "unpaced response time must not accumulate elapsed time, got {response:?}"
        );
    }

    #[tokio::test]
    async fn unlimited_strategy_does_not_pace() {
        let limiter = RateLimiter::unlimited();
        let started = Instant::now();
        for _ in 0..1000 {
            limiter.wait().await;
        }
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "Unlimited must not sleep; it is why a configured rate was silently ignored"
        );
        assert!(limiter.rate().is_infinite());
    }

    /// Per-worker rate division must reconstruct the tenant's configured rate.
    #[test]
    fn worker_rates_sum_to_configured_rate() {
        for workers in [1usize, 2, 5, 500] {
            let configured = 100.0f64;
            let per_worker = configured / workers as f64;
            let total: f64 = (0..workers).map(|_| per_worker).sum();
            assert!(
                (total - configured).abs() < 1e-9,
                "{workers} workers at {per_worker}/s summed to {total}, expected {configured}"
            );
        }
    }

    /// The campaign's control-plane settings, as recovered from the run logs:
    /// 100 req/s, 5 workers, 30 s baseline. Post-fix this must be a plain
    /// rate x duration; the pre-fix code produced 5200 ops instead.
    #[test]
    fn campaign_control_plane_baseline_op_count() {
        let (rate, workers, secs) = (100.0f64, 5usize, 30.0f64);

        let expected = rate * secs;
        assert_eq!(expected, 3000.0);

        // Pre-fix: rate/3 iterations per second, split 2 Pod workers (4 requests
        // per iteration) and 3 ConfigMap workers (6 per iteration).
        let (pod_workers, cm_workers) = (workers / 2, workers - workers / 2);
        let iters_per_worker = rate / 3.0 / workers as f64;
        let legacy = secs * iters_per_worker * (pod_workers as f64 * 4.0 + cm_workers as f64 * 6.0);
        assert_eq!(legacy, 5200.0);
        assert!((legacy / expected - 26.0 / 15.0).abs() < 1e-9);
    }

    #[test]
    fn degradation_and_fairness_bands() {
        assert_eq!(FairnessResult::calculate_degradation(10.0, 20.0), 2.0);

        // An absent phase must not produce a number. Returning 1.0 for a missing
        // baseline, or 0.0 for a missing stress phase, made "no data" look like
        // a measurement — and 0.0 graded as Excellent.
        assert!(FairnessResult::calculate_degradation(0.0, 20.0).is_nan());
        assert!(FairnessResult::calculate_degradation(10.0, 0.0).is_nan());

        let level = |d: f64| {
            FairnessResult {
                subsystem: "t".into(),
                baseline: PhaseResult::default(),
                unbalanced: PhaseResult::default(),
                latency_degradation: d,
                throughput_retention: 1.0,
            }
            .fairness_level()
        };
        assert_eq!(level(1.00), FairnessLevel::Excellent);
        assert_eq!(level(1.05), FairnessLevel::Excellent);
        assert_eq!(level(1.15), FairnessLevel::Good);
        assert_eq!(level(1.30), FairnessLevel::Moderate);
        assert_eq!(level(1.50), FairnessLevel::Poor);
        assert_eq!(level(9.91), FairnessLevel::Critical);
        // KubeVirt's published control-plane figure is below 1.0 (a speed-up).
        assert_eq!(level(0.68), FairnessLevel::Excellent);

        // NaN compares false against every bound, so without an explicit arm it
        // would fall through to Critical: a confident verdict from no data.
        assert_eq!(level(f64::NAN), FairnessLevel::Unknown);

        let empty_phase = FairnessResult {
            subsystem: "t".into(),
            baseline: PhaseResult::default(),
            unbalanced: PhaseResult::default(),
            latency_degradation: FairnessResult::calculate_degradation(0.05, 0.0),
            throughput_retention: 0.0,
        };
        assert!(!empty_phase.is_valid());
        assert_eq!(empty_phase.fairness_level(), FairnessLevel::Unknown);
    }

    /// Achieved rate must come from the dispatch timestamps, so that pod-based
    /// subsystems (which measure inside the pod) are not penalised for pod
    /// startup time the way a phase wall-clock denominator would penalise them.
    ///
    /// See `achieved_rate_ignores_the_schedule` for the other half: those
    /// timestamps have to be the clock, not the slot.
    #[test]
    fn achieved_rate_uses_observed_span() {
        let pts: Vec<MetricPoint> = (0..=10)
            .map(|i| MetricPoint {
                timestamp_secs: i as f64 * 0.5, // 11 points spanning 5 s
                latency_ms: 1.0,
                scheduled_latency_ms: None,
                slot_timestamp_secs: None,
                is_error: false,
                label: None,
            })
            .collect();
        let m = TenantMetrics::from_raw(pts);
        assert_eq!(m.operations, 11);
        assert!((m.observed_span_secs - 5.0).abs() < 1e-9);
        assert!((m.achieved_ops_per_sec() - 11.0 / 5.0).abs() < 1e-9);

        // The campaign's network settings: 15000 packets/s of 1000 B payload,
        // echoed. The paper quotes ~125 Mbps, which is the ONE-WAY payload; the
        // wire carries double that.
        let net = TenantMetrics {
            operations: 450_000,
            observed_span_secs: 30.0,
            ..Default::default()
        }
        .with_bytes_per_operation(1000.0 * 2.0);
        let mbps = net.achieved_bytes_per_sec.unwrap() * 8.0 / 1.0e6;
        assert!((net.achieved_ops_per_sec() - 15_000.0).abs() < 1e-9);
        assert!(
            (mbps - 240.0).abs() < 1e-6,
            "expected 240 Mbps on wire, got {mbps}"
        );
        assert!(
            (mbps / 2.0 - 120.0).abs() < 1e-6,
            "one-way payload should be ~120 Mbps"
        );

        // Degenerate inputs must not divide by zero.
        assert_eq!(TenantMetrics::from_raw(vec![]).achieved_ops_per_sec(), 0.0);
        let single = TenantMetrics::from_raw(vec![MetricPoint {
            timestamp_secs: 3.0,
            latency_ms: 1.0,
            scheduled_latency_ms: None,
            slot_timestamp_secs: None,
            is_error: false,
            label: None,
        }]);
        assert_eq!(single.achieved_ops_per_sec(), 0.0);
    }

    /// The achieved rate must be blind to the schedule.
    ///
    /// Numbers are one capsule 0.13.9 control-plane baseline: 474 operations
    /// from a tenant configured for 150 ops/s, over a 30 s phase. The generator
    /// got 15.8 ops/s and its schedule advanced 3.97 s.
    ///
    /// Denominated in schedule time the phase reports its own configured rate
    /// back — the operation count is in both numerator and denominator, so it
    /// cancels — and a run that delivered a tenth of its load looks perfect.
    /// That is what produced a manifest claiming 119.5 ops/s and 91.9%
    /// throughput retention for a run whose regular tenant retained 17.8%.
    #[test]
    fn achieved_rate_ignores_the_schedule() {
        const OPS: u64 = 474;
        const CONFIGURED_RATE: f64 = 150.0;
        const PHASE_SECS: f64 = 30.0;

        let points: Vec<MetricPoint> = (0..OPS)
            .map(|i| {
                let progress = i as f64 / (OPS - 1) as f64;
                MetricPoint {
                    // Dispatch is spread across the whole phase: the workers
                    // never stopped, each request just took ~330 ms.
                    timestamp_secs: progress * PHASE_SECS,
                    // The schedule advanced one slot per operation issued.
                    slot_timestamp_secs: Some(i as f64 / CONFIGURED_RATE),
                    latency_ms: 330.0,
                    scheduled_latency_ms: Some(13_900.0),
                    is_error: false,
                    label: None,
                }
            })
            .collect();

        let slot_span = points
            .last()
            .and_then(|p| p.slot_timestamp_secs)
            .expect("slot recorded");
        let m = TenantMetrics::from_raw(points);

        assert!((m.observed_span_secs - PHASE_SECS).abs() < 1e-9);
        assert!(
            (m.achieved_ops_per_sec() - 15.8).abs() < 0.1,
            "expected the delivered rate, got {}",
            m.achieved_ops_per_sec()
        );

        // The trap, stated as an assertion: the schedule span is the operation
        // count over the configured rate, so dividing by it restates the
        // configured rate no matter what the run did.
        assert!((slot_span - 3.153).abs() < 1e-3);
        let from_schedule = OPS as f64 / slot_span;
        assert!(
            (from_schedule - CONFIGURED_RATE).abs() < 1.0,
            "schedule-denominated rate should collapse onto the configured rate, got {from_schedule}"
        );
        assert!(from_schedule > 9.0 * m.achieved_ops_per_sec());
    }

    /// Reproduces the reference campaign's control-plane throughput collapse.
    /// capsule-proxy: 2714 ops over 30 s baseline, 136 ops over 60 s under stress.
    #[test]
    fn throughput_retention_detects_owner_throttling() {
        let base = 2714.0 / 30.0;
        let stress = 136.0 / 60.0;
        let retention = FairnessResult::calculate_throughput_retention(base, stress);
        assert!(
            retention < 0.03,
            "expected ~2.5% retention, got {:.4}",
            retention
        );

        // vCluster held its rate: 5084 ops / 30 s -> 9946 ops / 60 s.
        let held = FairnessResult::calculate_throughput_retention(5084.0 / 30.0, 9946.0 / 60.0);
        assert!(
            (held - 0.978).abs() < 0.01,
            "expected ~97.8%, got {held:.4}"
        );

        // A zero baseline cannot yield a ratio; the neutral value is 1.0.
        assert_eq!(
            FairnessResult::calculate_throughput_retention(0.0, 5.0),
            1.0
        );
    }

    /// QoS is the mechanism a shared node actually uses to arbitrate between
    /// tenants, so the exact resource shape per class has to be right.
    #[test]
    fn qos_classes_produce_the_expected_resource_shapes() {
        // Guaranteed demands requests == limits on CPU *and* memory. Anything
        // else silently downgrades the pod to Burstable.
        // Guaranteed ignores the requested values and pins them to the limits,
        // so a caller passing small requests cannot silently produce a Burstable
        // pod while believing it asked for Guaranteed.
        let split = PodResources::burstable(100, 1000, 128, 256);
        let guaranteed = QosClass::Guaranteed.resources_json(&split).unwrap();
        assert_eq!(guaranteed["requests"]["cpu"], "1000m");
        assert_eq!(guaranteed["limits"]["cpu"], "1000m");
        assert_eq!(guaranteed["requests"]["memory"], "256Mi");
        assert_eq!(guaranteed["limits"]["memory"], "256Mi");

        // Burstable keeps them apart: the request is what the scheduler charges
        // against node capacity, the limit is the cfs quota. Splitting them is
        // what lets ten intruder pods fit on a two-core KubeVirt tenant while
        // each is still allowed a full core when one is free.
        let burstable = QosClass::Burstable.resources_json(&split).unwrap();
        assert_eq!(burstable["requests"]["cpu"], "100m");
        assert_eq!(burstable["limits"]["cpu"], "1000m");
        assert_eq!(burstable["requests"]["memory"], "128Mi");
        assert_eq!(burstable["limits"]["memory"], "256Mi");

        // A request at or above the limit would be rejected by the API server,
        // so it is clamped below rather than passed through.
        let equal = QosClass::Burstable
            .resources_json(&PodResources::uniform(1000, 256))
            .unwrap();
        assert_eq!(equal["requests"]["cpu"], "999m");
        assert_eq!(equal["limits"]["cpu"], "1000m");

        // BestEffort requires the block to be absent; `resources: {}` is not
        // equivalent as far as the kubelet is concerned.
        assert!(QosClass::BestEffort.resources_json(&split).is_none());
    }

    #[test]
    fn apply_to_pod_sets_resources_and_runtime_class() {
        let template = || {
            serde_json::json!({
                "spec": { "containers": [
                    { "name": "a", "resources": { "requests": { "cpu": "100m" } } },
                    { "name": "b" }
                ] }
            })
        };

        let mut pod = template();
        QosClass::Guaranteed.apply_to_pod(
            &mut pod,
            &PodResources::uniform(1000, 256),
            Some("gvisor"),
        );
        let containers = pod["spec"]["containers"].as_array().unwrap();
        // Every container must carry the block, or the pod is not Guaranteed.
        for container in containers {
            assert_eq!(container["resources"]["limits"]["cpu"], "1000m");
        }
        assert_eq!(pod["spec"]["runtimeClassName"], "gvisor");

        // BestEffort must strip a pre-existing resources block, not merely skip it.
        let mut pod = template();
        QosClass::BestEffort.apply_to_pod(&mut pod, &PodResources::uniform(1000, 256), None);
        let containers = pod["spec"]["containers"].as_array().unwrap();
        assert!(containers.iter().all(|c| c.get("resources").is_none()));
        assert!(pod["spec"].get("runtimeClassName").is_none());
    }

    #[test]
    fn unix_utc_formatting() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // Leap day, and the last second before a year boundary.
        assert_eq!(format_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(format_unix_utc(1_735_689_599), "2024-12-31T23:59:59Z");
        // A timestamp from the reference campaign.
        assert_eq!(format_unix_utc(1_770_904_065), "2026-02-12T13:47:45Z");
    }

    #[test]
    fn manifest_captures_achieved_load_and_throttling() {
        let mk = |ops: u64, span: f64, lat: f64| TenantMetrics {
            operations: ops,
            observed_span_secs: span,
            avg_latency_ms: lat,
            raw: (0..ops)
                .map(|i| MetricPoint {
                    timestamp_secs: i as f64,
                    latency_ms: lat,
                    scheduled_latency_ms: None,
                    slot_timestamp_secs: None,
                    is_error: false,
                    label: None,
                })
                .collect(),
            ..Default::default()
        };

        // capsule-proxy control plane: throughput collapse without much error.
        let result = FairnessResult {
            subsystem: "Control Plane".into(),
            baseline: PhaseResult {
                tenant1: mk(2714, 30.0, 55.17),
                tenant2: mk(2730, 30.0, 54.91),
            },
            unbalanced: PhaseResult {
                tenant1: mk(136, 60.0, 2370.63),
                tenant2: mk(12274, 60.0, 2626.38),
            },
            latency_degradation: 42.97,
            throughput_retention: FairnessResult::calculate_throughput_retention(
                2714.0 / 30.0,
                136.0 / 60.0,
            ),
        };

        let m = TenantManifest::from_metrics(&result.unbalanced.tenant1);
        assert_eq!(m.operations, 136);
        // The fixture sets observed_span_secs explicitly, so the rate is over 60 s.
        assert!((m.achieved_ops_per_sec - 136.0 / 60.0).abs() < 1e-9);
        assert!(
            m.achieved_bytes_per_sec.is_none(),
            "only network sets bytes"
        );
        assert!(result.throughput_retention < 0.03);

        // The flag that tells a reader the degradation figure is a lower bound.
        assert!(result.throughput_retention < 0.95);

        let cfg = ConfigManifest::from_config(&FairnessConfig {
            tenant2_rate: 100.0,
            malicious_load_multiplier: 30.0,
            malicious_pod_multiplier: 100.0,
            ..Default::default()
        });
        // 100 x 30 x 100: the pod multiplier is part of the target, not a
        // separate factor applied later.
        assert_eq!(cfg.intruder_target_rate, 300_000.0);
        assert_eq!(cfg.effective_stress_factor, 3000.0);

        // The JSON shape is a contract consumed by the analysis pipeline.
        let manifest = RunManifest {
            schema_version: 1,
            subsystem_config: Some(serde_json::json!({ "volume": "pvc" })),
            subsystem: result.subsystem.clone(),
            metric: "API request latency".into(),
            solution_label: Some("capsule-proxy".into()),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: None,
            started_at_utc: format_unix_utc(1_770_904_065),
            run_timestamp: 1_770_904_065,
            baseline_csv: "control_plane_baseline_1770904065.csv".into(),
            unbalanced_csv: "control_plane_unbalanced_1770904065.csv".into(),
            config: cfg,
            baseline: PhaseManifest {
                tenant1: TenantManifest::from_metrics(&result.baseline.tenant1),
                tenant2: TenantManifest::from_metrics(&result.baseline.tenant2),
            },
            unbalanced: PhaseManifest {
                tenant1: TenantManifest::from_metrics(&result.unbalanced.tenant1),
                tenant2: TenantManifest::from_metrics(&result.unbalanced.tenant2),
            },
            latency_degradation: result.latency_degradation,
            throughput_retention: result.throughput_retention,
            fairness_level: result.fairness_level().to_string(),
            owner_throttled: result.throughput_retention < 0.95,
            intruder_load_ratio: 0.42,
            intruder_underloaded: true,
        };

        let v: serde_json::Value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["solution_label"], "capsule-proxy");
        assert_eq!(v["owner_throttled"], true);
        // A run where the intruder never applied its load must say so in the
        // manifest, or the analysis will compare it against runs that did.
        assert_eq!(v["intruder_underloaded"], true);
        assert_eq!(v["intruder_load_ratio"], 0.42);
        assert_eq!(v["config"]["intruder_target_rate"], 300_000.0);
        assert_eq!(v["started_at_utc"], "2026-02-12T13:47:45Z");
        assert!(v["unbalanced"]["tenant1"]["achieved_ops_per_sec"].is_number());
        // Absent optionals are omitted rather than serialised as null.
        assert!(v.get("git_commit").is_none());
        assert!(v["baseline"]["tenant1"].get("achieved_mbps").is_none());
    }

    /// The CSV column contract, which the Python analysis reads by name.
    ///
    /// Both optional columns are emitted as empty fields when absent rather
    /// than dropped, so every row has the same arity and a subsystem that has
    /// no schedule (the pod-based ones) still parses.
    #[tokio::test]
    async fn csv_carries_dispatch_and_slot_time_in_separate_columns() {
        let path = std::env::temp_dir().join(format!(
            "kumuteva-csv-{}-{}.csv",
            std::process::id(),
            line!()
        ));
        let path = path.to_str().expect("utf-8 temp path").to_string();

        let phase = PhaseResult {
            tenant1: TenantMetrics::from_raw(vec![MetricPoint {
                // Dispatched 12 s in, but only 1.5 s worth of schedule had been
                // consumed by then: the generator is 8x behind.
                timestamp_secs: 12.0,
                slot_timestamp_secs: Some(1.5),
                latency_ms: 330.0,
                scheduled_latency_ms: Some(10_830.0),
                is_error: false,
                label: Some("create-cm-0".to_string()),
            }]),
            tenant2: TenantMetrics::from_raw(vec![MetricPoint {
                // A pod-based subsystem: no schedule, so no slot.
                timestamp_secs: 4.0,
                slot_timestamp_secs: None,
                latency_ms: 2.0,
                scheduled_latency_ms: None,
                is_error: true,
                label: Some("tcp-ping-0".to_string()),
            }]),
        };

        write_csv(&path, &phase).await.expect("csv written");
        let written = tokio::fs::read_to_string(&path).await.expect("csv read");
        let _ = tokio::fs::remove_file(&path).await;

        let mut lines = written.lines();
        assert_eq!(
            lines.next().unwrap(),
            "tenant,timestamp_secs,latency_ms,is_error,label,scheduled_latency_ms,slot_timestamp_secs"
        );
        assert_eq!(
            lines.next().unwrap(),
            "tenant1,12.000,330.000,false,create-cm-0,10830.000,1.500"
        );
        assert_eq!(
            lines.next().unwrap(),
            "tenant2,4.000,2.000,true,tcp-ping-0,,"
        );
        assert!(lines.next().is_none());
    }

    #[test]
    fn tenant_metrics_excludes_nothing_and_reports_error_rate() {
        let pts = vec![
            MetricPoint {
                timestamp_secs: 0.0,
                latency_ms: 10.0,
                scheduled_latency_ms: None,
                slot_timestamp_secs: None,
                is_error: false,
                label: None,
            },
            MetricPoint {
                timestamp_secs: 1.0,
                latency_ms: 30.0,
                scheduled_latency_ms: None,
                slot_timestamp_secs: None,
                is_error: false,
                label: None,
            },
            MetricPoint {
                timestamp_secs: 2.0,
                latency_ms: 2000.0,
                scheduled_latency_ms: None,
                slot_timestamp_secs: None,
                is_error: true,
                label: None,
            },
        ];
        let m = TenantMetrics::from_raw(pts);
        assert_eq!(m.operations, 3);
        assert!((m.error_rate - 100.0 / 3.0).abs() < 1e-9);
        // Documents current behaviour: error points ARE included in the mean.
        // 2000 ms timeout sentinels therefore reach the latency statistics.
        assert!((m.avg_latency_ms - 680.0).abs() < 1e-9);
    }
}

#[cfg(test)]
mod intruder_escalation_tests {
    use super::*;

    /// The intruder must actually offer more load than the owner.
    ///
    /// `run_phase` splits a tenant's rate across its workers, so worker count
    /// alone cannot escalate: it cancels out. The control plane therefore scales
    /// the intruder's *total* rate by both multipliers, which is what the runner
    /// already advertises as "Nx effective load".
    #[test]
    fn worker_count_alone_does_not_escalate() {
        let rate = 20.0;
        for workers in [1usize, 5, 10, 500] {
            let per_worker = rate / workers as f64;
            let total: f64 = per_worker * workers as f64;
            assert!(
                (total - rate).abs() < 1e-9,
                "{workers} workers still offer {total}, not more than {rate}"
            );
        }
    }

    #[test]
    fn intruder_total_scales_with_both_multipliers() {
        // The reported configuration: rate 20, loadMultiplier 1, podMultiplier 10.
        let config = FairnessConfig {
            tenant1_rate: 20.0,
            tenant2_rate: 20.0,
            malicious_load_multiplier: 1.0,
            malicious_pod_multiplier: 10.0,
            ..FairnessConfig::default()
        };

        // Before the fix the intruder used malicious_rate() alone, which with a
        // load multiplier of 1.0 equals the owner's rate: no contention at all.
        assert_eq!(config.malicious_rate(), 20.0);

        let intruder_total = config.malicious_rate() * config.malicious_pod_multiplier;
        assert_eq!(intruder_total, 200.0);
        assert_eq!(intruder_total / config.tenant1_rate, 10.0);

        // Per worker it matches the owner's rate, so each added worker is
        // genuinely extra load rather than a smaller slice of the same load.
        let workers = 1.0 * config.malicious_pod_multiplier;
        assert_eq!(intruder_total / workers, config.tenant1_rate);
    }

    /// The runner prints the product as "effective load"; the offered rate must
    /// agree with that label, or the log states something the run does not do.
    #[test]
    fn effective_load_label_matches_offered_rate() {
        for (load, pods) in [(1.0, 10.0), (30.0, 100.0), (2.0, 1.0)] {
            let config = FairnessConfig {
                tenant1_rate: 10.0,
                tenant2_rate: 10.0,
                malicious_load_multiplier: load,
                malicious_pod_multiplier: pods,
                ..FairnessConfig::default()
            };
            let printed = config.malicious_load_multiplier * config.malicious_pod_multiplier;
            let offered = config.malicious_rate() * config.malicious_pod_multiplier;
            assert_eq!(offered / config.tenant1_rate, printed);
        }
    }
}
