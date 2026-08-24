//! Clean Workload (CPU) Fairness Assessor
//!
//! Measures CPU fairness using sysbench benchmark pods.

use std::sync::Arc;
use std::time::Duration;

/// Timeout for waiting on pod deletion during cleanup (prevents hanging)
const POD_DELETION_TIMEOUT_SECS: u64 = 60;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, PodResources, QosClass,
    RateLimitStrategy, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// What the intruder runs during the unbalanced phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FairnessWorkloadNoise {
    /// The same sysbench prime workload as the probe, only more of it.
    ///
    /// Purely CPU-bound: it never touches the cache hierarchy, the memory bus or
    /// the I/O path, so it exercises cgroup CPU shares and very little else.
    #[default]
    Prime,
    /// stress-ng across several resource dimensions at once.
    ///
    /// Real noisy-neighbour interference cascades between resources — cache
    /// thrashing and memory-bus saturation degrade a victim that is nominally
    /// getting its CPU share. This is the mode that tests those paths.
    Mixed,
}

impl std::fmt::Display for FairnessWorkloadNoise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FairnessWorkloadNoise::Prime => write!(f, "prime (CPU only)"),
            FairnessWorkloadNoise::Mixed => write!(f, "mixed (CPU, cache, memory, I/O)"),
        }
    }
}

/// Workload assessor configuration
#[derive(Debug, Clone)]
pub struct FairnessWorkloadConfig {
    /// Number of benchmark pods per tenant
    pub pods: u32,
    /// Number of CPU threads per pod
    pub threads: u32,
    /// Max prime number for sysbench (higher = longer tasks)
    pub max_prime: u32,
    /// Interference workload the intruder runs in the unbalanced phase
    pub intruder_noise: FairnessWorkloadNoise,
    /// QoS for the measuring probe. Guaranteed by default: an unstable probe
    /// cannot distinguish contention from its own throttling.
    pub probe_qos: QosClass,
    /// QoS for the intruder's interference pods. BestEffort by default, since a
    /// capped intruder cannot generate the contention the test is meant to induce.
    pub intruder_qos: QosClass,
    /// RuntimeClass for benchmark pods (e.g. a gVisor or Kata sandbox)
    pub runtime_class_name: Option<String>,
}

impl Default for FairnessWorkloadConfig {
    fn default() -> Self {
        Self {
            pods: 1,
            threads: 1,
            max_prime: 500000,
            intruder_noise: FairnessWorkloadNoise::default(),
            probe_qos: QosClass::Guaranteed,
            intruder_qos: QosClass::BestEffort,
            runtime_class_name: None,
        }
    }
}

/// CPU/memory allocation for a probe pod when its QoS class needs one.
const PROBE_CPU_LIMIT_MILLIS: u32 = 1000;
const PROBE_MEMORY_LIMIT_MI: u32 = 256;

/// See the fio constants in `storage::fairness`: the request is what decides
/// whether a pod can be placed on a small KubeVirt tenant node, the limit is
/// what decides whether it gets throttled once it is there.
const PROBE_CPU_REQUEST_MILLIS: u32 = 100;
const PROBE_MEMORY_REQUEST_MI: u32 = 64;

/// Resources for a workload pod under `qos`.
///
/// Guaranteed pins requests to the limits, so the request constants only take
/// effect for Burstable — which is the point of setting them low.
fn workload_resources(qos: QosClass) -> PodResources {
    match qos {
        QosClass::Guaranteed => {
            PodResources::uniform(PROBE_CPU_LIMIT_MILLIS, PROBE_MEMORY_LIMIT_MI)
        }
        _ => PodResources::burstable(
            PROBE_CPU_REQUEST_MILLIS,
            PROBE_CPU_LIMIT_MILLIS,
            PROBE_MEMORY_REQUEST_MI,
            PROBE_MEMORY_LIMIT_MI,
        ),
    }
}

// =============================================================================
// ASSESSOR
// =============================================================================

/// Workload fairness assessor using sysbench CPU benchmark
pub struct FairnessWorkloadAssessor {
    config: FairnessWorkloadConfig,
}

impl FairnessWorkloadAssessor {
    pub fn new(config: FairnessWorkloadConfig) -> Self {
        Self { config }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_pods: u32,
        t2_pods: u32,
        t1_rate: Option<f64>,
        t2_rate: Option<f64>,
        // Interference pods the intruder runs alongside its probe. Zero in the
        // baseline phase, which must stay symmetric.
        t2_interference_pods: u32,
    ) -> Result<PhaseResult> {
        let duration_secs = duration.as_secs();

        // Create all benchmark pods in parallel across tenants
        let config1 = self.config.clone();
        let config2 = self.config.clone();
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            create_sysbench_pods(&t1_clone, t1_pods, &config1, duration_secs, t1_rate),
            create_sysbench_pods(&t2_clone, t2_pods, &config2, duration_secs, t2_rate)
        )?;

        // Interference starts after the probes are running, so the probes measure
        // a system that is already under load rather than one ramping into it.
        if t2_interference_pods > 0 {
            create_interference_pods(&tenant2, t2_interference_pods, &self.config, duration_secs)
                .await?;
        }

        // Wait for completion in parallel across tenants
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            wait_for_completion(&t1_clone, t1_pods),
            wait_for_completion(&t2_clone, t2_pods)
        )?;

        // Collect results. Interference pods emit no metrics by design.
        let t1_points = collect_results(&tenant1, t1_pods).await?;
        let t2_points = collect_results(&tenant2, t2_pods).await?;

        // Did the generator actually reach the rate it was asked for?
        //
        // Worth checking on every run rather than assuming. The generator is
        // serial — one `sysbench --events=1 --threads=1` per iteration inside a
        // blocking loop — so a pod cannot exceed one event per event-duration
        // however the rate is configured. Whether the configured rate fits
        // therefore depends on the host CPU and on `maxPrime`, which no static
        // check can know; a config test used to assert a guess about it and was
        // simply wrong for this machine.
        //
        // It matters because falling short is invisible in the result. The
        // latencies still look fine — better, if anything, since a slower
        // offered load contends less — so an under-driven phase quietly
        // understates the degradation the experiment exists to measure.
        report_rate_shortfall("tenant1", &t1_points, t1_pods, t1_rate, duration_secs);
        report_rate_shortfall("tenant2", &t2_points, t2_pods, t2_rate, duration_secs);

        // Cleanup
        cleanup_pods(&tenant1, t1_pods).await?;
        cleanup_pods(&tenant2, t2_pods).await?;
        if t2_interference_pods > 0 {
            cleanup_interference_pods(&tenant2, t2_interference_pods).await?;
        }

        Ok(PhaseResult {
            tenant1: TenantMetrics::from_raw(t1_points),
            tenant2: TenantMetrics::from_raw(t2_points),
        })
    }
}

#[async_trait]
impl FairnessAssessor for FairnessWorkloadAssessor {
    fn name(&self) -> &'static str {
        "Workload"
    }

    fn metric(&self) -> &'static str {
        "CPU task latency"
    }

    fn configuration(&self) -> Option<serde_json::Value> {
        // `max_prime` sets how long one event takes, and so the ceiling on the
        // achievable rate; `intruder_noise` decides whether the interference is
        // CPU-only or multi-resource. Both change what the number means.
        Some(serde_json::json!({
            "pods": self.config.pods,
            "threads": self.config.threads,
            "max_prime": self.config.max_prime,
            "intruder_noise": self.config.intruder_noise.to_string(),
            "probe_qos": self.config.probe_qos.to_string(),
            "intruder_qos": self.config.intruder_qos.to_string(),
            "runtime_class_name": self.config.runtime_class_name,
        }))
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let rate = if matches!(config.strategy, RateLimitStrategy::Unlimited) {
            None
        } else {
            Some(config.tenant1_rate)
        };

        // Symmetric by construction: both tenants run the same probe at the same
        // rate, and neither generates interference.
        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pods,
            self.config.pods,
            rate,
            rate,
            0,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let t1_rate = if matches!(config.strategy, RateLimitStrategy::Unlimited) {
            None
        } else {
            Some(config.tenant1_rate)
        };
        let t2_rate = if matches!(config.strategy, RateLimitStrategy::Unlimited) {
            None
        } else {
            Some(config.malicious_rate())
        };

        let malicious_pods =
            ((self.config.pods as f64 * config.malicious_pod_multiplier) as u32).max(1);

        // In Mixed mode the intruder's scaled-up capacity goes into stress-ng
        // interference, and it keeps a single probe pod so that its own observed
        // latency remains a comparable series. In Prime mode the intruder simply
        // runs more of the probe workload, as before.
        let (t2_probe_pods, t2_interference_pods) = match self.config.intruder_noise {
            FairnessWorkloadNoise::Prime => (malicious_pods, 0),
            FairnessWorkloadNoise::Mixed => (1, malicious_pods),
        };

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pods,
            t2_probe_pods,
            t1_rate,
            t2_rate,
            t2_interference_pods,
        )
        .await
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn sysbench_pod(
    index: u32,
    config: &FairnessWorkloadConfig,
    duration_secs: u64,
    rate: Option<f64>,
) -> Pod {
    let rate_val = rate
        .map(|r| r.to_string())
        .unwrap_or_else(|| "None".to_string());

    // Python script to run sysbench with minimal overhead
    // This avoids the massive overhead of forking 'date', 'awk', 'grep' in a shell loop
    let python_script = format!(
        r#"
import subprocess
import time
import sys

THREADS = {threads}
MAX_PRIME = {max_prime}
DURATION = {duration}
RATE = {rate}

print(f"Starting benchmark: threads={{THREADS}}, prime={{MAX_PRIME}}, duration={{DURATION}}s, rate={{RATE}}", file=sys.stderr)

start_time = time.perf_counter()
end_time = time.time() + DURATION
i = 0
results = []

cmd = ["sysbench", "cpu", f"--threads={{THREADS}}", f"--cpu-max-prime={{MAX_PRIME}}", "--time=0", "--events=1", "run"]

while time.time() < end_time:
    iter_start = time.perf_counter()
    
    # Rate limiting
    if RATE is not None:
        expected_now = start_time + (i * (1.0/RATE))
        drift = expected_now - iter_start
        if drift > 0.001:
            time.sleep(drift)
    
    try:
        # Run sysbench and capture output
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        
        # Parse latency (looking for "total time: 0.0004s")
        for line in out.splitlines():
            if "total time:" in line:
                parts = line.split()
                if len(parts) >= 3:
                    latency_s = parts[2].replace("s", "")
                    ts = time.perf_counter() - start_time
                    results.append(f"{{ts:.3f}}:{{latency_s}}")
                    break
    except Exception as e:
        print(f"Error: {{e}}", file=sys.stderr)
        
    i += 1

print("RESULTS:" + ",".join(results))
"#,
        duration = duration_secs,
        rate = rate_val,
        threads = config.threads,
        max_prime = config.max_prime
    );

    let mut pod = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("workload-fairness-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "sysbench",
                "image": "python:3.11-alpine",
                "command": ["sh", "-c", format!("apk add --no-cache sysbench >/dev/null 2>&1 && python3 -c '{}'", python_script)],
            }]
        }
    });

    // The probe is Guaranteed by default: it is the measuring instrument, and a
    // throttled instrument cannot tell contention apart from its own cfs quota.
    config.probe_qos.apply_to_pod(
        &mut pod,
        &workload_resources(config.probe_qos),
        config.runtime_class_name.as_deref(),
    );

    serde_json::from_value(pod).unwrap()
}

/// A multi-resource interference pod for the intruder.
///
/// Deliberately *not* the probe workload. Prime computation saturates one core
/// and nothing else; a realistic noisy neighbour also thrashes the shared cache,
/// saturates the memory bus and issues I/O, which is what degrades a victim that
/// is nominally receiving its CPU share.
///
/// Emits no metrics: this pod exists to create contention, not to measure it.
fn interference_pod(index: u32, config: &FairnessWorkloadConfig, duration_secs: u64) -> Pod {
    // --cpu:      saturate scheduler run queues
    // --cache:    thrash shared L2/L3, which cgroup CPU shares do not partition
    // --vm:       saturate the memory bus with allocation and dirtying
    // --matrix:   floating point plus strided memory access
    // --io:       dirty page writeback pressure
    let workers = config.threads.max(1);
    let command = format!(
        "apk add --no-cache stress-ng >/dev/null 2>&1 && \
         stress-ng --cpu {workers} --cache {workers} --vm {workers} --vm-bytes 128M \
         --matrix {workers} --io {workers} --timeout {duration_secs}s --metrics-brief"
    );

    let mut pod = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("workload-interference-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "stress-ng",
                "image": "alpine:latest",
                "command": ["sh", "-c", command],
            }]
        }
    });

    // BestEffort by default. Capping the intruder would cap the interference and
    // understate what an unconstrained neighbour can actually do to a co-tenant.
    config.intruder_qos.apply_to_pod(
        &mut pod,
        &workload_resources(config.intruder_qos),
        config.runtime_class_name.as_deref(),
    );

    serde_json::from_value(pod).unwrap()
}

/// Launch the intruder's interference pods.
///
/// These are fire-and-forget: readiness is awaited so that the load is actually
/// running before the phase proceeds, but no results are collected from them.
async fn create_interference_pods(
    tenant: &TenantClusterConfig,
    pods: u32,
    config: &FairnessWorkloadConfig,
    duration_secs: u64,
) -> Result<()> {
    let mut pod_names = Vec::new();
    for i in 0..pods {
        let pod = interference_pod(i, config, duration_secs);
        let name = pod.metadata.name.clone().unwrap();
        tenant
            .cluster
            .create_pod_in_namespace(&pod, &tenant.namespace)
            .await?;
        pod_names.push(name);
    }

    for name in pod_names {
        tenant
            .cluster
            .wait_for_pod_to_be_ready(&name, &tenant.namespace)
            .await?;
    }

    Ok(())
}

async fn cleanup_interference_pods(tenant: &TenantClusterConfig, pods: u32) -> Result<()> {
    for i in 0..pods {
        let name = format!("workload-interference-{}", i);
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&name, &tenant.namespace)
            .await;
    }

    for i in 0..pods {
        let name = format!("workload-interference-{}", i);
        let _ = tokio::time::timeout(
            Duration::from_secs(POD_DELETION_TIMEOUT_SECS),
            tenant
                .cluster
                .wait_for_pod_deletion(&name, &tenant.namespace),
        )
        .await;
    }

    Ok(())
}

/// Create all sysbench pods for a tenant in parallel
async fn create_sysbench_pods(
    tenant: &TenantClusterConfig,
    pods: u32,
    config: &FairnessWorkloadConfig,
    duration_secs: u64,
    rate: Option<f64>,
) -> Result<()> {
    // First, create all pods without waiting
    let mut pod_names = Vec::new();
    for i in 0..pods {
        let pod = sysbench_pod(i, config, duration_secs, rate);
        let name = pod.metadata.name.clone().unwrap();
        tenant
            .cluster
            .create_pod_in_namespace(&pod, &tenant.namespace)
            .await?;
        pod_names.push(name);
    }

    // Then wait for all pods to be ready (they start executing immediately)
    for name in pod_names {
        tenant
            .cluster
            .wait_for_pod_to_be_ready(&name, &tenant.namespace)
            .await?;
    }

    Ok(())
}

async fn wait_for_completion(tenant: &TenantClusterConfig, pods: u32) -> Result<()> {
    use futures::{StreamExt, TryStreamExt};
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::WatchParams;
    use kube::Api;

    let api: Api<Pod> = Api::namespaced(tenant.cluster.client().clone(), &tenant.namespace);

    for i in 0..pods {
        let name = format!("workload-fairness-{}", i);

        // Helper to check if pod is completed
        let is_pod_completed = async |pod_name: &str| -> bool {
            if let Ok(pod) = api.get(pod_name).await {
                if let Some(status) = pod.status {
                    if let Some(phase) = status.phase {
                        return phase == "Succeeded" || phase == "Failed";
                    }
                }
            }
            false
        };

        // Pod not done yet, watch for completion
        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", name))
            .timeout(290);

        let mut stream = api.watch(&lp, "0").await?.boxed();

        while let Some(_event) = stream.try_next().await? {
            if is_pod_completed(&name).await {
                break;
            }
        }
    }
    Ok(())
}

async fn collect_results(tenant: &TenantClusterConfig, pods: u32) -> Result<Vec<MetricPoint>> {
    let mut points = Vec::new();

    for i in 0..pods {
        let name = format!("workload-fairness-{}", i);
        let logs = tenant
            .cluster
            .get_pod_logs(&name, &tenant.namespace)
            .await?;

        // Parse "RESULTS:ts1:time1,ts2:time2," format
        if let Some(results_start) = logs.find("RESULTS:") {
            let results_str = &logs[results_start + 8..];
            for (idx, entry) in results_str.split(',').enumerate() {
                let parts: Vec<&str> = entry.trim().split(':').collect();
                if parts.len() == 2 {
                    if let (Ok(ts), Ok(secs)) = (parts[0].parse::<f64>(), parts[1].parse::<f64>()) {
                        points.push(MetricPoint {
                            // Pacing happens inside the pod, so there is no dispatch schedule to
                            // measure against: the recorded latency is already the service time,
                            // and `ts` is already the pod's own dispatch clock.
                            scheduled_latency_ms: None,
                            slot_timestamp_secs: None,
                            timestamp_secs: ts,
                            latency_ms: secs * 1000.0, // seconds to ms
                            is_error: false,
                            label: Some(format!("sysbench-{}-{}", i, idx)),
                        });
                    }
                }
            }
        }
    }

    Ok(points)
}

async fn cleanup_pods(tenant: &TenantClusterConfig, pods: u32) -> Result<()> {
    // First, initiate deletion for all pods
    for i in 0..pods {
        let name = format!("workload-fairness-{}", i);
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&name, &tenant.namespace)
            .await;
    }

    // Then, wait for all pods to be fully deleted to avoid "AlreadyExists" errors
    // when creating new pods with the same names in subsequent phases
    // Use timeout to prevent hanging if pods are stuck in Terminating state
    for i in 0..pods {
        let name = format!("workload-fairness-{}", i);
        let _ = tokio::time::timeout(
            Duration::from_secs(POD_DELETION_TIMEOUT_SECS),
            tenant
                .cluster
                .wait_for_pod_deletion(&name, &tenant.namespace),
        )
        .await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container_of(pod: &Pod) -> &k8s_openapi::api::core::v1::Container {
        &pod.spec.as_ref().unwrap().containers[0]
    }

    /// The probe is the measuring instrument. If it is throttled by its own cfs
    /// quota it cannot distinguish neighbour contention from self-inflicted
    /// starvation, so it defaults to Guaranteed.
    #[test]
    fn probe_pod_is_guaranteed_by_default() {
        let config = FairnessWorkloadConfig::default();
        assert_eq!(config.probe_qos, QosClass::Guaranteed);

        let pod = sysbench_pod(0, &config, 30, Some(5.0));
        let resources = container_of(&pod).resources.as_ref().unwrap();
        let requests = resources.requests.as_ref().unwrap();
        let limits = resources.limits.as_ref().unwrap();
        assert_eq!(requests["cpu"].0, "1000m");
        assert_eq!(limits["cpu"].0, "1000m");
        assert_eq!(requests["memory"].0, limits["memory"].0);
    }

    /// Capping the intruder caps the interference, which would understate what an
    /// unconstrained neighbour can do to a co-tenant.
    #[test]
    fn interference_pod_is_best_effort_by_default() {
        let config = FairnessWorkloadConfig::default();
        assert_eq!(config.intruder_qos, QosClass::BestEffort);

        let pod = interference_pod(0, &config, 60);
        assert!(
            container_of(&pod).resources.is_none(),
            "a BestEffort pod must carry no resources block at all"
        );
        assert_eq!(
            pod.metadata.name.as_deref(),
            Some("workload-interference-0"),
            "interference pods need a distinct name so cleanup does not race the probes"
        );
    }

    #[test]
    fn interference_pod_exercises_more_than_cpu() {
        let config = FairnessWorkloadConfig {
            threads: 2,
            ..Default::default()
        };
        let pod = interference_pod(1, &config, 45);
        let command = container_of(&pod).command.as_ref().unwrap().join(" ");

        // A reviewer's objection was that prime computation is purely CPU-bound
        // and never touches the shared resources where interference actually
        // cascades. Each of these covers one of those paths.
        for dimension in ["--cpu 2", "--cache 2", "--vm 2", "--matrix 2", "--io 2"] {
            assert!(
                command.contains(dimension),
                "interference command missing {dimension}: {command}"
            );
        }
        assert!(command.contains("--timeout 45s"));
    }

    #[test]
    fn runtime_class_propagates_to_both_pod_kinds() {
        let config = FairnessWorkloadConfig {
            runtime_class_name: Some("kata".into()),
            ..Default::default()
        };
        for pod in [
            sysbench_pod(0, &config, 10, None),
            interference_pod(0, &config, 10),
        ] {
            assert_eq!(
                pod.spec.as_ref().unwrap().runtime_class_name.as_deref(),
                Some("kata")
            );
        }
    }
}

/// Warn when a phase generated materially fewer events than it was asked for.
///
/// This is the workload subsystem's validity check, and it has to be its own.
/// Elsewhere the same question is answered by the coordinated-omission factor
/// (`scheduled_latency_ms / latency_ms` on [`MetricPoint`]), but that requires
/// dispatching against an `OperationSchedule`, and this generator does not —
/// `collect_results` sets `scheduled_latency_ms: None`. Counting completed
/// events against the target is the signal available here.
///
/// Returns the achieved rate in events per second per pod, or `None` when no
/// target was set (the unlimited strategy, where there is nothing to fall short
/// of) or when the phase produced no samples at all — the latter is already
/// reported as a missing measurement elsewhere, and dividing by it here would
/// only add noise.
///
/// The 10% tolerance is deliberate rather than exact: the generator sleeps to
/// pace itself and the final iteration is usually truncated by the phase
/// ending, so a small undershoot is expected even on hardware with headroom to
/// spare. What this is looking for is the case where an event takes longer than
/// the requested interval, which does not undershoot slightly — it halves the
/// rate, or worse.
fn report_rate_shortfall(
    label: &str,
    points: &[MetricPoint],
    pods: u32,
    target_rate: Option<f64>,
    duration_secs: u64,
) -> Option<f64> {
    let target = target_rate?;
    if points.is_empty() || pods == 0 || duration_secs == 0 || target <= 0.0 {
        return None;
    }

    let achieved = points.len() as f64 / duration_secs as f64 / pods as f64;
    let ratio = achieved / target;

    if ratio < 0.9 {
        tracing::warn!(
            "{label}: generated {achieved:.2} events/s per pod against a target \
             of {target:.2} ({:.0}% of it). The load offered was lower than the \
             experiment specifies, so any degradation measured here understates \
             the real contention. A sysbench event at the configured maxPrime \
             probably takes longer than 1/{target:.2}s on this host.",
            ratio * 100.0
        );
    } else {
        tracing::info!("{label}: {achieved:.2} events/s per pod (target {target:.2})");
    }

    Some(achieved)
}

#[cfg(test)]
mod rate_shortfall_tests {
    use super::*;

    fn points(n: usize) -> Vec<MetricPoint> {
        (0..n)
            .map(|i| MetricPoint {
                timestamp_secs: i as f64,
                latency_ms: 1.0,
                // Deliberately None, matching `collect_results`: this generator
                // does not dispatch against an `OperationSchedule`, so neither
                // the coordinated-omission factor other subsystems use as their
                // validity check nor a scheduled slot exists here.
                scheduled_latency_ms: None,
                slot_timestamp_secs: None,
                is_error: false,
                label: None,
            })
            .collect()
    }

    #[test]
    fn a_phase_that_meets_its_target_reports_the_achieved_rate() {
        // 2 pods x 5 events/s x 10s = 100 samples.
        let achieved = report_rate_shortfall("t", &points(100), 2, Some(5.0), 10);
        assert_eq!(achieved, Some(5.0));
    }

    #[test]
    fn a_serial_generator_that_cannot_keep_up_is_detected() {
        // The case the deleted config assertion was groping at: an event
        // slower than the requested interval halves the achieved rate, and
        // nothing else in the results would show it.
        let achieved = report_rate_shortfall("t", &points(20), 2, Some(5.0), 10);
        assert_eq!(achieved, Some(1.0));
    }

    #[test]
    fn an_unlimited_phase_has_no_target_to_miss() {
        assert_eq!(report_rate_shortfall("t", &points(100), 2, None, 10), None);
    }

    #[test]
    fn an_empty_phase_is_left_to_the_missing_measurement_path() {
        // Reported elsewhere as an absent measurement; a 0% rate warning here
        // would be a second, less informative account of the same fact.
        assert_eq!(report_rate_shortfall("t", &[], 2, Some(5.0), 10), None);
    }
}
