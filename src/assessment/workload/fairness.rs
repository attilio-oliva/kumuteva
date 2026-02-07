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
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, RateLimitStrategy, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Workload assessor configuration
#[derive(Debug, Clone)]
pub struct FairnessWorkloadConfig {
    /// Number of benchmark pods per tenant
    pub pods: u32,
    /// Number of CPU threads per pod
    pub threads: u32,
    /// Max prime number for sysbench (higher = longer tasks)
    pub max_prime: u32,
}

impl Default for FairnessWorkloadConfig {
    fn default() -> Self {
        Self {
            pods: 1,
            threads: 1,
            max_prime: 500000,
        }
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

    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_pods: u32,
        t2_pods: u32,
        t1_rate: Option<f64>,
        t2_rate: Option<f64>,
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

        // Wait for completion in parallel across tenants
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            wait_for_completion(&t1_clone, t1_pods),
            wait_for_completion(&t2_clone, t2_pods)
        )?;

        // Collect results
        let t1_points = collect_results(&tenant1, t1_pods).await?;
        let t2_points = collect_results(&tenant2, t2_pods).await?;

        // Cleanup
        cleanup_pods(&tenant1, t1_pods).await?;
        cleanup_pods(&tenant2, t2_pods).await?;

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

        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pods,
            self.config.pods,
            rate,
            rate,
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

        let malicious_pods = (self.config.pods as f64 * config.malicious_pod_multiplier) as u32;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pods,
            malicious_pods.max(1),
            t1_rate,
            t2_rate,
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

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("workload-fairness-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "sysbench",
                "image": "python:3.11-alpine",
                "command": ["sh", "-c", format!("apk add --no-cache sysbench >/dev/null 2>&1 && python3 -c '{}'", python_script)],
                "resources": {
                    "requests": { "memory": "64Mi", "cpu": "100m" },
                    "limits": { "memory": "512Mi", "cpu": "1000m" }
                }
            }]
        }
    }))
    .unwrap()
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
