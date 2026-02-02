//! Workload Fairness Assessor
//!
//! This module implements the `FairnessAssessor` trait for the workload subsystem.
//! It measures compute latency fairness by comparing how a "regular" tenant's
//! task completion time is affected when a "malicious" tenant increases their
//! CPU load.
//!
//! Uses sysbench CPU benchmark to measure the time to complete a fixed workload,
//! running multiple iterations to get statistically significant results.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use crate::assessment::fairness_framework::{
    DetailedFairnessAssessor, DetailedPhaseResults, FairnessAssessor, FairnessTestConfig,
    MetricDataPoint, PhaseResults, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Workload fairness assessor configuration
#[derive(Debug, Clone)]
pub struct WorkloadFairnessConfig {
    /// Number of benchmark pods per tenant for baseline
    pub pods_per_tenant: u32,
    /// Number of CPU threads to use per benchmark pod
    pub threads_per_pod: u32,
    /// Number of prime numbers to calculate (workload size)
    /// Higher = longer task, more stable measurements
    pub max_prime: u32,
}

impl Default for WorkloadFairnessConfig {
    fn default() -> Self {
        Self {
            pods_per_tenant: 1,
            threads_per_pod: 1,
            max_prime: 500_000,
        }
    }
}

/// Workload fairness assessor using sysbench CPU benchmark
pub struct WorkloadFairnessAssessor {
    pub config: WorkloadFairnessConfig,
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl WorkloadFairnessAssessor {
    pub fn new(config: WorkloadFairnessConfig) -> Self {
        Self { config }
    }

    /// Run a test phase with specified pod counts
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        tenant1_pods: u32,
        tenant2_pods: u32,
    ) -> Result<PhaseResults> {
        let detailed = self
            .run_phase_detailed(tenant1, tenant2, duration, tenant1_pods, tenant2_pods)
            .await?;
        Ok(detailed.into())
    }

    /// Run a test phase and return detailed results with raw data for CSV export
    async fn run_phase_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        tenant1_pods: u32,
        tenant2_pods: u32,
    ) -> Result<DetailedPhaseResults> {
        let duration_secs = duration.as_secs();

        // Create benchmark pods for both tenants
        create_benchmark_pods(
            &tenant1,
            &tenant2,
            self.config.threads_per_pod,
            self.config.max_prime,
            duration_secs,
            tenant1_pods,
            tenant2_pods,
        )
        .await?;

        // Wait for completion
        wait_for_benchmark_completion(&tenant1, &tenant2, tenant1_pods, tenant2_pods).await?;

        // Collect latency results with raw data
        let (tenant1_raw, tenant2_raw) =
            collect_benchmark_results(&tenant1, &tenant2, tenant1_pods, tenant2_pods).await?;

        // Cleanup
        cleanup_benchmark_pods(&tenant1, tenant1_pods).await?;
        cleanup_benchmark_pods(&tenant2, tenant2_pods).await?;

        // Calculate statistics from raw data
        let (t1_avg, t1_std, t1_count) =
            calculate_stats(&tenant1_raw.iter().map(|p| p.latency_ms).collect::<Vec<_>>());
        let (t2_avg, t2_std, t2_count) =
            calculate_stats(&tenant2_raw.iter().map(|p| p.latency_ms).collect::<Vec<_>>());

        Ok(DetailedPhaseResults {
            tenant1: TenantMetrics {
                avg_latency_ms: t1_avg,
                std_deviation_ms: t1_std,
                total_operations: t1_count,
                error_rate: if tenant1_raw.is_empty() { 100.0 } else { 0.0 },
            },
            tenant2: TenantMetrics {
                avg_latency_ms: t2_avg,
                std_deviation_ms: t2_std,
                total_operations: t2_count,
                error_rate: if tenant2_raw.is_empty() { 100.0 } else { 0.0 },
            },
            tenant1_raw,
            tenant2_raw,
        })
    }
}

#[async_trait]
impl FairnessAssessor for WorkloadFairnessAssessor {
    fn name(&self) -> &'static str {
        "Workload"
    }

    fn operation_description(&self) -> &'static str {
        "CPU task completion latency"
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults> {
        // Both tenants run with the same number of pods
        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pods_per_tenant,
            self.config.pods_per_tenant,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults> {
        // Tenant1 stays regular, Tenant2 gets more pods (malicious)
        let malicious_pods =
            (self.config.pods_per_tenant as f64 * config.malicious_load_multiplier) as u32;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pods_per_tenant,
            malicious_pods.max(1),
        )
        .await
    }
}

#[async_trait]
impl DetailedFairnessAssessor for WorkloadFairnessAssessor {
    async fn run_baseline_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<DetailedPhaseResults> {
        self.run_phase_detailed(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pods_per_tenant,
            self.config.pods_per_tenant,
        )
        .await
    }

    async fn run_unbalanced_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<DetailedPhaseResults> {
        let malicious_pods =
            (self.config.pods_per_tenant as f64 * config.malicious_load_multiplier) as u32;

        self.run_phase_detailed(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pods_per_tenant,
            malicious_pods.max(1),
        )
        .await
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn calculate_stats(latencies: &[f64]) -> (f64, f64, u64) {
    if latencies.is_empty() {
        return (0.0, 0.0, 0);
    }

    let count = latencies.len() as u64;
    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;

    let variance =
        latencies.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / latencies.len() as f64;
    let std_dev = variance.sqrt();

    (avg, std_dev, count)
}

/// Create a sysbench CPU benchmark pod manifest
///
/// The pod runs sysbench in a loop for the specified duration, outputting
/// JSON-formatted results for each run. Each sysbench execution is one
/// measurement - the total time to complete a fixed CPU task.
fn benchmark_pod_manifest(threads: u32, max_prime: u32, duration_secs: u64, pod_index: u32) -> Pod {
    let pod_name = format!("workload-fairness-{}", pod_index);

    // Script that runs sysbench repeatedly and outputs the total time for each task
    // Each sysbench run = one data point = time to complete calculating primes up to max_prime
    let command = format!(
        r#"
apk add --no-cache sysbench > /dev/null 2>&1

END_TIME=$(($(date +%s) + {duration}))
ITERATION=0

echo "["

while [ $(date +%s) -lt $END_TIME ]; do
    # Run sysbench CPU test - calculate primes up to max_prime once
    OUTPUT=$(sysbench cpu \
        --cpu-max-prime={max_prime} \
        --threads={threads} \
        --time=0 \
        --events=1 \
        run 2>/dev/null)
    
    # Extract total time from output (in seconds)
    # sysbench outputs: "total time: X.XXXXs"
    TOTAL_TIME=$(echo "$OUTPUT" | grep "total time:" | awk '{{print $3}}' | tr -d 's')
    
    # Convert to milliseconds and output
    if [ -n "$TOTAL_TIME" ]; then
        LATENCY_MS=$(echo "scale=6; $TOTAL_TIME * 1000" | bc)
        
        if [ $ITERATION -gt 0 ]; then
            echo ","
        fi
        
        echo "{{\"iteration\": $ITERATION, \"latency_ms\": $LATENCY_MS}}"
        ITERATION=$((ITERATION + 1))
    fi
done

echo "]"
"#,
        duration = duration_secs,
        max_prime = max_prime,
        threads = threads
    );

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "benchmark",
                    "image": "alpine:latest",
                    "command": ["sh", "-c", command],
                    "resources": {
                        "requests": {
                            "memory": "64Mi",
                            "cpu": "100m"
                        },
                        "limits": {
                            "memory": "128Mi",
                            "cpu": "1000m"  // Allow up to 1 CPU core
                        }
                    }
                }
            ]
        }
    }))
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn create_benchmark_pods(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    threads: u32,
    max_prime: u32,
    duration_secs: u64,
    tenant1_pods: u32,
    tenant2_pods: u32,
) -> Result<()> {
    // Create pods for tenant1
    for i in 0..tenant1_pods {
        let pod = benchmark_pod_manifest(threads, max_prime, duration_secs, i);
        tenant1
            .cluster
            .create_pod_in_namespace(&pod, &tenant1.namespace)
            .await?;
    }

    // Create pods for tenant2
    for i in 0..tenant2_pods {
        let pod = benchmark_pod_manifest(threads, max_prime, duration_secs, i);
        tenant2
            .cluster
            .create_pod_in_namespace(&pod, &tenant2.namespace)
            .await?;
    }

    // Wait for pods to be ready
    for i in 0..tenant1_pods {
        let pod_name = format!("workload-fairness-{}", i);
        tenant1
            .cluster
            .wait_for_pod_to_be_ready(&pod_name, &tenant1.namespace)
            .await?;
    }

    for i in 0..tenant2_pods {
        let pod_name = format!("workload-fairness-{}", i);
        tenant2
            .cluster
            .wait_for_pod_to_be_ready(&pod_name, &tenant2.namespace)
            .await?;
    }

    Ok(())
}

async fn wait_for_benchmark_completion(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pods: u32,
    tenant2_pods: u32,
) -> Result<()> {
    // Wait for tenant1 pods
    for i in 0..tenant1_pods {
        wait_for_pod_completion(tenant1, i).await?;
    }

    // Wait for tenant2 pods
    for i in 0..tenant2_pods {
        wait_for_pod_completion(tenant2, i).await?;
    }

    Ok(())
}

async fn wait_for_pod_completion(tenant: &TenantClusterConfig, pod_index: u32) -> Result<()> {
    let pod_name = format!("workload-fairness-{}", pod_index);

    // Poll until pod completes (Succeeded or Failed)
    loop {
        if let Ok(pod) = tenant
            .cluster
            .get_pod_in_namespace(&pod_name, &tenant.namespace)
            .await
        {
            if let Some(status) = &pod.status {
                if let Some(phase) = &status.phase {
                    match phase.as_str() {
                        "Succeeded" | "Failed" => return Ok(()),
                        _ => {}
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn collect_benchmark_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pods: u32,
    tenant2_pods: u32,
) -> Result<(Vec<MetricDataPoint>, Vec<MetricDataPoint>)> {
    let mut tenant1_data = Vec::new();
    let mut tenant2_data = Vec::new();

    // Collect from tenant1 pods
    for i in 0..tenant1_pods {
        let pod_name = format!("workload-fairness-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&pod_name, &tenant1.namespace)
            .await?;

        if let Some(data_points) = parse_benchmark_results(&logs, i) {
            tenant1_data.extend(data_points);
        }
    }

    // Collect from tenant2 pods
    for i in 0..tenant2_pods {
        let pod_name = format!("workload-fairness-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&pod_name, &tenant2.namespace)
            .await?;

        if let Some(data_points) = parse_benchmark_results(&logs, i) {
            tenant2_data.extend(data_points);
        }
    }

    Ok((tenant1_data, tenant2_data))
}

fn parse_benchmark_results(logs: &str, pod_index: u32) -> Option<Vec<MetricDataPoint>> {
    // Find JSON array in logs
    let json_start = logs.find('[')?;
    let json_end = logs.rfind(']')?;

    if json_start >= json_end {
        return None;
    }

    let json_str = &logs[json_start..=json_end];

    // Parse JSON array
    let results: Vec<serde_json::Value> = serde_json::from_str(json_str).ok()?;

    let data_points: Vec<MetricDataPoint> = results
        .iter()
        .filter_map(|entry| {
            let iteration = entry["iteration"].as_u64()?;
            let latency_ms = entry["latency_ms"].as_f64()?;

            Some(MetricDataPoint {
                timestamp_secs: iteration as f64,
                latency_ms,
                is_error: false,
                operation: Some(format!("sysbench-cpu-pod-{}", pod_index)),
            })
        })
        .collect();

    if data_points.is_empty() {
        None
    } else {
        Some(data_points)
    }
}

async fn cleanup_benchmark_pods(tenant: &TenantClusterConfig, pod_count: u32) -> Result<()> {
    for i in 0..pod_count {
        let pod_name = format!("workload-fairness-{}", i);
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&pod_name, &tenant.namespace)
            .await;
    }

    // Wait for deletions
    for i in 0..pod_count {
        let pod_name = format!("workload-fairness-{}", i);
        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&pod_name, &tenant.namespace)
            .await;
    }

    Ok(())
}
