//! Storage Fairness Assessor
//!
//! This module implements the `FairnessAssessor` trait for the storage subsystem.
//! It measures I/O latency fairness by comparing how a "regular" tenant's disk
//! operation latency is affected when a "malicious" tenant increases their I/O load.
//!
//! Uses fio (Flexible I/O Tester) to measure I/O latency.

#![allow(dead_code)] // Framework code - will be used by callers

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

/// Storage fairness assessor configuration
#[derive(Debug, Clone)]
pub struct StorageFairnessConfig {
    /// Number of I/O benchmark pods per tenant for baseline
    pub pods_per_tenant: u32,
    /// I/O block size in KB
    pub block_size_kb: u32,
    /// File size to write/read in MB
    pub file_size_mb: u32,
    /// Test scenario (random or sequential I/O)
    pub scenario: StorageTestScenario,
}

/// Storage test scenario
#[derive(Debug, Clone, Copy)]
pub enum StorageTestScenario {
    /// Random I/O testing with fio
    RandomIO,
    /// Sequential read/write testing
    SequentialIO,
}

impl Default for StorageFairnessConfig {
    fn default() -> Self {
        Self {
            pods_per_tenant: 1,
            block_size_kb: 4, // 4KB blocks typical for database workloads
            file_size_mb: 100,
            scenario: StorageTestScenario::RandomIO,
        }
    }
}

/// Storage fairness assessor using fio for latency measurement
pub struct StorageFairnessAssessor {
    pub config: StorageFairnessConfig,
}

impl StorageFairnessAssessor {
    pub fn new(config: StorageFairnessConfig) -> Self {
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
        create_storage_pods(
            &tenant1,
            &tenant2,
            self.config.block_size_kb,
            duration_secs,
            self.config.file_size_mb,
            tenant1_pods,
            tenant2_pods,
            &self.config.scenario,
        )
        .await?;

        // Wait for completion
        wait_for_storage_pods_completion(&tenant1, &tenant2, tenant1_pods, tenant2_pods).await?;

        // Collect latency results with raw data
        let (tenant1_raw, tenant2_raw) =
            collect_storage_latency_detailed(&tenant1, &tenant2, tenant1_pods, tenant2_pods)
                .await?;

        // Cleanup
        cleanup_storage_pods(&tenant1, tenant1_pods).await?;
        cleanup_storage_pods(&tenant2, tenant2_pods).await?;

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
impl FairnessAssessor for StorageFairnessAssessor {
    fn name(&self) -> &'static str {
        "Storage"
    }

    fn operation_description(&self) -> &'static str {
        "I/O operation latency"
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
impl DetailedFairnessAssessor for StorageFairnessAssessor {
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

fn storage_benchmark_pod_manifest(
    scenario: &StorageTestScenario,
    block_size_kb: u32,
    duration_secs: u64,
    file_size_mb: u32,
    pod_index: u32,
) -> Pod {
    let pod_name = format!("storage-fairness-{}", pod_index);

    // fio command to measure latency
    // --output-format=json gives us structured output with latency stats
    // clat = completion latency (what we care about)
    let command = match scenario {
        StorageTestScenario::SequentialIO => {
            // Sequential I/O with fio - measure latency
            format!(
                "apk add --no-cache fio jq && \
                 mkdir -p /data && \
                 fio --name=seq-rw \
                 --ioengine=sync \
                 --rw=rw \
                 --bs={}k \
                 --size={}m \
                 --numjobs=1 \
                 --runtime={} \
                 --time_based=1 \
                 --group_reporting=1 \
                 --filename=/data/fio-test-file \
                 --output-format=json \
                 --output=/data/fio_result.json && \
                 cat /data/fio_result.json",
                block_size_kb, file_size_mb, duration_secs
            )
        }
        StorageTestScenario::RandomIO => {
            // Random I/O with fio - measure latency
            format!(
                "apk add --no-cache fio jq && \
                 mkdir -p /data && \
                 fio --name=random-rw \
                 --ioengine=libaio \
                 --iodepth=4 \
                 --rw=randrw \
                 --rwmixread=50 \
                 --bs={}k \
                 --direct=1 \
                 --size={}m \
                 --numjobs=1 \
                 --runtime={} \
                 --time_based=1 \
                 --group_reporting=1 \
                 --filename=/data/fio-test-file \
                 --output-format=json \
                 --output=/data/fio_result.json && \
                 cat /data/fio_result.json",
                block_size_kb, file_size_mb, duration_secs
            )
        }
    };

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
                    "name": "storage-benchmark",
                    "image": "alpine:latest",
                    "command": ["sh", "-c", command],
                    "volumeMounts": [
                        {
                            "name": "benchmark-storage",
                            "mountPath": "/data"
                        }
                    ],
                    "resources": {
                        "requests": {
                            "memory": "128Mi",
                            "cpu": "100m"
                        },
                        "limits": {
                            "memory": "512Mi",
                            "cpu": "500m"
                        }
                    }
                }
            ],
            "volumes": [
                {
                    "name": "benchmark-storage",
                    "emptyDir": {
                        "sizeLimit": format!("{}Mi", file_size_mb * 2)
                    }
                }
            ]
        }
    }))
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn create_storage_pods(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    block_size_kb: u32,
    duration_secs: u64,
    file_size_mb: u32,
    tenant1_pods: u32,
    tenant2_pods: u32,
    scenario: &StorageTestScenario,
) -> Result<()> {
    // Create pods for tenant1
    for i in 0..tenant1_pods {
        create_storage_benchmark_pod(
            tenant1,
            block_size_kb,
            duration_secs,
            file_size_mb,
            i,
            scenario,
        )
        .await?;
    }

    // Create pods for tenant2
    for i in 0..tenant2_pods {
        create_storage_benchmark_pod(
            tenant2,
            block_size_kb,
            duration_secs,
            file_size_mb,
            i,
            scenario,
        )
        .await?;
    }

    Ok(())
}

async fn create_storage_benchmark_pod(
    tenant: &TenantClusterConfig,
    block_size_kb: u32,
    duration_secs: u64,
    file_size_mb: u32,
    pod_index: u32,
    scenario: &StorageTestScenario,
) -> Result<Pod> {
    let benchmark_pod = storage_benchmark_pod_manifest(
        scenario,
        block_size_kb,
        duration_secs,
        file_size_mb,
        pod_index,
    );
    let pod_name = benchmark_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&benchmark_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&pod_name, &tenant.namespace)
        .await?;

    Ok(benchmark_pod)
}

async fn wait_for_storage_pods_completion(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pods: u32,
    tenant2_pods: u32,
) -> Result<()> {
    // Wait for tenant1 pods
    for i in 0..tenant1_pods {
        wait_for_storage_pod_completion(tenant1, i).await?;
    }

    // Wait for tenant2 pods
    for i in 0..tenant2_pods {
        wait_for_storage_pod_completion(tenant2, i).await?;
    }

    Ok(())
}

async fn wait_for_storage_pod_completion(
    tenant: &TenantClusterConfig,
    pod_index: u32,
) -> Result<()> {
    let pod_name = format!("storage-fairness-{}", pod_index);

    // Check if already terminated
    let status = tenant
        .cluster
        .get_pod_in_namespace(&pod_name, &tenant.namespace)
        .await?;

    if let Some(s) = status.status.as_ref() {
        if let Some(phase) = s.phase.as_ref() {
            if phase == "Succeeded" || phase == "Failed" {
                return Ok(());
            }
        }
    }

    // Watch for completion
    tenant
        .cluster
        .watch_pod_until_condition(&pod_name, &tenant.namespace, |status_event| async move {
            if let kube::api::WatchEvent::Modified(status) = status_event {
                status
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.as_ref())
                    .map(|phase| phase == "Succeeded" || phase == "Failed")
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .await?;

    Ok(())
}

async fn collect_storage_latency_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pods: u32,
    tenant2_pods: u32,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let (t1_raw, t2_raw) =
        collect_storage_latency_detailed(tenant1, tenant2, tenant1_pods, tenant2_pods).await?;
    Ok((
        t1_raw.iter().map(|p| p.latency_ms).collect(),
        t2_raw.iter().map(|p| p.latency_ms).collect(),
    ))
}

async fn collect_storage_latency_detailed(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pods: u32,
    tenant2_pods: u32,
) -> Result<(Vec<MetricDataPoint>, Vec<MetricDataPoint>)> {
    let mut tenant1_data = Vec::new();
    let mut tenant2_data = Vec::new();

    // Collect from tenant1 pods
    for i in 0..tenant1_pods {
        let pod_name = format!("storage-fairness-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&pod_name, &tenant1.namespace)
            .await?;

        if let Some(latency_data) = parse_fio_latency_detailed(&logs, i) {
            tenant1_data.extend(latency_data);
        }
    }

    // Collect from tenant2 pods
    for i in 0..tenant2_pods {
        let pod_name = format!("storage-fairness-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&pod_name, &tenant2.namespace)
            .await?;

        if let Some(latency_data) = parse_fio_latency_detailed(&logs, i) {
            tenant2_data.extend(latency_data);
        }
    }

    Ok((tenant1_data, tenant2_data))
}

fn parse_fio_latency(logs: &str) -> Option<f64> {
    // Parse FIO JSON output to extract completion latency (clat)
    // fio reports latency in nanoseconds, we convert to milliseconds

    let json_start = logs.find('{');
    let json_end = logs.rfind('}');

    if let (Some(start), Some(end)) = (json_start, json_end) {
        let json_str = &logs[start..=end];
        if let Ok(fio_result) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Some(jobs) = fio_result["jobs"].as_array() {
                if let Some(job) = jobs.first() {
                    // Try to get average completion latency from read operations
                    if let Some(read_clat_mean) = job["read"]["clat_ns"]["mean"].as_f64() {
                        if read_clat_mean > 0.0 {
                            // Convert nanoseconds to milliseconds
                            return Some(read_clat_mean / 1_000_000.0);
                        }
                    }

                    // Fall back to write latency if read is not available
                    if let Some(write_clat_mean) = job["write"]["clat_ns"]["mean"].as_f64() {
                        if write_clat_mean > 0.0 {
                            return Some(write_clat_mean / 1_000_000.0);
                        }
                    }

                    // Try older fio format (clat without _ns suffix, in usec)
                    if let Some(read_clat_mean) = job["read"]["clat"]["mean"].as_f64() {
                        if read_clat_mean > 0.0 {
                            // Convert microseconds to milliseconds
                            return Some(read_clat_mean / 1_000.0);
                        }
                    }

                    if let Some(write_clat_mean) = job["write"]["clat"]["mean"].as_f64() {
                        if write_clat_mean > 0.0 {
                            return Some(write_clat_mean / 1_000.0);
                        }
                    }
                }
            }
        }
    }

    // Fallback: look for clat pattern in text output
    for line in logs.lines() {
        // fio text output: "clat (usec): min=123, max=456, avg=234.56, stdev=12.34"
        // or: "clat (nsec): min=123, max=456, avg=234.56, stdev=12.34"
        if line.contains("clat") && line.contains("avg=") {
            let is_nsec = line.contains("nsec");
            let is_usec = line.contains("usec");
            let is_msec = line.contains("msec");

            if let Some(avg_start) = line.find("avg=") {
                let avg_part = &line[avg_start + 4..];
                let avg_end = avg_part.find(',').unwrap_or(avg_part.len());
                let avg_str = &avg_part[..avg_end].trim();

                if let Ok(avg) = avg_str.parse::<f64>() {
                    if is_nsec {
                        return Some(avg / 1_000_000.0); // ns to ms
                    } else if is_usec {
                        return Some(avg / 1_000.0); // us to ms
                    } else if is_msec {
                        return Some(avg); // already ms
                    }
                }
            }
        }
    }

    None
}

fn parse_fio_latency_detailed(logs: &str, pod_index: u32) -> Option<Vec<MetricDataPoint>> {
    // Parse FIO JSON output to extract latency data with percentile breakdown for CSV export

    let json_start = logs.find('{');
    let json_end = logs.rfind('}');

    if let (Some(start), Some(end)) = (json_start, json_end) {
        let json_str = &logs[start..=end];
        if let Ok(fio_result) = serde_json::from_str::<serde_json::Value>(json_str) {
            let mut data_points = Vec::new();

            if let Some(jobs) = fio_result["jobs"].as_array() {
                for (job_idx, job) in jobs.iter().enumerate() {
                    // Extract read latencies
                    if let Some(read_clat) = job.get("read").and_then(|r| r.get("clat_ns")) {
                        if let Some(mean) = read_clat["mean"].as_f64() {
                            if mean > 0.0 {
                                data_points.push(MetricDataPoint {
                                    timestamp_secs: job_idx as f64,
                                    latency_ms: mean / 1_000_000.0,
                                    is_error: false,
                                    operation: Some(format!("fio-read-pod-{}", pod_index)),
                                });
                            }
                        }

                        // Also add percentile data points if available
                        if let Some(percentile) = read_clat.get("percentile") {
                            for (pct, val) in [
                                ("50.000000", "p50"),
                                ("95.000000", "p95"),
                                ("99.000000", "p99"),
                            ] {
                                if let Some(lat) = percentile[pct].as_f64() {
                                    if lat > 0.0 {
                                        data_points.push(MetricDataPoint {
                                            timestamp_secs: job_idx as f64,
                                            latency_ms: lat / 1_000_000.0,
                                            is_error: false,
                                            operation: Some(format!(
                                                "fio-read-{}-pod-{}",
                                                val, pod_index
                                            )),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // Extract write latencies
                    if let Some(write_clat) = job.get("write").and_then(|w| w.get("clat_ns")) {
                        if let Some(mean) = write_clat["mean"].as_f64() {
                            if mean > 0.0 {
                                data_points.push(MetricDataPoint {
                                    timestamp_secs: job_idx as f64,
                                    latency_ms: mean / 1_000_000.0,
                                    is_error: false,
                                    operation: Some(format!("fio-write-pod-{}", pod_index)),
                                });
                            }
                        }

                        // Also add percentile data points if available
                        if let Some(percentile) = write_clat.get("percentile") {
                            for (pct, val) in [
                                ("50.000000", "p50"),
                                ("95.000000", "p95"),
                                ("99.000000", "p99"),
                            ] {
                                if let Some(lat) = percentile[pct].as_f64() {
                                    if lat > 0.0 {
                                        data_points.push(MetricDataPoint {
                                            timestamp_secs: job_idx as f64,
                                            latency_ms: lat / 1_000_000.0,
                                            is_error: false,
                                            operation: Some(format!(
                                                "fio-write-{}-pod-{}",
                                                val, pod_index
                                            )),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If no detailed data, fall back to summary
            if data_points.is_empty() {
                if let Some(latency) = parse_fio_latency(logs) {
                    data_points.push(MetricDataPoint {
                        timestamp_secs: 0.0,
                        latency_ms: latency,
                        is_error: false,
                        operation: Some(format!("fio-summary-pod-{}", pod_index)),
                    });
                }
            }

            if !data_points.is_empty() {
                return Some(data_points);
            }
        }
    }

    None
}

async fn cleanup_storage_pods(tenant: &TenantClusterConfig, pod_count: u32) -> Result<()> {
    for i in 0..pod_count {
        let pod_name = format!("storage-fairness-{}", i);

        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&pod_name, &tenant.namespace)
            .await;
    }

    // Wait for deletion
    for i in 0..pod_count {
        let pod_name = format!("storage-fairness-{}", i);

        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&pod_name, &tenant.namespace)
            .await;
    }

    Ok(())
}
