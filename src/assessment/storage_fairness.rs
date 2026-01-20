//! Storage Fairness Assessor
//!
//! This module implements the `FairnessAssessor` trait for the storage subsystem.
//! It measures I/O throughput fairness by comparing how a "regular" tenant's disk
//! performance is affected when a "malicious" tenant increases their I/O load.
//!
//! Uses fio (Flexible I/O Tester) to measure disk throughput.

#![allow(dead_code)] // Framework code - will be used by callers

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use crate::assessment::fairness::{
    FairnessAssessor, FairnessTestConfig, PhaseResults, TenantMetrics,
};
use crate::verifier::TenantClusterConfig;

// =============================================================================
// STORAGE FAIRNESS ASSESSOR
// =============================================================================

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
            block_size_kb: 1024,
            file_size_mb: 100,
            scenario: StorageTestScenario::RandomIO,
        }
    }
}

/// Storage fairness assessor using fio
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

        // Collect results
        let (tenant1_throughputs, tenant2_throughputs) = collect_storage_results(
            &tenant1,
            &tenant2,
            tenant1_pods,
            tenant2_pods,
            &self.config.scenario,
        )
        .await?;

        // Cleanup
        cleanup_storage_pods(&tenant1, tenant1_pods).await?;
        cleanup_storage_pods(&tenant2, tenant2_pods).await?;

        // Calculate averages
        let tenant1_avg = if tenant1_throughputs.is_empty() {
            0.0
        } else {
            tenant1_throughputs.iter().sum::<f64>() / tenant1_throughputs.len() as f64
        };

        let tenant2_avg = if tenant2_throughputs.is_empty() {
            0.0
        } else {
            tenant2_throughputs.iter().sum::<f64>() / tenant2_throughputs.len() as f64
        };

        Ok(PhaseResults {
            tenant1: TenantMetrics {
                primary_metric: tenant1_avg,
                secondary_metrics: vec![
                    ("pods".to_string(), tenant1_pods as f64),
                    ("samples".to_string(), tenant1_throughputs.len() as f64),
                ],
                error_rate: 0.0,
            },
            tenant2: TenantMetrics {
                primary_metric: tenant2_avg,
                secondary_metrics: vec![
                    ("pods".to_string(), tenant2_pods as f64),
                    ("samples".to_string(), tenant2_throughputs.len() as f64),
                ],
                error_rate: 0.0,
            },
        })
    }
}

#[async_trait]
impl FairnessAssessor for StorageFairnessAssessor {
    fn name(&self) -> &'static str {
        "Storage"
    }

    fn metric_unit(&self) -> &'static str {
        "MB/s"
    }

    fn higher_is_better(&self) -> bool {
        true // Higher throughput is better
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

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn storage_benchmark_pod_manifest(
    scenario: &StorageTestScenario,
    block_size_kb: u32,
    duration_secs: u64,
    file_size_mb: u32,
    pod_index: u32,
) -> Pod {
    let pod_name = format!("storage-fairness-{}", pod_index);

    let command = match scenario {
        StorageTestScenario::SequentialIO => {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "apk add --no-cache bc fio && \
                     echo 'Starting sequential I/O benchmark...' && \
                     dd if=/dev/zero of=/data/testfile bs={block_size_kb}K count={} oflag=sync 2>&1 | tee /tmp/dd_write.log && \
                     write_throughput=$(tail -1 /tmp/dd_write.log | awk '{{for(i=1;i<=NF;i++) if($i~/MB\\/s/) print $(i-1)}}') && \
                     echo \"THROUGHPUT_RESULT: $write_throughput MB/s\" && \
                     sleep 5",
                    file_size_mb * 1024 / block_size_kb,
                ),
            ]
        }
        StorageTestScenario::RandomIO => {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "apk add --no-cache fio && \
                     echo 'Starting random I/O benchmark with fio...' && \
                     mkdir -p /data && \
                     fio --name=random-rw \
                     --ioengine=libaio \
                     --iodepth=4 \
                     --rw=randrw \
                     --rwmixread=50 \
                     --bs={block_size_kb}k \
                     --direct=1 \
                     --size={file_size_mb}m \
                     --numjobs=1 \
                     --runtime={duration_secs} \
                     --time_based=1 \
                     --group_reporting=1 \
                     --filename=/data/fio-test-file \
                     --output-format=json \
                     --output=/data/fio_result.json && \
                     echo 'FIO benchmark completed' && \
                     bw=$(grep -o '\"bw\"[[:space:]]*:[[:space:]]*[0-9]*' /data/fio_result.json | head -1 | grep -o '[0-9]*') && \
                     bw_mbs=$(echo \"scale=2; $bw / 1024\" | bc) && \
                     echo \"THROUGHPUT_RESULT: $bw_mbs MB/s\" && \
                     sleep 5"
                ),
            ]
        }
    };

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name
        },
        "spec": {
            "restartPolicy": "OnFailure",
            "containers": [
                {
                    "name": "storage-benchmark",
                    "image": "alpine:latest",
                    "command": command,
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
        if let Some(statuses) = s.container_statuses.as_ref() {
            if let Some(cs) = statuses.first() {
                if let Some(state) = cs.state.as_ref() {
                    if let Some(term) = state.terminated.as_ref() {
                        if term.exit_code == 0 {
                            return Ok(());
                        }
                    }
                }
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
                    .and_then(|s| s.container_statuses.as_ref())
                    .and_then(|statuses| statuses.first())
                    .and_then(|cs| cs.state.as_ref())
                    .and_then(|state| state.terminated.as_ref())
                    .map(|term| term.exit_code == 0)
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .await?;

    Ok(())
}

async fn collect_storage_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pods: u32,
    tenant2_pods: u32,
    scenario: &StorageTestScenario,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let mut tenant1_throughputs = Vec::new();
    let mut tenant2_throughputs = Vec::new();

    // Collect from tenant1 pods
    for i in 0..tenant1_pods {
        let pod_name = format!("storage-fairness-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&pod_name, &tenant1.namespace)
            .await?;

        if let Ok(throughput) = parse_storage_benchmark_logs(&logs, scenario) {
            tenant1_throughputs.push(throughput);
        }
    }

    // Collect from tenant2 pods
    for i in 0..tenant2_pods {
        let pod_name = format!("storage-fairness-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&pod_name, &tenant2.namespace)
            .await?;

        if let Ok(throughput) = parse_storage_benchmark_logs(&logs, scenario) {
            tenant2_throughputs.push(throughput);
        }
    }

    Ok((tenant1_throughputs, tenant2_throughputs))
}

fn parse_storage_benchmark_logs(logs: &str, scenario: &StorageTestScenario) -> Result<f64> {
    // First, look for our standardized output format
    for line in logs.lines() {
        if line.contains("THROUGHPUT_RESULT:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "THROUGHPUT_RESULT:" && i + 1 < parts.len() {
                    if let Ok(throughput) = parts[i + 1].parse::<f64>() {
                        return Ok(throughput);
                    }
                }
            }
        }
    }

    // Fallback parsing based on scenario
    match scenario {
        StorageTestScenario::SequentialIO => {
            // Parse dd output for throughput (MB/s)
            for line in logs.lines().rev() {
                if line.contains("MB/s") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if part.contains("MB/s") && i > 0 {
                            if let Ok(throughput) = parts[i - 1].parse::<f64>() {
                                return Ok(throughput);
                            }
                        }
                    }
                }
            }
        }
        StorageTestScenario::RandomIO => {
            // Parse FIO JSON output
            let json_start = logs.find('{');
            let json_end = logs.rfind('}');

            if let (Some(start), Some(end)) = (json_start, json_end) {
                let json_str = &logs[start..=end];
                if let Ok(fio_result) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(jobs) = fio_result["jobs"].as_array() {
                        if let Some(job) = jobs.first() {
                            // Try read bandwidth first
                            if let Some(read_bw) = job["read"]["bw"].as_f64() {
                                if read_bw > 0.0 {
                                    return Ok(read_bw / 1024.0); // Convert KB/s to MB/s
                                }
                            }
                            // Then write bandwidth
                            if let Some(write_bw) = job["write"]["bw"].as_f64() {
                                if write_bw > 0.0 {
                                    return Ok(write_bw / 1024.0);
                                }
                            }
                        }
                    }
                }
            }

            // Fallback: look for bw= pattern
            for line in logs.lines() {
                if line.contains("bw=") && line.contains("KB/s") {
                    if let Some(bw_start) = line.find("bw=") {
                        let bw_part = &line[bw_start + 3..];
                        if let Some(kb_pos) = bw_part.find("KB/s") {
                            let bw_str = &bw_part[..kb_pos];
                            if let Ok(bw) = bw_str.parse::<f64>() {
                                return Ok(bw / 1024.0);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Could not parse storage throughput from logs"
    ))
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
