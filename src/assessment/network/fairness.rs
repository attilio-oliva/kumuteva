//! Network Fairness Assessor
//!
//! This module implements the `FairnessAssessor` trait for the network subsystem.
//! It measures network latency fairness by comparing how a "regular" tenant's
//! network round-trip time is affected when a "malicious" tenant increases their
//! network traffic.
//!
//! Uses iperf3 in TCP mode with JSON output to measure RTT (round-trip time).

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
use crate::verifier::TenantClusterConfig;

/// Network fairness assessor configuration
#[derive(Debug, Clone)]
pub struct NetworkFairnessConfig {
    /// Number of iperf3 client-server pod pairs per tenant for baseline
    pub pod_pairs_per_tenant: u32,
}

impl Default for NetworkFairnessConfig {
    fn default() -> Self {
        Self {
            pod_pairs_per_tenant: 1,
        }
    }
}

/// Network fairness assessor using iperf3 RTT measurement
pub struct NetworkFairnessAssessor {
    pub config: NetworkFairnessConfig,
}

impl NetworkFairnessAssessor {
    pub fn new(config: NetworkFairnessConfig) -> Self {
        Self { config }
    }

    /// Run a test phase with specified pod pair counts
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        tenant1_pod_pairs: u32,
        tenant2_pod_pairs: u32,
    ) -> Result<PhaseResults> {
        let detailed = self
            .run_phase_detailed(
                tenant1,
                tenant2,
                duration,
                tenant1_pod_pairs,
                tenant2_pod_pairs,
            )
            .await?;
        Ok(detailed.into())
    }

    /// Run a test phase and return detailed results with raw data for CSV export
    async fn run_phase_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        tenant1_pod_pairs: u32,
        tenant2_pod_pairs: u32,
    ) -> Result<DetailedPhaseResults> {
        let duration_secs = duration.as_secs();

        // Create iperf3 pod pairs for both tenants
        create_pods_for_test(
            &tenant1,
            &tenant2,
            duration_secs,
            tenant1_pod_pairs,
            tenant2_pod_pairs,
        )
        .await?;

        // Wait for completion
        wait_for_pods_completion(&tenant1, &tenant2, tenant1_pod_pairs, tenant2_pod_pairs).await?;

        // Collect RTT results from iperf3 JSON output (with raw data)
        let (tenant1_raw, tenant2_raw) =
            collect_rtt_results_detailed(&tenant1, &tenant2, tenant1_pod_pairs, tenant2_pod_pairs)
                .await?;

        // Cleanup all pods
        cleanup_pods(&tenant1, tenant1_pod_pairs).await?;
        cleanup_pods(&tenant2, tenant2_pod_pairs).await?;

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
impl FairnessAssessor for NetworkFairnessAssessor {
    fn name(&self) -> &'static str {
        "Network"
    }

    fn operation_description(&self) -> &'static str {
        "Network round-trip latency"
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults> {
        // Both tenants run with the same number of pod pairs
        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pod_pairs_per_tenant,
            self.config.pod_pairs_per_tenant,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults> {
        // Tenant1 stays regular, Tenant2 gets more pod pairs (malicious)
        let malicious_pod_pairs =
            (self.config.pod_pairs_per_tenant as f64 * config.malicious_load_multiplier) as u32;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pod_pairs_per_tenant,
            malicious_pod_pairs.max(1),
        )
        .await
    }
}

#[async_trait]
impl DetailedFairnessAssessor for NetworkFairnessAssessor {
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
            self.config.pod_pairs_per_tenant,
            self.config.pod_pairs_per_tenant,
        )
        .await
    }

    async fn run_unbalanced_detailed(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<DetailedPhaseResults> {
        let malicious_pod_pairs =
            (self.config.pod_pairs_per_tenant as f64 * config.malicious_load_multiplier) as u32;

        self.run_phase_detailed(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pod_pairs_per_tenant,
            malicious_pod_pairs.max(1),
        )
        .await
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn calculate_stats(values: &[f64]) -> (f64, f64, u64) {
    if values.is_empty() {
        return (0.0, 0.0, 0);
    }

    let count = values.len() as u64;
    let avg = values.iter().sum::<f64>() / values.len() as f64;

    let variance = values.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / values.len() as f64;
    let std_dev = variance.sqrt();

    (avg, std_dev, count)
}

/// Create an iperf3 server pod
fn iperf3_server_pod_manifest(pod_index: u32) -> Pod {
    let pod_name = format!("net-fairness-srv-{}", pod_index);

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
                    "name": "iperf3",
                    "image": "networkstatic/iperf3",
                    "ports": [{"containerPort": 5201}],
                    "args": ["-s", "--one-off"]
                }
            ]
        }
    }))
    .unwrap()
}

/// Create an iperf3 client pod with JSON output for RTT measurement
fn iperf3_client_pod_manifest(server_ip: &str, duration_secs: u64, pod_index: u32) -> Pod {
    let pod_name = format!("net-fairness-cli-{}", pod_index);

    // Use TCP mode with JSON output - iperf3 reports mean_rtt in the JSON
    // The --get-server-output flag ensures we get complete results
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
                    "name": "iperf3",
                    "image": "networkstatic/iperf3",
                    "args": [
                        "-c", server_ip,
                        "-t", duration_secs.to_string(),
                        "--json"
                    ]
                }
            ]
        }
    }))
    .unwrap()
}

async fn create_pods_for_test(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    duration_secs: u64,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<()> {
    // Create pod pairs for tenant1
    for i in 0..tenant1_pod_pairs {
        create_iperf3_pod_pair(tenant1, duration_secs, i).await?;
    }

    // Create pod pairs for tenant2
    for i in 0..tenant2_pod_pairs {
        create_iperf3_pod_pair(tenant2, duration_secs, i).await?;
    }

    Ok(())
}

async fn create_iperf3_pod_pair(
    tenant: &TenantClusterConfig,
    duration_secs: u64,
    pair_index: u32,
) -> Result<()> {
    // Create server
    let server_pod = iperf3_server_pod_manifest(pair_index);
    let server_name = server_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&server_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&server_name, &tenant.namespace)
        .await?;

    // Get server IP with retry
    let mut server_ip = tenant
        .cluster
        .get_pod_ip(&server_name, &tenant.namespace)
        .await
        .unwrap_or_default();

    let mut attempts = 0;
    while server_ip.is_empty() && attempts < 10 {
        attempts += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
        server_ip = tenant
            .cluster
            .get_pod_ip(&server_name, &tenant.namespace)
            .await
            .unwrap_or_default();
    }

    if server_ip.is_empty() {
        return Err(anyhow::anyhow!("iperf3 server pod has no IP"));
    }

    // Give server time to start listening
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Create client
    let client_pod = iperf3_client_pod_manifest(&server_ip, duration_secs, pair_index);
    let client_name = client_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&client_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&client_name, &tenant.namespace)
        .await?;

    Ok(())
}

async fn wait_for_pods_completion(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<()> {
    // Wait for tenant1 client pods
    for i in 0..tenant1_pod_pairs {
        wait_for_pod_completion(tenant1, &format!("net-fairness-cli-{}", i)).await?;
    }

    // Wait for tenant2 client pods
    for i in 0..tenant2_pod_pairs {
        wait_for_pod_completion(tenant2, &format!("net-fairness-cli-{}", i)).await?;
    }

    Ok(())
}

async fn wait_for_pod_completion(tenant: &TenantClusterConfig, pod_name: &str) -> Result<()> {
    // Check if already terminated
    let status = tenant
        .cluster
        .get_pod_in_namespace(pod_name, &tenant.namespace)
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
        .watch_pod_until_condition(pod_name, &tenant.namespace, |status_event| async move {
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

async fn collect_rtt_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let (t1_raw, t2_raw) =
        collect_rtt_results_detailed(tenant1, tenant2, tenant1_pod_pairs, tenant2_pod_pairs)
            .await?;
    Ok((
        t1_raw.iter().map(|p| p.latency_ms).collect(),
        t2_raw.iter().map(|p| p.latency_ms).collect(),
    ))
}

async fn collect_rtt_results_detailed(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<(Vec<MetricDataPoint>, Vec<MetricDataPoint>)> {
    let mut tenant1_data = Vec::new();
    let mut tenant2_data = Vec::new();

    // Collect from tenant1 client pods
    for i in 0..tenant1_pod_pairs {
        let pod_name = format!("net-fairness-cli-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&pod_name, &tenant1.namespace)
            .await?;

        if let Some(rtt_data) = parse_iperf3_rtt_detailed(&logs, i) {
            tenant1_data.extend(rtt_data);
        }
    }

    // Collect from tenant2 client pods
    for i in 0..tenant2_pod_pairs {
        let pod_name = format!("net-fairness-cli-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&pod_name, &tenant2.namespace)
            .await?;

        if let Some(rtt_data) = parse_iperf3_rtt_detailed(&logs, i) {
            tenant2_data.extend(rtt_data);
        }
    }

    Ok((tenant1_data, tenant2_data))
}

fn parse_iperf3_rtt(logs: &str) -> Option<f64> {
    // Parse iperf3 JSON output to extract mean_rtt
    // JSON structure: { "end": { "streams": [{ "sender": { "mean_rtt": 12345 } }] } }
    // mean_rtt is in microseconds, we convert to milliseconds

    let json_start = logs.find('{');
    let json_end = logs.rfind('}');

    if let (Some(start), Some(end)) = (json_start, json_end) {
        let json_str = &logs[start..=end];
        if let Ok(iperf_result) = serde_json::from_str::<serde_json::Value>(json_str) {
            // Try to get mean_rtt from the sender stream
            if let Some(streams) = iperf_result["end"]["streams"].as_array() {
                if let Some(stream) = streams.first() {
                    // Try sender first (preferred)
                    if let Some(mean_rtt) = stream["sender"]["mean_rtt"].as_f64() {
                        if mean_rtt > 0.0 {
                            // Convert microseconds to milliseconds
                            return Some(mean_rtt / 1000.0);
                        }
                    }
                    // Fall back to receiver
                    if let Some(mean_rtt) = stream["receiver"]["mean_rtt"].as_f64() {
                        if mean_rtt > 0.0 {
                            return Some(mean_rtt / 1000.0);
                        }
                    }
                }
            }

            // Alternative: try sum_sent/sum_received for aggregated results
            if let Some(mean_rtt) = iperf_result["end"]["sum_sent"]["mean_rtt"].as_f64() {
                if mean_rtt > 0.0 {
                    return Some(mean_rtt / 1000.0);
                }
            }

            if let Some(mean_rtt) = iperf_result["end"]["sum_received"]["mean_rtt"].as_f64() {
                if mean_rtt > 0.0 {
                    return Some(mean_rtt / 1000.0);
                }
            }
        }
    }

    None
}

fn parse_iperf3_rtt_detailed(logs: &str, pod_index: u32) -> Option<Vec<MetricDataPoint>> {
    // Parse iperf3 JSON output to extract interval RTT data for CSV export
    // JSON structure includes intervals array with per-second measurements

    let json_start = logs.find('{');
    let json_end = logs.rfind('}');

    if let (Some(start), Some(end)) = (json_start, json_end) {
        let json_str = &logs[start..=end];
        if let Ok(iperf_result) = serde_json::from_str::<serde_json::Value>(json_str) {
            let mut data_points = Vec::new();

            // Try to extract interval data for per-second measurements
            if let Some(intervals) = iperf_result["intervals"].as_array() {
                for (idx, interval) in intervals.iter().enumerate() {
                    // Get timestamp from interval
                    let timestamp = interval["sum"]["start"].as_f64().unwrap_or(idx as f64);

                    // Try to get RTT from streams in this interval
                    if let Some(streams) = interval["streams"].as_array() {
                        for stream in streams {
                            if let Some(rtt) = stream["rtt"].as_f64() {
                                if rtt > 0.0 {
                                    data_points.push(MetricDataPoint {
                                        timestamp_secs: timestamp,
                                        latency_ms: rtt / 1000.0, // microseconds to ms
                                        is_error: false,
                                        operation: Some(format!("iperf3-pod-{}", pod_index)),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // If no interval data, fall back to summary mean_rtt
            if data_points.is_empty() {
                if let Some(mean_rtt) = parse_iperf3_rtt(logs) {
                    data_points.push(MetricDataPoint {
                        timestamp_secs: 0.0,
                        latency_ms: mean_rtt,
                        is_error: false,
                        operation: Some(format!("iperf3-pod-{}-summary", pod_index)),
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

async fn cleanup_pods(tenant: &TenantClusterConfig, pod_pairs: u32) -> Result<()> {
    // Delete all pods
    for i in 0..pod_pairs {
        let server_name = format!("net-fairness-srv-{}", i);
        let client_name = format!("net-fairness-cli-{}", i);

        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&server_name, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&client_name, &tenant.namespace)
            .await;
    }

    // Wait for deletions
    for i in 0..pod_pairs {
        let server_name = format!("net-fairness-srv-{}", i);
        let client_name = format!("net-fairness-cli-{}", i);

        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&server_name, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&client_name, &tenant.namespace)
            .await;
    }

    Ok(())
}
