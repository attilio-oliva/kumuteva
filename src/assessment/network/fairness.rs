//! Network Fairness Assessor
//!
//! Measures network latency using iperf3 pod pairs.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use crate::assessment::fairness_assessor::{
    calculate_stats, FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Network assessor configuration
#[derive(Debug, Clone)]
pub struct FairnessNetworkConfig {
    /// Number of iperf3 client-server pod pairs per tenant
    pub pod_pairs: u32,
}

impl Default for FairnessNetworkConfig {
    fn default() -> Self {
        Self { pod_pairs: 1 }
    }
}

// =============================================================================
// ASSESSOR
// =============================================================================

/// Network fairness assessor using iperf3
pub struct FairnessNetworkAssessor {
    config: FairnessNetworkConfig,
}

impl FairnessNetworkAssessor {
    pub fn new(config: FairnessNetworkConfig) -> Self {
        Self { config }
    }

    /// Run a test phase
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_pairs: u32,
        t2_pairs: u32,
        t1_bandwidth_mbps: Option<f64>,
        t2_bandwidth_mbps: Option<f64>,
    ) -> Result<PhaseResult> {
        let duration_secs = duration.as_secs();

        // Create iperf3 pod pairs
        for i in 0..t1_pairs {
            create_iperf3_pair(&tenant1, i, duration_secs, t1_bandwidth_mbps).await?;
        }
        for i in 0..t2_pairs {
            create_iperf3_pair(&tenant2, i, duration_secs, t2_bandwidth_mbps).await?;
        }

        // Wait for completion
        wait_for_completion(&tenant1, t1_pairs).await?;
        wait_for_completion(&tenant2, t2_pairs).await?;

        // Collect results
        let t1_points = collect_results(&tenant1, t1_pairs).await?;
        let t2_points = collect_results(&tenant2, t2_pairs).await?;

        // Cleanup
        cleanup_pods(&tenant1, t1_pairs).await?;
        cleanup_pods(&tenant2, t2_pairs).await?;

        Ok(PhaseResult {
            tenant1: TenantMetrics::from_raw(t1_points),
            tenant2: TenantMetrics::from_raw(t2_points),
        })
    }
}

#[async_trait]
impl FairnessAssessor for FairnessNetworkAssessor {
    fn name(&self) -> &'static str {
        "Network"
    }

    fn metric(&self) -> &'static str {
        "round-trip latency"
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        // Convert rate to bandwidth (rough approximation)
        let bandwidth = rate_to_bandwidth(config.tenant1_rate);

        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pod_pairs,
            self.config.pod_pairs,
            bandwidth,
            bandwidth,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let t1_bw = rate_to_bandwidth(config.tenant1_rate);
        let t2_bw = rate_to_bandwidth(config.malicious_rate());
        let malicious_pairs =
            (self.config.pod_pairs as f64 * config.malicious_load_multiplier) as u32;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pod_pairs,
            malicious_pairs.max(1),
            t1_bw,
            t2_bw,
        )
        .await
    }
}

// =============================================================================
// HELPERS
// =============================================================================

/// Convert rate (ops/sec) to bandwidth (Mbps)
fn rate_to_bandwidth(rate: f64) -> Option<f64> {
    if rate <= 0.0 {
        None
    } else {
        // Rough approximation: 1 op ~= 1KB, so rate * 8 / 1000 Mbps
        Some((rate * 8.0 / 1000.0).max(1.0))
    }
}

fn iperf3_server_pod(index: u32) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("net-fairness-srv-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "iperf3",
                "image": "networkstatic/iperf3",
                "args": ["-s"]
            }]
        }
    }))
    .unwrap()
}

fn iperf3_client_pod(index: u32, server_ip: &str, duration: u64, bandwidth: Option<f64>) -> Pod {
    let mut args = vec![
        "-c".to_string(),
        server_ip.to_string(),
        "-t".to_string(),
        duration.to_string(),
        "--json".to_string(),
    ];

    if let Some(bw) = bandwidth {
        args.push("-b".to_string());
        args.push(format!("{}M", bw as u64));
    }

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("net-fairness-cli-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "iperf3",
                "image": "networkstatic/iperf3",
                "args": args
            }]
        }
    }))
    .unwrap()
}

async fn create_iperf3_pair(
    tenant: &TenantClusterConfig,
    index: u32,
    duration: u64,
    bandwidth: Option<f64>,
) -> Result<()> {
    // Create server
    let server = iperf3_server_pod(index);
    let server_name = server.metadata.name.clone().unwrap();
    tenant
        .cluster
        .create_pod_in_namespace(&server, &tenant.namespace)
        .await?;
    tenant
        .cluster
        .wait_for_pod_to_be_ready(&server_name, &tenant.namespace)
        .await?;

    // Get server IP
    let mut server_ip = String::new();
    for _ in 0..10 {
        if let Ok(ip) = tenant
            .cluster
            .get_pod_ip(&server_name, &tenant.namespace)
            .await
        {
            if !ip.is_empty() {
                server_ip = ip;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if server_ip.is_empty() {
        return Err(anyhow::anyhow!("Failed to get server IP"));
    }

    // Wait for server to start listening
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Create client
    let client = iperf3_client_pod(index, &server_ip, duration, bandwidth);
    let client_name = client.metadata.name.clone().unwrap();
    tenant
        .cluster
        .create_pod_in_namespace(&client, &tenant.namespace)
        .await?;
    tenant
        .cluster
        .wait_for_pod_to_be_ready(&client_name, &tenant.namespace)
        .await?;

    Ok(())
}

async fn wait_for_completion(tenant: &TenantClusterConfig, pairs: u32) -> Result<()> {
    for i in 0..pairs {
        let name = format!("net-fairness-cli-{}", i);
        // Wait for pod to succeed or fail
        tenant
            .cluster
            .watch_pod_until_condition(&name, &tenant.namespace, |event| async move {
                if let kube::api::WatchEvent::Modified(pod) = event {
                    if let Some(status) = pod.status {
                        if let Some(phase) = status.phase {
                            return phase == "Succeeded" || phase == "Failed";
                        }
                    }
                }
                false
            })
            .await?;
    }
    Ok(())
}

async fn collect_results(tenant: &TenantClusterConfig, pairs: u32) -> Result<Vec<MetricPoint>> {
    let mut points = Vec::new();

    for i in 0..pairs {
        let name = format!("net-fairness-cli-{}", i);
        let logs = tenant
            .cluster
            .get_pod_logs(&name, &tenant.namespace)
            .await?;

        if let Some(rtt) = parse_iperf3_rtt(&logs) {
            points.push(MetricPoint {
                timestamp_secs: 0.0,
                latency_ms: rtt,
                is_error: false,
                label: Some(format!("iperf3-{}", i)),
            });
        }
    }

    Ok(points)
}

fn parse_iperf3_rtt(logs: &str) -> Option<f64> {
    let json_start = logs.find('{')?;
    let json_end = logs.rfind('}')?;
    let json_str = &logs[json_start..=json_end];

    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // Try to get mean_rtt from streams
    if let Some(streams) = v["end"]["streams"].as_array() {
        if let Some(stream) = streams.first() {
            if let Some(rtt) = stream["sender"]["mean_rtt"].as_f64() {
                if rtt > 0.0 {
                    return Some(rtt / 1000.0); // microseconds to ms
                }
            }
        }
    }

    // Fallback to sum_sent
    if let Some(rtt) = v["end"]["sum_sent"]["mean_rtt"].as_f64() {
        if rtt > 0.0 {
            return Some(rtt / 1000.0);
        }
    }

    None
}

async fn cleanup_pods(tenant: &TenantClusterConfig, pairs: u32) -> Result<()> {
    for i in 0..pairs {
        let server = format!("net-fairness-srv-{}", i);
        let client = format!("net-fairness-cli-{}", i);
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&server, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&client, &tenant.namespace)
            .await;
    }
    Ok(())
}
