//! Network Fairness Assessor
//!
//! This module implements the `FairnessAssessor` trait for the network subsystem.
//! It measures bandwidth fairness by comparing how a "regular" tenant's network
//! throughput is affected when a "malicious" tenant increases their network usage.
//!
//! Uses iperf3 to measure bandwidth between pod pairs.

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
// NETWORK FAIRNESS ASSESSOR
// =============================================================================

/// Network fairness assessor configuration
#[derive(Debug, Clone)]
pub struct NetworkFairnessConfig {
    /// Number of iperf3 client-server pod pairs per tenant for baseline
    pub pod_pairs_per_tenant: u32,
    /// Bandwidth limit in Mbps for baseline (0 = unlimited)
    pub bandwidth_limit_mbps: u32,
}

impl Default for NetworkFairnessConfig {
    fn default() -> Self {
        Self {
            pod_pairs_per_tenant: 1,
            bandwidth_limit_mbps: 100_000, // Essentially unlimited
        }
    }
}

/// Network fairness assessor using iperf3
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
        let duration_secs = duration.as_secs();

        // Create pod pairs for both tenants
        create_pods_for_test(
            &tenant1,
            &tenant2,
            self.config.bandwidth_limit_mbps,
            duration_secs,
            tenant1_pod_pairs,
            tenant2_pod_pairs,
        )
        .await?;

        // Wait for completion
        wait_for_pods_completion(&tenant1, &tenant2, tenant1_pod_pairs, tenant2_pod_pairs).await?;

        // Collect results
        let (tenant1_bandwidths, tenant2_bandwidths) =
            collect_results(&tenant1, &tenant2, tenant1_pod_pairs, tenant2_pod_pairs).await?;

        // Cleanup
        cleanup_pods(&tenant1, tenant1_pod_pairs).await?;
        cleanup_pods(&tenant2, tenant2_pod_pairs).await?;

        // Calculate averages
        let tenant1_avg = if tenant1_bandwidths.is_empty() {
            0.0
        } else {
            tenant1_bandwidths.iter().sum::<f64>() / tenant1_bandwidths.len() as f64
        };

        let tenant2_avg = if tenant2_bandwidths.is_empty() {
            0.0
        } else {
            tenant2_bandwidths.iter().sum::<f64>() / tenant2_bandwidths.len() as f64
        };

        Ok(PhaseResults {
            tenant1: TenantMetrics {
                primary_metric: tenant1_avg,
                secondary_metrics: vec![
                    ("pod_pairs".to_string(), tenant1_pod_pairs as f64),
                    ("samples".to_string(), tenant1_bandwidths.len() as f64),
                ],
                error_rate: 0.0, // TODO: Track errors from iperf3
            },
            tenant2: TenantMetrics {
                primary_metric: tenant2_avg,
                secondary_metrics: vec![
                    ("pod_pairs".to_string(), tenant2_pod_pairs as f64),
                    ("samples".to_string(), tenant2_bandwidths.len() as f64),
                ],
                error_rate: 0.0,
            },
        })
    }
}

#[async_trait]
impl FairnessAssessor for NetworkFairnessAssessor {
    fn name(&self) -> &'static str {
        "Network"
    }

    fn metric_unit(&self) -> &'static str {
        "Mbps"
    }

    fn higher_is_better(&self) -> bool {
        true // Higher bandwidth is better
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

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn benchmark_pod_manifest(
    bandwidth_limit_mbps: u32,
    duration_secs: u64,
    server_ip: Option<String>,
    pair_index: u32,
) -> Pod {
    let is_server = server_ip.is_none();

    let pod_name = if is_server {
        format!("net-fairness-srv-{}", pair_index)
    } else {
        format!("net-fairness-cli-{}", pair_index)
    };

    let bandwidth_limit = format!("{}M", bandwidth_limit_mbps);

    let args: Vec<String> = if is_server {
        vec![
            "iperf3".to_string(),
            "-s".to_string(),
            "--one-off".to_string(),
        ]
    } else {
        vec![
            "iperf3".to_string(),
            "-c".to_string(),
            server_ip.unwrap_or_default(),
            "-t".to_string(),
            duration_secs.to_string(),
            "--bandwidth".to_string(),
            bandwidth_limit,
            "--udp".to_string(),
        ]
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
                    "name": "iperf3",
                    "image": "networkstatic/iperf3",
                    "ports": [
                        {
                            "containerPort": 5201
                        }
                    ],
                    "args": args
                }
            ]
        }
    }))
    .unwrap()
}

async fn create_pods_for_test(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    bandwidth_limit_mbps: u32,
    duration_secs: u64,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<()> {
    // Create pod pairs for tenant1
    for i in 0..tenant1_pod_pairs {
        create_benchmark_pod_pair(tenant1, bandwidth_limit_mbps, duration_secs, i).await?;
    }

    // Create pod pairs for tenant2
    for i in 0..tenant2_pod_pairs {
        create_benchmark_pod_pair(tenant2, bandwidth_limit_mbps, duration_secs, i).await?;
    }

    Ok(())
}

async fn create_benchmark_pod_pair(
    tenant: &TenantClusterConfig,
    bandwidth: u32,
    duration_secs: u64,
    pair_index: u32,
) -> Result<(Pod, Pod)> {
    // Create server pod
    let server_pod = benchmark_pod_manifest(bandwidth, duration_secs, None, pair_index);
    let server_pod_name = server_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&server_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&server_pod_name, &tenant.namespace)
        .await?;

    // Get server IP with retry
    let mut server_ip = tenant
        .cluster
        .get_pod_ip(&server_pod_name, &tenant.namespace)
        .await
        .unwrap_or_default();

    let mut attempts = 0;
    while server_ip.is_empty() && attempts < 8 {
        attempts += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
        server_ip = tenant
            .cluster
            .get_pod_ip(&server_pod_name, &tenant.namespace)
            .await
            .unwrap_or_default();
    }

    if server_ip.is_empty() {
        return Err(anyhow::anyhow!("Server pod has no IP after waiting"));
    }

    // Give the iperf3 server a moment to start listening
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Create client pod
    let client_pod = benchmark_pod_manifest(bandwidth, duration_secs, Some(server_ip), pair_index);
    let client_pod_name = client_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&client_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&client_pod_name, &tenant.namespace)
        .await?;

    Ok((server_pod, client_pod))
}

async fn wait_for_pods_completion(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<()> {
    // Wait for tenant1 client pods
    for i in 0..tenant1_pod_pairs {
        wait_for_client_pod_completion(tenant1, i).await?;
    }

    // Wait for tenant2 client pods
    for i in 0..tenant2_pod_pairs {
        wait_for_client_pod_completion(tenant2, i).await?;
    }

    Ok(())
}

async fn wait_for_client_pod_completion(
    tenant: &TenantClusterConfig,
    pair_index: u32,
) -> Result<()> {
    let client_pod_name = format!("net-fairness-cli-{}", pair_index);

    // Check if already terminated (either Succeeded or Failed phase)
    let status = tenant
        .cluster
        .get_pod_in_namespace(&client_pod_name, &tenant.namespace)
        .await?;

    if let Some(s) = status.status.as_ref() {
        if let Some(phase) = s.phase.as_ref() {
            if phase == "Succeeded" || phase == "Failed" {
                return Ok(());
            }
        }
    }

    // Watch for completion (either success or failure)
    tenant
        .cluster
        .watch_pod_until_condition(
            &client_pod_name,
            &tenant.namespace,
            |status_event| async move {
                if let kube::api::WatchEvent::Modified(status) = status_event {
                    // Check pod phase - Succeeded or Failed means the pod has finished
                    status
                        .status
                        .as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|phase| phase == "Succeeded" || phase == "Failed")
                        .unwrap_or(false)
                } else {
                    false
                }
            },
        )
        .await?;

    Ok(())
}

async fn collect_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let mut tenant1_bandwidths = Vec::new();
    let mut tenant2_bandwidths = Vec::new();

    // Collect from tenant1 client pods
    for i in 0..tenant1_pod_pairs {
        let client_pod_name = format!("net-fairness-cli-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&client_pod_name, &tenant1.namespace)
            .await?;

        if let Ok(bandwidth) = parse_iperf3_bandwidth(&logs) {
            tenant1_bandwidths.push(bandwidth);
        }
    }

    // Collect from tenant2 client pods
    for i in 0..tenant2_pod_pairs {
        let client_pod_name = format!("net-fairness-cli-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&client_pod_name, &tenant2.namespace)
            .await?;

        if let Ok(bandwidth) = parse_iperf3_bandwidth(&logs) {
            tenant2_bandwidths.push(bandwidth);
        }
    }

    Ok((tenant1_bandwidths, tenant2_bandwidths))
}

fn parse_iperf3_bandwidth(logs: &str) -> Result<f64> {
    // Look for the summary line with bandwidth
    // iperf3 outputs lines like: "[SUM]   0.00-10.00  sec  1.15 GBytes  989 Mbits/sec"
    for line in logs.lines().rev() {
        if line.contains("Mbits/sec") || line.contains("Gbits/sec") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "Mbits/sec" && i > 0 {
                    if let Ok(bw) = parts[i - 1].parse::<f64>() {
                        return Ok(bw);
                    }
                }
                if *part == "Gbits/sec" && i > 0 {
                    if let Ok(bw) = parts[i - 1].parse::<f64>() {
                        return Ok(bw * 1000.0); // Convert to Mbps
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Could not parse iperf3 bandwidth from logs"
    ))
}

async fn cleanup_pods(tenant: &TenantClusterConfig, pod_pairs: u32) -> Result<()> {
    for i in 0..pod_pairs {
        let server_pod_name = format!("net-fairness-srv-{}", i);
        let client_pod_name = format!("net-fairness-cli-{}", i);

        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&server_pod_name, &tenant.namespace)
            .await;

        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&client_pod_name, &tenant.namespace)
            .await;
    }

    // Wait for deletion
    for i in 0..pod_pairs {
        let server_pod_name = format!("net-fairness-srv-{}", i);
        let client_pod_name = format!("net-fairness-cli-{}", i);

        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&server_pod_name, &tenant.namespace)
            .await;

        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&client_pod_name, &tenant.namespace)
            .await;
    }

    Ok(())
}
