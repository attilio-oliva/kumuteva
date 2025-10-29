use std::sync::Arc;

use crate::verifier::{FairnessTestResults, TenantClusterConfig};
use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;

/// Fairness checks for network resources between tenants
/// The idea is to start in both tenant a pair of pods with a sort of iperf server working in kubernets
/// We then measure the bandwidth achieved between the two tenants and check that they are similarly distributed

/// Than to check whether the bandwidth is fairly distributed we  redo the test with tenant1 having a considerably
/// higher bandwidth limit and observe the changes in the achieved bandwidth for both tenants.

pub struct NetworkFairnessTestConfig {
    /// Duration of each bandwidth test
    pub test_duration_secs: u64,
    /// Bandwidth limit for tenant in the initial test with both tenants having this bandwidth (in Mbps)
    pub regular_bandwidth_limit_mbps: u32,
    /// Bandwidth limit for tenant1 in the second test (in Mbps)
    pub boosted_bandwidth_limit_mbps: u32,
    /// Acceptable deviation percentage for fairness check
    pub acceptable_deviation_percent: f64,
}

impl Default for NetworkFairnessTestConfig {
    fn default() -> Self {
        NetworkFairnessTestConfig {
            test_duration_secs: 30,
            regular_bandwidth_limit_mbps: 10,
            boosted_bandwidth_limit_mbps: 100,
            acceptable_deviation_percent: 20.0,
        }
    }
}

pub struct NetworkFairnessTestResults {
    pub regular_bandwidths: (f64, f64),
    pub unequal_bandwidths: (f64, f64),
    pub acceptable_deviation_percent: f64,
    pub fairness_passed: bool,
}

impl NetworkFairnessTestResults {
    pub fn analyze(
        regular: (f64, f64),
        unequal: (f64, f64),
        acceptable_deviation_percent: f64,
    ) -> NetworkFairnessTestResults {
        let (reg1, reg2) = regular;
        let (uneq1, uneq2) = unequal;

        let reg_diff_percent = ((reg1 - reg2).abs() / ((reg1 + reg2) / 2.0)) * 100.0;
        let unequal_diff_percent = ((uneq1 - uneq2).abs() / ((uneq1 + uneq2) / 2.0)) * 100.0;

        let fairness_passed = reg_diff_percent <= acceptable_deviation_percent;
        let boost_effective = unequal_diff_percent > reg_diff_percent;

        NetworkFairnessTestResults {
            regular_bandwidths: (reg1, reg2),
            unequal_bandwidths: (uneq1, uneq2),
            acceptable_deviation_percent,
            fairness_passed: fairness_passed && boost_effective,
        }
    }
}

pub fn benchmark_pod_manifest(
    bandwidth_limit_mbps: u32,
    duration_secs: u64,
    server_ip: Option<String>,
) -> Pod {
    let is_server = server_ip.is_none();

    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "net-bench-pod-srv",
        },
        "spec": {
            "containers": [
                {
                    "name": "net-bench-pod-srv",
                    "image": "networkstatic/iperf3",
                    "ports": [
                        {
                            "containerPort": 5201,
                        }
                    ],
                    "args": [
                        "iperf3",
                        if let Some(server_ip) = &server_ip {
                            format!("-c {}", server_ip)
                        } else {
                            "-s".to_string()
                        },
                        "-t", duration_secs.to_string(),
                        "--bandwidth", format!("{}M", bandwidth_limit_mbps),
                        if is_server {
                            "--one-off".to_string()
                        } else {
                            "".to_string()
                        },
                    ],
                }
            ]
        }
    }
    ))
    .unwrap()
}

pub async fn check_network_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: NetworkFairnessTestConfig,
) -> Result<NetworkFairnessTestResults> {
    create_pods_for_fairness_test(
        (tenant1.clone(), config.regular_bandwidth_limit_mbps),
        (tenant2.clone(), config.regular_bandwidth_limit_mbps),
        config.test_duration_secs,
    )
    .await?;

    wait_for_pods_completion(&tenant1, &tenant2).await?;

    let regular_results = collect_fairness_test_results(&tenant1, &tenant2).await?;

    create_pods_for_fairness_test(
        (tenant1.clone(), config.boosted_bandwidth_limit_mbps),
        (tenant2.clone(), config.regular_bandwidth_limit_mbps),
        config.test_duration_secs,
    )
    .await?;

    let boosted_results = collect_fairness_test_results(&tenant1, &tenant2).await?;
    Ok(NetworkFairnessTestResults::analyze(
        regular_results,
        boosted_results,
        config.acceptable_deviation_percent,
    ))
}

async fn create_pods_for_fairness_test(
    tenant1: (Arc<TenantClusterConfig>, u32),
    tenant2: (Arc<TenantClusterConfig>, u32),
    duration_secs: u64,
) -> Result<()> {
    let (tenant1, bandwidth1) = tenant1;
    let (tenant2, bandwidth2) = tenant2;

    let (server1, client1) = create_benchmark_pod_pair(&tenant1, bandwidth1, duration_secs).await?;

    let (server2, client2) = create_benchmark_pod_pair(&tenant2, bandwidth2, duration_secs).await?;
    Ok(())
}

async fn create_benchmark_pod_pair(
    tenant: &TenantClusterConfig,
    bandwidth: u32,
    duration_secs: u64,
) -> Result<(Pod, Pod)> {
    let server_pod = benchmark_pod_manifest(bandwidth, duration_secs, None);
    let server_pod_name = server_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&server_pod, &tenant.namespace)
        .await?;

    let server_ip = tenant
        .cluster
        .get_pod_ip(&server_pod_name, &tenant.namespace)
        .await?;

    let client_pod = benchmark_pod_manifest(bandwidth, duration_secs, Some(server_ip));
    tenant
        .cluster
        .create_pod_in_namespace(&client_pod, &tenant.namespace)
        .await?;

    Ok((server_pod, client_pod))
}
async fn wait_for_pods_completion(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<()> {
    tenant1
        .cluster
        .watch_pod_until_condition(
            "net-bench-pod-srv",
            &tenant1.namespace,
            |status_event| async move {
                if let kube::api::WatchEvent::Modified(status) = status_event {
                    status
                        .status
                        .as_ref()
                        .and_then(|s| s.container_statuses.as_ref())
                        .and_then(|statuses| statuses.first())
                        .and_then(|cs| cs.state.as_ref())
                        .and_then(|state| state.terminated.as_ref())
                        .is_some()
                } else {
                    false
                }
            },
        )
        .await?;

    tenant2
        .cluster
        .watch_pod_until_condition(
            "net-bench-pod-srv",
            &tenant2.namespace,
            |status_event| async move {
                if let kube::api::WatchEvent::Modified(status) = status_event {
                    status
                        .status
                        .as_ref()
                        .and_then(|s| s.container_statuses.as_ref())
                        .and_then(|statuses| statuses.first())
                        .and_then(|cs| cs.state.as_ref())
                        .and_then(|state| state.terminated.as_ref())
                        .is_some()
                } else {
                    false
                }
            },
        )
        .await?;
    Ok(())
}

async fn collect_fairness_test_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<(f64, f64)> {
    let tenant1_client_logs = tenant1
        .cluster
        .get_pod_logs("net-bench-pod-srv", &tenant1.namespace)
        .await?;

    let tenant2_client_logs = tenant2
        .cluster
        .get_pod_logs("net-bench-pod-srv", &tenant2.namespace)
        .await?;

    let tenant1_bandwidth = parse_iperf3_bandwidth(&tenant1_client_logs)?;
    let tenant2_bandwidth = parse_iperf3_bandwidth(&tenant2_client_logs)?;

    Ok((tenant1_bandwidth, tenant2_bandwidth))
}

fn parse_iperf3_bandwidth(logs: &str) -> Result<f64> {
    for line in logs.lines().rev() {
        if line.contains("receiver") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let bandwidth_str = parts[6];
                let bandwidth_unit = parts[7];

                let bandwidth: f64 = bandwidth_str.parse()?;
                let bandwidth_mbps = match bandwidth_unit {
                    "Kbits/sec" => bandwidth / 1000.0,
                    "Mbits/sec" => bandwidth,
                    "Gbits/sec" => bandwidth * 1000.0,
                    _ => return Err(anyhow::anyhow!("Unknown bandwidth unit")),
                };
                return Ok(bandwidth_mbps);
            }
        }
    }
    Err(anyhow::anyhow!(
        "Could not find bandwidth information in logs"
    ))
}
