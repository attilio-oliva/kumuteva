use std::{f32::consts::E, sync::Arc, time::Duration};

use crate::verifier::{FairnessTestResults, TenantClusterConfig};
use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;

/// Fairness checks for network resources between tenants
/// The idea is to start in both tenant a pair of pods with a sort of iperf server working in kubernets
/// We then measure the bandwidth achieved between the two tenants and check that they are similarly distributed

/// Than to check whether the bandwidth is fairly distributed we  redo the test with tenant1 having a considerably
/// higher bandwidth limit and observe the changes in the achieved bandwidth for both tenants.

/// Generic test configuration that can be reused for different test cases
#[derive(Clone, Debug)]
pub struct TestCaseConfig {
    /// Duration of each bandwidth test
    pub test_duration_secs: u64,
    /// Bandwidth limit for tenant1 (in Mbps)
    pub tenant1_bandwidth_limit_mbps: u32,
    /// Bandwidth limit for tenant2 (in Mbps)
    pub tenant2_bandwidth_limit_mbps: u32,
    /// Number of pod pairs for tenant1
    pub tenant1_pod_pairs: u32,
    /// Number of pod pairs for tenant2
    pub tenant2_pod_pairs: u32,
}

impl Default for TestCaseConfig {
    fn default() -> Self {
        TestCaseConfig {
            test_duration_secs: 60,
            tenant1_bandwidth_limit_mbps: 100_000,
            tenant2_bandwidth_limit_mbps: 100_000,
            tenant1_pod_pairs: 1,
            tenant2_pod_pairs: 1,
        }
    }
}

/// Test scenario defines how to conduct network fairness tests
#[derive(Clone, Debug)]
pub enum TestScenario {
    /// Local iperf3 testing with client-server pairs within each tenant
    LocalIperf3,
    RemoteIperf3 {
        server_ip: String,
        port_range: (u16, u16),
    },
}

impl TestScenario {
    pub fn name(&self) -> &'static str {
        match self {
            TestScenario::LocalIperf3 => "local-iperf3",
            TestScenario::RemoteIperf3 { .. } => "remote-iperf3",
        }
    }
}

/// Network fairness test configuration combining scenario and test cases
#[derive(Clone, Debug)]
pub struct NetworkFairnessTestConfig {
    /// The test scenario to execute
    pub scenario: TestScenario,
    /// Configuration for the regular test case (both tenants equal)
    pub regular_test: TestCaseConfig,
    /// Configuration for the unbalanced test case (tenant1 boosted)
    pub unbalanced_test: TestCaseConfig,
    /// Acceptable deviation percentage for fairness check
    pub acceptable_deviation_percent: f64,
}

impl Default for NetworkFairnessTestConfig {
    fn default() -> Self {
        let regular_test = TestCaseConfig {
            test_duration_secs: 60,
            tenant1_bandwidth_limit_mbps: 100_000,
            tenant2_bandwidth_limit_mbps: 100_000,
            tenant1_pod_pairs: 1,
            tenant2_pod_pairs: 1,
        };

        let unbalanced_test = TestCaseConfig {
            test_duration_secs: 60,
            tenant1_bandwidth_limit_mbps: 200_000,
            tenant2_bandwidth_limit_mbps: 100_000,
            tenant1_pod_pairs: 1,
            tenant2_pod_pairs: 1,
        };

        NetworkFairnessTestConfig {
            scenario: TestScenario::LocalIperf3,
            regular_test,
            unbalanced_test,
            acceptable_deviation_percent: 20.0,
        }
    }
}

impl NetworkFairnessTestConfig {
    /// Create a new configuration with custom regular and unbalanced test cases
    pub fn new(
        scenario: TestScenario,
        regular_test: TestCaseConfig,
        unbalanced_test: TestCaseConfig,
        acceptable_deviation_percent: f64,
    ) -> Self {
        NetworkFairnessTestConfig {
            scenario,
            regular_test,
            unbalanced_test,
            acceptable_deviation_percent,
        }
    }
    /// Create a balanced test configuration where both test cases are identical
    pub fn balanced(
        scenario: TestScenario,
        test_case: TestCaseConfig,
        acceptable_deviation_percent: f64,
    ) -> Self {
        NetworkFairnessTestConfig {
            scenario,
            regular_test: test_case.clone(),
            unbalanced_test: test_case,
            acceptable_deviation_percent,
        }
    }

    /// Create a simple configuration with just bandwidth differences
    pub fn simple_bandwidth_test(
        scenario: TestScenario,
        regular_bandwidth_mbps: u32,
        boosted_bandwidth_mbps: u32,
        duration_secs: u64,
        acceptable_deviation_percent: f64,
    ) -> Self {
        let regular_test = TestCaseConfig {
            test_duration_secs: duration_secs,
            tenant1_bandwidth_limit_mbps: regular_bandwidth_mbps,
            tenant2_bandwidth_limit_mbps: regular_bandwidth_mbps,
            tenant1_pod_pairs: 1,
            tenant2_pod_pairs: 1,
        };

        let unbalanced_test = TestCaseConfig {
            test_duration_secs: duration_secs,
            tenant1_bandwidth_limit_mbps: boosted_bandwidth_mbps,
            tenant2_bandwidth_limit_mbps: regular_bandwidth_mbps,
            tenant1_pod_pairs: 5,
            tenant2_pod_pairs: 1,
        };

        NetworkFairnessTestConfig {
            scenario,
            regular_test,
            unbalanced_test,
            acceptable_deviation_percent,
        }
    }

    /// Create a remote iperf3 test configuration
    pub fn remote_iperf3_test(
        server_ip: &str,
        port_range: (u16, u16),
        regular_bandwidth_mbps: u32,
        boosted_bandwidth_mbps: u32,
        duration_secs: u64,
        acceptable_deviation_percent: f64,
    ) -> Self {
        let scenario = TestScenario::RemoteIperf3 {
            server_ip: String::from(server_ip),
            port_range,
        };
        Self::simple_bandwidth_test(
            scenario,
            regular_bandwidth_mbps,
            boosted_bandwidth_mbps,
            duration_secs,
            acceptable_deviation_percent,
        )
    }
}

pub struct NetworkFairnessTestResults {
    pub regular_bandwidths: (Vec<f64>, Vec<f64>),
    pub unequal_bandwidths: (Vec<f64>, Vec<f64>),
    pub acceptable_deviation_percent: f64,
    pub fairness_passed: bool,
}

impl NetworkFairnessTestResults {
    pub fn analyze(
        regular: (Vec<f64>, Vec<f64>),
        unequal: (Vec<f64>, Vec<f64>),
        acceptable_deviation_percent: f64,
    ) -> NetworkFairnessTestResults {
        let (reg1, reg2) = &regular;
        let (uneq1, uneq2) = &unequal;

        // Calculate average bandwidth for each tenant
        let reg1_avg: f64 = reg1.iter().sum::<f64>() / reg1.len() as f64;
        let reg2_avg: f64 = reg2.iter().sum::<f64>() / reg2.len() as f64;
        let uneq1_avg: f64 = uneq1.iter().sum::<f64>() / uneq1.len() as f64;
        let uneq2_avg: f64 = uneq2.iter().sum::<f64>() / uneq2.len() as f64;

        let reg_diff_percent =
            ((reg1_avg - reg2_avg).abs() / ((reg1_avg + reg2_avg) / 2.0)) * 100.0;
        let unequal_diff_percent =
            ((uneq1_avg - uneq2_avg).abs() / ((uneq1_avg + uneq2_avg) / 2.0)) * 100.0;

        let t1_diff = (uneq1_avg - reg1_avg).abs() / reg1_avg * 100.0;
        let t2_diff = (uneq2_avg - reg2_avg).abs() / reg2_avg * 100.0;

        // let fairness_passed = reg_diff_percent <= acceptable_deviation_percent;
        let fairness_passed = t2_diff <= acceptable_deviation_percent;
        // let boost_effective = unequal_diff_percent > reg_diff_percent;

        NetworkFairnessTestResults {
            regular_bandwidths: regular,
            unequal_bandwidths: unequal,
            acceptable_deviation_percent,
            fairness_passed,
        }
    }
}

pub fn benchmark_pod_manifest(
    bandwidth_limit_mbps: u32,
    duration_secs: u64,
    server_ip: Option<String>,
    pair_index: u32,
    port: Option<u16>,
) -> Pod {
    let is_server = server_ip.is_none();

    let pod_name = if is_server {
        format!("net-bench-pod-srv-{}", pair_index)
    } else {
        format!("net-bench-pod-cli-{}", pair_index)
    };

    let server_ip = server_ip.unwrap_or_default();
    let duration_secs = duration_secs.to_string();
    let bandwidth_limit = format!("{}M", bandwidth_limit_mbps);
    let port = port.unwrap_or(5201);
    let port_arg = format!("{}", port);

    let args = if is_server {
        vec!["iperf3", "-s", "--one-off"]
    } else {
        vec![
            "iperf3",
            "-c",
            &server_ip,
            "-t",
            &duration_secs,
            "--bandwidth",
            &bandwidth_limit,
            "--udp",
            "-p",
            &port_arg,
        ]
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

pub async fn check_network_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: NetworkFairnessTestConfig,
) -> Result<NetworkFairnessTestResults> {
    match config.scenario {
        TestScenario::LocalIperf3 => check_local_iperf3_fairness(tenant1, tenant2, config).await,
        TestScenario::RemoteIperf3 { .. } => {
            check_remote_iperf3_fairness(tenant1, tenant2, config).await
        }
    }
}
async fn check_local_iperf3_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: NetworkFairnessTestConfig,
) -> Result<NetworkFairnessTestResults> {
    // Execute regular test case
    let regular_results =
        execute_local_test_case(tenant1.clone(), tenant2.clone(), &config.regular_test).await?;

    // Execute unbalanced test case
    let unbalanced_results =
        execute_local_test_case(tenant1.clone(), tenant2.clone(), &config.unbalanced_test).await?;

    Ok(NetworkFairnessTestResults::analyze(
        regular_results,
        unbalanced_results,
        config.acceptable_deviation_percent,
    ))
}

async fn check_remote_iperf3_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: NetworkFairnessTestConfig,
) -> Result<NetworkFairnessTestResults> {
    let (server_ip, port_range) = match &config.scenario {
        TestScenario::RemoteIperf3 {
            server_ip,
            port_range,
        } => (server_ip.clone(), *port_range),
        _ => return Err(anyhow::anyhow!("Invalid scenario for remote iperf3 test")),
    };

    // Execute regular test case
    let regular_results = execute_remote_test_case(
        tenant1.clone(),
        tenant2.clone(),
        &config.regular_test,
        &server_ip,
        port_range,
    )
    .await?;

    // Execute unbalanced test case
    let unbalanced_results = execute_remote_test_case(
        tenant1.clone(),
        tenant2.clone(),
        &config.unbalanced_test,
        &server_ip,
        port_range,
    )
    .await?;

    Ok(NetworkFairnessTestResults::analyze(
        regular_results,
        unbalanced_results,
        config.acceptable_deviation_percent,
    ))
}

async fn execute_local_test_case(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    test_config: &TestCaseConfig,
) -> Result<(Vec<f64>, Vec<f64>)> {
    create_pods_for_fairness_test(
        (tenant1.clone(), test_config.tenant1_bandwidth_limit_mbps),
        (tenant2.clone(), test_config.tenant2_bandwidth_limit_mbps),
        test_config.test_duration_secs,
        test_config.tenant1_pod_pairs,
        test_config.tenant2_pod_pairs,
    )
    .await?;

    wait_for_pods_completion(
        &tenant1,
        &tenant2,
        test_config.tenant1_pod_pairs,
        test_config.tenant2_pod_pairs,
    )
    .await?;

    let results = collect_fairness_test_results(
        &tenant1,
        &tenant2,
        test_config.tenant1_pod_pairs,
        test_config.tenant2_pod_pairs,
    )
    .await?;

    // Clean up pods after collecting results
    cleanup_pods(&tenant1, test_config.tenant1_pod_pairs).await?;
    cleanup_pods(&tenant2, test_config.tenant2_pod_pairs).await?;

    Ok(results)
}
async fn create_pods_for_fairness_test(
    tenant1: (Arc<TenantClusterConfig>, u32),
    tenant2: (Arc<TenantClusterConfig>, u32),
    duration_secs: u64,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<()> {
    let (tenant1, bandwidth1) = tenant1;
    let (tenant2, bandwidth2) = tenant2;

    // Create multiple pod pairs for tenant1
    for i in 0..tenant1_pod_pairs {
        create_benchmark_pod_pair(&tenant1, bandwidth1, duration_secs, i).await?;
    }

    // Create multiple pod pairs for tenant2
    for i in 0..tenant2_pod_pairs {
        create_benchmark_pod_pair(&tenant2, bandwidth2, duration_secs, i).await?;
    }

    Ok(())
}

async fn execute_remote_test_case(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    test_config: &TestCaseConfig,
    server_ip: &str,
    port_range: (u16, u16),
) -> Result<(Vec<f64>, Vec<f64>)> {
    create_remote_client_pods(
        (tenant1.clone(), test_config.tenant1_bandwidth_limit_mbps),
        (tenant2.clone(), test_config.tenant2_bandwidth_limit_mbps),
        test_config.test_duration_secs,
        test_config.tenant1_pod_pairs,
        test_config.tenant2_pod_pairs,
        server_ip,
        port_range,
    )
    .await?;

    wait_for_remote_clients_completion(
        &tenant1,
        &tenant2,
        test_config.tenant1_pod_pairs,
        test_config.tenant2_pod_pairs,
    )
    .await?;

    let results = collect_fairness_test_results(
        &tenant1,
        &tenant2,
        test_config.tenant1_pod_pairs,
        test_config.tenant2_pod_pairs,
    )
    .await?;

    // Clean up pods after collecting results
    cleanup_remote_client_pods(&tenant1, test_config.tenant1_pod_pairs).await?;
    cleanup_remote_client_pods(&tenant2, test_config.tenant2_pod_pairs).await?;
    Ok(results)
}

async fn create_remote_client_pods(
    tenant1: (Arc<TenantClusterConfig>, u32),
    tenant2: (Arc<TenantClusterConfig>, u32),
    duration_secs: u64,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
    server_ip: &str,
    port_range: (u16, u16),
) -> Result<()> {
    let (tenant1, bandwidth1) = tenant1;
    let (tenant2, bandwidth2) = tenant2;

    let t1_base_port = port_range.0;
    let t2_base_port = port_range.0 + (tenant1_pod_pairs as u16);

    if t2_base_port + tenant2_pod_pairs as u16 > port_range.1 {
        return Err(anyhow::anyhow!(
            "Not enough ports in the specified range for the number of pod pairs"
        ));
    }

    // Create multiple client pods for tenant1
    for i in 0..tenant1_pod_pairs {
        create_remote_client_pod(
            &tenant1,
            bandwidth1,
            duration_secs,
            i,
            server_ip,
            t1_base_port + (i as u16),
        )
        .await?;
    }

    // Create multiple client pods for tenant2
    for i in 0..tenant2_pod_pairs {
        create_remote_client_pod(
            &tenant2,
            bandwidth2,
            duration_secs,
            i,
            server_ip,
            t2_base_port + (i as u16),
        )
        .await?;
    }

    Ok(())
}

async fn create_remote_client_pod(
    tenant: &TenantClusterConfig,
    bandwidth: u32,
    duration_secs: u64,
    pair_index: u32,
    server_ip: &str,
    port: u16,
) -> Result<Pod> {
    let client_pod = benchmark_pod_manifest(
        bandwidth,
        duration_secs,
        Some(server_ip.to_string()),
        pair_index,
        Some(port),
    );
    let client_pod_name = client_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&client_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&client_pod_name, &tenant.namespace)
        .await?;

    Ok(client_pod)
}

async fn wait_for_remote_clients_completion(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<()> {
    // Wait for all client pods in tenant1 to complete
    for i in 0..tenant1_pod_pairs {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        // first check if is already terminated
        let status = tenant1
            .cluster
            .get_pod_in_namespace(&client_pod_name, &tenant1.namespace)
            .await?;

        if let Some(s) = status.status.as_ref() {
            if let Some(statuses) = s.container_statuses.as_ref() {
                if let Some(cs) = statuses.first() {
                    if let Some(state) = cs.state.as_ref() {
                        if let Some(term) = state.terminated.as_ref() {
                            if term.exit_code == 0 {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        tenant1
            .cluster
            .watch_pod_until_condition(
                &client_pod_name,
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
                            // check if is terminated with success
                            .map(|term| term.exit_code == 0)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                },
            )
            .await?;
    }

    for i in 0..tenant2_pod_pairs {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        // first check if is already terminated
        let status = tenant2
            .cluster
            .get_pod_in_namespace(&client_pod_name, &tenant2.namespace)
            .await?;

        if let Some(s) = status.status.as_ref() {
            if let Some(statuses) = s.container_statuses.as_ref() {
                if let Some(cs) = statuses.first() {
                    if let Some(state) = cs.state.as_ref() {
                        if let Some(term) = state.terminated.as_ref() {
                            if term.exit_code == 0 {
                                continue;
                            }
                        }
                    }
                }
            }
        }

        tenant2
            .cluster
            .watch_pod_until_condition(
                &client_pod_name,
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
                            // check if is terminated with success
                            .map(|term| term.exit_code == 0)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                },
            )
            .await?;
    }

    Ok(())
}

async fn cleanup_remote_client_pods(
    tenant: &TenantClusterConfig,
    pod_pairs_per_tenant: u32,
) -> Result<()> {
    // Delete all client pods (no server pods for remote scenario)
    for i in 0..pod_pairs_per_tenant {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        tenant
            .cluster
            .delete_pod_in_namespace(&client_pod_name, &tenant.namespace)
            .await?;
    }

    // Wait for all pods to be deleted
    for i in 0..pod_pairs_per_tenant {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        tenant
            .cluster
            .wait_for_pod_deletion(&client_pod_name, &tenant.namespace)
            .await?;
    }

    Ok(())
}

async fn create_benchmark_pod_pair(
    tenant: &TenantClusterConfig,
    bandwidth: u32,
    duration_secs: u64,
    pair_index: u32,
) -> Result<(Pod, Pod)> {
    let server_pod = benchmark_pod_manifest(bandwidth, duration_secs, None, pair_index, None);
    let server_pod_name = server_pod.metadata.name.clone().unwrap();

    tenant
        .cluster
        .create_pod_in_namespace(&server_pod, &tenant.namespace)
        .await?;

    tenant
        .cluster
        .wait_for_pod_to_be_ready(&server_pod_name, &tenant.namespace)
        .await?;

    // Ensure we obtain a non-empty pod IP (some CNI setups assign IP slightly after Ready).
    // Retry a few times with a short delay, and error out if still empty.
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
        return Err(anyhow::anyhow!(
            "server pod has no IP after waiting; avoid client falling back to loopback"
        ));
    }

    let client_pod =
        benchmark_pod_manifest(bandwidth, duration_secs, Some(server_ip), pair_index, None);
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
    // Wait for all client pods in tenant1 to complete
    for i in 0..tenant1_pod_pairs {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        // first check if is already terminated
        let status = tenant1
            .cluster
            .get_pod_in_namespace(&client_pod_name, &tenant1.namespace)
            .await?;

        if let Some(s) = status.status.as_ref() {
            if let Some(statuses) = s.container_statuses.as_ref() {
                if let Some(cs) = statuses.first() {
                    if let Some(state) = cs.state.as_ref() {
                        if let Some(term) = state.terminated.as_ref() {
                            if term.exit_code == 0 {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        tenant1
            .cluster
            .watch_pod_until_condition(
                &client_pod_name,
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
                            // check if is terminated with success
                            .map(|term| term.exit_code == 0)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                },
            )
            .await?;
    }

    // Wait for all client pods in tenant2 to complete
    for i in 0..tenant2_pod_pairs {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        // first check if is already terminated
        let status = tenant2
            .cluster
            .get_pod_in_namespace(&client_pod_name, &tenant2.namespace)
            .await?;

        if let Some(s) = status.status.as_ref() {
            if let Some(statuses) = s.container_statuses.as_ref() {
                if let Some(cs) = statuses.first() {
                    if let Some(state) = cs.state.as_ref() {
                        if let Some(term) = state.terminated.as_ref() {
                            if term.exit_code == 0 {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        tenant2
            .cluster
            .watch_pod_until_condition(
                &client_pod_name,
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
                            // check if is terminated with success
                            .map(|term| term.exit_code == 0)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                },
            )
            .await?;
    }

    // Wait for all server pods in tenant1 to complete
    for i in 0..tenant1_pod_pairs {
        let server_pod_name = format!("net-bench-pod-srv-{}", i);

        // first check if is already terminated
        let status = tenant1
            .cluster
            .get_pod_in_namespace(&server_pod_name, &tenant1.namespace)
            .await?;

        if let Some(s) = status.status.as_ref() {
            if let Some(statuses) = s.container_statuses.as_ref() {
                if let Some(cs) = statuses.first() {
                    if let Some(state) = cs.state.as_ref() {
                        if let Some(_term) = state.terminated.as_ref() {
                            continue;
                        }
                    }
                }
            }
        }

        tenant1
            .cluster
            .watch_pod_until_condition(
                &server_pod_name,
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
    }

    // Wait for all server pods in tenant2 to complete
    for i in 0..tenant2_pod_pairs {
        let server_pod_name = format!("net-bench-pod-srv-{}", i);

        // first check if is already terminated
        let status = tenant2
            .cluster
            .get_pod_in_namespace(&server_pod_name, &tenant2.namespace)
            .await?;

        if let Some(s) = status.status.as_ref() {
            if let Some(statuses) = s.container_statuses.as_ref() {
                if let Some(cs) = statuses.first() {
                    if let Some(state) = cs.state.as_ref() {
                        if let Some(_term) = state.terminated.as_ref() {
                            continue;
                        }
                    }
                }
            }
        }

        tenant2
            .cluster
            .watch_pod_until_condition(
                &server_pod_name,
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
    }

    Ok(())
}

async fn collect_fairness_test_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_pairs: u32,
    tenant2_pod_pairs: u32,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let mut tenant1_bandwidths = Vec::new();
    let mut tenant2_bandwidths = Vec::new();

    // Collect results from all client pods in tenant1
    for i in 0..tenant1_pod_pairs {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&client_pod_name, &tenant1.namespace)
            .await?;

        let bandwidth = parse_iperf3_bandwidth(&logs)?;
        tenant1_bandwidths.push(bandwidth);
    }

    // Collect results from all client pods in tenant2
    for i in 0..tenant2_pod_pairs {
        let client_pod_name = format!("net-bench-pod-cli-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&client_pod_name, &tenant2.namespace)
            .await?;

        let bandwidth = parse_iperf3_bandwidth(&logs)?;
        tenant2_bandwidths.push(bandwidth);
    }

    Ok((tenant1_bandwidths, tenant2_bandwidths))
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

async fn cleanup_pods(tenant: &TenantClusterConfig, pod_pairs_per_tenant: u32) -> Result<()> {
    // Delete all server and client pods
    for i in 0..pod_pairs_per_tenant {
        let server_pod_name = format!("net-bench-pod-srv-{}", i);
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        tenant
            .cluster
            .delete_pod_in_namespace(&server_pod_name, &tenant.namespace)
            .await?;
        tenant
            .cluster
            .delete_pod_in_namespace(&client_pod_name, &tenant.namespace)
            .await?;
    }

    // Wait for all pods to be deleted
    for i in 0..pod_pairs_per_tenant {
        let server_pod_name = format!("net-bench-pod-srv-{}", i);
        let client_pod_name = format!("net-bench-pod-cli-{}", i);

        tenant
            .cluster
            .wait_for_pod_deletion(&server_pod_name, &tenant.namespace)
            .await?;

        tenant
            .cluster
            .wait_for_pod_deletion(&client_pod_name, &tenant.namespace)
            .await?;
    }

    Ok(())
}
