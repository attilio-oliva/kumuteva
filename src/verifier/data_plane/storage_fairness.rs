use std::sync::Arc;

use crate::verifier::TenantClusterConfig;
use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;
use std::fmt::Display;

/// Storage fairness checks for disk I/O resources between tenants
/// The idea is to start pods in both tenants that perform intensive disk I/O operations
/// We then measure the throughput achieved by each tenant and check that they are fairly distributed

/// To check whether the storage bandwidth is fairly distributed we redo the test with tenant1 having
/// considerably more pods performing I/O and observe the changes in the achieved throughput for both tenants.

/// Generic test configuration that can be reused for different test cases
#[derive(Clone, Debug)]
pub struct StorageTestCaseConfig {
    /// Duration of each storage test in seconds
    pub test_duration_secs: u64,
    /// I/O block size in KB for tenant1
    pub tenant1_block_size_kb: u32,
    /// I/O block size in KB for tenant2
    pub tenant2_block_size_kb: u32,
    /// Number of I/O pods for tenant1
    pub tenant1_pod_count: u32,
    /// Number of I/O pods for tenant2
    pub tenant2_pod_count: u32,
    /// File size to write/read in MB
    pub file_size_mb: u32,
}

impl Default for StorageTestCaseConfig {
    fn default() -> Self {
        StorageTestCaseConfig {
            test_duration_secs: 60,
            tenant1_block_size_kb: 1024,
            tenant2_block_size_kb: 1024,
            tenant1_pod_count: 1,
            tenant2_pod_count: 1,
            file_size_mb: 100,
        }
    }
}

/// Test scenario defines how to conduct storage fairness tests
#[derive(Clone, Debug)]
pub enum StorageTestScenario {
    /// Sequential read/write testing with dd commands
    SequentialIO,
    /// Random I/O testing with fio
    RandomIO,
}

impl StorageTestScenario {
    pub fn name(&self) -> &'static str {
        match self {
            StorageTestScenario::SequentialIO => "sequential-io",
            StorageTestScenario::RandomIO => "random-io",
        }
    }
}

/// Storage fairness test configuration combining scenario and test cases
#[derive(Clone, Debug)]
pub struct StorageFairnessTestConfig {
    /// The test scenario to execute
    pub scenario: StorageTestScenario,
    /// Configuration for the regular test case (both tenants equal)
    pub regular_test: StorageTestCaseConfig,
    /// Configuration for the unbalanced test case (tenant1 boosted)
    pub unbalanced_test: StorageTestCaseConfig,
    /// Acceptable deviation percentage for fairness check
    pub acceptable_deviation_percent: f64,
}

impl Default for StorageFairnessTestConfig {
    fn default() -> Self {
        let regular_test = StorageTestCaseConfig {
            test_duration_secs: 60,
            tenant1_block_size_kb: 1024,
            tenant2_block_size_kb: 1024,
            tenant1_pod_count: 1,
            tenant2_pod_count: 1,
            file_size_mb: 100,
        };

        let unbalanced_test = StorageTestCaseConfig {
            test_duration_secs: 60,
            tenant1_block_size_kb: 1024,
            tenant2_block_size_kb: 1024,
            tenant1_pod_count: 5,
            tenant2_pod_count: 1,
            file_size_mb: 100,
        };

        StorageFairnessTestConfig {
            scenario: StorageTestScenario::RandomIO,
            regular_test,
            unbalanced_test,
            acceptable_deviation_percent: 20.0,
        }
    }
}

impl StorageFairnessTestConfig {
    /// Create a new configuration with custom regular and unbalanced test cases
    pub fn new(
        scenario: StorageTestScenario,
        regular_test: StorageTestCaseConfig,
        unbalanced_test: StorageTestCaseConfig,
        acceptable_deviation_percent: f64,
    ) -> Self {
        StorageFairnessTestConfig {
            scenario,
            regular_test,
            unbalanced_test,
            acceptable_deviation_percent,
        }
    }

    /// Create a balanced test configuration where both test cases are identical
    pub fn balanced(
        scenario: StorageTestScenario,
        test_case: StorageTestCaseConfig,
        acceptable_deviation_percent: f64,
    ) -> Self {
        StorageFairnessTestConfig {
            scenario,
            regular_test: test_case.clone(),
            unbalanced_test: test_case,
            acceptable_deviation_percent,
        }
    }

    /// Create a simple configuration with just pod count differences
    pub fn simple_pod_count_test(
        scenario: StorageTestScenario,
        regular_pod_count: u32,
        boosted_pod_count: u32,
        duration_secs: u64,
        acceptable_deviation_percent: f64,
    ) -> Self {
        let regular_test = StorageTestCaseConfig {
            test_duration_secs: duration_secs,
            tenant1_block_size_kb: 1024,
            tenant2_block_size_kb: 1024,
            tenant1_pod_count: regular_pod_count,
            tenant2_pod_count: regular_pod_count,
            file_size_mb: 100,
        };

        let unbalanced_test = StorageTestCaseConfig {
            test_duration_secs: duration_secs,
            tenant1_block_size_kb: 1024,
            tenant2_block_size_kb: 1024,
            tenant1_pod_count: boosted_pod_count,
            tenant2_pod_count: regular_pod_count,
            file_size_mb: 100,
        };

        StorageFairnessTestConfig {
            scenario,
            regular_test,
            unbalanced_test,
            acceptable_deviation_percent,
        }
    }
}

pub struct StorageFairnessTestResults {
    pub regular_throughputs: (Vec<f64>, Vec<f64>),
    pub unequal_throughputs: (Vec<f64>, Vec<f64>),
    pub acceptable_deviation_percent: f64,
    pub fairness_passed: bool,
}

impl StorageFairnessTestResults {
    pub fn analyze(
        regular: (Vec<f64>, Vec<f64>),
        unequal: (Vec<f64>, Vec<f64>),
        acceptable_deviation_percent: f64,
    ) -> StorageFairnessTestResults {
        let (reg1, reg2) = &regular;
        let (uneq1, uneq2) = &unequal;

        // Calculate average throughput for each tenant
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

        // Fairness check: tenant2 should not be significantly affected by tenant1's increased load
        let fairness_passed = t2_diff <= acceptable_deviation_percent;

        StorageFairnessTestResults {
            regular_throughputs: regular,
            unequal_throughputs: unequal,
            acceptable_deviation_percent,
            fairness_passed,
        }
    }
}

pub fn storage_benchmark_pod_manifest(
    scenario: &StorageTestScenario,
    block_size_kb: u32,
    duration_secs: u64,
    file_size_mb: u32,
    pod_index: u32,
) -> Pod {
    let pod_name = format!("storage-bench-pod-{}", pod_index);

    let command = match scenario {
        StorageTestScenario::SequentialIO => {
            vec![
    "sh".to_string(),
    "-c".to_string(),
    format!(
        "apk add --no-cache bc fio && \
         echo 'Starting storage benchmark...' && \
         echo 'Writing {file_size_mb}MB file with {block_size_kb}KB blocks...' && \
         start_time=$(date +%s.%N) && \
         dd if=/dev/zero of=/data/testfile bs={block_size_kb}K count={} oflag=sync 2>&1 | tee /tmp/dd_write.log && \
         write_throughput=$(tail -1 /tmp/dd_write.log | awk '{{for(i=1;i<=NF;i++) if($i~/MB\\/s/) print $(i-1)}}') && \
         echo \"$write_throughput\" > /data/write_result.txt && \
         echo 'Reading file back...' && \
         dd if=/data/testfile of=/dev/null bs={block_size_kb}K 2>&1 | tee /tmp/dd_read.log && \
         read_throughput=$(tail -1 /tmp/dd_read.log | awk '{{for(i=1;i<=NF;i++) if($i~/MB\\/s/) print $(i-1)}}') && \
         echo \"$read_throughput\" > /data/read_result.txt && \
         end_time=$(date +%s.%N) && \
         echo \"Total time: $(echo \"$end_time - $start_time\" | bc)s\" && \
         echo 'Benchmark completed. Results:' && \
         echo \"Write: $(cat /data/write_result.txt) MB/s\" && \
         echo \"Read: $(cat /data/read_result.txt) MB/s\" && \
         sleep 10",
        file_size_mb * 1024 / block_size_kb,
    )
]
        }
        StorageTestScenario::RandomIO => {
            vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "apk add --no-cache bc fio && \
             echo 'Starting random I/O benchmark with fio...' && \
             echo 'FIO version:' && fio --version && \
             echo 'Creating test directory...' && \
             mkdir -p /data && \
             echo 'Starting FIO benchmark...' && \
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
             echo 'Raw FIO output:' && \
             cat /data/fio_result.json && \
             echo 'Extracting bandwidth...' && \
             grep -o '\"bw\"[[:space:]]*:[[:space:]]*[0-9]*' /data/fio_result.json | head -1 | grep -o '[0-9]*' > /data/bandwidth.txt && \
             echo 'Bandwidth result:' && \
             cat /data/bandwidth.txt && \
             sleep 10"
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
                    // Remove the args field entirely
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

pub async fn check_storage_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: StorageFairnessTestConfig,
) -> Result<StorageFairnessTestResults> {
    match config.scenario {
        StorageTestScenario::SequentialIO | StorageTestScenario::RandomIO => {
            check_storage_io_fairness(tenant1, tenant2, config).await
        }
    }
}

async fn check_storage_io_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: StorageFairnessTestConfig,
) -> Result<StorageFairnessTestResults> {
    // Execute regular test case
    let regular_results = execute_storage_test_case(
        tenant1.clone(),
        tenant2.clone(),
        &config.regular_test,
        &config.scenario,
    )
    .await?;

    // Execute unbalanced test case
    let unbalanced_results = execute_storage_test_case(
        tenant1.clone(),
        tenant2.clone(),
        &config.unbalanced_test,
        &config.scenario,
    )
    .await?;

    Ok(StorageFairnessTestResults::analyze(
        regular_results,
        unbalanced_results,
        config.acceptable_deviation_percent,
    ))
}

async fn execute_storage_test_case(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    test_config: &StorageTestCaseConfig,
    scenario: &StorageTestScenario,
) -> Result<(Vec<f64>, Vec<f64>)> {
    create_storage_benchmark_pods(
        (tenant1.clone(), test_config.tenant1_block_size_kb),
        (tenant2.clone(), test_config.tenant2_block_size_kb),
        test_config.test_duration_secs,
        test_config.tenant1_pod_count,
        test_config.tenant2_pod_count,
        test_config.file_size_mb,
        scenario,
    )
    .await?;

    wait_for_storage_pods_completion(
        &tenant1,
        &tenant2,
        test_config.tenant1_pod_count,
        test_config.tenant2_pod_count,
    )
    .await?;

    let results = collect_storage_test_results(
        &tenant1,
        &tenant2,
        test_config.tenant1_pod_count,
        test_config.tenant2_pod_count,
        scenario,
    )
    .await?;

    // Clean up pods after collecting results
    cleanup_storage_pods(&tenant1, test_config.tenant1_pod_count).await?;
    cleanup_storage_pods(&tenant2, test_config.tenant2_pod_count).await?;

    Ok(results)
}

async fn create_storage_benchmark_pods(
    tenant1: (Arc<TenantClusterConfig>, u32),
    tenant2: (Arc<TenantClusterConfig>, u32),
    duration_secs: u64,
    tenant1_pod_count: u32,
    tenant2_pod_count: u32,
    file_size_mb: u32,
    scenario: &StorageTestScenario,
) -> Result<()> {
    let (tenant1, block_size1) = tenant1;
    let (tenant2, block_size2) = tenant2;

    // Create multiple pods for tenant1
    for i in 0..tenant1_pod_count {
        create_storage_benchmark_pod(
            &tenant1,
            block_size1,
            duration_secs,
            file_size_mb,
            i,
            scenario,
        )
        .await?;
    }

    // Create multiple pods for tenant2
    for i in 0..tenant2_pod_count {
        create_storage_benchmark_pod(
            &tenant2,
            block_size2,
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
    tenant1_pod_count: u32,
    tenant2_pod_count: u32,
) -> Result<()> {
    // Wait for all pods in tenant1 to complete
    for i in 0..tenant1_pod_count {
        let pod_name = format!("storage-bench-pod-{}", i);

        // Check if already terminated
        let status = tenant1
            .cluster
            .get_pod_in_namespace(&pod_name, &tenant1.namespace)
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
            .watch_pod_until_condition(&pod_name, &tenant1.namespace, |status_event| async move {
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
    }

    // Wait for all pods in tenant2 to complete
    for i in 0..tenant2_pod_count {
        let pod_name = format!("storage-bench-pod-{}", i);

        // Check if already terminated
        let status = tenant2
            .cluster
            .get_pod_in_namespace(&pod_name, &tenant2.namespace)
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
            .watch_pod_until_condition(&pod_name, &tenant2.namespace, |status_event| async move {
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
    }

    Ok(())
}

async fn collect_storage_test_results(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    tenant1_pod_count: u32,
    tenant2_pod_count: u32,
    scenario: &StorageTestScenario,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let mut tenant1_throughputs = Vec::new();
    let mut tenant2_throughputs = Vec::new();

    // Collect results from all pods in tenant1
    for i in 0..tenant1_pod_count {
        let pod_name = format!("storage-bench-pod-{}", i);
        let logs = tenant1
            .cluster
            .get_pod_logs(&pod_name, &tenant1.namespace)
            .await?;

        let throughput = parse_storage_benchmark_logs(&logs, scenario)?;
        tenant1_throughputs.push(throughput);
    }

    // Collect results from all pods in tenant2
    for i in 0..tenant2_pod_count {
        let pod_name = format!("storage-bench-pod-{}", i);
        let logs = tenant2
            .cluster
            .get_pod_logs(&pod_name, &tenant2.namespace)
            .await?;

        let throughput = parse_storage_benchmark_logs(&logs, scenario)?;
        tenant2_throughputs.push(throughput);
    }

    Ok((tenant1_throughputs, tenant2_throughputs))
}

fn parse_storage_benchmark_logs(logs: &str, scenario: &StorageTestScenario) -> Result<f64> {
    match scenario {
        StorageTestScenario::SequentialIO => {
            // Parse dd output for throughput (MB/s)
            for line in logs.lines().rev() {
                if line.contains("MB/s") {
                    // Extract the throughput value
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if part.contains("MB/s") && i > 0 {
                            let throughput_str = parts[i - 1];
                            if let Ok(throughput) = throughput_str.parse::<f64>() {
                                return Ok(throughput);
                            }
                        }
                    }
                }
                // Also look for "Write:" or "Read:" patterns
                if line.starts_with("Write:") || line.starts_with("Read:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(throughput) = parts[1].parse::<f64>() {
                            return Ok(throughput);
                        }
                    }
                }
            }
        }
        StorageTestScenario::RandomIO => {
            // First check for our extracted bandwidth file
            for line in logs.lines() {
                if line.starts_with("Bandwidth result:") {
                    // Next line should contain the bandwidth
                    continue;
                }
                // Try to parse the line after "Bandwidth result:"
                if logs.contains("Bandwidth result:") {
                    let lines: Vec<&str> = logs.lines().collect();
                    for (i, line) in lines.iter().enumerate() {
                        if line.contains("Bandwidth result:") && i + 1 < lines.len() {
                            if let Ok(bw_kb) = lines[i + 1].trim().parse::<f64>() {
                                // Convert KB/s to MB/s
                                return Ok(bw_kb / 1024.0);
                            }
                        }
                    }
                }
            }

            // Fallback: Parse FIO JSON output directly
            let json_start = logs.find('{');
            let json_end = logs.rfind('}');

            if let (Some(start), Some(end)) = (json_start, json_end) {
                let json_str = &logs[start..=end];
                if let Ok(fio_result) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(jobs) = fio_result["jobs"].as_array() {
                        if let Some(job) = jobs.first() {
                            // Try read bandwidth first, then write bandwidth
                            if let Some(read_bw) = job["read"]["bw"].as_f64() {
                                if read_bw > 0.0 {
                                    return Ok(read_bw / 1024.0); // Convert KB/s to MB/s
                                }
                            }
                            if let Some(write_bw) = job["write"]["bw"].as_f64() {
                                if write_bw > 0.0 {
                                    return Ok(write_bw / 1024.0); // Convert KB/s to MB/s
                                }
                            }
                            // Try mixed workload bandwidth
                            if let Some(mixed_bw) = job["mixed"]["bw"].as_f64() {
                                if mixed_bw > 0.0 {
                                    return Ok(mixed_bw / 1024.0);
                                }
                            }
                        }
                    }
                }
            }

            // Last fallback: look for any bandwidth values in the output
            for line in logs.lines() {
                if line.contains("bw=") && line.contains("KB/s") {
                    if let Some(bw_start) = line.find("bw=") {
                        let bw_part = &line[bw_start + 3..];
                        if let Some(kb_pos) = bw_part.find("KB/s") {
                            let bw_str = &bw_part[..kb_pos];
                            if let Ok(bw) = bw_str.parse::<f64>() {
                                return Ok(bw / 1024.0); // Convert KB/s to MB/s
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Could not find throughput information in logs for scenario: {:?}\nLogs sample:\n{}",
        scenario,
        logs.lines().take(10).collect::<Vec<_>>().join("\n")
    ))
}

async fn cleanup_storage_pods(tenant: &TenantClusterConfig, pod_count: u32) -> Result<()> {
    // Delete all storage benchmark pods
    for i in 0..pod_count {
        let pod_name = format!("storage-bench-pod-{}", i);

        tenant
            .cluster
            .delete_pod_in_namespace(&pod_name, &tenant.namespace)
            .await?;
    }

    // Wait for all pods to be deleted
    for i in 0..pod_count {
        let pod_name = format!("storage-bench-pod-{}", i);

        tenant
            .cluster
            .wait_for_pod_deletion(&pod_name, &tenant.namespace)
            .await?;
    }

    Ok(())
}

impl Display for StorageFairnessTestResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Storage Fairness Test Results:")?;
        writeln!(
            f,
            "Regular Test - Tenant1 Throughputs (MB/s): {:?}",
            self.regular_throughputs.0
        )?;
        writeln!(
            f,
            "Regular Test - Tenant2 Throughputs (MB/s): {:?}",
            self.regular_throughputs.1
        )?;
        writeln!(
            f,
            "Unbalanced Test - Tenant1 Throughputs (MB/s): {:?}",
            self.unequal_throughputs.0
        )?;
        writeln!(
            f,
            "Unbalanced Test - Tenant2 Throughputs (MB/s): {:?}",
            self.unequal_throughputs.1
        )?;
        writeln!(
            f,
            "Acceptable Deviation Percent: {}%",
            self.acceptable_deviation_percent
        )?;
        writeln!(
            f,
            "Fairness Check Passed: {}",
            if self.fairness_passed { "Yes" } else { "No" }
        )
    }
}
