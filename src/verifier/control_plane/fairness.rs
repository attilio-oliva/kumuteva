//! This module contains the implementation of the fairness test.
//!
//! The evaluation is based on the average delay of requests from each tenant towards the control plane.
//! Initially, the two tenants taken in consideration makes few requests at the same rate to measure
//! the base request delay.
//! Afterward, one tenats labeled as malicious starts making way more requests per seconds compared
//! to the other regular tenant.
//!
//! The test defines:
//! - **Scenario**: a set of sequential requests that are looped.
//! - **Initiator**: the one (thread) initiating the requests of a *Scenario*
//! - **InitiatorsPool**: a set of initiator with the same *Role*.
//! - **Role**: can either be *malicious* (making lots of requests) or *regular* (a normal amount)
//! - **Overseer**: the one (thread) aggregating the metrics from an *InitiatorsPool* and
//!   evaluating the stop conditions according to its *Role* for all the *InitiatorsPool*
//!

use std::fmt::Display;
use std::sync::OnceLock;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::verifier::TenantClusterConfig;
use anyhow::{Ok, Result};
use k8s_openapi::api::{apps::v1::Deployment, core::v1::ConfigMap};
use kube::{api::Patch, runtime::reflector::Lookup};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairnessTestConfig {
    pub regular_requesters: usize,
    pub malicious_requesters: usize,
    pub regular_request_rate: f64,
    pub malicious_request_rate: f64,
    pub baseline_test_duration: Duration,
    pub test_duration: Duration,
    pub metrics_send_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessTestResults {
    pub test_config: FairnessTestConfig,
    pub baseline_metrics: BaselineMetrics,
    pub regular_tenant_metrics: Vec<RequestMetrics>,
    pub malicious_tenant_metrics: Vec<RequestMetrics>,
    pub final_results: FinalResults,
    pub test_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalResults {
    pub regular_avg_latency_ms: f64,
    pub regular_relative_increase_percent: f64,
    pub regular_error_rate: f64,
    pub malicious_avg_latency_ms: f64,
    pub malicious_error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetrics {
    pub tenant1_avg_latency_ms: f64,
    pub tenant2_avg_latency_ms: f64,
    pub tenant1_error_rate: f64,
    pub tenant2_error_rate: f64,
}

impl Default for FairnessTestConfig {
    fn default() -> Self {
        // Helper function to parse environment variables with defaults
        fn parse_env_var<T: std::str::FromStr>(var_name: &str, default: T) -> T {
            std::env::var(var_name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        Self {
            regular_requesters: parse_env_var("REGULAR_REQUESTERS", 1),
            malicious_requesters: parse_env_var("MALICIOUS_REQUESTERS", 500),
            regular_request_rate: parse_env_var("REGULAR_REQUEST_RATE", 50.0),
            malicious_request_rate: parse_env_var("MALICIOUS_REQUEST_RATE", 5000.0),
            baseline_test_duration: Duration::from_secs(10),
            test_duration: Duration::from_secs(60),
            metrics_send_interval: Duration::from_secs(1),
        }
    }
}

static GLOBAL_TEST_START: OnceLock<Instant> = OnceLock::new();

fn get_global_timestamp() -> f64 {
    let test_start = GLOBAL_TEST_START.get_or_init(Instant::now);
    test_start.elapsed().as_secs_f64()
}

// Implement the check_fairness function
pub async fn check_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
    config: FairnessTestConfig,
) -> Result<FairnessTestResults> {
    // Initialize global start time at the beginning of the test
    GLOBAL_TEST_START.get_or_init(Instant::now);

    // Create scenarios with synthetic test values
    let regular_scenario = Arc::new(Scenario {
        requests: vec![
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Create,
            },
            Request {
                resource: ResourceKind::ConfigMap,
                operation: RequestOperation::Create,
            },
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Update,
            },
            Request {
                resource: ResourceKind::ConfigMap,
                operation: RequestOperation::Delete,
            },
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Delete,
            },
        ],
    });

    let malicious_scenario = Arc::new(Scenario {
        requests: vec![
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Create,
            },
            Request {
                resource: ResourceKind::ConfigMap,
                operation: RequestOperation::Create,
            },
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Update,
            },
            Request {
                resource: ResourceKind::ConfigMap,
                operation: RequestOperation::Delete,
            },
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Delete,
            },
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Create,
            },
            Request {
                resource: ResourceKind::Deployment,
                operation: RequestOperation::Delete,
            },
        ],
    });

    // Create initiator pools for both regular and malicious scenarios
    let regular_pool = InitiatorsPool {
        initiators: (0..config.regular_requesters)
            .map(|idx| Initiator {
                role: Role::Regular,
                scenario: Arc::clone(&regular_scenario),
                uid: format!("regular-initiator-{}", idx),
                request_metrics: vec![],
                metrics_send_interval: config.metrics_send_interval,
                request_rate: config.regular_request_rate, // Regular initiators make fewer requests
            })
            .collect(),
    };

    let malicious_pool = InitiatorsPool {
        initiators: (0..config.malicious_requesters)
            .map(|idx| Initiator {
                scenario: Arc::clone(&regular_scenario),
                // In case we want a different workload for malicious initiators,
                // scenario: Arc::clone(&malicious_scenario),
                role: Role::Malicious,
                uid: format!("malicious-initiator-{}", idx),
                request_metrics: vec![],
                metrics_send_interval: config.metrics_send_interval,
                request_rate: config.malicious_request_rate, // Malicious initiators make more requests
            })
            .collect(),
    };

    // print all the ids
    // for initiator in &malicious_pool.initiators {
    //     println!("Malicious initiator id: {}", initiator.uid);
    // }
    // for initiator in &regular_pool.initiators {
    //     println!("Regular initiator id: {}", initiator.uid);
    // }

    println!(
        "Regular initiators: {}, Malicious initiators: {}",
        config.regular_requesters, config.malicious_requesters
    );

    let malicious_overseer = Overseer::new(
        Role::Malicious, // The role is used to determine evaluation criteria
        malicious_pool,
    );

    // Create overseer to manage the test
    let regular_overseer = Overseer::new(
        Role::Regular, // The role is used to determine evaluation criteria
        regular_pool,
    );

    // Run the test for a specific duration
    let regular_t2_overseer = regular_overseer.clone();
    let baseline_result_t1 =
        regular_overseer.run(Arc::clone(&tenant1), config.baseline_test_duration);
    let baseline_result_t2 =
        regular_t2_overseer.run(Arc::clone(&tenant2), config.baseline_test_duration);

    // Wait for the test to finish
    let (baseline_test_t1, baseline_test_t2) =
        tokio::try_join!(baseline_result_t1, baseline_result_t2)?;

    let (baseline_metrics_t1, baseline_metrics_history_t1) = baseline_test_t1;
    let (baseline_metrics_t2, baseline_metrics_history_t2) = baseline_test_t2;

    // Export baseline data immediately after collection
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    save_baseline_csv_data(
        &baseline_metrics_history_t1,
        &baseline_metrics_history_t2,
        timestamp,
    )
    .await?;

    // cleanup(&tenant1).await?;
    // cleanup(&tenant2).await?;

    let baseline_avg_response_time_t1 = baseline_metrics_t1.average_duration;

    let regular_result_t1 = regular_overseer.run(Arc::clone(&tenant1), config.test_duration);
    let malicious_result_t2 = malicious_overseer.run(Arc::clone(&tenant2), config.test_duration);

    let (regular_test_t1, malicious_test_t2) =
        tokio::try_join!(regular_result_t1, malicious_result_t2)?;

    let (regular_result, regular_metrics_history) = regular_test_t1;
    let (malicious_result, malicious_metrics_history) = malicious_test_t2;

    let regular_avg_response_time_t1 = regular_result.average_duration;
    // how much did t1 response time increase from baseline
    let relative_increase_avg_response_time_t1 = (regular_avg_response_time_t1.as_secs_f64()
        - baseline_avg_response_time_t1.as_secs_f64())
        / baseline_avg_response_time_t1.as_secs_f64();
    let relative_multiplier_avg_response_time_t1 =
        regular_avg_response_time_t1.as_secs_f64() / baseline_avg_response_time_t1.as_secs_f64();

    println!(
        "Avg Response Time: Baseline {:.2?}, Unbalanced scenario {:.2?}, Relative Increase: {:.2}%, Relative Multiplier: {:.2}",
        baseline_avg_response_time_t1,
        regular_avg_response_time_t1,
        relative_increase_avg_response_time_t1 * 100.0,
        relative_multiplier_avg_response_time_t1
    );

    // Evaluate test success based on error rates
    let regular_error_rate = regular_result.error_rate;
    println!(
        "Regular tenant error rate: {:.2}% ({} errors out of {} requests)",
        regular_error_rate * 100.0,
        regular_result.error_count,
        regular_result.total_requests
    );
    // Malicious tenant error rate is not used in the fairness test, but can be logged
    let malicious_error_rate = malicious_result.error_rate;
    println!(
        "Malicious tenant error rate: {:.2}% ({} errors out of {} requests)",
        malicious_error_rate * 100.0,
        malicious_result.error_count,
        malicious_result.total_requests
    );

    // Test fails if regular tenant experiences significant errors
    let test_passed_error = regular_error_rate < 0.05; // Less than 5% errors allowed
    let test_passed_latency = relative_increase_avg_response_time_t1 < 2.0; // Less than 50% increase allowed
    let test_passed = test_passed_error && test_passed_latency;

    println!(
        "Fairness test result: {}",
        if test_passed {
            "PASSED"
        } else {
            "FAILED - Regular tenants experienced too many errors"
        }
    );

    let _ = cleanup(&tenant1).await;
    let _ = cleanup(&tenant2).await;

    // Prepare the final results
    let final_results = FinalResults {
        regular_avg_latency_ms: regular_avg_response_time_t1.as_millis() as f64,
        regular_relative_increase_percent: relative_increase_avg_response_time_t1 * 100.0,
        regular_error_rate,
        malicious_avg_latency_ms: malicious_result.average_duration.as_millis() as f64,
        malicious_error_rate,
    };

    // Prepare the baseline metrics
    let baseline_metrics = BaselineMetrics {
        tenant1_avg_latency_ms: baseline_avg_response_time_t1.as_millis() as f64,
        tenant2_avg_latency_ms: regular_avg_response_time_t1.as_millis() as f64,
        tenant1_error_rate: regular_result.error_rate,
        tenant2_error_rate: malicious_result.error_rate,
    };

    // Prepare the test results
    let test_results = FairnessTestResults {
        test_config: config,
        baseline_metrics,
        regular_tenant_metrics: regular_metrics_history,
        malicious_tenant_metrics: malicious_metrics_history,
        final_results,
        test_passed,
    };

    // Save the results to CSV files
    save_csv_data(&test_results, timestamp).await?;

    Ok(test_results)
}

async fn save_baseline_csv_data(
    tenant1_metrics: &[RequestMetrics],
    tenant2_metrics: &[RequestMetrics],
    timestamp: u64,
) -> Result<()> {
    use tokio::fs;

    let baseline_t1_filename = format!("fairness_baseline_tenant1_{}.csv", timestamp);
    let baseline_t2_filename = format!("fairness_baseline_tenant2_{}.csv", timestamp);

    let mut t1_csv_content =
        String::from("start_time,role,duration_ms,operation,resource,is_error\n");
    let mut t2_csv_content =
        String::from("start_time,role,duration_ms,operation,resource,is_error\n");

    for point in tenant1_metrics {
        t1_csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            point.start_time_seconds,
            point.initiator_role,
            point.duration.as_millis(),
            point.operation,
            point.request_type,
            point.is_error
        ));
    }

    for point in tenant2_metrics {
        t2_csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            point.start_time_seconds,
            point.initiator_role,
            point.duration.as_millis(),
            point.operation,
            point.request_type,
            point.is_error
        ));
    }

    fs::write(&baseline_t1_filename, t1_csv_content).await?;
    fs::write(&baseline_t2_filename, t2_csv_content).await?;

    println!("Baseline CSV data saved to: {}", baseline_t1_filename);
    println!("Baseline CSV data saved to: {}", baseline_t2_filename);

    // Also save baseline metadata
    let baseline_metadata_filename = format!("fairness_baseline_metadata_{}.json", timestamp);
    let baseline_t1_avg = AverageMetrics::calculate(tenant1_metrics);
    let baseline_t2_avg = AverageMetrics::calculate(tenant2_metrics);

    let baseline_metadata = serde_json::json!({
        "tenant1_metrics": {
            "avg_latency_ms": baseline_t1_avg.average_duration.as_millis(),
            "total_requests": baseline_t1_avg.total_requests,
            "error_rate": baseline_t1_avg.error_rate,
            "std_deviation_ms": baseline_t1_avg.std_deviation.as_millis()
        },
        "tenant2_metrics": {
            "avg_latency_ms": baseline_t2_avg.average_duration.as_millis(),
            "total_requests": baseline_t2_avg.total_requests,
            "error_rate": baseline_t2_avg.error_rate,
            "std_deviation_ms": baseline_t2_avg.std_deviation.as_millis()
        },
        "test_phase": "baseline"
    });

    fs::write(
        &baseline_metadata_filename,
        serde_json::to_string_pretty(&baseline_metadata)?,
    )
    .await?;
    println!("Baseline metadata saved to: {}", baseline_metadata_filename);

    Ok(())
}

async fn save_csv_data(results: &FairnessTestResults, timestamp: u64) -> Result<()> {
    use tokio::fs;

    let regular_filename = format!("fairness_test_data_regular_{}.csv", timestamp);
    let malicious_filename = format!("fairness_test_data_malicious_{}.csv", timestamp);
    let mut regular_csv_content =
        String::from("start_time,role,duration_ms,operation,resource,is_error\n");
    let mut malicious_csv_content =
        String::from("start_time,role,duration_ms,operation,resource,is_error\n");

    for point in &results.regular_tenant_metrics {
        regular_csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            point.start_time_seconds,
            point.initiator_role,
            point.duration.as_millis(),
            point.operation,
            point.request_type,
            point.is_error
        ));
    }

    for point in &results.malicious_tenant_metrics {
        malicious_csv_content.push_str(&format!(
            "{},{},{},{},{},{}\n",
            point.start_time_seconds,
            point.initiator_role,
            point.duration.as_millis(),
            point.operation,
            point.request_type,
            point.is_error
        ));
    }

    fs::write(&regular_filename, regular_csv_content).await?;
    fs::write(&malicious_filename, malicious_csv_content).await?;
    println!("CSV data saved to: {}", regular_filename);
    println!("CSV data saved to: {}", malicious_filename);

    // Also save metadata as JSON
    let metadata_filename = format!("fairness_test_metadata_{}.json", timestamp);
    let metadata = serde_json::json!({
        "test_config": results.test_config,
        "baseline_metrics": results.baseline_metrics,
        "final_results": results.final_results,
        "test_passed": results.test_passed
    });
    fs::write(&metadata_filename, serde_json::to_string_pretty(&metadata)?).await?;
    println!("Metadata saved to: {}", metadata_filename);

    Ok(())
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Role {
    Malicious,
    Regular,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Malicious => write!(f, "Malicious"),
            Role::Regular => write!(f, "Regular"),
        }
    }
}

#[derive(Clone)]
struct Initiator {
    scenario: Arc<Scenario>,
    role: Role,
    uid: String,
    request_metrics: Vec<RequestMetrics>,
    metrics_send_interval: Duration,
    request_rate: f64,
}

struct Scenario {
    requests: Vec<Request>,
}

struct Request {
    resource: ResourceKind,
    operation: RequestOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ResourceKind {
    ConfigMap,
    Deployment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum RequestOperation {
    Create,
    Update,
    Delete,
}
impl Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceKind::ConfigMap => write!(f, "ConfigMap"),
            ResourceKind::Deployment => write!(f, "Deployment"),
        }
    }
}

impl Display for RequestOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestOperation::Create => write!(f, "Create"),
            RequestOperation::Update => write!(f, "Update"),
            RequestOperation::Delete => write!(f, "Delete"),
        }
    }
}

#[derive(Clone)]
struct InitiatorsPool {
    initiators: Vec<Initiator>,
}

#[derive(Clone)]
struct Overseer {
    role: Role,
    pool: InitiatorsPool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetrics {
    request_type: ResourceKind,
    operation: RequestOperation,
    start_time_seconds: f64,
    duration: Duration,
    initiator_role: Role,
    is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AverageMetrics {
    start_time_seconds: f64,
    end_time_seconds: f64,
    request_type: ResourceKind,
    operation: RequestOperation,
    average_duration: Duration,
    std_deviation: Duration,
    total_duration: Duration,
    total_requests: usize,
    error_count: usize,
    error_rate: f64,
    initiator_role: Role,
}

impl AverageMetrics {
    fn calculate(requests: &[RequestMetrics]) -> Self {
        // Calculate average and standard deviation
        let total_duration: Duration = requests.iter().map(|m| m.duration).sum();
        let average_duration = total_duration / requests.len() as u32;

        // Calculate variance and std deviation (existing code)
        let variance = requests
            .iter()
            .map(|m| {
                let diff = m.duration.as_secs_f64() - average_duration.as_secs_f64();
                diff * diff
            })
            .sum::<f64>()
            / requests.len() as f64;
        let std_deviation = Duration::from_secs_f64(variance.sqrt());

        // Count errors
        let error_count = requests.iter().filter(|m| m.is_error).count();
        let error_rate = error_count as f64 / requests.len() as f64;

        Self {
            start_time_seconds: requests[0].start_time_seconds,
            end_time_seconds: requests.last().unwrap().start_time_seconds,
            request_type: requests[0].request_type.clone(),
            operation: requests[0].operation.clone(),
            average_duration,
            std_deviation,
            total_duration,
            total_requests: requests.len(),
            error_count,
            error_rate,
            initiator_role: requests[0].initiator_role,
        }
    }

    fn aggregate_averages(requests: &[AverageMetrics]) -> Self {
        let total_duration: Duration = requests.iter().map(|m| m.total_duration).sum();
        let total_requests: usize = requests.iter().map(|m| m.total_requests).sum();

        let average_duration = total_duration / total_requests as u32;
        // Calculate weighted variance using the formula:
        // weighted_var = sum(weight_i * (var_i + (mean_i - overall_mean)²)) / sum(weight_i)
        let weighted_variance = requests
            .iter()
            .map(|m| {
                let weight = m.total_requests as f64;
                let group_variance = m.std_deviation.as_secs_f64().powi(2); // Convert std_dev back to variance
                let mean_diff = m.average_duration.as_secs_f64() - average_duration.as_secs_f64();

                // This accounts for both within-group variance and between-group variance
                weight * (group_variance + mean_diff.powi(2))
            })
            .sum::<f64>()
            / total_requests as f64;

        // Convert variance back to std_deviation
        let std_deviation = Duration::from_secs_f64(weighted_variance.sqrt());

        // Count errors
        let error_count = requests.iter().map(|m| m.error_count).sum();
        let error_rate = error_count as f64 / total_requests as f64;

        // Use the first item's metadata for the aggregated metrics
        Self {
            start_time_seconds: requests[0].start_time_seconds,
            end_time_seconds: requests.last().unwrap().end_time_seconds,
            request_type: requests[0].request_type.clone(),
            operation: requests[0].operation.clone(),
            average_duration,
            std_deviation,
            total_duration,
            total_requests,
            initiator_role: requests[0].initiator_role,
            error_count,
            error_rate,
        }
    }
}

impl Overseer {
    fn new(role: Role, pool: InitiatorsPool) -> Self {
        Self { role, pool }
    }

    async fn run(
        &self,
        tenant_config: Arc<TenantClusterConfig>,
        duration: Duration,
    ) -> Result<(AverageMetrics, Vec<RequestMetrics>)> {
        // Create channel for metrics collection
        let (metrics_tx, mut metrics_rx) = mpsc::channel(5);

        // Create a completion channel to signal when all initiators are done
        let (completion_tx, mut completion_rx) = mpsc::channel::<()>(self.pool.initiators.len());
        let initiator_count = self.pool.initiators.len();

        // Spawn initiators according to the role
        let mut handles = self
            .pool
            .spawn_initiators(metrics_tx, completion_tx, tenant_config)
            .await;

        // Collect metrics for the specified duration
        let metrics_collector = tokio::spawn(async move {
            let mut tenant_metrics: HashMap<String, Vec<RequestMetrics>> = HashMap::new();
            let mut completed = 0;

            // Use a timeout to ensure we don't wait forever
            let collection_timeout = tokio::time::sleep(duration + Duration::from_secs(5));
            tokio::pin!(collection_timeout);

            loop {
                tokio::select! {
                    // Timeout case
                    _ = &mut collection_timeout => {
                        println!("Metrics collection timed out");
                        break;
                    }
                    // Receive metrics
                    maybe_metrics = metrics_rx.recv() => {
                        match maybe_metrics {
                            Some(metrics) => {
                                // println!("Collected metric from role: {}", metric.initiator_role);
                                tenant_metrics
                                    .entry(metrics.first().unwrap().initiator_role.to_string())
                                    .or_default()
                                    .extend(metrics);
                            }
                            None => {
                                println!("Metrics channel closed, ending collection");
                                break;
                            }
                        }
                    }
                    // Track completions
                    maybe_completion = completion_rx.recv() => {
                        match maybe_completion {
                            Some(_) => {
                                completed += 1;
                                // println!("Initiator completed: {}/{}", completed, initiator_count);
                                if completed >= initiator_count {
                                    println!("All initiators completed");
                                    break;
                                }
                            }
                            None => {
                                println!("Completion channel closed");
                                break;
                            }
                        }
                    }
                }
            }

            tenant_metrics
        });

        // Wait for the specified duration
        tokio::time::sleep(duration).await;
        println!("Test duration completed, stopping initiators...");

        // Stop all initiators
        for (_, stop_tx) in handles.drain(..) {
            let _ = stop_tx.send(());
        }

        // Wait for all initiators to finish
        for (handle, _) in handles {
            if let Err(e) = handle.await {
                eprintln!("Error waiting for initiator: {:?}", e);
            }
        }

        // Get collected metrics once all the initiators finish to send their last metrics
        let tenant_metrics = metrics_collector.await?;

        if !tenant_metrics.contains_key(&self.role.to_string()) {
            return Err(anyhow::anyhow!(
                "No metrics collected for role: {}",
                self.role
            ));
        }

        let average_metrics =
            AverageMetrics::calculate(tenant_metrics.get(&self.role.to_string()).unwrap());
        println!(
            "Role: {}, Requests: {}, Avg Duration: {:.2?}, Std Dev: {:.2?}",
            self.role,
            average_metrics.total_requests,
            average_metrics.average_duration,
            average_metrics.std_deviation
        );

        Ok((
            average_metrics,
            tenant_metrics.get(&self.role.to_string()).unwrap().to_vec(),
        ))
    }
}

impl Initiator {
    async fn run(
        mut self,
        scenario: Arc<Scenario>,
        metrics_tx: mpsc::Sender<Vec<RequestMetrics>>,
        mut stop_rx: broadcast::Receiver<()>,
        completion_tx: mpsc::Sender<()>,
        tenant_config: Arc<TenantClusterConfig>,
    ) {
        let mut update_overseer_interval = tokio::time::interval(self.metrics_send_interval);
        // Use a rate limiter to control request frequency
        let mut request_rate_interval =
            tokio::time::interval(Duration::from_secs_f64(1.0 / self.request_rate));
        let mut scenario_step = 0;
        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    // Send any pending metrics and signal completion.
                    self.send_final(&metrics_tx, &completion_tx).await;
                    break;
                }
                _ = update_overseer_interval.tick() => {
                    if !self.request_metrics.is_empty() {
                        //let avg = AverageMetrics::calculate(&self.request_metrics);
                        //if metrics_tx.send(avg).await.is_err() { break; }
                        if metrics_tx
                            .send(self.request_metrics.clone())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        self.request_metrics.clear();
                    }
                }
                _ = request_rate_interval.tick() => {
                    // Process the scenario requests at the defined rate
                    self.process_scenario_step(Arc::clone(&scenario), scenario_step, &tenant_config).await;
                    scenario_step = (scenario_step + 1) % scenario.requests.len();
                }
            }
        }
    }

    async fn send_final(
        &self,
        metrics_tx: &mpsc::Sender<Vec<RequestMetrics>>,
        completion_tx: &mpsc::Sender<()>,
    ) {
        if !self.request_metrics.is_empty() {
            // let avg = AverageMetrics::calculate(&self.request_metrics);
            // let _ = metrics_tx.send(avg).await;
            let _ = metrics_tx.send(self.request_metrics.clone()).await;
        }
        let _ = completion_tx.send(()).await;
    }

    async fn process_scenario_step(
        &mut self,
        scenario: Arc<Scenario>,
        step_index: usize,
        tenant_config: &Arc<TenantClusterConfig>,
    ) {
        if step_index >= scenario.requests.len() {
            eprintln!(
                "Step index {} out of bounds for scenario with {} requests",
                step_index,
                scenario.requests.len()
            );
            return;
        }

        let request = &scenario.requests[step_index];
        let start = Instant::now();
        let start_timestamp = get_global_timestamp();
        let result = request.send(tenant_config, self.uid.clone()).await;
        let duration = start.elapsed();

        let is_error = result.is_err();
        // if is_error {
        //     eprintln!(
        //         "Error in request from {:?} initiator {}: {:?}",
        //         self.role, self.uid, result
        //     );
        // }

        // println!(
        //     "Role: {}, Request: {:?} / {:?}, Duration: {:.2?}, Error: {}",
        //     self.role, request.resource, request.operation, duration, is_error
        // );

        self.request_metrics.push(RequestMetrics {
            request_type: request.resource.clone(),
            operation: request.operation.clone(),
            start_time_seconds: start_timestamp,
            duration,
            initiator_role: self.role,
            is_error,
        });
    }
}

impl InitiatorsPool {
    async fn spawn_initiators(
        &self,
        metrics_tx: mpsc::Sender<Vec<RequestMetrics>>,
        completion_tx: mpsc::Sender<()>,
        tenant_config: Arc<TenantClusterConfig>,
    ) -> Vec<(JoinHandle<()>, broadcast::Sender<()>)> {
        let mut handles = Vec::new();
        let (stop_tx, _) = broadcast::channel(1);

        for initiator in &self.initiators {
            let initiator_clone = initiator.clone();
            let scenario_clone = Arc::clone(&initiator.scenario);
            let metrics_tx_clone = metrics_tx.clone();
            let completion_tx_clone = completion_tx.clone();
            let tenant_config_clone = Arc::clone(&tenant_config);
            let stop_tx_clone = stop_tx.clone();
            let handle = tokio::spawn(async move {
                initiator_clone
                    .run(
                        scenario_clone,
                        metrics_tx_clone,
                        stop_tx_clone.subscribe(),
                        completion_tx_clone,
                        tenant_config_clone,
                    )
                    .await;
            });

            handles.push((handle, stop_tx.clone()));
        }

        handles
    }
}

async fn cleanup(tenant: &TenantClusterConfig) -> Result<()> {
    println!("Cleaning up resources in namespace: {}", tenant.namespace);
    // list all config maps in the namespace
    let config_maps = tenant
        .cluster
        .list_namespaced_resources::<ConfigMap>(&tenant.namespace)
        .await?;

    // if the config map starts with "fairness-test-config-", delete it
    for config_map in config_maps {
        if config_map
            .name()
            .unwrap()
            .starts_with("fairness-test-config-")
        {
            tenant
                .cluster
                .delete_resource_in_namespace::<ConfigMap>(
                    &config_map.name().unwrap(),
                    &tenant.namespace,
                )
                .await?;
        }
    }

    // list all deployments in the namespace
    let deployments = tenant
        .cluster
        .list_namespaced_resources::<Deployment>(&tenant.namespace)
        .await?;

    // if the deployment starts with "fairness-test-", delete it
    for deployment in deployments {
        // Check if the deployment name starts with "fairness-test-"
        if deployment.name().unwrap().starts_with("fairness-test-") {
            tenant
                .cluster
                .delete_resource_in_namespace::<Deployment>(
                    &deployment.name().unwrap(),
                    &tenant.namespace,
                )
                .await?;
        }
    }

    Ok(())
}

impl Request {
    pub async fn send(
        &self,
        tenant_config: &TenantClusterConfig,
        sender_uid: String,
    ) -> anyhow::Result<()> {
        let config_map: ConfigMap = serde_json::from_value(serde_json::json!(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": format!("fairness-test-config-{}", sender_uid),
                    "namespace": tenant_config.namespace,
                },
                "data": {
                    "key": "example-value",
                }
            }
        ))?;

        let deployment: Deployment = serde_json::from_value(serde_json::json!(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": format!("fairness-test-{}", sender_uid),
                    "namespace": tenant_config.namespace,
                },
                "spec": {
                    "replicas": 1,
                    "selector": {
                        "matchLabels": {
                            "app": "fairness-test"
                        }
                    },
                    "template": {
                        "metadata": {
                            "labels": {
                                "app": "fairness-test"
                            }
                        },
                        "spec": {
                            "containers": [
                                {
                                    "name": "fairness-test",
                                    "image": "nginx:latest",
                                }
                            ]
                        }
                    }
                }
            }
        ))?;

        match self.operation {
            RequestOperation::Create => match self.resource {
                ResourceKind::ConfigMap => {
                    tenant_config
                        .cluster
                        .create_namespaced_resource(&config_map, &tenant_config.namespace)
                        .await?;

                    // Wait for the config map to be created
                    tenant_config
                        .cluster
                        .wait_for_resource_creation::<ConfigMap>(
                            &config_map.name().unwrap(),
                            &tenant_config.namespace,
                        )
                        .await?;
                }
                ResourceKind::Deployment => {
                    tenant_config
                        .cluster
                        .create_namespaced_resource(&deployment, &tenant_config.namespace)
                        .await?;

                    // Wait for the deployment to be created
                    tenant_config
                        .cluster
                        .wait_for_resource_creation::<Deployment>(
                            &deployment.name().unwrap(),
                            &tenant_config.namespace,
                        )
                        .await?;

                    // tenant_config
                    //     .cluster
                    //     .watch_namespaced_resource_until_condition::<Deployment, _, _>(
                    //         &deployment.name().unwrap(),
                    //         &tenant_config.namespace,
                    //         3,
                    //         |_event| async {
                    //             let deployment = tenant_config
                    //                 .cluster
                    //                 .get_resource_in_namespace::<Deployment>(
                    //                     &deployment.name().unwrap(),
                    //                     &tenant_config.namespace,
                    //                 )
                    //                 .await
                    //                 .unwrap();

                    //             let desired_replicas =
                    //                 deployment.spec.as_ref().unwrap().replicas.unwrap_or(1);

                    //             let available_replicas = deployment
                    //                 .status
                    //                 .as_ref()
                    //                 .unwrap()
                    //                 .available_replicas
                    //                 .unwrap_or(0);
                    //             available_replicas == desired_replicas
                    //         },
                    //     )
                    //     .await?;
                }
            },
            RequestOperation::Delete => match self.resource {
                ResourceKind::ConfigMap => {
                    tenant_config
                        .cluster
                        .delete_resource_in_namespace::<ConfigMap>(
                            &config_map.name().unwrap(),
                            &tenant_config.namespace,
                        )
                        .await?;

                    // tenant_config
                    //     .cluster
                    //     .wait_namespaced_resource_deletion::<ConfigMap>(
                    //         &config_map.name().unwrap(),
                    //         &tenant_config.namespace,
                    //     )
                    //     .await?;
                }
                ResourceKind::Deployment => {
                    tenant_config
                        .cluster
                        .delete_resource_in_namespace::<Deployment>(
                            &deployment.name().unwrap(),
                            &tenant_config.namespace,
                        )
                        .await?;

                    // tenant_config
                    //     .cluster
                    //     .wait_namespaced_resource_deletion::<Deployment>(
                    //         &deployment.name().unwrap(),
                    //         &tenant_config.namespace,
                    //     )
                    //     .await?;
                }
            },
            RequestOperation::Update => match self.resource {
                ResourceKind::ConfigMap => {
                    let random_value = rand::random::<u32>();
                    let patch_data = Patch::Merge(json!({
                        "data": {
                            "key": format!("example-value-{}", random_value),
                        }
                    }));

                    tenant_config
                        .cluster
                        .patch_namespaced_resource::<ConfigMap, _>(
                            &config_map.name().unwrap(),
                            &tenant_config.namespace,
                            &patch_data,
                        )
                        .await?;
                }
                ResourceKind::Deployment => {
                    let replicas = tenant_config
                        .cluster
                        .get_resource_in_namespace::<Deployment>(
                            &deployment.name().unwrap(),
                            &tenant_config.namespace,
                        )
                        .await?
                        .spec
                        .as_ref()
                        .unwrap()
                        .replicas
                        .unwrap_or(1);

                    let patch_data = Patch::Merge(json!({
                        "spec": {
                            "replicas": replicas + 1,
                        }
                    }));
                    tenant_config
                        .cluster
                        .patch_namespaced_resource::<Deployment, _>(
                            &deployment.name().unwrap(),
                            &tenant_config.namespace,
                            &patch_data,
                        )
                        .await?;
                }
            },
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::cluster::KubernetesClient;

    use super::*;

    #[tokio::test]
    async fn test_check_fairness() {
        let tenant1 = Arc::new(TenantClusterConfig {
            namespace: "tenant1".to_string(),
            cluster: KubernetesClient::infer().await.unwrap(),
        });
        let tenant2 = Arc::new(TenantClusterConfig {
            namespace: "tenant2".to_string(),
            cluster: KubernetesClient::infer().await.unwrap(),
        });

        let result = check_fairness(tenant1, tenant2, FairnessTestConfig::default()).await;
        assert!(result.is_ok());
    }
}
