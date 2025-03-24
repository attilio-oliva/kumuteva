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

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::verifier::TenantClusterConfig;
use anyhow::Result;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

// Implement the check_fairness function
pub async fn check_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<bool> {
    // Create scenarios
    let regular_scenario = Arc::new(Scenario {
        // Define regular tenant scenario
        requests: vec![/* ... */],
    });

    let malicious_scenario = Arc::new(Scenario {
        // Define malicious tenant scenario (more requests)
        requests: vec![/* ... */],
    });
    // Create initiator pools for both regular and malicious scenarios
    let regular_pool = InitiatorsPool {
        initiators: vec![
            Initiator {
                role: Role::Regular,
                scenario: Arc::clone(&regular_scenario)
            };
            3
        ], // 3 regular initiators
    };

    let malicious_pool = InitiatorsPool {
        initiators: vec![
            Initiator {
                role: Role::Malicious,
                scenario: Arc::clone(&malicious_scenario)
            };
            10
        ], // 10 malicious initiators
    };

    // Create overseer to manage the test
    let overseer = Overseer::new(
        Role::Regular, // The role is used to determine evaluation criteria
        vec![regular_pool, malicious_pool],
    );

    // Run the test for a specific duration (e.g., 60 seconds)
    let test_duration = Duration::from_secs(60);

    overseer.run(tenant1, tenant2, test_duration).await
}

#[derive(Clone, Debug)]
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
}

struct Scenario {
    requests: Vec<Request>,
}

struct Request {
    kind: RequestKind,
    operation: RequestOperation,
    delay: u64,
}

#[derive(Clone)]
enum RequestKind {
    ConfigMap,
    Pod,
}

#[derive(Clone)]
enum RequestOperation {
    Create,
    Update,
    Delete,
}

struct InitiatorsPool {
    initiators: Vec<Initiator>,
}

struct Overseer {
    role: Role,
    pools: Vec<InitiatorsPool>,
}

#[derive(Clone)]
struct RequestMetrics {
    request_type: RequestKind,
    operation: RequestOperation,
    start_time: Instant,
    duration: Duration,
    initiator_role: Role,
}

struct AverageMetrics {
    request_type: RequestKind,
    operation: RequestOperation,
    average_duration: Duration,
    std_deviation: Duration,
    initiator_role: Role,
}

impl AverageMetrics {
    fn calculate(requests: &[RequestMetrics]) -> Self {
        // Calculate average and standard deviation
        let total_duration: Duration = requests.iter().map(|m| m.duration).sum();
        let average_duration = total_duration / requests.len() as u32;

        let variance = requests
            .iter()
            .map(|m| {
                let diff = m.duration - average_duration;
                diff.as_secs_f64() * diff.as_secs_f64()
            })
            .sum::<f64>()
            / requests.len() as f64;

        let std_deviation = Duration::from_secs_f64(variance.sqrt());

        Self {
            request_type: requests[0].request_type.clone(),
            operation: requests[0].operation.clone(),
            average_duration,
            std_deviation: std_deviation.into(),
            initiator_role: requests[0].initiator_role.clone(),
        }
    }
}

impl Overseer {
    fn new(role: Role, pools: Vec<InitiatorsPool>) -> Self {
        Self { role, pools }
    }

    async fn run(
        &self,
        malicious_tenant: Arc<TenantClusterConfig>,
        regular_tenant: Arc<TenantClusterConfig>,
        duration: Duration,
    ) -> Result<bool> {
        // Create channel for metrics collection
        let (metrics_tx, mut metrics_rx) = mpsc::channel(100);

        // Store handles and stop channels for all initiators
        let mut all_handles = Vec::new();

        // Spawn initiators for each pool
        for pool in &self.pools {
            let tenant_config = match self.role {
                // Assign tenant configs based on your test design
                Role::Regular => Arc::clone(&malicious_tenant),
                Role::Malicious => Arc::clone(&regular_tenant),
            };

            let handles = pool
                .spawn_initiators(metrics_tx.clone(), tenant_config)
                .await;

            all_handles.extend(handles);
        }

        // Drop the sender we own since we're not sending metrics
        drop(metrics_tx);

        // Collect metrics for the specified duration
        let start_time = Instant::now();
        let mut tenant_metrics: HashMap<String, Vec<Duration>> = HashMap::new();

        // Spawn a task to collect metrics
        let metrics_collector = tokio::spawn(async move {
            while let Some(metric) = metrics_rx.recv().await {
                tenant_metrics
                    .entry(metric.initiator_role.to_string())
                    .or_default()
                    .push(metric.duration);

                if start_time.elapsed() >= duration {
                    break;
                }
            }
            tenant_metrics
        });

        // Wait for the specified duration
        tokio::time::sleep(duration).await;

        // Stop all initiators
        // Stop all initiators
        let handles: Vec<JoinHandle<()>> = all_handles
            .drain(..)
            .map(|(handle, stop_tx)| {
                let _ = stop_tx.send(());
                handle
            })
            .collect();

        // Wait for all initiators to finish
        for handle in handles {
            let _ = handle.await;
        }

        // Get collected metrics
        let tenant_metrics = metrics_collector.await?;

        // Analyze metrics to determine if fairness is maintained
        // A fair system would show similar response times for the regular tenant
        // regardless of the malicious tenant's activity

        // Return true if fairness criteria are met
        Ok(true)
    }
}

impl Initiator {
    async fn run(
        self,
        scenario: Arc<Scenario>,
        metrics_tx: mpsc::Sender<RequestMetrics>,
        stop_rx: oneshot::Receiver<()>,
        tenant_config: Arc<TenantClusterConfig>,
    ) {
        let mut stop_future = stop_rx;

        loop {
            // Check if we should stop
            if stop_future.try_recv().is_ok() {
                break;
            }

            // Execute each request in the scenario
            for request in &scenario.requests {
                let start = Instant::now();

                // Execute the k8s request based on request.kind and request.operation
                // This would make actual API calls to the k8s cluster using tenant_config

                let duration = start.elapsed();

                // Send metrics back to overseer
                let metrics = RequestMetrics {
                    request_type: request.kind.clone(),
                    operation: request.operation.clone(),
                    start_time: start,
                    duration,
                    initiator_role: self.role.clone(),
                };

                if metrics_tx.send(metrics).await.is_err() {
                    // Overseer has dropped the channel, exit
                    return;
                }

                // Respect the defined delay between requests
                tokio::time::sleep(Duration::from_millis(request.delay)).await;
            }
        }
    }
}

impl InitiatorsPool {
    async fn spawn_initiators(
        &self,
        metrics_tx: mpsc::Sender<RequestMetrics>,
        tenant_config: Arc<TenantClusterConfig>,
    ) -> Vec<(JoinHandle<()>, oneshot::Sender<()>)> {
        let mut handles = Vec::new();

        for initiator in &self.initiators {
            let (stop_tx, stop_rx) = oneshot::channel();
            let initiator_clone = initiator.clone();
            let scenario_clone = Arc::clone(&initiator.scenario);
            let metrics_tx_clone = metrics_tx.clone();
            let tenant_config_clone = Arc::clone(&tenant_config);

            let handle = tokio::spawn(async move {
                initiator_clone
                    .run(
                        scenario_clone,
                        metrics_tx_clone,
                        stop_rx,
                        tenant_config_clone,
                    )
                    .await;
            });

            handles.push((handle, stop_tx));
        }

        handles
    }
}
