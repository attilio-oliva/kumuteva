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
use anyhow::{Ok, Result};
use k8s_openapi::api::{
    apps::v1::Deployment,
    core::v1::{ConfigMap, Pod},
};
use kube::{api::Patch, runtime::reflector::Lookup};
use rand::Rng;
use serde_json::json;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
};

// Implement the check_fairness function
pub async fn check_fairness(
    tenant1: Arc<TenantClusterConfig>,
    tenant2: Arc<TenantClusterConfig>,
) -> Result<bool> {
    let regular_requesters = 3;
    let malicious_requesters = 10;
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
        initiators: (0..regular_requesters) // 3 regular initiators
            .map(|idx| Initiator {
                role: Role::Regular,
                scenario: Arc::clone(&regular_scenario),
                uid: format!("regular-initiator-{}", idx),
                request_metrics: vec![],
                metrics_send_interval: Duration::from_secs(3),
            })
            .collect(),
    };

    let malicious_pool = InitiatorsPool {
        initiators: (0..malicious_requesters)
            .map(|idx| // 10 malicious initiators
            Initiator {
                scenario: Arc::clone(&malicious_scenario),
                role: Role::Malicious,
                uid: format!("malicious-initiator-{}", idx),
                request_metrics: vec![],
                metrics_send_interval: Duration::from_secs(3),
            })
            .collect(),
    };

    // print all the ids
    for initiator in &malicious_pool.initiators {
        println!("Malicious initiator id: {}", initiator.uid);
    }
    for initiator in &regular_pool.initiators {
        println!("Regular initiator id: {}", initiator.uid);
    }

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
    let test_duration = Duration::from_secs(10);

    let regular_result = regular_overseer.run(Arc::clone(&tenant1), test_duration);
    let malicious_result = malicious_overseer.run(Arc::clone(&tenant2), test_duration);

    // Wait for the test to finish
    let (regular_metrics, malicious_metrics) = tokio::try_join!(regular_result, malicious_result)?;

    cleanup(&tenant1).await?;
    cleanup(&tenant2).await?;

    // Return the result of the test
    Ok(true)
}

#[derive(Clone, Debug, Copy)]
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
}

struct Scenario {
    requests: Vec<Request>,
}

struct Request {
    resource: ResourceKind,
    operation: RequestOperation,
}

#[derive(Debug, Clone)]
enum ResourceKind {
    ConfigMap,
    Deployment,
}

#[derive(Debug, Clone)]
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
    pool: InitiatorsPool,
}

#[derive(Debug, Clone)]
struct RequestMetrics {
    request_type: ResourceKind,
    operation: RequestOperation,
    start_time: Instant,
    duration: Duration,
    initiator_role: Role,
}

#[derive(Debug, Clone)]
struct AverageMetrics {
    request_type: ResourceKind,
    operation: RequestOperation,
    average_duration: Duration,
    std_deviation: Duration,
    total_duration: Duration,
    total_requests: usize,
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
                let diff = m.duration.as_secs_f64() - average_duration.as_secs_f64();
                diff * diff
            })
            .sum::<f64>()
            / requests.len() as f64;

        let std_deviation = Duration::from_secs_f64(variance.sqrt());

        Self {
            request_type: requests[0].request_type.clone(),
            operation: requests[0].operation.clone(),
            average_duration,
            std_deviation,
            total_duration,
            total_requests: requests.len(),
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
        // Use the first item's metadata for the aggregated metrics
        Self {
            request_type: requests[0].request_type.clone(),
            operation: requests[0].operation.clone(),
            average_duration,
            std_deviation,
            total_duration,
            total_requests,
            initiator_role: requests[0].initiator_role,
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
    ) -> Result<HashMap<String, Vec<AverageMetrics>>> {
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
        let mut tenant_metrics: HashMap<String, Vec<AverageMetrics>> = HashMap::new();

        // Spawn a task to collect the last metrics before stopping
        let metrics_collector = tokio::spawn(async move {
            let mut completed_initiators = 0;

            loop {
                tokio::select! {
                    Some(metric) = metrics_rx.recv() => {
                        tenant_metrics
                            .entry(metric.initiator_role.to_string())
                            .or_default()
                            .push(metric);
                    }

                    Some(_) = completion_rx.recv() => {
                        completed_initiators += 1;
                        // All initiators have sent their final metrics and signaled completion
                        if completed_initiators >= initiator_count {
                            break;
                        }
                    }

                    else => {
                        // All channels closed, exit
                        break;
                    }
                }
            }

            tenant_metrics
        });

        // Wait for the specified duration
        tokio::time::sleep(duration).await;

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

        // Log collected metrics
        for (role, metrics) in &tenant_metrics {
            if metrics.is_empty() {
                println!("Role: {}, No metrics collected", role);
                continue;
            }

            let average_metrics = AverageMetrics::aggregate_averages(metrics);
            println!(
                "Role: {}, Requests: {}, Avg Duration: {:.2?}, Std Dev: {:.2?}",
                role,
                average_metrics.total_requests,
                average_metrics.average_duration,
                average_metrics.std_deviation
            );
        }

        Ok(tenant_metrics)
    }
}

impl Initiator {
    async fn run(
        mut self,
        scenario: Arc<Scenario>,
        metrics_tx: mpsc::Sender<AverageMetrics>,
        stop_rx: broadcast::Receiver<()>,
        completion_tx: mpsc::Sender<()>,
        tenant_config: Arc<TenantClusterConfig>,
    ) {
        let mut stop_rx = stop_rx;
        let uid = self.uid.clone();

        // Create an interval timer that fires at the specified interval
        let mut metrics_interval = tokio::time::interval(self.metrics_send_interval);

        loop {
            tokio::select! {
                // If we receive a stop signal, exit the loop.
                _ = stop_rx.recv() => {
                    self.stop(metrics_tx, completion_tx).await;
                    break;
                }
                // When the metrics interval timer fires, send metrics
                _ = metrics_interval.tick() => {
                    if !self.request_metrics.is_empty() {
                        let average_metrics = AverageMetrics::calculate(&self.request_metrics);
                        if metrics_tx.send(average_metrics).await.is_err() {
                            // Overseer has dropped the channel, exit
                            return;
                        }
                        // Clear the metrics after sending
                        self.request_metrics.clear();
                    }
                }
                // Otherwise, process one full iteration of the scenario.
                _ = async {
                    // Execute each request in the scenario
                    for request in &scenario.requests {
                        let start = Instant::now();

                        // Execute the k8s request based on request.kind and request.operation
                        // This would make actual API calls to the k8s cluster using tenant_config
                        // For simplicity, we'll just sleep for the request delay
                        // let random_factor = rand::rng().random_range(0..=99);
                        let result = request.send(&tenant_config, uid.clone()).await;
                        if let Err(e) = result {
                            eprintln!("Error sending request: {:?}", e);
                        }

                        let duration = start.elapsed();

                        // Send metrics back to overseer
                        let metrics = RequestMetrics {
                            request_type: request.resource.clone(),
                            operation: request.operation.clone(),
                            start_time: start,
                            duration,
                            initiator_role: self.role,
                        };

                        println!(
                            "Role: {}, Request: {:?}, Operation: {:?}, Duration: {:.2?}",
                            self.role, request.resource, request.operation, duration
                        );

                        self.request_metrics.push(metrics);

                        // Here a logic to obtain a desired requests-per-second rate will be implemented
                        // For now, we just sleep for a bit to simulate the delay
                        //tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => {}
            }
        }
    }

    pub async fn stop(
        &self,
        metrics_tx: mpsc::Sender<AverageMetrics>,
        completion_tx: mpsc::Sender<()>,
    ) {
        if !self.request_metrics.is_empty() {
            let average_metrics = AverageMetrics::calculate(&self.request_metrics);

            // Send the final metrics
            if let Err(e) = metrics_tx.send(average_metrics).await {
                eprintln!("Failed to send final metrics: {}", e);
            }
        }

        // Signal that this initiator is complete
        let _ = completion_tx.send(()).await;
    }
}

impl InitiatorsPool {
    async fn spawn_initiators(
        &self,
        metrics_tx: mpsc::Sender<AverageMetrics>,
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
                        .wait_for_resource_to_be_created::<ConfigMap>(
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
                        .wait_for_resource_to_be_created::<Deployment>(
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
    use crate::cluster::KubernetesCluster;

    use super::*;

    #[tokio::test]
    async fn test_check_fairness() {
        let tenant1 = Arc::new(TenantClusterConfig {
            namespace: "tenant1".to_string(),
            cluster: KubernetesCluster::infer().await.unwrap(),
        });
        let tenant2 = Arc::new(TenantClusterConfig {
            namespace: "tenant2".to_string(),
            cluster: KubernetesCluster::infer().await.unwrap(),
        });

        let result = check_fairness(tenant1, tenant2).await;
        assert!(result.is_ok());
    }
}
