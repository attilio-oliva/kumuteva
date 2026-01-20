//! Control Plane Fairness Assessor
//!
//! This module implements the `FairnessAssessor` trait for the control plane subsystem.
//! It measures API request latency fairness by comparing how a "regular" tenant's
//! performance is affected when a "malicious" tenant floods the API server with requests.

#![allow(dead_code)] // Framework code - will be used by callers

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::{apps::v1::Deployment, core::v1::ConfigMap};
use kube::runtime::reflector::Lookup;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::assessment::fairness::{
    FairnessAssessor, FairnessTestConfig, PhaseResults, TenantMetrics,
};
use crate::verifier::TenantClusterConfig;

// =============================================================================
// CONTROL PLANE FAIRNESS ASSESSOR
// =============================================================================

/// Control plane fairness assessor configuration
#[derive(Debug, Clone)]
pub struct ControlPlaneFairnessConfig {
    /// Number of concurrent requesters for baseline/regular behavior
    pub regular_requesters: usize,
    /// Request rate per requester for baseline/regular behavior (requests/sec)
    pub regular_request_rate: f64,
    /// Interval for collecting and sending metrics
    pub metrics_send_interval: Duration,
}

impl Default for ControlPlaneFairnessConfig {
    fn default() -> Self {
        Self {
            regular_requesters: 1,
            regular_request_rate: 50.0,
            metrics_send_interval: Duration::from_secs(1),
        }
    }
}

/// Control plane fairness assessor
pub struct ControlPlaneFairnessAssessor {
    pub config: ControlPlaneFairnessConfig,
}

impl ControlPlaneFairnessAssessor {
    pub fn new(config: ControlPlaneFairnessConfig) -> Self {
        Self { config }
    }

    /// Create the scenario (sequence of API operations) for the test
    fn create_scenario() -> Arc<Scenario> {
        Arc::new(Scenario {
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
        })
    }

    /// Run a test phase with specified configuration for both tenants
    #[allow(clippy::too_many_arguments)]
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        tenant1_requesters: usize,
        tenant1_rate: f64,
        tenant2_requesters: usize,
        tenant2_rate: f64,
    ) -> Result<PhaseResults> {
        let scenario = Self::create_scenario();

        // Create initiator pools for both tenants
        let tenant1_pool = InitiatorsPool {
            initiators: (0..tenant1_requesters)
                .map(|idx| Initiator {
                    role: Role::Tenant1,
                    scenario: Arc::clone(&scenario),
                    uid: format!("t1-initiator-{}", idx),
                    request_metrics: vec![],
                    metrics_send_interval: self.config.metrics_send_interval,
                    request_rate: tenant1_rate,
                })
                .collect(),
        };

        let tenant2_pool = InitiatorsPool {
            initiators: (0..tenant2_requesters)
                .map(|idx| Initiator {
                    role: Role::Tenant2,
                    scenario: Arc::clone(&scenario),
                    uid: format!("t2-initiator-{}", idx),
                    request_metrics: vec![],
                    metrics_send_interval: self.config.metrics_send_interval,
                    request_rate: tenant2_rate,
                })
                .collect(),
        };

        // Create overseers
        let tenant1_overseer = Overseer::new(Role::Tenant1, tenant1_pool);
        let tenant2_overseer = Overseer::new(Role::Tenant2, tenant2_pool);

        // Run both tenants concurrently
        let result_t1 = tenant1_overseer.run(tenant1.clone(), duration);
        let result_t2 = tenant2_overseer.run(tenant2.clone(), duration);

        let (metrics_t1, metrics_t2) = tokio::try_join!(result_t1, result_t2)?;

        // Cleanup resources
        let _ = cleanup(&tenant1).await;
        let _ = cleanup(&tenant2).await;

        Ok(PhaseResults {
            tenant1: TenantMetrics {
                primary_metric: metrics_t1.average_duration.as_secs_f64() * 1000.0, // Convert to ms
                secondary_metrics: vec![
                    (
                        "std_deviation_ms".to_string(),
                        metrics_t1.std_deviation.as_secs_f64() * 1000.0,
                    ),
                    (
                        "total_requests".to_string(),
                        metrics_t1.total_requests as f64,
                    ),
                ],
                error_rate: metrics_t1.error_rate * 100.0,
            },
            tenant2: TenantMetrics {
                primary_metric: metrics_t2.average_duration.as_secs_f64() * 1000.0,
                secondary_metrics: vec![
                    (
                        "std_deviation_ms".to_string(),
                        metrics_t2.std_deviation.as_secs_f64() * 1000.0,
                    ),
                    (
                        "total_requests".to_string(),
                        metrics_t2.total_requests as f64,
                    ),
                ],
                error_rate: metrics_t2.error_rate * 100.0,
            },
        })
    }
}

#[async_trait]
impl FairnessAssessor for ControlPlaneFairnessAssessor {
    fn name(&self) -> &'static str {
        "Control Plane"
    }

    fn metric_unit(&self) -> &'static str {
        "ms"
    }

    fn higher_is_better(&self) -> bool {
        false // Lower latency is better
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults> {
        // Both tenants run with the same (regular) configuration
        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.regular_requesters,
            self.config.regular_request_rate,
            self.config.regular_requesters,
            self.config.regular_request_rate,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessTestConfig,
    ) -> Result<PhaseResults> {
        // Tenant1 stays regular, Tenant2 becomes "malicious" with increased load
        let malicious_requesters =
            (self.config.regular_requesters as f64 * config.malicious_load_multiplier) as usize;
        let malicious_rate = self.config.regular_request_rate * config.malicious_load_multiplier;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.regular_requesters,
            self.config.regular_request_rate,
            malicious_requesters.max(1), // At least 1 requester
            malicious_rate,
        )
        .await
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Role {
    Tenant1,
    Tenant2,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Tenant1 => write!(f, "Tenant1"),
            Role::Tenant2 => write!(f, "Tenant2"),
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
struct RequestMetrics {
    request_type: ResourceKind,
    operation: RequestOperation,
    start_time_seconds: f64,
    duration: Duration,
    initiator_role: Role,
    is_error: bool,
}

#[derive(Debug, Clone)]
struct AverageMetrics {
    average_duration: Duration,
    std_deviation: Duration,
    total_requests: usize,
    error_count: usize,
    error_rate: f64,
}

impl AverageMetrics {
    fn calculate(requests: &[RequestMetrics]) -> Self {
        if requests.is_empty() {
            return Self {
                average_duration: Duration::ZERO,
                std_deviation: Duration::ZERO,
                total_requests: 0,
                error_count: 0,
                error_rate: 0.0,
            };
        }

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

        let error_count = requests.iter().filter(|m| m.is_error).count();
        let error_rate = error_count as f64 / requests.len() as f64;

        Self {
            average_duration,
            std_deviation,
            total_requests: requests.len(),
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
    ) -> Result<AverageMetrics> {
        let (metrics_tx, mut metrics_rx) = mpsc::channel(5);
        let (completion_tx, mut completion_rx) = mpsc::channel::<()>(self.pool.initiators.len());
        let initiator_count = self.pool.initiators.len();

        let mut handles = self
            .pool
            .spawn_initiators(metrics_tx, completion_tx, tenant_config)
            .await;

        let role = self.role;
        let metrics_collector = tokio::spawn(async move {
            let mut tenant_metrics: HashMap<String, Vec<RequestMetrics>> = HashMap::new();
            let mut completed = 0;

            let collection_timeout = tokio::time::sleep(duration + Duration::from_secs(5));
            tokio::pin!(collection_timeout);

            loop {
                tokio::select! {
                    _ = &mut collection_timeout => {
                        break;
                    }
                    maybe_metrics = metrics_rx.recv() => {
                        match maybe_metrics {
                            Some(metrics) => {
                                if let Some(first) = metrics.first() {
                                    tenant_metrics
                                        .entry(first.initiator_role.to_string())
                                        .or_default()
                                        .extend(metrics);
                                }
                            }
                            None => break,
                        }
                    }
                    maybe_completion = completion_rx.recv() => {
                        match maybe_completion {
                            Some(_) => {
                                completed += 1;
                                if completed >= initiator_count {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            tenant_metrics
        });

        tokio::time::sleep(duration).await;

        for (_, stop_tx) in handles.drain(..) {
            let _ = stop_tx.send(());
        }

        let tenant_metrics = metrics_collector.await?;

        let metrics = tenant_metrics
            .get(&self.role.to_string())
            .map(|m| AverageMetrics::calculate(m))
            .unwrap_or_else(|| AverageMetrics {
                average_duration: Duration::ZERO,
                std_deviation: Duration::ZERO,
                total_requests: 0,
                error_count: 0,
                error_rate: 0.0,
            });

        println!(
            "    {} - Requests: {}, Avg: {:.2?}, StdDev: {:.2?}, Errors: {:.1}%",
            role,
            metrics.total_requests,
            metrics.average_duration,
            metrics.std_deviation,
            metrics.error_rate * 100.0
        );

        Ok(metrics)
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
        let mut request_rate_interval =
            tokio::time::interval(Duration::from_secs_f64(1.0 / self.request_rate));
        let mut scenario_step = 0;
        let start_time = Instant::now();

        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    self.send_final(&metrics_tx, &completion_tx).await;
                    break;
                }
                _ = update_overseer_interval.tick() => {
                    if !self.request_metrics.is_empty() {
                        if metrics_tx.send(self.request_metrics.clone()).await.is_err() {
                            break;
                        }
                        self.request_metrics.clear();
                    }
                }
                _ = request_rate_interval.tick() => {
                    self.process_scenario_step(
                        Arc::clone(&scenario),
                        scenario_step,
                        &tenant_config,
                        start_time,
                    ).await;
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
            let _ = metrics_tx.send(self.request_metrics.clone()).await;
        }
        let _ = completion_tx.send(()).await;
    }

    async fn process_scenario_step(
        &mut self,
        scenario: Arc<Scenario>,
        step_index: usize,
        tenant_config: &Arc<TenantClusterConfig>,
        test_start: Instant,
    ) {
        if step_index >= scenario.requests.len() {
            return;
        }

        let request = &scenario.requests[step_index];
        let start = Instant::now();
        let start_timestamp = test_start.elapsed().as_secs_f64();
        let result = request.send(tenant_config, self.uid.clone()).await;
        let duration = start.elapsed();

        self.request_metrics.push(RequestMetrics {
            request_type: request.resource.clone(),
            operation: request.operation.clone(),
            start_time_seconds: start_timestamp,
            duration,
            initiator_role: self.role,
            is_error: result.is_err(),
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
    // List and delete config maps starting with "fairness-test-config-"
    if let Ok(config_maps) = tenant
        .cluster
        .list_namespaced_resources::<ConfigMap>(&tenant.namespace)
        .await
    {
        for config_map in config_maps {
            if let Some(name) = config_map.name() {
                if name.starts_with("fairness-test-config-") {
                    let _ = tenant
                        .cluster
                        .delete_resource_in_namespace::<ConfigMap>(&name, &tenant.namespace)
                        .await;
                }
            }
        }
    }

    // List and delete deployments starting with "fairness-test-"
    if let Ok(deployments) = tenant
        .cluster
        .list_namespaced_resources::<Deployment>(&tenant.namespace)
        .await
    {
        for deployment in deployments {
            if let Some(name) = deployment.name() {
                if name.starts_with("fairness-test-") {
                    let _ = tenant
                        .cluster
                        .delete_resource_in_namespace::<Deployment>(&name, &tenant.namespace)
                        .await;
                }
            }
        }
    }

    Ok(())
}

impl Request {
    async fn send(
        &self,
        tenant_config: &TenantClusterConfig,
        sender_uid: String,
    ) -> anyhow::Result<()> {
        let config_map_name = format!("fairness-test-config-{}", sender_uid);
        let deployment_name = format!("fairness-test-{}", sender_uid);

        match (&self.resource, &self.operation) {
            (ResourceKind::ConfigMap, RequestOperation::Create) => {
                let config_map: ConfigMap = serde_json::from_value(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": config_map_name,
                        "namespace": tenant_config.namespace,
                    },
                    "data": {
                        "key": "example-value",
                    }
                }))?;
                tenant_config
                    .cluster
                    .create_namespaced_resource(&config_map, &tenant_config.namespace)
                    .await?;
            }
            (ResourceKind::ConfigMap, RequestOperation::Update) => {
                let random_value = rand::random::<u32>();
                let patch = kube::api::Patch::Merge(serde_json::json!({
                    "data": {
                        "key": format!("updated-value-{}", random_value),
                    }
                }));
                tenant_config
                    .cluster
                    .patch_namespaced_resource::<ConfigMap, _>(
                        &config_map_name,
                        &tenant_config.namespace,
                        &patch,
                    )
                    .await?;
            }
            (ResourceKind::ConfigMap, RequestOperation::Delete) => {
                tenant_config
                    .cluster
                    .delete_resource_in_namespace::<ConfigMap>(
                        &config_map_name,
                        &tenant_config.namespace,
                    )
                    .await?;
            }
            (ResourceKind::Deployment, RequestOperation::Create) => {
                let deployment: Deployment = serde_json::from_value(serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "name": deployment_name,
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
                                "containers": [{
                                    "name": "nginx",
                                    "image": "nginx:latest",
                                    "ports": [{
                                        "containerPort": 80
                                    }]
                                }]
                            }
                        }
                    }
                }))?;
                tenant_config
                    .cluster
                    .create_namespaced_resource(&deployment, &tenant_config.namespace)
                    .await?;
            }
            (ResourceKind::Deployment, RequestOperation::Update) => {
                let patch = kube::api::Patch::Merge(serde_json::json!({
                    "spec": {
                        "replicas": 2
                    }
                }));
                tenant_config
                    .cluster
                    .patch_namespaced_resource::<Deployment, _>(
                        &deployment_name,
                        &tenant_config.namespace,
                        &patch,
                    )
                    .await?;
            }
            (ResourceKind::Deployment, RequestOperation::Delete) => {
                tenant_config
                    .cluster
                    .delete_resource_in_namespace::<Deployment>(
                        &deployment_name,
                        &tenant_config.namespace,
                    )
                    .await?;
            }
        }

        Ok(())
    }
}
