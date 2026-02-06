//! Control Plane Fairness Assessor
//!
//! Simplified implementation using the unified fairness framework.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::Api;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, RateLimiter, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Control plane assessor configuration
#[derive(Debug, Clone)]
pub struct FairnessControlPlaneConfig {
    /// Number of concurrent workers per tenant
    pub workers: usize,
}

impl Default for FairnessControlPlaneConfig {
    fn default() -> Self {
        Self { workers: 1 }
    }
}

// =============================================================================
// ASSESSOR
// =============================================================================

/// Control plane fairness assessor using ConfigMap CRUD operations
pub struct FairnessControlPlaneAssessor {
    config: FairnessControlPlaneConfig,
}

impl FairnessControlPlaneAssessor {
    pub fn new(config: FairnessControlPlaneConfig) -> Self {
        Self { config }
    }

    /// Cleanup resources created by the test
    async fn cleanup_resources(&self, tenant: &TenantClusterConfig) -> Result<()> {
        let client = tenant.cluster.client().clone();
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &tenant.namespace);
        let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), &tenant.namespace);

        let lp = ListParams::default().labels("kumuteva.io/test=control-plane");

        let _ = cm_api
            .delete_collection(&DeleteParams::default(), &lp)
            .await;
        let _ = deploy_api
            .delete_collection(&DeleteParams::default(), &lp)
            .await;
        Ok(())
    }

    /// Run workload for a single tenant
    async fn run_tenant(
        &self,
        tenant: &TenantClusterConfig,
        duration: Duration,
        rate_limiter: &RateLimiter,
        worker_id: usize,
    ) -> Result<Vec<MetricPoint>> {
        let client = tenant.cluster.client().clone();
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &tenant.namespace);
        let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), &tenant.namespace);

        let start_time = Instant::now();
        let deadline = start_time + duration;
        let mut handles = Vec::new();
        let mut counter = 0u64;

        while Instant::now() < deadline {
            // Wait for rate limiter
            rate_limiter.wait().await;

            let name = format!("fairness-test-{}-{}", worker_id, counter);
            let cm_api = cm_api.clone();
            let deploy_api = deploy_api.clone();
            let namespace = tenant.namespace.clone();

            // Spawn the operation to allow concurrency (pipelining)
            // This ensures we can meet the target rate even if latency > interval
            let handle = tokio::spawn(async move {
                let mut points = Vec::new();
                let labels = std::collections::BTreeMap::from([
                    ("kumuteva.io/test".to_string(), "control-plane".to_string()),
                    ("app".to_string(), name.clone()),
                ]);

                // 1. Create ConfigMap
                let cm = ConfigMap {
                    metadata: kube::api::ObjectMeta {
                        name: Some(name.clone()),
                        namespace: Some(namespace.clone()),
                        labels: Some(labels.clone()),
                        ..Default::default()
                    },
                    data: Some([("key".to_string(), "value".to_string())].into()),
                    ..Default::default()
                };

                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res_cm_create = cm_api.create(&PostParams::default(), &cm).await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res_cm_create.is_err(),
                    label: Some(format!("create-cm-{}", name)),
                });

                // 2. Create Deployment
                let deployment = Deployment {
                    metadata: kube::api::ObjectMeta {
                        name: Some(name.clone()),
                        namespace: Some(namespace.clone()),
                        labels: Some(labels.clone()),
                        ..Default::default()
                    },
                    spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
                        replicas: Some(1),
                        selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                            match_labels: Some(std::collections::BTreeMap::from([(
                                "app".to_string(),
                                name.clone(),
                            )])),
                            ..Default::default()
                        },
                        template: k8s_openapi::api::core::v1::PodTemplateSpec {
                            metadata: Some(kube::api::ObjectMeta {
                                labels: Some(std::collections::BTreeMap::from([(
                                    "app".to_string(),
                                    name.clone(),
                                )])),
                                ..Default::default()
                            }),
                            spec: Some(k8s_openapi::api::core::v1::PodSpec {
                                containers: vec![k8s_openapi::api::core::v1::Container {
                                    name: "nginx".to_string(),
                                    image: Some("nginx:alpine".to_string()),
                                    ..Default::default()
                                }],
                                ..Default::default()
                            }),
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res_deploy_create =
                    deploy_api.create(&PostParams::default(), &deployment).await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res_deploy_create.is_err(),
                    label: Some(format!("create-deploy-{}", name)),
                });

                // 3. Update ConfigMap
                if res_cm_create.is_ok() {
                    let patch = serde_json::json!({ "data": { "key": "updated-value" } });
                    let ts = start_time.elapsed().as_secs_f64();
                    let op_start = Instant::now();
                    let res = cm_api
                        .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
                        .await;
                    points.push(MetricPoint {
                        timestamp_secs: ts,
                        latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                        is_error: res.is_err(),
                        label: Some(format!("update-cm-{}", name)),
                    });
                }

                // 4. Update Deployment (scale up)
                if res_deploy_create.is_ok() {
                    let patch = serde_json::json!({ "spec": { "replicas": 2 } });
                    let ts = start_time.elapsed().as_secs_f64();
                    let op_start = Instant::now();
                    let res = deploy_api
                        .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
                        .await;
                    points.push(MetricPoint {
                        timestamp_secs: ts,
                        latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                        is_error: res.is_err(),
                        label: Some(format!("update-deploy-{}", name)),
                    });
                }
                // 5. List ConfigMaps
                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res = cm_api
                    .list(&ListParams::default().labels(&format!("app={}", name)))
                    .await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res.is_err(),
                    label: Some(format!("list-cm-{}", name)),
                });

                // 6. List Deployments
                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res = deploy_api
                    .list(&ListParams::default().labels(&format!("app={}", name)))
                    .await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res.is_err(),
                    label: Some(format!("list-deploy-{}", name)),
                });

                // 7. Delete ConfigMap
                if res_cm_create.is_ok() {
                    let ts = start_time.elapsed().as_secs_f64();
                    let op_start = Instant::now();
                    let res = cm_api.delete(&name, &DeleteParams::default()).await;
                    points.push(MetricPoint {
                        timestamp_secs: ts,
                        latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                        is_error: res.is_err(),
                        label: Some(format!("delete-cm-{}", name)),
                    });
                }

                // 8. Delete Deployment
                if res_deploy_create.is_ok() {
                    let ts = start_time.elapsed().as_secs_f64();
                    let op_start = Instant::now();
                    let res = deploy_api.delete(&name, &DeleteParams::default()).await;
                    points.push(MetricPoint {
                        timestamp_secs: ts,
                        latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                        is_error: res.is_err(),
                        label: Some(format!("delete-deploy-{}", name)),
                    });
                }
                points
            });

            handles.push(handle);
            counter += 1;
        }

        let mut points = Vec::with_capacity(handles.len() * 6);
        for handle in handles {
            if let Ok(task_points) = handle.await {
                points.extend(task_points);
            }
        }

        Ok(points)
    }

    /// Run phase with specified configuration
    #[allow(clippy::too_many_arguments)]
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_limiter: RateLimiter,
        t2_limiter: RateLimiter,
        t1_workers: usize,
        t2_workers: usize,
    ) -> Result<PhaseResult> {
        // Run both tenants concurrently
        let t1 = tenant1.clone();
        let t2 = tenant2.clone();

        // Cleanup before starting to ensure clean state
        let _ = self.cleanup_resources(&t1).await;
        let _ = self.cleanup_resources(&t2).await;

        let t1_handle = tokio::spawn(async move {
            let mut all_points = Vec::new();
            let mut handles = Vec::new();

            // Spawn worker tasks for tenant1
            for i in 0..t1_workers {
                let tenant = t1.clone();
                // Adjust rate because each scenario performs 6 operations
                let ops_per_scenario = 6.0;
                let adjusted_rate = if t1_limiter.rate().is_infinite() {
                    0.0
                } else {
                    t1_limiter.rate() / ops_per_scenario
                };

                let limiter = RateLimiter::new(t1_limiter.strategy, adjusted_rate);
                let dur = duration;

                handles.push(tokio::spawn(async move {
                    let assessor = FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                        workers: 1,
                    });
                    assessor.run_tenant(&tenant, dur, &limiter, i).await
                }));
            }

            for handle in handles {
                if let Ok(Ok(points)) = handle.await {
                    all_points.extend(points);
                }
            }

            all_points
        });

        let t2_handle = tokio::spawn(async move {
            let mut all_points = Vec::new();
            let mut handles = Vec::new();

            // Spawn worker tasks for tenant2
            for i in 0..t2_workers {
                let tenant = t2.clone();
                // Adjust rate because each scenario performs 6 operations
                let ops_per_scenario = 6.0;
                let adjusted_rate = if t2_limiter.rate().is_infinite() {
                    0.0
                } else {
                    t2_limiter.rate() / ops_per_scenario
                };

                let limiter = RateLimiter::new(t2_limiter.strategy, adjusted_rate);
                let dur = duration;

                handles.push(tokio::spawn(async move {
                    let assessor = FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                        workers: 1,
                    });
                    assessor.run_tenant(&tenant, dur, &limiter, i).await
                }));
            }

            for handle in handles {
                if let Ok(Ok(points)) = handle.await {
                    all_points.extend(points);
                }
            }

            all_points
        });

        let (t1_points, t2_points) = tokio::try_join!(t1_handle, t2_handle)?;

        // Cleanup after finishing
        let _ = self.cleanup_resources(&tenant1).await;
        let _ = self.cleanup_resources(&tenant2).await;

        Ok(PhaseResult {
            tenant1: TenantMetrics::from_raw(t1_points),
            tenant2: TenantMetrics::from_raw(t2_points),
        })
    }
}

#[async_trait]
impl FairnessAssessor for FairnessControlPlaneAssessor {
    fn name(&self) -> &'static str {
        "Control Plane"
    }

    fn metric(&self) -> &'static str {
        "API request latency"
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            config.tenant1_limiter(),
            config.tenant2_limiter(),
            self.config.workers,
            self.config.workers,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let malicious_workers =
            (self.config.workers as f64 * config.malicious_pod_multiplier) as usize;
        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            config.tenant1_limiter(),
            config.tenant2_malicious_limiter(),
            self.config.workers,
            malicious_workers.max(1),
        )
        .await
    }
}
