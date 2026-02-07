//! Control Plane Fairness Assessor
//!
//! Simplified implementation using the unified fairness framework.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams, WatchParams};
use kube::Api;
use tracing::info;

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
    /// Maximum number of concurrent workers per tenant
    /// This is used to control the level of concurrency and achieve the desired request rates for each tenant
    pub max_workers: usize,
}

impl Default for FairnessControlPlaneConfig {
    fn default() -> Self {
        Self { max_workers: 1 }
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
        let start_time = Instant::now();
        let deadline = start_time + duration;
        let mut points = Vec::new();
        let mut counter = 0u64;

        while Instant::now() < deadline {
            // Wait for rate limiter
            rate_limiter.wait().await;

            let name = format!("fairness-test-{}-{}", worker_id, counter);
            let namespace = tenant.namespace.clone();

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
            let res_cm_create = tenant
                .cluster
                .create_namespaced_resource(&cm, &tenant.namespace)
                .await;

            points.push(MetricPoint {
                timestamp_secs: ts,
                latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                is_error: res_cm_create.is_err(),
                label: Some(format!("create-cm-{}", name)),
            });

            // 2. Create nginx Pod
            let deployment = Pod {
                metadata: kube::api::ObjectMeta {
                    name: Some(name.clone()),
                    namespace: Some(namespace.clone()),
                    labels: Some(labels.clone()),
                    ..Default::default()
                },
                spec: Some(k8s_openapi::api::core::v1::PodSpec {
                    containers: vec![k8s_openapi::api::core::v1::Container {
                        name: "nginx".to_string(),
                        image: Some("nginx:latest".to_string()),
                        image_pull_policy: Some("IfNotPresent".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            };

            let ts = start_time.elapsed().as_secs_f64();
            let op_start = Instant::now();
            let res_pod_create = tenant
                .cluster
                .create_namespaced_resource(&deployment, &tenant.namespace)
                .await;
            points.push(MetricPoint {
                timestamp_secs: ts,
                latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                is_error: res_pod_create.is_err(),
                label: Some(format!("create-deploy-{}", name)),
            });

            // 3. Update ConfigMap
            if res_cm_create.is_ok() {
                let patch = serde_json::json!({ "data": { "key": "updated-value" } });
                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res: Result<ConfigMap> = tenant
                    .cluster
                    .patch_namespaced_resource(&name, &tenant.namespace, &Patch::Merge(&patch))
                    .await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res.is_err(),
                    label: Some(format!("update-cm-{}", name)),
                });
            }

            //  Wait for pods to be ready (watch for deployment to be ready)
            if res_pod_create.is_ok() {
                let _ = tenant
                    .cluster
                    .wait_for_pod_readiness_timeout(
                        &name,
                        &tenant.namespace,
                        (deadline - Instant::now()).as_secs() as u32,
                    )
                    .await;
            }

            // 4. Update Pod (add label)
            if res_pod_create.is_ok() {
                let patch = serde_json::json!({ "metadata": { "labels": { "updated": "true" } } });
                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res: Result<Pod> = tenant
                    .cluster
                    .patch_namespaced_resource(&name, &tenant.namespace, &Patch::Merge(&patch))
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
            let res = tenant
                .cluster
                .list_namespaced_resources::<ConfigMap>(&tenant.namespace)
                .await;
            points.push(MetricPoint {
                timestamp_secs: ts,
                latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                is_error: res.is_err(),
                label: Some(format!("list-cm-{}", name)),
            });

            // 6. List Pods
            let ts = start_time.elapsed().as_secs_f64();
            let op_start = Instant::now();
            let res = tenant
                .cluster
                .list_namespaced_resources::<Pod>(&tenant.namespace)
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
                let res = tenant
                    .cluster
                    .delete_resource_in_namespace::<ConfigMap>(&name, &tenant.namespace)
                    .await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res.is_err(),
                    label: Some(format!("delete-cm-{}", name)),
                });
            }

            // 8. Delete Deployment
            if res_pod_create.is_ok() {
                let ts = start_time.elapsed().as_secs_f64();
                let op_start = Instant::now();
                let res = tenant
                    .cluster
                    .delete_resource_in_namespace::<Pod>(&name, &tenant.namespace)
                    .await;
                points.push(MetricPoint {
                    timestamp_secs: ts,
                    latency_ms: op_start.elapsed().as_secs_f64() * 1000.0,
                    is_error: res.is_err(),
                    label: Some(format!("delete-deploy-{}", name)),
                });
            }

            // Wait for pod to be deleted
            if res_pod_create.is_ok() {
                let _ = tenant
                    .cluster
                    .wait_for_pod_deletion_timeout(
                        &name,
                        &tenant.namespace,
                        (deadline - Instant::now()).as_secs() as u32,
                    )
                    .await;
            }

            counter += 1;
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

        // manipulate the number of workers to reach the desired request rate per tenant
        let target_t1_workers: usize = if t1_limiter.rate().is_infinite() {
            1
        } else {
            let ops_per_scenario = 6.0; // Each scenario performs 6 operations
            let desired_rate = t1_limiter.rate() / ops_per_scenario;
            let workers = (desired_rate / t1_workers as f64).ceil() as usize;
            workers.min(self.config.max_workers)
        };

        let target_t2_workers: usize = if t2_limiter.rate().is_infinite() {
            1
        } else {
            let ops_per_scenario = 6.0; // Each scenario performs 6 operations
            let desired_rate = t2_limiter.rate() / ops_per_scenario;
            let workers = (desired_rate / t2_workers as f64).ceil() as usize;
            workers.min(t2_workers)
        };
        info!(
            "Target workers - tenant1: {}, tenant2: {}",
            target_t1_workers, target_t2_workers
        );

        let t1_handle = tokio::spawn(async move {
            let mut all_points = Vec::new();
            let mut handles = Vec::new();

            // Spawn worker tasks for tenant1
            info!(
                "Starting tenant1 with {} workers at rate {:.2} ops/sec",
                t1_workers,
                t1_limiter.rate()
            );
            for i in 0..t1_workers {
                let tenant = t1.clone();
                // Adjust rate because each scenario performs 6 operations
                let ops_per_scenario = 6.0;
                let adjusted_rate = if t1_limiter.rate().is_infinite() {
                    0.0
                } else {
                    let rate = t1_limiter.rate() / ops_per_scenario;

                    rate / t1_workers as f64
                };

                let limiter = RateLimiter::new(t1_limiter.strategy, adjusted_rate);
                let dur = duration;

                handles.push(tokio::spawn(async move {
                    let assessor = FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                        max_workers: 1,
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
            info!(
                "Starting tenant2 with {} workers at rate {:.2} ops/sec",
                t2_workers,
                t2_limiter.rate()
            );
            for i in 0..t2_workers {
                let tenant = t2.clone();
                // Adjust rate because each scenario performs 6 operations
                let ops_per_scenario = 6.0;
                let adjusted_rate = if t2_limiter.rate().is_infinite() {
                    0.0
                } else {
                    let rate = t2_limiter.rate() / ops_per_scenario;

                    rate / t2_workers as f64
                };

                let limiter = RateLimiter::new(t2_limiter.strategy, adjusted_rate);
                let dur = duration;

                handles.push(tokio::spawn(async move {
                    let assessor = FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                        max_workers: 1,
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
            self.config.max_workers,
            self.config.max_workers,
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
            (self.config.max_workers as f64 * config.malicious_pod_multiplier) as usize;
        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            config.tenant1_limiter(),
            config.tenant2_malicious_limiter(),
            self.config.max_workers,
            malicious_workers.max(1),
        )
        .await
    }
}
