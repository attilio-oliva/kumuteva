//! Control Plane Fairness Assessor
//!
//! Simplified implementation using the unified fairness framework.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::api::{DeleteParams, ListParams, Patch};
use kube::Api;

use tracing::info;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, OperationSchedule, PhaseResult, RateLimiter,
    TenantMetrics,
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
// OPERATION GATING
// =============================================================================

/// Issue a single API request on schedule and record its response and service time.
///
/// The schedule advances once per *request*, not once per CRUD scenario. This is
/// what makes the configured rate equal the achieved request rate: a scenario
/// issuing six requests and one issuing four both emit at the same ops/sec.
///
/// Two latencies and two time bases are recorded, and only the first of each is
/// reported.
///
/// `timestamp_secs` is when the request was actually dispatched, measured from
/// the phase start. `slot_timestamp_secs` is when it was *due*. The first is a
/// clock and the second is an operation counter (`issued / rate`), so they
/// diverge exactly as far as the generator has fallen behind. Plots and rates
/// use the clock; charting the schedule instead compresses a 60 s phase into
/// however many seconds' worth of schedule the run managed to reach.
///
/// `latency_ms` runs from actual dispatch to completion: the time the API server
/// spent on the request, and the number the degradation factor is computed from.
///
/// `scheduled_latency_ms` runs from the operation's *scheduled slot*, so it also
/// charges the request for any wait between when it was due and when a worker
/// was free to send it. That wait is modelled, not observed — these workers are
/// sequential loops, so a request not yet sent is not queued anywhere real — and
/// under sustained overload it grows with the phase duration rather than
/// converging. It therefore serves as a validity check: divided by `latency_ms`
/// it gives the coordinated-omission factor, and a value near 1.0 is what says
/// the probe kept up and its latency describes the platform rather than its own
/// backlog.
///
/// Every operation in a scenario is issued unconditionally, even when an earlier
/// step failed. A load generator's contract is to offer a defined request rate;
/// a GET against a name whose CREATE failed is still a real API request and is
/// recorded with `is_error: true`. Skipping dependent steps would make the
/// offered load a function of the failure rate, which is precisely the coupling
/// that made the previous implementation's load unmeasurable.
macro_rules! timed_operation {
    ($points:expr, $schedule:expr, $label:expr, $call:expr) => {{
        let schedule_start = $schedule.start();
        let intended = $schedule.next_slot().await;
        let slot_timestamp_secs = intended
            .saturating_duration_since(schedule_start)
            .as_secs_f64();
        let dispatched = Instant::now();
        let timestamp_secs = dispatched
            .saturating_duration_since(schedule_start)
            .as_secs_f64();
        let result = $call.await;
        let completed = Instant::now();

        let scheduled_ms = completed.saturating_duration_since(intended).as_secs_f64() * 1000.0;
        let service_ms = completed
            .saturating_duration_since(dispatched)
            .as_secs_f64()
            * 1000.0;

        $points.push(MetricPoint {
            timestamp_secs,
            latency_ms: service_ms,
            scheduled_latency_ms: Some(scheduled_ms),
            slot_timestamp_secs: Some(slot_timestamp_secs),
            is_error: result.is_err(),
            label: Some($label),
        });
        result
    }};
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

    /// Run workload for a single tenant - performs CRUD operations on ConfigMaps
    async fn run_stress_test_on_configmap(
        &self,
        tenant: &TenantClusterConfig,
        duration: Duration,
        schedule: &mut OperationSchedule,
        worker_id: usize,
    ) -> Result<Vec<MetricPoint>> {
        // Deadline is anchored to the schedule origin so every worker in a phase
        // covers the same window, regardless of when its task happened to start.
        let deadline = schedule.start() + duration;
        let mut points = Vec::new();
        let mut counter = 0u64;

        while Instant::now() < deadline {
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

            let _ = timed_operation!(
                points,
                schedule,
                format!("create-cm-{}", name),
                tenant
                    .cluster
                    .create_namespaced_resource(&cm, &tenant.namespace)
            );

            // 2. Get ConfigMap
            let _ = timed_operation!(
                points,
                schedule,
                format!("get-cm-{}", name),
                tenant
                    .cluster
                    .get_resource_in_namespace::<ConfigMap>(&name, &tenant.namespace)
            );

            // 3. Update ConfigMap
            let patch = serde_json::json!({ "data": { "key": "updated-value" } });
            let _: Result<ConfigMap> = timed_operation!(
                points,
                schedule,
                format!("update-cm-{}", name),
                tenant.cluster.patch_namespaced_resource(
                    &name,
                    &tenant.namespace,
                    &Patch::Merge(&patch)
                )
            );

            // 4. Get ConfigMap again to verify update
            let _ = timed_operation!(
                points,
                schedule,
                format!("get-updated-cm-{}", name),
                tenant
                    .cluster
                    .get_resource_in_namespace::<ConfigMap>(&name, &tenant.namespace)
            );

            // 5. List ConfigMaps
            let _ = timed_operation!(
                points,
                schedule,
                format!("list-cm-{}", name),
                tenant
                    .cluster
                    .list_namespaced_resources::<ConfigMap>(&tenant.namespace)
            );

            // 6. Delete ConfigMap
            let _ = timed_operation!(
                points,
                schedule,
                format!("delete-cm-{}", name),
                tenant
                    .cluster
                    .delete_resource_in_namespace::<ConfigMap>(&name, &tenant.namespace)
            );

            counter += 1;
        }

        Ok(points)
    }

    async fn run_stress_test_on_pod(
        &self,
        tenant: &TenantClusterConfig,
        duration: Duration,
        schedule: &mut OperationSchedule,
        worker_id: usize,
    ) -> Result<Vec<MetricPoint>> {
        // Deadline is anchored to the schedule origin so every worker in a phase
        // covers the same window, regardless of when its task happened to start.
        let deadline = schedule.start() + duration;
        let mut points = Vec::new();
        let mut counter = 0u64;

        while Instant::now() < deadline {
            let name: String = format!("fairness-pod-{}-{}", worker_id, counter);
            let namespace = tenant.namespace.clone();

            let labels = std::collections::BTreeMap::from([
                ("kumuteva.io/test".to_string(), "control-plane".to_string()),
                ("app".to_string(), name.clone()),
            ]);

            // 1. Create Pod
            let pod: Pod = serde_json::from_value(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name.clone(),
                    "namespace": namespace.clone(),
                    "labels": labels.clone(),
                },
                "spec": {
                    "containers": [
                        {
                            "name": "pause",
                            "image": "k8s.gcr.io/pause:3.5",
                            "imagePullPolicy": "IfNotPresent",
                            "resources": {
                                "requests": {
                                    "cpu": "10m",
                                    "memory": "10Mi"
                                },
                                "limits": {
                                    "cpu": "20m",
                                    "memory": "20Mi"
                                }
                            }
                        }
                    ]
                }
            }))?;

            let _ = timed_operation!(
                points,
                schedule,
                format!("create-pod-{}", name),
                tenant
                    .cluster
                    .create_namespaced_resource(&pod, &tenant.namespace)
            );

            // NOTE: pod readiness is deliberately NOT awaited. This metric measures
            // API admission latency only, not scheduling or container start. The
            // paper's methodology section must say so explicitly.

            // 2. Update Pod (add label)
            let patch = serde_json::json!({ "metadata": { "labels": { "updated": "true" } } });
            let _: Result<Pod> = timed_operation!(
                points,
                schedule,
                format!("update-pod-{}", name),
                tenant.cluster.patch_namespaced_resource(
                    &name,
                    &tenant.namespace,
                    &Patch::Merge(&patch)
                )
            );

            // 3. List Pods
            let _ = timed_operation!(
                points,
                schedule,
                format!("list-pod-{}", name),
                tenant
                    .cluster
                    .list_namespaced_resources::<Pod>(&tenant.namespace)
            );

            // 4. Delete Pod
            let _ = timed_operation!(
                points,
                schedule,
                format!("delete-pod-{}", name),
                tenant
                    .cluster
                    .delete_resource_in_namespace::<Pod>(&name, &tenant.namespace)
            );

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

        // Split each tenant's workers between the Pod and ConfigMap scenarios.
        //
        // The split no longer affects the offered request rate: `timed_operation!` gates
        // every individual API call, so a ConfigMap worker (6 requests/iteration)
        // and a Pod worker (4 requests/iteration) both emit at the same ops/sec.
        // Previously the rate was divided by a hardcoded `ops_per_scenario = 3.0`
        // while the scenarios issued 6 and 4 requests respectively, which inflated
        // the achieved rate to (2*4 + 3*6) / (5*3) = 1.733x configured at 5 workers.
        let distribute_workers = |total_workers: usize| {
            let pod_workers = total_workers / 2; // Allocate 1/2 of workers to Pod operations
            let cm_workers = total_workers - pod_workers;
            (pod_workers, cm_workers)
        };

        let (t1_pod_workers, t1_cm_workers) = distribute_workers(t1_workers);
        let (t2_pod_workers, t2_cm_workers) = distribute_workers(t2_workers);

        info!(
            "Worker distribution - tenant1: {} pod workers, {} cm workers; tenant2: {} pod workers, {} cm workers",
            t1_pod_workers, t1_cm_workers, t2_pod_workers, t2_cm_workers
        );

        // One time origin for the whole phase, fixed before any worker starts.
        // Both tenants and every worker schedule their intended dispatch times
        // against it, so the recorded timestamps share an axis and the response
        // times are measured against a schedule that does not drift with load.
        let phase_start = Instant::now();

        let t1_handle = tokio::spawn(async move {
            let mut all_points = Vec::new();
            let mut handles = Vec::new();

            // Spawn worker tasks for tenant1
            info!(
                "Starting tenant1: {} workers, {:.2} ops/sec total ({:.2} per worker)",
                t1_workers,
                t1_limiter.rate(),
                t1_limiter.rate() / t1_workers.max(1) as f64
            );
            for i in 0..t1_workers {
                let tenant = t1.clone();
                // Each worker gets an equal share of the tenant's request rate.
                // Summed across workers this yields exactly the configured ops/sec.
                let adjusted_rate = if t1_limiter.rate().is_infinite() {
                    0.0
                } else {
                    t1_limiter.rate() / t1_workers as f64
                };

                // Every worker in the phase shares one time origin, so their intended
                // dispatch times form a single coherent schedule.
                let mut schedule = OperationSchedule::new(phase_start, adjusted_rate);
                let dur = duration;

                if i < t1_pod_workers {
                    handles.push(tokio::spawn(async move {
                        let assessor =
                            FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                                max_workers: 1,
                            });
                        assessor
                            .run_stress_test_on_pod(&tenant, dur, &mut schedule, i)
                            .await
                    }));
                } else {
                    handles.push(tokio::spawn(async move {
                        let assessor =
                            FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                                max_workers: 1,
                            });
                        assessor
                            .run_stress_test_on_configmap(&tenant, dur, &mut schedule, i)
                            .await
                    }));
                }
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
                "Starting tenant2: {} workers, {:.2} ops/sec total ({:.2} per worker)",
                t2_workers,
                t2_limiter.rate(),
                t2_limiter.rate() / t2_workers.max(1) as f64
            );
            for i in 0..t2_workers {
                let tenant = t2.clone();
                // Each worker gets an equal share of the tenant's request rate.
                // Summed across workers this yields exactly the configured ops/sec.
                let adjusted_rate = if t2_limiter.rate().is_infinite() {
                    0.0
                } else {
                    t2_limiter.rate() / t2_workers as f64
                };

                // Every worker in the phase shares one time origin, so their intended
                // dispatch times form a single coherent schedule.
                let mut schedule = OperationSchedule::new(phase_start, adjusted_rate);
                let dur = duration;

                if i < t2_pod_workers {
                    handles.push(tokio::spawn(async move {
                        let assessor =
                            FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                                max_workers: 1,
                            });
                        assessor
                            .run_stress_test_on_pod(&tenant, dur, &mut schedule, i)
                            .await
                    }));
                } else {
                    handles.push(tokio::spawn(async move {
                        let assessor =
                            FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                                max_workers: 1,
                            });
                        assessor
                            .run_stress_test_on_configmap(&tenant, dur, &mut schedule, i)
                            .await
                    }));
                }
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

    fn configuration(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "max_workers": self.config.max_workers,
            // Pod readiness is deliberately not awaited: this measures API
            // admission latency, not scheduling or container start.
            "measures": "api admission latency only",
        }))
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
            ((self.config.max_workers as f64 * config.malicious_pod_multiplier) as usize).max(1);

        // The intruder's *total* offered rate is escalated by both multipliers,
        // matching the "Nx effective load" the runner prints, which is their
        // product.
        //
        // Adding workers alone cannot do it: `run_phase` splits a tenant's rate
        // evenly across its workers, so the count cancels out and ten workers
        // sharing 20 ops/s still offer 20 ops/s. That left `podMultiplier` a
        // no-op for the control plane — with the default `loadMultiplier` of 1.0
        // the intruder ran at exactly the owner's rate and no contention was
        // induced at all. Scaling the total here keeps the per-worker rate equal
        // to the baseline's, so each extra worker genuinely adds load.
        let malicious_rate = config.malicious_rate() * config.malicious_pod_multiplier;
        let malicious_limiter = RateLimiter::new(config.strategy, malicious_rate);

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            config.tenant1_limiter(),
            malicious_limiter,
            self.config.max_workers,
            malicious_workers,
        )
        .await
    }
}
