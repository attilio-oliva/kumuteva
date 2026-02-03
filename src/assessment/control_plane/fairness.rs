//! Control Plane Fairness Assessor
//!
//! Simplified implementation using the unified fairness framework.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{DeleteParams, PostParams};
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

    /// Run workload for a single tenant
    async fn run_tenant(
        &self,
        tenant: &TenantClusterConfig,
        duration: Duration,
        rate_limiter: &RateLimiter,
        worker_id: usize,
    ) -> Result<Vec<MetricPoint>> {
        let api: Api<ConfigMap> =
            Api::namespaced(tenant.cluster.client().clone(), &tenant.namespace);
        let start_time = Instant::now();
        let deadline = start_time + duration;
        let mut points = Vec::new();
        let mut counter = 0u64;

        while Instant::now() < deadline {
            // Wait for rate limiter
            rate_limiter.wait().await;

            let name = format!("fairness-test-{}-{}", worker_id, counter);
            let timestamp = start_time.elapsed().as_secs_f64();

            // Create ConfigMap
            let cm = ConfigMap {
                metadata: kube::api::ObjectMeta {
                    name: Some(name.clone()),
                    namespace: Some(tenant.namespace.clone()),
                    ..Default::default()
                },
                data: Some([("key".to_string(), "value".to_string())].into()),
                ..Default::default()
            };

            let op_start = Instant::now();
            let result = api.create(&PostParams::default(), &cm).await;
            let latency = op_start.elapsed().as_secs_f64() * 1000.0;

            points.push(MetricPoint {
                timestamp_secs: timestamp,
                latency_ms: latency,
                is_error: result.is_err(),
                label: Some(format!("create-{}", name)),
            });

            // Delete ConfigMap (cleanup)
            if result.is_ok() {
                let _ = api.delete(&name, &DeleteParams::default()).await;
            }

            counter += 1;
        }

        Ok(points)
    }

    /// Run phase with specified configuration
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_limiter: RateLimiter,
        t2_limiter: RateLimiter,
    ) -> Result<PhaseResult> {
        // Run both tenants concurrently
        let t1 = tenant1.clone();
        let t2 = tenant2.clone();
        let workers = self.config.workers;

        let t1_handle = tokio::spawn(async move {
            let mut all_points = Vec::new();
            let mut handles = Vec::new();

            // Spawn worker tasks for tenant1
            for i in 0..workers {
                let tenant = t1.clone();
                let limiter = RateLimiter::new(t1_limiter.strategy, t1_limiter.rate());
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
            for i in 0..workers {
                let tenant = t2.clone();
                let limiter = RateLimiter::new(t2_limiter.strategy, t2_limiter.rate());
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
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            config.tenant1_limiter(),
            config.tenant2_malicious_limiter(),
        )
        .await
    }
}
