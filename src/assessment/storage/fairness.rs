//! Storage Fairness Assessor
//!
//! Measures storage I/O latency using fio benchmark pods.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Storage test scenario
#[derive(Debug, Clone, Copy, Default)]
pub enum FairnessStorageScenario {
    #[default]
    RandomIO,
    SequentialIO,
}

/// Storage assessor configuration
#[derive(Debug, Clone)]
pub struct FairnessStorageConfig {
    /// Number of fio benchmark pods per tenant
    pub pods: u32,
    /// I/O block size in KB
    pub block_size_kb: u32,
    /// Test file size in MB
    pub file_size_mb: u32,
    /// Test scenario (random or sequential I/O)
    pub scenario: FairnessStorageScenario,
}

impl Default for FairnessStorageConfig {
    fn default() -> Self {
        Self {
            pods: 1,
            block_size_kb: 4,
            file_size_mb: 100,
            scenario: FairnessStorageScenario::RandomIO,
        }
    }
}

// =============================================================================
// ASSESSOR
// =============================================================================

/// Storage fairness assessor using fio
pub struct FairnessStorageAssessor {
    config: FairnessStorageConfig,
}

impl FairnessStorageAssessor {
    pub fn new(config: FairnessStorageConfig) -> Self {
        Self { config }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_pods: u32,
        t2_pods: u32,
        t1_rate_iops: Option<u32>,
        t2_rate_iops: Option<u32>,
    ) -> Result<PhaseResult> {
        let duration_secs = duration.as_secs();

        // Create all benchmark pods in parallel across tenants
        let config1 = self.config.clone();
        let config2 = self.config.clone();
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            create_fio_pods(&t1_clone, t1_pods, &config1, duration_secs, t1_rate_iops),
            create_fio_pods(&t2_clone, t2_pods, &config2, duration_secs, t2_rate_iops)
        )?;

        // Wait for completion in parallel across tenants
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            wait_for_completion(&t1_clone, t1_pods),
            wait_for_completion(&t2_clone, t2_pods)
        )?;

        // Collect results
        let t1_points = collect_results(&tenant1, t1_pods).await?;
        let t2_points = collect_results(&tenant2, t2_pods).await?;

        // Cleanup
        cleanup_pods(&tenant1, t1_pods).await?;
        cleanup_pods(&tenant2, t2_pods).await?;

        Ok(PhaseResult {
            tenant1: TenantMetrics::from_raw(t1_points),
            tenant2: TenantMetrics::from_raw(t2_points),
        })
    }
}

#[async_trait]
impl FairnessAssessor for FairnessStorageAssessor {
    fn name(&self) -> &'static str {
        "Storage"
    }

    fn metric(&self) -> &'static str {
        "I/O latency"
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let rate_iops = rate_to_iops(config.tenant1_rate);

        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pods,
            self.config.pods,
            rate_iops,
            rate_iops,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let t1_iops = rate_to_iops(config.tenant1_rate);
        let t2_iops = rate_to_iops(config.malicious_rate());
        let malicious_pods = (self.config.pods as f64 * config.malicious_load_multiplier) as u32;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pods,
            malicious_pods.max(1),
            t1_iops,
            t2_iops,
        )
        .await
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn rate_to_iops(rate: f64) -> Option<u32> {
    if rate <= 0.0 {
        None
    } else {
        Some(rate as u32)
    }
}

fn fio_pod(
    index: u32,
    config: &FairnessStorageConfig,
    duration_secs: u64,
    rate_iops: Option<u32>,
) -> Pod {
    let rate_param = rate_iops
        .map(|r| format!(" --rate_iops={}", r))
        .unwrap_or_default();

    let (job_name, extra_args) = match config.scenario {
        FairnessStorageScenario::RandomIO => (
            "random-rw",
            "--ioengine=libaio --iodepth=4 --rw=randrw --rwmixread=50 --direct=1",
        ),
        FairnessStorageScenario::SequentialIO => ("seq-rw", "--ioengine=sync --rw=rw"),
    };

    let command = format!(
        "apk add --no-cache fio && \
         mkdir -p /data && \
         fio --name={} {} \
         --bs={}k --size={}m --numjobs=1 \
         --runtime={} --time_based=1 --group_reporting=1 \
         --filename=/data/fio-test-file \
         --output-format=json{} 2>&1",
        job_name, extra_args, config.block_size_kb, config.file_size_mb, duration_secs, rate_param
    );

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("storage-fairness-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "fio",
                "image": "alpine:latest",
                "command": ["sh", "-c", command],
                "volumeMounts": [{
                    "name": "data",
                    "mountPath": "/data"
                }],
                "resources": {
                    "requests": { "memory": "128Mi", "cpu": "100m" },
                    "limits": { "memory": "512Mi", "cpu": "500m" }
                }
            }],
            "volumes": [{
                "name": "data",
                "emptyDir": { "sizeLimit": format!("{}Mi", config.file_size_mb * 2) }
            }]
        }
    }))
    .unwrap()
}

/// Create all fio pods for a tenant in parallel
async fn create_fio_pods(
    tenant: &TenantClusterConfig,
    pods: u32,
    config: &FairnessStorageConfig,
    duration_secs: u64,
    rate_iops: Option<u32>,
) -> Result<()> {
    // First, create all pods without waiting
    let mut pod_names = Vec::new();
    for i in 0..pods {
        let pod = fio_pod(i, config, duration_secs, rate_iops);
        let name = pod.metadata.name.clone().unwrap();
        tenant
            .cluster
            .create_pod_in_namespace(&pod, &tenant.namespace)
            .await?;
        pod_names.push(name);
    }

    // Then wait for all pods to be ready (they start executing immediately)
    for name in pod_names {
        tenant
            .cluster
            .wait_for_pod_to_be_ready(&name, &tenant.namespace)
            .await?;
    }

    Ok(())
}

async fn wait_for_completion(tenant: &TenantClusterConfig, pods: u32) -> Result<()> {
    use futures::{StreamExt, TryStreamExt};
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::WatchParams;
    use kube::Api;

    let api: Api<Pod> = Api::namespaced(tenant.cluster.client().clone(), &tenant.namespace);

    for i in 0..pods {
        let name = format!("storage-fairness-{}", i);

        // Helper to check if pod is completed
        let is_completed = |pod: &Pod| -> bool {
            pod.status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| p == "Succeeded" || p == "Failed")
                .unwrap_or(false)
        };

        // First check if pod already completed (avoid race with watch)
        if let Ok(pod) = api.get(&name).await {
            if is_completed(&pod) {
                continue;
            }
        }

        // Watch for completion
        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", name))
            .timeout(290);

        let mut stream = api.watch(&lp, "0").await?.boxed();

        while let Some(event) = stream.try_next().await? {
            match event {
                kube::api::WatchEvent::Modified(pod) => {
                    if is_completed(&pod) {
                        break;
                    }
                }
                _ => {
                    // On any other event (Bookmark, Added, etc.), check pod status directly
                    if let Ok(pod) = api.get(&name).await {
                        if is_completed(&pod) {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn collect_results(tenant: &TenantClusterConfig, pods: u32) -> Result<Vec<MetricPoint>> {
    let mut points = Vec::new();

    for i in 0..pods {
        let name = format!("storage-fairness-{}", i);
        let logs = tenant
            .cluster
            .get_pod_logs(&name, &tenant.namespace)
            .await?;

        if let Some(latency) = parse_fio_latency(&logs) {
            points.push(MetricPoint {
                timestamp_secs: 0.0,
                latency_ms: latency,
                is_error: false,
                label: Some(format!("fio-{}", i)),
            });
        }
    }

    Ok(points)
}

fn parse_fio_latency(logs: &str) -> Option<f64> {
    let json_start = logs.find('{')?;
    let json_end = logs.rfind('}')?;
    let json_str = &logs[json_start..=json_end];

    let v: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // Try to get clat (completion latency) from jobs
    if let Some(jobs) = v["jobs"].as_array() {
        if let Some(job) = jobs.first() {
            // Try read latency
            if let Some(mean) = job["read"]["clat_ns"]["mean"].as_f64() {
                if mean > 0.0 {
                    return Some(mean / 1_000_000.0); // ns to ms
                }
            }
            // Try write latency
            if let Some(mean) = job["write"]["clat_ns"]["mean"].as_f64() {
                if mean > 0.0 {
                    return Some(mean / 1_000_000.0);
                }
            }
        }
    }

    None
}

async fn cleanup_pods(tenant: &TenantClusterConfig, pods: u32) -> Result<()> {
    // First, initiate deletion for all pods
    for i in 0..pods {
        let name = format!("storage-fairness-{}", i);
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&name, &tenant.namespace)
            .await;
    }

    // Then, wait for all pods to be fully deleted to avoid "AlreadyExists" errors
    // when creating new pods with the same names in subsequent phases
    for i in 0..pods {
        let name = format!("storage-fairness-{}", i);
        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&name, &tenant.namespace)
            .await;
    }

    Ok(())
}
