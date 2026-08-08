//! Storage Fairness Assessor
//!
//! Measures storage I/O latency using fio benchmark pods.

use std::sync::Arc;
use std::time::Duration;

/// Timeout for waiting on pod deletion during cleanup (prevents hanging)
const POD_DELETION_TIMEOUT_SECS: u64 = 60;

/// Timeout for waiting on PVC deletion. Longer than the pod timeout because the
/// claim cannot start terminating until its pod is gone, and the provisioner
/// then has to release the underlying volume.
const PVC_DELETION_TIMEOUT_SECS: u64 = 120;

/// Resources for an fio pod.
///
/// The limit is a full core: a half-core cap starves the I/O submission path
/// and the measured latency then reflects cfs throttling rather than storage
/// contention, which is what capped the published campaign at ~78k IOPS.
///
/// The *request* is deliberately far lower. Requests are what the scheduler
/// subtracts from node capacity, and a KubeVirt tenant is a pair of small VMs —
/// ten intruder pods requesting a full core each cannot be placed there at all,
/// however idle the host underneath. Asking for little and being allowed a lot
/// keeps every solution runnable under one configuration.
const FIO_CPU_REQUEST_MILLIS: u32 = 100;
const FIO_CPU_LIMIT_MILLIS: u32 = 1000;
const FIO_MEMORY_REQUEST_MI: u32 = 128;
const FIO_MEMORY_LIMIT_MI: u32 = 512;

/// Resources for an fio pod under `qos`.
///
/// Guaranteed pins requests to the limits, so the request constants above only
/// take effect for Burstable — which is exactly why they are set low.
fn fio_resources(qos: QosClass) -> PodResources {
    match qos {
        QosClass::Guaranteed => PodResources::uniform(FIO_CPU_LIMIT_MILLIS, FIO_MEMORY_LIMIT_MI),
        _ => PodResources::burstable(
            FIO_CPU_REQUEST_MILLIS,
            FIO_CPU_LIMIT_MILLIS,
            FIO_MEMORY_REQUEST_MI,
            FIO_MEMORY_LIMIT_MI,
        ),
    }
}

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use tracing::warn;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, PodResources, QosClass,
    TenantMetrics,
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

/// Which storage path the benchmark exercises.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FairnessStorageVolume {
    /// Node-local ephemeral storage.
    ///
    /// Useful as a floor for node-level I/O contention, but it is *not* the
    /// subsystem the tenancy model is defined over: it bypasses the PV/PVC
    /// abstraction entirely and never touches the CSI driver or the backend.
    #[default]
    EmptyDir,
    /// A dynamically provisioned PersistentVolumeClaim — the real tenant path.
    Pvc,
}

impl std::fmt::Display for FairnessStorageVolume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FairnessStorageVolume::EmptyDir => write!(f, "emptyDir"),
            FairnessStorageVolume::Pvc => write!(f, "pvc"),
        }
    }
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
    /// Outstanding I/Os per fio job, for the libaio random scenario.
    ///
    /// This is a *ceiling* on in-flight requests, not a driver of load: by
    /// Little's law the queue actually occupied is `rate x latency`, so at a
    /// rate-capped offered load a deeper queue changes nothing. It matters at
    /// saturation, where latency rises and occupancy climbs to meet the ceiling
    /// — at which point too shallow a depth throttles the intruder exactly when
    /// it should be flooding the device, and makes `achieved < target`
    /// ambiguous between a saturated disk and an exhausted fio queue.
    ///
    /// The sequential scenario uses the synchronous ioengine, where the notion
    /// does not apply.
    pub iodepth: u32,
    /// Storage path under test: node-local ephemeral, or the PV/CSI path
    pub volume: FairnessStorageVolume,
    /// StorageClass for the PVC mode; `None` uses the cluster default
    pub storage_class_name: Option<String>,
    /// QoS class for fio pods. Guaranteed by default so the benchmark is not
    /// throttled by its own cfs quota.
    pub qos_class: QosClass,
    /// RuntimeClass for fio pods (e.g. a gVisor or Kata sandbox)
    pub runtime_class_name: Option<String>,
}

impl Default for FairnessStorageConfig {
    fn default() -> Self {
        Self {
            pods: 1,
            block_size_kb: 4,
            file_size_mb: 100,
            scenario: FairnessStorageScenario::RandomIO,
            iodepth: 4,
            volume: FairnessStorageVolume::default(),
            storage_class_name: None,
            qos_class: QosClass::Guaranteed,
            runtime_class_name: None,
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

        // Clear anything a previous, possibly interrupted, run left behind.
        // Without this a single failed run makes every later one fail at create.
        cleanup_leftovers(&tenant1, t1_pods, &self.config).await;
        cleanup_leftovers(&tenant2, t2_pods, &self.config).await;

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
        cleanup_pods(&tenant1, t1_pods, &self.config).await?;
        cleanup_pods(&tenant2, t2_pods, &self.config).await?;

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

    fn configuration(&self) -> Option<serde_json::Value> {
        // `volume` above all: nothing else in a result set distinguishes the
        // real CSI path from node-local ephemeral storage, and they measure
        // different subsystems.
        Some(serde_json::json!({
            "volume": self.config.volume.to_string(),
            "storage_class_name": self.config.storage_class_name,
            "pods": self.config.pods,
            "block_size_kb": self.config.block_size_kb,
            "file_size_mb": self.config.file_size_mb,
            "scenario": format!("{:?}", self.config.scenario),
            "iodepth": self.config.iodepth,
            "qos_class": self.config.qos_class.to_string(),
            "runtime_class_name": self.config.runtime_class_name,
        }))
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
        let malicious_pods = (self.config.pods as f64 * config.malicious_pod_multiplier) as u32;

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

/// Convert a configured operation rate into a *total* IOPS target.
///
/// Rounds rather than truncating: `rate as u32` turned any sub-1 rate into 0,
/// which fio reads as "no cap" — the opposite of the intent.
fn rate_to_iops(rate: f64) -> Option<u32> {
    if rate <= 0.0 || !rate.is_finite() {
        None
    } else {
        Some(rate.round().max(1.0) as u32)
    }
}

/// Build fio's `--rate_iops` argument for a mixed read/write workload.
///
/// fio applies a single `--rate_iops` value to each data direction separately,
/// so `--rate_iops=N` on a 50/50 `randrw` job caps reads at N *and* writes at N,
/// delivering 2N IOPS in total. The reference campaign configured 10 000 and
/// measured exactly 20 000 ops/s because of this. Splitting the total across the
/// two directions makes the configured rate mean what it says.
fn rate_iops_argument(total_iops: Option<u32>) -> String {
    match total_iops {
        None => String::new(),
        Some(total) => {
            let read = total / 2;
            let write = total - read;
            format!(" --rate_iops={},{}", read.max(1), write.max(1))
        }
    }
}

fn fio_pod(
    index: u32,
    config: &FairnessStorageConfig,
    duration_secs: u64,
    rate_iops: Option<u32>,
) -> Pod {
    let rate_param = rate_iops_argument(rate_iops);

    let (job_name, extra_args) = match config.scenario {
        FairnessStorageScenario::RandomIO => (
            "random-rw",
            format!(
                "--ioengine=libaio --iodepth={} --rw=randrw --rwmixread=50 --direct=1",
                config.iodepth.max(1)
            ),
        ),
        FairnessStorageScenario::SequentialIO => ("seq-rw", "--ioengine=sync --rw=rw".to_string()),
    };

    // Use --write_lat_log to capture per-IO latencies
    // Log format: time (msec), latency (nsec), direction (0=read, 1=write), block size, offset, command priority
    // After fio completes, we cat the latency logs and prefix with LATLOG: for easy parsing
    let command = format!(
        "apk add --no-cache fio && \
         mkdir -p /data && \
         fio --name={} {} \
         --bs={}k --size={}m --numjobs=1 \
         --runtime={} --time_based=1 \
         --filename=/data/fio-test-file \
         --write_lat_log=/data/latency \
         --log_avg_msec=0 {} 2>&1 && \
         echo 'LATLOG_START' && \
         cat /data/latency_clat.*.log 2>/dev/null || cat /data/latency_clat.log 2>/dev/null || echo 'NO_LAT_LOG' && \
         echo 'LATLOG_END'",
        job_name, extra_args, config.block_size_kb, config.file_size_mb, duration_secs, rate_param
    );

    // In PVC mode the pod mounts the claim created alongside it, so the I/O
    // traverses the CSI driver and the storage backend. In emptyDir mode it stays
    // on the node's ephemeral filesystem.
    let volume = match config.volume {
        FairnessStorageVolume::EmptyDir => serde_json::json!({
            "name": "data",
            "emptyDir": { "sizeLimit": format!("{}Mi", config.file_size_mb * 2) }
        }),
        FairnessStorageVolume::Pvc => serde_json::json!({
            "name": "data",
            "persistentVolumeClaim": { "claimName": fio_claim_name(index) }
        }),
    };

    let mut pod = serde_json::json!({
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
            }],
            "volumes": [volume]
        }
    });

    // Previously this pod requested 100m and capped at 500m CPU, which made it
    // Burstable by accident and throttled the very I/O benchmark it was running:
    // a half-core cap starves the submission path and the measured latency then
    // reflects cfs throttling rather than storage contention. Guaranteed with a
    // full core by default.
    config.qos_class.apply_to_pod(
        &mut pod,
        &fio_resources(config.qos_class),
        config.runtime_class_name.as_deref(),
    );

    serde_json::from_value(pod).unwrap()
}

/// Name of the claim backing fio pod `index`.
fn fio_claim_name(index: u32) -> String {
    format!("storage-fairness-claim-{}", index)
}

/// A PersistentVolumeClaim sized to hold the fio test file with headroom.
///
/// One claim per pod rather than one shared per tenant: co-resident pods writing
/// through separate claims contend at the backend, which is the interference the
/// storage subsystem is supposed to be tested for. A single shared claim would
/// additionally serialise them at the volume and confound the two effects.
fn fio_claim(index: u32, config: &FairnessStorageConfig) -> PersistentVolumeClaim {
    let mut spec = serde_json::json!({
        "accessModes": ["ReadWriteOnce"],
        "resources": {
            "requests": { "storage": format!("{}Mi", (config.file_size_mb * 2).max(64)) }
        }
    });
    if let Some(class) = &config.storage_class_name {
        spec["storageClassName"] = serde_json::json!(class);
    }

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": fio_claim_name(index),
            "labels": { "kumuteva.io/test": "storage-fairness" }
        },
        "spec": spec
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
    // Claims must exist and bind before the pods that mount them are scheduled.
    // Provisioning happens outside the measured window: fio's own --write_lat_log
    // timestamps start when fio starts, so bind latency cannot leak into the
    // reported numbers.
    if config.volume == FairnessStorageVolume::Pvc {
        for i in 0..pods {
            let claim = fio_claim(i, config);
            tenant
                .cluster
                .create_namespaced_resource(&claim, &tenant.namespace)
                .await?;
        }
    }

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
    let mut empty = Vec::new();

    for i in 0..pods {
        let name = format!("storage-fairness-{}", i);
        let logs = tenant
            .cluster
            .get_pod_logs(&name, &tenant.namespace)
            .await?;

        let pod_points = parse_fio_latency_log(&logs, i);
        if pod_points.is_empty() {
            empty.push(name);
        }
        points.extend(pod_points);
    }

    // A pod that produced no samples is missing data, not a pod that was idle:
    // fio always writes a latency log. Failing here is deliberate, because the
    // alternative is silent corruption — a phase whose owner contributed nothing
    // yields a mean of 0, which `calculate_degradation` turns into delta = 0.00
    // and the summary then prints as "Excellent". Three of five runs in the
    // first corrected campaign reported exactly that.
    //
    // The usual cause is container log rotation. fio emits one line per I/O, so
    // 10k IOPS over 60 s is ~600k lines, roughly 20 MB — more than the 10 Mi
    // Kubernetes keeps by default. Once the rotation drops the `LATLOG_START`
    // marker the parser cannot find the section and returns nothing at all,
    // which is why losses appear as whole pods rather than truncated tails.
    if !empty.is_empty() {
        anyhow::bail!(
            "no fio samples from {} of {} pod(s) in {} ({}). \
             The latency log is most likely being truncated by container log \
             rotation; raise containerLogMaxSize on the node, or lower the \
             storage rate or phase duration.",
            empty.len(),
            pods,
            tenant.namespace,
            empty.join(", ")
        );
    }

    Ok(points)
}

/// Parse fio latency log output
/// Log format: time (msec), latency (nsec), direction (0=read, 1=write), block size, offset, command priority
fn parse_fio_latency_log(logs: &str, pod_index: u32) -> Vec<MetricPoint> {
    let mut points = Vec::new();

    // Find the latency log section between LATLOG_START and LATLOG_END
    let start_marker = "LATLOG_START";
    let end_marker = "LATLOG_END";

    let start_pos = match logs.find(start_marker) {
        Some(pos) => pos + start_marker.len(),
        None => return points,
    };

    let end_pos = match logs[start_pos..].find(end_marker) {
        Some(pos) => start_pos + pos,
        None => logs.len(),
    };

    let log_section = &logs[start_pos..end_pos];

    // Parse each line: time_msec, latency_nsec, direction, block_size, offset, ...
    for line in log_section.lines() {
        let line = line.trim();
        if line.is_empty() || line == "NO_LAT_LOG" {
            continue;
        }

        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 2 {
            // First field: time in milliseconds since start
            // Second field: latency in nanoseconds
            if let (Ok(time_ms), Ok(latency_ns)) =
                (parts[0].parse::<f64>(), parts[1].parse::<f64>())
            {
                // Third field is the data direction. A mixed randrw job emits both,
                // and read and write latency differ by a wide margin on a network
                // or CSI-backed volume, so pooling them into one mean produces a
                // mixture whose composition can shift between phases. Keep the
                // direction in the label so the two can be separated downstream.
                let direction = parts
                    .get(2)
                    .and_then(|d| d.parse::<u8>().ok())
                    .map(|d| match d {
                        0 => "read",
                        1 => "write",
                        2 => "trim",
                        _ => "other",
                    })
                    .unwrap_or("unknown");

                points.push(MetricPoint {
                    // Pacing happens inside the pod, so there is no dispatch schedule to
                    // measure against: the recorded latency is already the service time.
                    scheduled_latency_ms: None,
                    timestamp_secs: time_ms / 1000.0, // Convert ms to seconds
                    latency_ms: latency_ns / 1_000_000.0, // Convert ns to ms
                    is_error: false,
                    label: Some(format!("fio-{}-{}", direction, pod_index)),
                });
            }
        }
    }

    points
}

async fn cleanup_pods(
    tenant: &TenantClusterConfig,
    pods: u32,
    config: &FairnessStorageConfig,
) -> Result<()> {
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
    // Use timeout to prevent hanging if pods are stuck in Terminating state
    for i in 0..pods {
        let name = format!("storage-fairness-{}", i);
        let _ = tokio::time::timeout(
            Duration::from_secs(POD_DELETION_TIMEOUT_SECS),
            tenant
                .cluster
                .wait_for_pod_deletion(&name, &tenant.namespace),
        )
        .await;
    }

    // Claims are removed only after their pods are gone — a bound PVC cannot be
    // deleted while still mounted. Leaving them behind would let the next phase
    // inherit a warmed volume, and would leak PVs when the StorageClass retains.
    if config.volume == FairnessStorageVolume::Pvc {
        delete_claims(tenant, pods).await;
    }

    Ok(())
}

/// Delete the fio claims and wait until they are actually gone.
///
/// Waiting is the point. `delete` on a PVC only marks it: the
/// `kubernetes.io/pvc-protection` finalizer holds the object until every pod
/// mounting it has terminated, and the object lingers in `Terminating` for some
/// time afterwards. Issuing the delete and returning immediately meant the next
/// run reached `create` while the claim still existed and failed with
/// `AlreadyExists: persistentvolumeclaims "storage-fairness-claim-0"`, which
/// aborted the whole invocation — taking the workload subsystem with it.
///
/// Failures are logged rather than swallowed. The previous `let _ =` hid the
/// difference between "deleted" and "the API rejected the request", which is
/// exactly the information needed when the next run cannot create the claim.
async fn delete_claims(tenant: &TenantClusterConfig, pods: u32) {
    for i in 0..pods {
        let name = fio_claim_name(i);
        if let Err(error) = tenant
            .cluster
            .delete_resource_in_namespace::<PersistentVolumeClaim>(&name, &tenant.namespace)
            .await
        {
            // Not found is the normal case when nothing was left behind.
            let message = error.to_string();
            if !message.contains("NotFound") && !message.contains("not found") {
                warn!("could not delete PVC {name}: {message}");
            }
            continue;
        }

        match tokio::time::timeout(
            Duration::from_secs(PVC_DELETION_TIMEOUT_SECS),
            tenant
                .cluster
                .wait_for_namespaced_resource_deletion::<PersistentVolumeClaim>(
                    &name,
                    &tenant.namespace,
                ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!("error while awaiting deletion of PVC {name}: {error}"),
            Err(_) => warn!(
                "PVC {name} still present after {PVC_DELETION_TIMEOUT_SECS}s; \
                 a later run may fail with AlreadyExists"
            ),
        }
    }
}

/// Remove anything a previous run left behind before creating new objects.
///
/// A run killed part-way — Ctrl-C, an OOM, a failure in another subsystem —
/// leaves its pods and claims in place, and every later run then fails at
/// `create`. The control-plane assessor already clears its own resources at the
/// start of a phase for this reason; storage did not, so a single interrupted
/// run poisoned the namespace until it was cleaned by hand.
async fn cleanup_leftovers(
    tenant: &TenantClusterConfig,
    pods: u32,
    config: &FairnessStorageConfig,
) {
    if let Err(error) = cleanup_pods(tenant, pods, config).await {
        warn!("pre-run cleanup for {} reported: {error}", tenant.namespace);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fio caps each data direction independently, so a single `--rate_iops=N`
    /// on a 50/50 randrw job delivers 2N IOPS. The reference campaign configured
    /// 10 000 and measured exactly 20 000 ops/s as a result.
    #[test]
    fn rate_iops_argument_splits_across_directions() {
        assert_eq!(
            rate_iops_argument(Some(10_000)),
            " --rate_iops=5000,5000",
            "a 10k total must be split, not applied twice"
        );
        // Odd totals keep the sum exact rather than rounding both halves.
        assert_eq!(rate_iops_argument(Some(101)), " --rate_iops=50,51");
        // A cap of 1 must not degrade into 0, which fio reads as "uncapped".
        assert_eq!(rate_iops_argument(Some(1)), " --rate_iops=1,1");
        assert_eq!(rate_iops_argument(None), "");
    }

    #[test]
    fn rate_to_iops_rounds_instead_of_truncating() {
        // `rate as u32` truncated sub-1 rates to 0, which fio treats as no cap —
        // the opposite of what a low configured rate asks for.
        assert_eq!(rate_to_iops(0.4), Some(1));
        assert_eq!(rate_to_iops(0.6), Some(1));
        assert_eq!(rate_to_iops(9.7), Some(10));
        assert_eq!(rate_to_iops(0.0), None);
        assert_eq!(rate_to_iops(-5.0), None);
        assert_eq!(rate_to_iops(f64::NAN), None);
        assert_eq!(rate_to_iops(f64::INFINITY), None);
    }

    /// Read and write latency differ widely on a CSI-backed volume, so the two
    /// directions must stay separable rather than being pooled into one mean.
    #[test]
    fn fio_log_parser_preserves_io_direction() {
        let log = "\
LATLOG_START
1000, 250000, 0, 4096, 0
1001, 900000, 1, 4096, 4096
1002, 300000, 2, 4096, 8192
LATLOG_END";
        let points = parse_fio_latency_log(log, 7);
        assert_eq!(points.len(), 3);

        let labels: Vec<&str> = points.iter().map(|p| p.label.as_deref().unwrap()).collect();
        assert_eq!(labels, ["fio-read-7", "fio-write-7", "fio-trim-7"]);

        // ms -> s for the timestamp, ns -> ms for the latency.
        assert!((points[0].timestamp_secs - 1.0).abs() < 1e-9);
        assert!((points[0].latency_ms - 0.25).abs() < 1e-9);
        assert!((points[1].latency_ms - 0.9).abs() < 1e-9);

        // Pod-side pacing means there is no dispatch schedule to correct against.
        assert!(points.iter().all(|p| p.scheduled_latency_ms.is_none()));
    }

    #[test]
    fn fio_log_parser_tolerates_missing_or_malformed_sections() {
        assert!(parse_fio_latency_log("no markers here", 0).is_empty());
        assert!(parse_fio_latency_log("LATLOG_START\nNO_LAT_LOG\nLATLOG_END", 0).is_empty());
        // A truncated line without a direction column still yields a point.
        let points = parse_fio_latency_log("LATLOG_START\n5, 1000000\nLATLOG_END", 3);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].label.as_deref(), Some("fio-unknown-3"));
    }

    #[test]
    fn pvc_mode_mounts_a_claim_and_emptydir_does_not() {
        let pvc_config = FairnessStorageConfig {
            volume: FairnessStorageVolume::Pvc,
            storage_class_name: Some("fast-ssd".into()),
            ..Default::default()
        };
        let pod = fio_pod(2, &pvc_config, 30, Some(100));
        let volume = &pod.spec.as_ref().unwrap().volumes.as_ref().unwrap()[0];
        assert_eq!(
            volume
                .persistent_volume_claim
                .as_ref()
                .map(|c| c.claim_name.as_str()),
            Some("storage-fairness-claim-2")
        );
        assert!(volume.empty_dir.is_none());

        let claim = fio_claim(2, &pvc_config);
        assert_eq!(
            claim.spec.as_ref().unwrap().storage_class_name.as_deref(),
            Some("fast-ssd")
        );

        // Without an explicit class the cluster default must apply, so the field
        // has to be absent rather than set to an empty string.
        let default_class = FairnessStorageConfig {
            volume: FairnessStorageVolume::Pvc,
            ..Default::default()
        };
        assert!(fio_claim(0, &default_class)
            .spec
            .as_ref()
            .unwrap()
            .storage_class_name
            .is_none());

        let ephemeral = FairnessStorageConfig::default();
        let pod = fio_pod(0, &ephemeral, 30, None);
        let volume = &pod.spec.as_ref().unwrap().volumes.as_ref().unwrap()[0];
        assert!(volume.empty_dir.is_some());
        assert!(volume.persistent_volume_claim.is_none());
    }
}
