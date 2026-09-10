mod assessment;
mod cluster;
mod commands;
mod external_crds;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context};
use assessment::TenantClusterConfig;
use clap::{Parser, Subcommand, ValueEnum};
use cluster::TenantsPortMapping;
use cluster::{
    ClusterProfile, CniPlugin, ControlPlaneIsolation, DataPlaneIsolation, KindCluster,
    KubernetesClient, KubernetesClusterBuilder, NetworkIsolationStrategy, SandboxRuntime,
    StorageIsolationStrategy,
};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};
use serde::Deserialize;
use tracing::Level;

use crate::assessment::fairness_assessor::{
    QosClass, RateLimitStrategy as FairnessRateLimitStrategy,
};
use crate::assessment::{FairnessStorageScenario, FairnessStorageVolume, FairnessWorkloadNoise};

use crate::cluster::{HostClusterType, K3sCluster, PreExistingCluster};

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULTS & CONFIGURATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

mod defaults {
    use super::{RateLimitStrategy, StorageScenario, StorageVolumeMode};

    // We define STR variants for clap help text (concat! macro requires literals/str constants)
    // and typed variants for actual logic.

    pub const BASELINE_DURATION: u64 = 30;
    pub const TEST_DURATION: u64 = 60;

    pub const RATE_STRATEGY: RateLimitStrategy = RateLimitStrategy::FixedDelay;

    pub const RATE: f64 = 10.0;
    pub const LOAD_MULT: f64 = 1.0;
    pub const POD_MULT: f64 = 10.0;

    // Subsystem defaults
    pub const CP_REQUESTERS: usize = 1;

    pub const WL_PODS: u32 = 1;
    pub const WL_THREADS: u32 = 1;
    pub const WL_PRIME: u32 = 500_000;

    pub const NET_POD_PAIRS: u32 = 1;
    pub const NET_STREAMS: u32 = 4;
    pub const NET_PACKET_SIZE: u32 = 512;

    pub const ST_PODS: u32 = 1;
    pub const ST_BLOCK_SIZE: u32 = 4;
    pub const ST_FILE_SIZE: u32 = 100;
    pub const ST_IODEPTH: u32 = 4;
    pub const ST_SCENARIO: StorageScenario = StorageScenario::Random;
    pub const ST_VOLUME: StorageVolumeMode = StorageVolumeMode::EmptyDir;

    pub const OUTPUT_DIR: &str = "fairness_results";
}

// ═══════════════════════════════════════════════════════════════════════════
// TYPES & ENUMS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ClusterEnvironmentType {
    #[clap(name = "native", alias = "na")]
    Native,
    #[clap(name = "capsule", alias = "cap", alias = "caps")]
    Capsule,
    /// Capsule with the Tenant's policy fields populated, rather than an owner
    /// and defaults. Separate from `capsule` because the two score very
    /// differently on policy-inspecting tools while being the same operator at
    /// the same version.
    #[clap(name = "capsule-hardened", alias = "caps-hard", alias = "ch")]
    CapsuleHardened,
    #[clap(name = "capsule-proxy", alias = "cap-proxy", alias = "cp")]
    CapsuleProxy,
    #[clap(name = "kubezoo", alias = "kz")]
    KubeZoo,
    #[clap(name = "vcluster", alias = "vc")]
    VCluster,
    #[clap(name = "kubevirt", alias = "kv")]
    KubeVirt,
    #[clap(name = "kamaji", alias = "kam")]
    Kamaji,
}

impl ClusterEnvironmentType {
    fn as_str(&self) -> &str {
        match self {
            ClusterEnvironmentType::Native => "native",
            ClusterEnvironmentType::Capsule => "capsule",
            ClusterEnvironmentType::CapsuleHardened => "capsule-hardened",
            ClusterEnvironmentType::CapsuleProxy => "capsule-proxy",
            ClusterEnvironmentType::KubeZoo => "kubezoo",
            ClusterEnvironmentType::VCluster => "vcluster",
            ClusterEnvironmentType::KubeVirt => "kubevirt",
            ClusterEnvironmentType::Kamaji => "kamaji",
        }
    }
}

/// A data-plane isolation technology, applied on top of a control-plane
/// solution rather than instead of one.
///
/// The two planes are orthogonal — every control-plane solution measured so far
/// breaches the data plane — so these compose with `--type` instead of
/// replacing it, and the results table reads `native+network-policy`.
///
/// Variants are added as their provisioning lands. A technology that cannot be
/// provisioned has no business being selectable: the failure mode would be a
/// cluster that quietly lacks the isolation the label claims, which reads as
/// the technology not working.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum DataPlaneTechnology {
    /// A deny-all NetworkPolicy between tenant namespaces.
    ///
    /// Enforced, because the host cluster's CNI is [`CniPlugin::DEFAULT`] in
    /// every run and it implements NetworkPolicy. That was not always so: on
    /// kind's `kindnet` a policy is accepted, stored, and enforced by nobody,
    /// so this row measured the policy being *written* rather than obeyed, and
    /// a separate `calico` variant existed to pair the two. With a
    /// policy-enforcing CNI underneath everything, the pair collapsed into this
    /// one row.
    ///
    /// The consequence worth knowing: there is no longer a way to ask for a
    /// policy that nothing enforces, which used to be available as a control.
    #[clap(name = "network-policy", alias = "netpol")]
    NetworkPolicy,

    /// Kube-OVN as the cluster CNI, with the deny-all NetworkPolicy.
    ///
    /// The baseline for the Kube-OVN rows: the CNI and nothing more. Its own
    /// isolation features — per-tenant Subnets, custom VPCs — are separate
    /// technologies layered on this, and measuring it plain is what shows they
    /// are doing the work rather than the CNI swap.
    #[clap(name = "kubeovn")]
    KubeOvn,

    /// Kube-OVN with a private Subnet per tenant, and no NetworkPolicy.
    ///
    /// The policy is deliberately absent. Isolation here comes from OVN
    /// refusing to route between subnets, and leaving the policy out is what
    /// makes the comparison against `kubeovn` attribute the difference to the
    /// subnet rather than to the two of them together.
    #[clap(name = "kubeovn-subnet")]
    KubeOvnSubnet,

    /// Kube-OVN with a VPC of its own per tenant, and no NetworkPolicy.
    ///
    /// One VPC is one logical router, so the tenants have no route between
    /// them — isolation by absence of a path rather than by a rule dropping
    /// packets on a shared one. The only configuration here that can earn
    /// `hard`, and the one that pays for it: a custom VPC gives up NodePort,
    /// node access and cluster DNS, which is what the autonomy columns are for.
    #[clap(name = "kubeovn-vpc")]
    KubeOvnVpc,

    /// A DNS server per tenant, answering only for that tenant's namespace.
    ///
    /// Cluster DNS resolves every Service for every client, so one tenant can
    /// enumerate another's by name whether or not it can reach them. This gives
    /// each tenant a CoreDNS scoped with the `namespaces` directive, so the
    /// other tenant's names return NXDOMAIN.
    ///
    /// Independent of any CNI and of any control-plane solution — ordinary pods
    /// on ordinary cluster networking — so it composes with anything else under
    /// test: `--data-plane calico,scoped-dns` or `--type capsule --data-plane
    /// scoped-dns` are both meaningful.
    #[clap(name = "scoped-dns")]
    ScopedDns,

    /// gVisor as a sandboxed runtime, with probes running under it.
    ///
    /// Syscalls are serviced by a user-space kernel rather than the host's,
    /// which is what the privileged-syscall and host-namespace properties are
    /// asking about. Opt-in per pod through a RuntimeClass, so this measures
    /// what a sandboxed tenant gets rather than what the platform compels.
    #[clap(name = "gvisor")]
    GVisor,

    /// Kata Containers as a sandboxed runtime, with probes running under it.
    ///
    /// Each pod becomes a lightweight VM with its own kernel. Where gVisor
    /// refuses a privileged container outright, Kata runs it inside the guest,
    /// so the properties gVisor can only forbid are ones Kata may be able to
    /// permit and still isolate.
    #[clap(name = "kata")]
    Kata,

    /// A StorageClass per tenant, with `reclaimPolicy: Retain`.
    ///
    /// Not an isolation mechanism, and does not claim to be. It supplies the
    /// documented route to a Retain volume, so that `Create And Mount Volume
    /// with Retain Reclaim Policy` measures reclaim policy rather than the
    /// hostPath PersistentVolume a tenant otherwise has to build by hand.
    ///
    /// Encryption — the one data-plane answer to volume rebinding — is not
    /// here: it needs a CSI that resolves a per-namespace key, and every such
    /// driver is iSCSI-backed, which cannot attach on a kind node at all.
    #[clap(name = "storage-classes")]
    StorageClasses,
}

impl DataPlaneTechnology {
    fn as_str(&self) -> &str {
        match self {
            DataPlaneTechnology::NetworkPolicy => "network-policy",
            DataPlaneTechnology::KubeOvn => "kubeovn",
            DataPlaneTechnology::KubeOvnSubnet => "kubeovn-subnet",
            DataPlaneTechnology::KubeOvnVpc => "kubeovn-vpc",
            DataPlaneTechnology::ScopedDns => "scoped-dns",
            DataPlaneTechnology::GVisor => "gvisor",
            DataPlaneTechnology::Kata => "kata",
            DataPlaneTechnology::StorageClasses => "storage-classes",
        }
    }

    /// The CNI this technology needs, when it needs one other than the default.
    ///
    /// Only Kube-OVN does: its isolation features are the CNI's own. Everything
    /// else runs on [`CniPlugin::DEFAULT`].
    fn cni(&self) -> Option<CniPlugin> {
        match self {
            DataPlaneTechnology::NetworkPolicy => None,
            DataPlaneTechnology::KubeOvn
            | DataPlaneTechnology::KubeOvnSubnet
            | DataPlaneTechnology::KubeOvnVpc => Some(CniPlugin::KubeOvn),
            // Need no particular CNI.
            DataPlaneTechnology::ScopedDns
            | DataPlaneTechnology::GVisor
            | DataPlaneTechnology::Kata
            | DataPlaneTechnology::StorageClasses => None,
        }
    }

    /// Whether this technology writes the cross-tenant NetworkPolicy.
    ///
    /// `KubeOvnSubnet` deliberately does not: its isolation is the subnet, and
    /// adding a policy on top would make the two indistinguishable.
    fn writes_network_policy(&self) -> bool {
        matches!(
            self,
            DataPlaneTechnology::NetworkPolicy | DataPlaneTechnology::KubeOvn
        )
    }

    /// Whether this technology gives each tenant its own private OVN Subnet.
    fn uses_private_subnet(&self) -> bool {
        matches!(self, DataPlaneTechnology::KubeOvnSubnet)
    }

    /// Whether this technology gives each tenant its own OVN VPC.
    fn uses_tenant_vpc(&self) -> bool {
        matches!(self, DataPlaneTechnology::KubeOvnVpc)
    }

    /// Whether this technology gives each tenant a namespace-scoped resolver.
    fn uses_scoped_dns(&self) -> bool {
        matches!(self, DataPlaneTechnology::ScopedDns)
    }

    /// Whether this technology gives each tenant a StorageClass of its own.
    fn uses_tenant_storage_class(&self) -> bool {
        matches!(self, DataPlaneTechnology::StorageClasses)
    }

    /// The sandboxed runtime this technology installs, if it is one.
    fn sandbox_runtime(&self) -> Option<SandboxRuntime> {
        match self {
            DataPlaneTechnology::GVisor => Some(SandboxRuntime::GVisor),
            DataPlaneTechnology::Kata => Some(SandboxRuntime::Kata),
            _ => None,
        }
    }

    /// What this technology needs decided before the cluster exists.
    ///
    /// See [`ClusterProfile`]. Most technologies need nothing here and are
    /// applied to a running cluster; a CNI or a sandboxed runtime cannot be.
    fn cluster_profile(&self) -> ClusterProfile {
        // The CNI is not decided here any more. Every cluster gets one — see
        // `SolutionUnderTest::cluster_profile` — so a technology that needs a
        // particular one says so through `cni()` and this only carries what is
        // left: the containerd patches and mounts a sandboxed runtime needs
        // before the node boots.
        let mut profile = ClusterProfile::default();
        if let Some(runtime) = self.sandbox_runtime() {
            profile
                .containerd_config_patches
                .push(runtime.containerd_patch());
            // Kata needs the host's /dev/kvm inside the node; gVisor asks for
            // nothing. Both go through the profile because a mount, like the
            // containerd patch, has to be decided before the node boots.
            profile.extra_mounts.extend(runtime.extra_mounts());
        }
        profile
    }
}

/// What is being measured: a control-plane solution, plus whatever data-plane
/// technologies are layered on it.
///
/// The two travel together because neither describes the measurement alone —
/// `capsule` and `capsule+network-policy` are different clusters producing
/// different results — and because everything derived from the choice, the
/// cluster profile and the label a result file records, needs both.
#[derive(Debug, Clone)]
pub struct SolutionUnderTest {
    pub control_plane: ClusterEnvironmentType,
    pub data_plane: Vec<DataPlaneTechnology>,
}

impl SolutionUnderTest {
    /// The name a result file records, e.g. `capsule+network-policy`.
    ///
    /// The data-plane technologies are part of it because they change what was
    /// measured: a report labelled `native` that was taken with a CNI swapped
    /// underneath it would be indistinguishable from one that was not.
    pub fn label(&self) -> String {
        std::iter::once(self.control_plane.as_str())
            .chain(self.data_plane.iter().map(DataPlaneTechnology::as_str))
            .collect::<Vec<_>>()
            .join("+")
    }

    /// The CNI to install on the host cluster.
    ///
    /// Always one, never none: every cluster this harness builds gets an
    /// explicit CNI, and unless a technology names its own that is
    /// [`CniPlugin::DEFAULT`].
    ///
    /// kind's own `kindnet` is deliberately not among the options. It ignores
    /// NetworkPolicy, so a policy row on it measures the policy being *written*
    /// rather than obeyed — and, less obviously, it addresses pods `/24`, which
    /// a KubeVirt guest inherits through its `bridge` binding. Two tenants' VMs
    /// on one node then believe they are on-link, ARP for each other, and are
    /// never answered, because kindnet routes pods rather than bridging them.
    /// Cross-tenant traffic died at address resolution and the harness reported
    /// isolation the platform was not providing. A `/32` CNI has no on-link
    /// subnet to get wrong.
    ///
    /// At most one may be named: a cluster has a single CNI, and two would
    /// fight over the same node configuration rather than compose.
    fn cni(&self) -> anyhow::Result<CniPlugin> {
        let mut chosen: Vec<CniPlugin> = self.data_plane.iter().filter_map(|t| t.cni()).collect();
        // Several Kube-OVN technologies compose, and they all name Kube-OVN.
        // Asking for the same CNI twice is agreement, not a conflict.
        chosen.dedup_by(|a, b| a == b);
        match chosen.as_slice() {
            [] => Ok(CniPlugin::DEFAULT),
            [one] => Ok(*one),
            many => Err(anyhow!(
                "{} CNIs selected ({:?}) — a cluster has one, and they are \
                 alternatives to compare in separate runs, not layers to stack",
                many.len(),
                many
            )),
        }
    }

    /// The sandboxed runtime to install, if any. At most one.
    fn sandbox_runtime(&self) -> anyhow::Result<Option<SandboxRuntime>> {
        let chosen: Vec<SandboxRuntime> = self
            .data_plane
            .iter()
            .filter_map(DataPlaneTechnology::sandbox_runtime)
            .collect();
        match chosen.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            many => Err(anyhow!(
                "{} sandboxed runtimes selected ({:?}) — they are alternatives to \
                 compare in separate runs, not layers to stack",
                many.len(),
                many
            )),
        }
    }

    /// Everything the selected technologies need decided before the cluster
    /// exists, merged into one profile.
    fn cluster_profile(&self) -> ClusterProfile {
        // The CNI leads: kind's default is always off and the pod subnet is the
        // chosen CNI's, so the cluster is created for the network it will
        // actually have rather than coming up on kindnet and being adopted
        // afterwards.
        let cni = self.cni().unwrap_or(CniPlugin::DEFAULT);
        let mut combined = ClusterProfile {
            disable_default_cni: true,
            pod_subnet: Some(cni.pod_subnet().to_string()),
            ..Default::default()
        };
        for profile in self
            .data_plane
            .iter()
            .map(DataPlaneTechnology::cluster_profile)
        {
            combined
                .containerd_config_patches
                .extend(profile.containerd_config_patches);
            combined.extra_mounts.extend(profile.extra_mounts);
        }
        combined
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ChosenClusterProvider {
    #[clap(name = "kind")]
    Kind,
    #[clap(name = "k3s")]
    K3s,
    #[clap(name = "none")]
    None,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum StorageScenario {
    Random,
    Sequential,
}

/// Which storage path the fairness benchmark exercises.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Default)]
pub enum StorageVolumeMode {
    /// Node-local ephemeral storage — a floor for node I/O contention, but it
    /// bypasses the PV/PVC abstraction the storage subsystem is defined over.
    #[default]
    EmptyDir,
    /// A dynamically provisioned PVC: the real tenant storage path, through CSI.
    Pvc,
}

impl From<StorageVolumeMode> for FairnessStorageVolume {
    fn from(mode: StorageVolumeMode) -> Self {
        match mode {
            StorageVolumeMode::EmptyDir => FairnessStorageVolume::EmptyDir,
            StorageVolumeMode::Pvc => FairnessStorageVolume::Pvc,
        }
    }
}

/// Interference the intruder generates during the unbalanced phase.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Default)]
pub enum WorkloadNoiseMode {
    /// More of the same CPU-bound prime workload the probe runs.
    #[default]
    Prime,
    /// Multi-resource stress-ng: CPU, cache, memory bus and I/O together.
    Mixed,
}

impl From<WorkloadNoiseMode> for FairnessWorkloadNoise {
    fn from(mode: WorkloadNoiseMode) -> Self {
        match mode {
            WorkloadNoiseMode::Prime => FairnessWorkloadNoise::Prime,
            WorkloadNoiseMode::Mixed => FairnessWorkloadNoise::Mixed,
        }
    }
}

fn parse_workload_noise_from_str(s: &str) -> Option<WorkloadNoiseMode> {
    match s.to_lowercase().as_str() {
        "prime" | "cpu" => Some(WorkloadNoiseMode::Prime),
        "mixed" | "stress-ng" | "stressng" | "multi" => Some(WorkloadNoiseMode::Mixed),
        _ => None,
    }
}

/// Kubernetes QoS class requested for benchmark pods.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Default)]
pub enum PodQosClass {
    /// requests == limits; stable, never throttled below its request.
    #[default]
    Guaranteed,
    /// requests < limits; may burst and may be throttled.
    Burstable,
    /// No resource constraints at all.
    BestEffort,
}

impl From<PodQosClass> for QosClass {
    fn from(class: PodQosClass) -> Self {
        match class {
            PodQosClass::Guaranteed => QosClass::Guaranteed,
            PodQosClass::Burstable => QosClass::Burstable,
            PodQosClass::BestEffort => QosClass::BestEffort,
        }
    }
}

fn parse_qos_class_from_str(s: &str) -> Option<PodQosClass> {
    match s.to_lowercase().replace(['-', '_'], "").as_str() {
        "guaranteed" => Some(PodQosClass::Guaranteed),
        "burstable" => Some(PodQosClass::Burstable),
        "besteffort" => Some(PodQosClass::BestEffort),
        _ => None,
    }
}

fn parse_storage_volume_from_str(s: &str) -> Option<StorageVolumeMode> {
    match s.to_lowercase().as_str() {
        "emptydir" | "empty-dir" | "ephemeral" => Some(StorageVolumeMode::EmptyDir),
        "pvc" | "persistentvolumeclaim" | "csi" => Some(StorageVolumeMode::Pvc),
        _ => None,
    }
}

impl From<StorageScenario> for FairnessStorageScenario {
    fn from(scenario: StorageScenario) -> Self {
        match scenario {
            StorageScenario::Random => FairnessStorageScenario::RandomIO,
            StorageScenario::Sequential => FairnessStorageScenario::SequentialIO,
        }
    }
}

fn parse_storage_scenario_from_str(s: &str) -> Option<StorageScenario> {
    match s.to_lowercase().as_str() {
        "random" => Some(StorageScenario::Random),
        "sequential" | "seq" => Some(StorageScenario::Sequential),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum RateLimitStrategy {
    Unlimited,
    FixedDelay,
    Adaptive,
}

impl From<RateLimitStrategy> for FairnessRateLimitStrategy {
    fn from(strategy: RateLimitStrategy) -> Self {
        match strategy {
            RateLimitStrategy::Unlimited => FairnessRateLimitStrategy::Unlimited,
            RateLimitStrategy::FixedDelay => FairnessRateLimitStrategy::FixedDelay,
            RateLimitStrategy::Adaptive => FairnessRateLimitStrategy::Adaptive,
        }
    }
}

fn parse_rate_strategy_from_str(s: &str) -> Option<RateLimitStrategy> {
    match s.to_lowercase().as_str() {
        "unlimited" => Some(RateLimitStrategy::Unlimited),
        "fixeddelay" | "fixed_delay" | "fixed-delay" => Some(RateLimitStrategy::FixedDelay),
        "adaptive" => Some(RateLimitStrategy::Adaptive),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION LAYERS (BUILDER PATTERN)
// ═══════════════════════════════════════════════════════════════════════════

/// The Final, Clean Configuration Struct
#[derive(Debug, Clone)]
pub struct FairnessConfig {
    pub baseline_duration: Duration,
    pub test_duration: Duration,
    pub rate_strategy: RateLimitStrategy,
    pub rate_limit: f64,
    pub load_multiplier: f64,
    pub pod_multiplier: f64,

    // Subsystem enable flags
    pub run_cp: bool,
    pub run_storage: bool,
    pub run_network: bool,
    pub run_workload: bool,

    // Subsystem configs
    pub cp_rate: f64,
    pub cp_requesters: usize,
    pub cp_load_multiplier: f64,
    pub cp_pod_multiplier: f64,

    pub net_rate: f64,
    pub net_load_multiplier: f64,
    pub net_pod_multiplier: f64,
    pub net_pod_pairs: u32,
    pub net_streams: u32,
    pub net_packet_size: u32,

    pub st_rate: f64,
    pub st_load_multiplier: f64,
    pub st_pod_multiplier: f64,
    pub st_pods: u32,
    pub st_block_size: u32,
    pub st_file_size: u32,
    pub st_scenario: StorageScenario,
    pub st_iodepth: u32,
    pub st_volume: StorageVolumeMode,
    pub st_storage_class: Option<String>,

    pub wl_rate: f64,
    pub wl_load_multiplier: f64,
    pub wl_pod_multiplier: f64,
    pub wl_pods: u32,
    pub wl_threads: u32,
    pub wl_max_prime: u32,
    pub wl_noise: WorkloadNoiseMode,
    pub probe_qos: PodQosClass,
    pub intruder_qos: PodQosClass,
    pub runtime_class: Option<String>,

    pub export_csv: bool,
    pub output_dir: String,
    pub solution_label: Option<String>,
}

/// Layer 1: YAML Configuration
#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FairnessYamlLayer {
    /// Declared by the campaign file and not otherwise used. Modelled so the
    /// file validates: with `deny_unknown_fields` an unmodelled key is an
    /// error, and silently accepting this one would defeat the check.
    #[serde(default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    global: GlobalConfigYaml,
    #[serde(default)]
    control_plane: ControlPlaneConfigYaml,
    #[serde(default)]
    network: NetworkConfigYaml,
    #[serde(default)]
    storage: StorageConfigYaml,
    #[serde(default)]
    workload: WorkloadConfigYaml,
    #[serde(default)]
    export: ExportConfigYaml,
}

#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GlobalConfigYaml {
    probe_qos: Option<String>,
    intruder_qos: Option<String>,
    runtime_class_name: Option<String>,
    baseline_duration_seconds: Option<u64>,
    test_duration_seconds: Option<u64>,
    rate_strategy: Option<String>,
    rate: Option<f64>,
    load_multiplier: Option<f64>,
    pod_multiplier: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlPlaneConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    requesters: Option<usize>,
    /// Escalation for this subsystem alone, overriding the global
    /// `podMultiplier`. A subsystem saturates at its own load: on a 16-core
    /// node the network path needs ~30x before the victim degrades at all,
    /// while 10x is already past what the control plane can absorb.
    pod_multiplier: Option<f64>,

    /// The other half of the same escalation, overriding the global
    /// `loadMultiplier` for this subsystem alone.
    ///
    /// The two are not interchangeable. `podMultiplier` adds pods and raises
    /// the offered rate together, so per-pod demand stays flat; this raises
    /// the rate on the pods already there. For the network that is the
    /// difference that matters: pods are the expensive axis — each pair is two
    /// Python processes on the same node as the victim's own generator — so
    /// reaching a saturating packet rate by pod count alone spends the node's
    /// CPU on load generation and starves the instrument doing the measuring.
    /// Pushing harder per pod reaches the same wire rate for far fewer
    /// processes.
    ///
    /// It has its own ceiling: a stream blocked on a response cannot exceed
    /// 1/latency, so past some point the rate is simply not delivered. Check
    /// the achieved escalation the run prints under `Malicious:` rather than
    /// assuming the configured figure was met.
    load_multiplier: Option<f64>,
}
#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    pod_pairs: Option<u32>,
    streams: Option<u32>,
    packet_size_bytes: Option<u32>,
    /// Escalation for this subsystem alone, overriding the global
    /// `podMultiplier`. A subsystem saturates at its own load: on a 16-core
    /// node the network path needs ~30x before the victim degrades at all,
    /// while 10x is already past what the control plane can absorb.
    pod_multiplier: Option<f64>,

    /// The other half of the same escalation, overriding the global
    /// `loadMultiplier` for this subsystem alone.
    ///
    /// The two are not interchangeable. `podMultiplier` adds pods and raises
    /// the offered rate together, so per-pod demand stays flat; this raises
    /// the rate on the pods already there. For the network that is the
    /// difference that matters: pods are the expensive axis — each pair is two
    /// Python processes on the same node as the victim's own generator — so
    /// reaching a saturating packet rate by pod count alone spends the node's
    /// CPU on load generation and starves the instrument doing the measuring.
    /// Pushing harder per pod reaches the same wire rate for far fewer
    /// processes.
    ///
    /// It has its own ceiling: a stream blocked on a response cannot exceed
    /// 1/latency, so past some point the rate is simply not delivered. Check
    /// the achieved escalation the run prints under `Malicious:` rather than
    /// assuming the configured figure was met.
    load_multiplier: Option<f64>,
}
#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StorageConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    pods: Option<u32>,
    block_size_kb: Option<u32>,
    file_size_mb: Option<u32>,
    scenario: Option<String>,
    iodepth: Option<u32>,
    volume: Option<String>,
    storage_class_name: Option<String>,
    /// Escalation for this subsystem alone, overriding the global
    /// `podMultiplier`. A subsystem saturates at its own load: on a 16-core
    /// node the network path needs ~30x before the victim degrades at all,
    /// while 10x is already past what the control plane can absorb.
    pod_multiplier: Option<f64>,

    /// The other half of the same escalation, overriding the global
    /// `loadMultiplier` for this subsystem alone.
    ///
    /// The two are not interchangeable. `podMultiplier` adds pods and raises
    /// the offered rate together, so per-pod demand stays flat; this raises
    /// the rate on the pods already there. For the network that is the
    /// difference that matters: pods are the expensive axis — each pair is two
    /// Python processes on the same node as the victim's own generator — so
    /// reaching a saturating packet rate by pod count alone spends the node's
    /// CPU on load generation and starves the instrument doing the measuring.
    /// Pushing harder per pod reaches the same wire rate for far fewer
    /// processes.
    ///
    /// It has its own ceiling: a stream blocked on a response cannot exceed
    /// 1/latency, so past some point the rate is simply not delivered. Check
    /// the achieved escalation the run prints under `Malicious:` rather than
    /// assuming the configured figure was met.
    load_multiplier: Option<f64>,
}
#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkloadConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    pods: Option<u32>,
    threads: Option<u32>,
    max_prime: Option<u32>,
    noise: Option<String>,
    /// Escalation for this subsystem alone, overriding the global
    /// `podMultiplier`. A subsystem saturates at its own load: on a 16-core
    /// node the network path needs ~30x before the victim degrades at all,
    /// while 10x is already past what the control plane can absorb.
    pod_multiplier: Option<f64>,

    /// The other half of the same escalation, overriding the global
    /// `loadMultiplier` for this subsystem alone.
    ///
    /// The two are not interchangeable. `podMultiplier` adds pods and raises
    /// the offered rate together, so per-pod demand stays flat; this raises
    /// the rate on the pods already there. For the network that is the
    /// difference that matters: pods are the expensive axis — each pair is two
    /// Python processes on the same node as the victim's own generator — so
    /// reaching a saturating packet rate by pod count alone spends the node's
    /// CPU on load generation and starves the instrument doing the measuring.
    /// Pushing harder per pod reaches the same wire rate for far fewer
    /// processes.
    ///
    /// It has its own ceiling: a stream blocked on a response cannot exceed
    /// 1/latency, so past some point the rate is simply not delivered. Check
    /// the achieved escalation the run prints under `Malicious:` rather than
    /// assuming the configured figure was met.
    load_multiplier: Option<f64>,
}
#[derive(Debug, Deserialize, Default)]
// Unknown keys are an error, not a shrug. A campaign file written for a
// newer binary — or with a typo — used to be read silently, the unknown
// setting dropped, and the run would proceed at whatever the default was:
// `podMultiplier` under `network:` was ignored by an older binary and the
// campaign escalated 10x while the file said 30x, with nothing to show for
// it but numbers that looked plausible.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportConfigYaml {
    csv: Option<bool>,
    output_dir: Option<String>,
}

/// Arguments for `kumuteva verify`.
#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    /// Path to tenant1 kubeconfig file (owner role) [required]
    #[clap(value_name = "tenant1-kubeconfig")]
    tenant1_kubeconfig_path: PathBuf,
    /// Path to tenant2 kubeconfig file (attacker role) [required]
    #[clap(value_name = "tenant2-kubeconfig")]
    tenant2_kubeconfig_path: PathBuf,

    #[clap(long = "tenant1-ns", default_value = "tenant1")]
    tenant1_namespace: String,
    #[clap(long = "tenant2-ns", default_value = "tenant2")]
    tenant2_namespace: String,

    /// Also write the report as JSON to this path.
    ///
    /// The printed table stays the default. This exists so the assessment
    /// can be joined against other tools' output programmatically instead
    /// of being transcribed by hand.
    #[clap(long = "output-json", value_name = "PATH")]
    output_json: Option<PathBuf>,

    /// Write the full list of assessable properties to this path and exit.
    ///
    /// Needs no cluster. The kubectl-mtb mapping keys on the exact resource
    /// and operation strings emitted here, and the paper's coverage count
    /// is derived from them rather than counted by hand.
    #[clap(long = "list-properties", value_name = "PATH")]
    list_properties: Option<PathBuf>,

    /// Multi-tenancy solution under test, recorded in the JSON report.
    ///
    /// Without it nothing in a result file says which solution produced it,
    /// which is the provenance gap that left a published value untraceable.
    #[clap(long = "solution-label", value_name = "NAME")]
    solution_label: Option<String>,

    /// Run every probe under this RuntimeClass, e.g. `gvisor` or `kata`.
    ///
    /// A RuntimeClass is opt-in per pod, so this measures what a sandboxed
    /// tenant gets rather than what the platform compels. Naming a handler the
    /// node's containerd does not know leaves probes in `ContainerCreating`
    /// instead of failing outright, so check the sandbox is real before
    /// believing a verdict taken under it.
    #[clap(long = "runtime-class", value_name = "NAME")]
    runtime_class: Option<String>,

    /// Point every probe at this DNS server instead of the cluster's own.
    ///
    /// Needed where the cluster resolver is unreachable from the tenant — a
    /// Kube-OVN custom VPC has no route to it, and nothing injects a
    /// replacement. Without this the DNS experiment measures the missing route
    /// rather than whether one tenant can resolve another's names.
    #[clap(long = "dns-nameserver", value_name = "IP")]
    dns_nameserver: Option<String>,

    /// Assess control plane isolation (exclusive if any system is specified)
    #[clap(long = "control-plane", alias = "cp")]
    control_plane: bool,
    /// Assess storage isolation (exclusive if any system is specified)
    #[clap(long = "storage", alias = "st")]
    storage: bool,
    /// Assess network isolation (exclusive if any system is specified)
    #[clap(long = "network", alias = "net")]
    network: bool,
    /// Assess workload isolation (exclusive if any system is specified)
    #[clap(long = "workload", alias = "wl")]
    workload: bool,

    #[clap(long, default_value = "false")]
    verbose: bool,
}

/// Arguments for `kumuteva setup`.
#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    /// Use an existing cluster instead of creating a new one
    /// Provide kubeconfig path for the existing cluster
    #[clap(long = "existing-cluster", short = 'f')]
    existing_cluster_kubeconfig: Option<PathBuf>,

    /// Output directory for generated kubeconfig files
    #[clap(long = "output", short = 'o')]
    output_dir: Option<PathBuf>,

    /// Name of the cluster to use or create.
    #[clap(long)]
    cluster_name: String,

    /// Multitenancy solution for handling tenant clusters
    #[clap(long = "type", short = 't', default_value = "vcluster")]
    kind: ClusterEnvironmentType,

    /// Data-plane isolation technologies to apply on top of `--type`.
    ///
    /// Additive and orthogonal to the control-plane solution: `--type native
    /// --data-plane network-policy` measures the technology on its own, and
    /// `--type capsule --data-plane network-policy` measures the combination.
    /// Repeat the flag or comma-separate to apply several.
    #[clap(long = "data-plane", value_enum, value_delimiter = ',')]
    data_plane: Vec<DataPlaneTechnology>,

    /// Host cluster provider to use for the underlying cluster
    #[clap(long = "provider", short = 'p', default_value = "kind")]
    provider: ChosenClusterProvider,
    #[clap(flatten)]
    tenant1: Tenant1SetupConfig,
    #[clap(flatten)]
    tenant2: Tenant2SetupConfig,

    /// Enable verbose output
    #[clap(long, default_value = "false")]
    verbose: bool,
}

/// Layer 2: CLI Configuration
#[derive(Debug, Parser, Default)]
pub struct FairnessCliLayer {
    /// Path to tenant1 kubeconfig file (regular tenant) [required]
    #[clap(value_name = "tenant1-kubeconfig")]
    pub tenant1_kubeconfig_path: PathBuf,
    /// Path to tenant2 kubeconfig file (malicious tenant) [required]
    #[clap(value_name = "tenant2-kubeconfig")]
    pub tenant2_kubeconfig_path: PathBuf,

    /// Path to YAML configuration file
    #[clap(long = "config", short = 'f')]
    pub config_file: Option<PathBuf>,

    /// Namespace for tenant1
    #[clap(long = "tenant1-ns", default_value = "tenant1")]
    pub tenant1_namespace: String,
    /// Namespace for tenant2
    #[clap(long = "tenant2-ns", default_value = "tenant2")]
    pub tenant2_namespace: String,

    // Flags (Implicit booleans)
    #[clap(long = "control-plane", alias = "cp")]
    pub control_plane: bool,
    #[clap(long = "storage", alias = "st")]
    pub storage: bool,
    #[clap(long = "network", alias = "net")]
    pub network: bool,
    #[clap(long = "workload", alias = "wl")]
    pub workload: bool,

    /// Duration of baseline phase in seconds (balanced scenario) [default: 30s]
    #[clap(long)]
    pub baseline_duration: Option<u64>,

    /// Duration of test phase in seconds (unbalanced scenario) [default: 60s]
    #[clap(long)]
    pub test_duration: Option<u64>,

    /// Rate strategy [default: fixed-delay]
    #[clap(long, value_enum)]
    pub rate_strategy: Option<RateLimitStrategy>,

    /// Overall request rate limit for malicious tenant (applies to all subsystems unless overridden) [default: 10.0 req/s]
    #[clap(long = "rate")]
    pub rate_limit: Option<f64>,

    /// Malicious load multiplier (how much moore req/s per pod) [default: 1.0]
    #[clap(long)]
    pub load_multiplier: Option<f64>,

    /// Malicious pod multiplier [default: 10]
    #[clap(long)]
    pub pod_multiplier: Option<f64>,

    // Subsystem Overrides
    /// Custom rate limit for control plane assessment (overrides global rate)
    #[clap(long)]
    pub cp_rate: Option<f64>,
    /// Custom rate limit for network assessment (overrides global rate)
    #[clap(long)]
    pub net_rate: Option<f64>,
    /// Custom rate limit for storage assessment (overrides global rate)
    #[clap(long)]
    pub st_rate: Option<f64>,
    /// Custom rate limit for workload assessment (overrides global rate)
    #[clap(long)]
    pub wl_rate: Option<f64>,

    // Subsystem Details
    /// Number of concurrent requesters for control plane assessment [default: 1]
    #[clap(long)]
    pub cp_requesters: Option<usize>,

    /// Number of workload pods to run in parallel [default: 1]
    #[clap(long)]
    pub wl_pods: Option<u32>,
    /// Number of threads per workload pod [default: 1]
    #[clap(long)]
    pub wl_threads: Option<u32>,
    /// Max prime number for CPU stress in workload assessment [default: 500000]
    #[clap(long)]
    pub wl_max_prime: Option<u32>,

    /// Interference the intruder generates in the unbalanced phase: the same
    /// prime workload, or a multi-resource stress-ng mix [default: prime]
    #[clap(long, value_enum)]
    pub wl_noise: Option<WorkloadNoiseMode>,

    /// QoS class for measuring probe pods across all subsystems [default: guaranteed]
    #[clap(long, value_enum)]
    pub probe_qos: Option<PodQosClass>,

    /// QoS class for intruder interference pods [default: best-effort]
    #[clap(long, value_enum)]
    pub intruder_qos: Option<PodQosClass>,

    /// RuntimeClass for all benchmark pods, e.g. a gVisor or Kata sandbox
    #[clap(long)]
    pub runtime_class: Option<String>,

    /// Number of network pod pairs (client/server) [default: 1]
    #[clap(long)]
    pub net_pod_pairs: Option<u32>,
    /// Number of network streams per pod pair [default: 4]
    #[clap(long)]
    pub net_streams: Option<u32>,
    /// Network packet size in bytes [default: 512]
    #[clap(long)]
    pub net_packet_size: Option<u32>,

    /// Number of storage pods to run in parallel [default: 1]
    #[clap(long)]
    pub st_pods: Option<u32>,
    /// Storage block size in KB [default: 4]
    #[clap(long)]
    pub st_block_size: Option<u32>,
    /// Storage file size in MB [default: 100]
    #[clap(long)]
    pub st_file_size: Option<u32>,
    /// Storage scenario [default: random]
    #[clap(long, value_enum)]
    pub st_scenario: Option<StorageScenario>,

    /// Outstanding I/Os per fio job in the random scenario [default: 4].
    ///
    /// A ceiling, not a load knob: occupancy is rate x latency, so this only
    /// binds at saturation — where too small a value throttles the intruder and
    /// makes a short-falling achieved rate ambiguous between a saturated device
    /// and an exhausted queue.
    #[clap(long)]
    pub st_iodepth: Option<u32>,

    /// Storage path exercised by the benchmark: node-local ephemeral, or a PVC
    /// through the CSI driver [default: emptydir]
    #[clap(long, value_enum)]
    pub st_volume: Option<StorageVolumeMode>,

    /// StorageClass to use in PVC mode [default: cluster default]
    #[clap(long)]
    pub st_storage_class: Option<String>,

    // Export
    /// Export results to CSV file(s) [default: false]
    #[clap(long)]
    pub export_csv: bool,

    /// Output directory for CSV export [default: fairness_results]
    #[clap(short = 'o', long)]
    pub output_dir: Option<String>,

    /// Multi-tenancy solution under test, recorded in the run manifest
    /// (e.g. capsule, capsule-proxy, kubezoo, vcluster, kubevirt)
    #[clap(long)]
    pub solution_label: Option<String>,

    /// Enable verbose output [default: false]
    #[clap(long, default_value = "false")]
    pub verbose: bool,
}

/// The Builder Logic
#[derive(Default)]
pub struct FairnessConfigBuilder {
    yaml: Option<FairnessYamlLayer>,
    cli: Option<FairnessCliLayer>,
}

impl FairnessConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_yaml(mut self, path: Option<&PathBuf>) -> anyhow::Result<Self> {
        if let Some(p) = path {
            let content = std::fs::read_to_string(p)
                .with_context(|| format!("Failed to read config file: {}", p.display()))?;
            let yaml: FairnessYamlLayer = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse YAML config: {}", p.display()))?;
            self.yaml = Some(yaml);
        }
        Ok(self)
    }

    pub fn with_cli(mut self, cli: FairnessCliLayer) -> Self {
        self.cli = Some(cli);
        self
    }

    pub fn build(self) -> FairnessConfig {
        let cli = self.cli.unwrap_or_default();
        let yaml = self.yaml.unwrap_or_default();

        // 1. Resolve Global Settings
        let baseline_duration = cli
            .baseline_duration
            .or(yaml.global.baseline_duration_seconds)
            .unwrap_or(defaults::BASELINE_DURATION);

        let test_duration = cli
            .test_duration
            .or(yaml.global.test_duration_seconds)
            .unwrap_or(defaults::TEST_DURATION);

        let rate_strategy = cli
            .rate_strategy
            .or_else(|| {
                yaml.global
                    .rate_strategy
                    .as_deref()
                    .and_then(parse_rate_strategy_from_str)
            })
            .unwrap_or(defaults::RATE_STRATEGY);

        let rate_limit = cli
            .rate_limit
            .or(yaml.global.rate)
            .unwrap_or(defaults::RATE);

        let load_multiplier = cli
            .load_multiplier
            .or(yaml.global.load_multiplier)
            .unwrap_or(defaults::LOAD_MULT);

        let pod_multiplier = cli
            .pod_multiplier
            .or(yaml.global.pod_multiplier)
            .unwrap_or(defaults::POD_MULT);

        // 2. Resolve Execution Flags
        let any_cli_flag = cli.control_plane || cli.storage || cli.network || cli.workload;
        let any_yaml_flag = yaml.control_plane.enabled.is_some()
            || yaml.network.enabled.is_some()
            || yaml.storage.enabled.is_some()
            || yaml.workload.enabled.is_some();

        let (run_cp, run_st, run_net, run_wl) = if any_cli_flag {
            (cli.control_plane, cli.storage, cli.network, cli.workload)
        } else if any_yaml_flag {
            (
                yaml.control_plane.enabled.unwrap_or(false),
                yaml.storage.enabled.unwrap_or(false),
                yaml.network.enabled.unwrap_or(false),
                yaml.workload.enabled.unwrap_or(false),
            )
        } else {
            (true, true, true, true)
        };

        // 3. Resolve Subsystems

        // Storage
        let st_scenario = cli
            .st_scenario
            .or_else(|| {
                yaml.storage
                    .scenario
                    .as_deref()
                    .and_then(parse_storage_scenario_from_str)
            })
            .unwrap_or(defaults::ST_SCENARIO);

        let st_volume = cli
            .st_volume
            .or_else(|| {
                yaml.storage
                    .volume
                    .as_deref()
                    .and_then(parse_storage_volume_from_str)
            })
            .unwrap_or(defaults::ST_VOLUME);

        let st_storage_class = cli
            .st_storage_class
            .clone()
            .or_else(|| yaml.storage.storage_class_name.clone());

        // Workload
        let wl_noise = cli
            .wl_noise
            .or_else(|| {
                yaml.workload
                    .noise
                    .as_deref()
                    .and_then(parse_workload_noise_from_str)
            })
            .unwrap_or_default();

        let probe_qos = cli
            .probe_qos
            .or_else(|| {
                yaml.global
                    .probe_qos
                    .as_deref()
                    .and_then(parse_qos_class_from_str)
            })
            .unwrap_or(PodQosClass::Guaranteed);

        let intruder_qos = cli
            .intruder_qos
            .or_else(|| {
                yaml.global
                    .intruder_qos
                    .as_deref()
                    .and_then(parse_qos_class_from_str)
            })
            .unwrap_or(PodQosClass::BestEffort);

        let runtime_class = cli
            .runtime_class
            .clone()
            .or_else(|| yaml.global.runtime_class_name.clone());

        FairnessConfig {
            baseline_duration: Duration::from_secs(baseline_duration),
            test_duration: Duration::from_secs(test_duration),
            rate_strategy,
            rate_limit,
            load_multiplier,
            pod_multiplier,

            run_cp,
            run_storage: run_st,
            run_network: run_net,
            run_workload: run_wl,

            cp_rate: cli
                .cp_rate
                .or(yaml.control_plane.rate)
                .unwrap_or(rate_limit),
            cp_requesters: cli
                .cp_requesters
                .or(yaml.control_plane.requesters)
                .unwrap_or(defaults::CP_REQUESTERS),
            cp_load_multiplier: yaml
                .control_plane
                .load_multiplier
                .unwrap_or(load_multiplier),
            cp_pod_multiplier: yaml.control_plane.pod_multiplier.unwrap_or(pod_multiplier),

            net_rate: cli.net_rate.or(yaml.network.rate).unwrap_or(rate_limit),
            net_load_multiplier: yaml.network.load_multiplier.unwrap_or(load_multiplier),
            net_pod_multiplier: yaml.network.pod_multiplier.unwrap_or(pod_multiplier),
            net_pod_pairs: cli
                .net_pod_pairs
                .or(yaml.network.pod_pairs)
                .unwrap_or(defaults::NET_POD_PAIRS),
            net_streams: cli
                .net_streams
                .or(yaml.network.streams)
                .unwrap_or(defaults::NET_STREAMS),
            net_packet_size: cli
                .net_packet_size
                .or(yaml.network.packet_size_bytes)
                .unwrap_or(defaults::NET_PACKET_SIZE),

            st_rate: cli.st_rate.or(yaml.storage.rate).unwrap_or(rate_limit),
            st_load_multiplier: yaml.storage.load_multiplier.unwrap_or(load_multiplier),
            st_pod_multiplier: yaml.storage.pod_multiplier.unwrap_or(pod_multiplier),
            st_pods: cli
                .st_pods
                .or(yaml.storage.pods)
                .unwrap_or(defaults::ST_PODS),
            st_block_size: cli
                .st_block_size
                .or(yaml.storage.block_size_kb)
                .unwrap_or(defaults::ST_BLOCK_SIZE),
            st_file_size: cli
                .st_file_size
                .or(yaml.storage.file_size_mb)
                .unwrap_or(defaults::ST_FILE_SIZE),
            st_scenario,
            st_iodepth: cli
                .st_iodepth
                .or(yaml.storage.iodepth)
                .unwrap_or(defaults::ST_IODEPTH),
            st_volume,
            st_storage_class,

            wl_rate: cli.wl_rate.or(yaml.workload.rate).unwrap_or(rate_limit),
            wl_load_multiplier: yaml.workload.load_multiplier.unwrap_or(load_multiplier),
            wl_pod_multiplier: yaml.workload.pod_multiplier.unwrap_or(pod_multiplier),
            wl_pods: cli
                .wl_pods
                .or(yaml.workload.pods)
                .unwrap_or(defaults::WL_PODS),
            wl_threads: cli
                .wl_threads
                .or(yaml.workload.threads)
                .unwrap_or(defaults::WL_THREADS),
            wl_max_prime: cli
                .wl_max_prime
                .or(yaml.workload.max_prime)
                .unwrap_or(defaults::WL_PRIME),
            wl_noise,
            probe_qos,
            intruder_qos,
            runtime_class,

            export_csv: cli.export_csv || yaml.export.csv.unwrap_or(false),
            output_dir: cli
                .output_dir
                .or(yaml.export.output_dir)
                .unwrap_or_else(|| defaults::OUTPUT_DIR.to_string()),
            solution_label: cli.solution_label,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CLI MAIN STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Parser)]
#[clap(name = "multi-tenancy-verifier")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

// The Fairness variant carries the whole CLI layer and is much larger than the
// others. This enum is constructed exactly once, at argument-parsing time, so
// the size difference costs nothing and boxing it would only obscure the parser.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Commands {
    /// Setup test environment with two tenants given a cluster environment type
    Setup(SetupArgs),
    /// Verify isolation between two clusters
    Verify(VerifyArgs),
    /// Run fairness assessment tests between two tenants
    Fairness(FairnessCliLayer),
}

#[derive(Debug, Parser)]
pub struct Tenant1SetupConfig {
    #[clap(
        long = "tenant1",
        name = "tenant1",
        value_names = &["TENANT1_NAMESPACE", "TENANT1_MAPPING"],
        num_args = 1..=2,
        conflicts_with_all = &["tenant1_ns", "tenant1_mapping"]
    )]
    tenant1_short: Option<Vec<String>>,
    #[clap(
        long = "tenant1-ns",
        default_value = "tenant1",
        conflicts_with = "tenant1"
    )]
    tenant1_ns: String,
    #[clap(long = "tenant1-mapping", value_parser = parse_mapping, default_value = "30010:30001", conflicts_with = "tenant1")]
    tenant1_mapping: (u16, u16),
}

#[derive(Debug, Parser)]
pub struct Tenant2SetupConfig {
    #[clap(
        long = "tenant2",
        name = "tenant2",
        value_names = &["TENANT2_NAMESPACE", "TENANT2_MAPPING"],
        num_args = 1..=2,
        conflicts_with_all = &["tenant2_ns", "tenant2_mapping"]
    )]
    tenant2_short: Option<Vec<String>>,
    #[clap(
        long = "tenant2-ns",
        default_value = "tenant2",
        conflicts_with = "tenant2"
    )]
    tenant2_ns: String,
    #[clap(long = "tenant2-mapping", value_parser = parse_mapping, default_value = "30020:30002", conflicts_with = "tenant2")]
    tenant2_mapping: (u16, u16),
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Setup(args) => commands::setup::run(args).await?,
        Commands::Verify(args) => commands::verify::run(args).await?,
        Commands::Fairness(cli_args) => commands::fairness::run(cli_args).await?,
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

async fn get_or_create_tenant_cluster(
    host_cluster: &HostClusterType,
    tenant: &str,
    kubeconfig_path: PathBuf,
    solution: &SolutionUnderTest,
) -> anyhow::Result<KubernetesClient> {
    if let Ok(existing_cluster) = KubernetesClient::load_with_retry(&kubeconfig_path, 3).await {
        println!("Tenant {} cluster already exists", tenant);
        if let Ok(health) = existing_cluster.list_all_pods().await {
            println!(
                "Tenant {} cluster is healthy ({} pods)",
                tenant,
                health.items.len()
            );
            return Ok(existing_cluster);
        } else {
            println!("Tenant {} cluster is not healthy, recreating...", tenant);
        }
    }

    println!("Creating {} cluster", tenant);

    // Each solution differs only in which `ControlPlaneIsolation` it names, so
    // it is chosen first and the builder is driven once. The seven arms used to
    // repeat `.with_isolation_technology(...).build().await?` verbatim, which
    // left nowhere to add the data-plane technologies without doing it seven
    // times.
    let control_plane = match solution.control_plane {
        ClusterEnvironmentType::Capsule => ControlPlaneIsolation::Capsule(tenant.to_string()),
        ClusterEnvironmentType::CapsuleHardened => {
            ControlPlaneIsolation::CapsuleHardened(tenant.to_string())
        }
        ClusterEnvironmentType::CapsuleProxy => {
            ControlPlaneIsolation::CapsuleProxy(tenant.to_string())
        }
        ClusterEnvironmentType::VCluster => ControlPlaneIsolation::VCluster(tenant.to_string()),
        ClusterEnvironmentType::KubeVirt => ControlPlaneIsolation::KubeVirt(tenant.to_string()),
        ClusterEnvironmentType::Kamaji => ControlPlaneIsolation::Kamaji(tenant.to_string()),
        ClusterEnvironmentType::Native => ControlPlaneIsolation::None(tenant.to_string()),
        _ => return Err(anyhow!("Unsupported cluster environment type")),
    };

    let mut builder = KubernetesClusterBuilder::new(host_cluster.clone())
        .with_kubeconfig_path(kubeconfig_path)
        .with_isolation_technology(control_plane);

    // Applied after the control plane, which is also the order `build` runs
    // them in: a tenant namespace has to exist before a policy can be written
    // into it.
    // The CNI is not applied here — it belongs to the host cluster and was
    // installed once, before any tenant existed.
    for technology in &solution.data_plane {
        if technology.writes_network_policy() {
            builder = builder.with_isolation_technology(NetworkIsolationStrategy::NetworkPolicy(
                tenant.to_string(),
            ));
        }
        if technology.uses_private_subnet() {
            builder = builder.with_isolation_technology(
                NetworkIsolationStrategy::KubeOvnPrivateSubnet(tenant.to_string()),
            );
        }
        if technology.uses_tenant_vpc() {
            builder = builder.with_isolation_technology(
                NetworkIsolationStrategy::KubeOvnTenantVpc(tenant.to_string()),
            );
        }
        if technology.uses_scoped_dns() {
            builder = builder.with_isolation_technology(NetworkIsolationStrategy::ScopedTenantDns(
                tenant.to_string(),
            ));
        }
        if technology.uses_tenant_storage_class() {
            builder = builder.with_isolation_technology(DataPlaneIsolation::Storage(
                StorageIsolationStrategy::PerTenantStorageClass(tenant.to_string()),
            ));
        }
    }

    builder.build().await
}

pub async fn setup_test_environment(
    existing_cluster_kubeconfig: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    cluster_name: &str,
    solution: &SolutionUnderTest,
    provider: ChosenClusterProvider,
    tenant1: Tenant1SetupConfig,
    tenant2: Tenant2SetupConfig,
) -> anyhow::Result<()> {
    // Resolved before the cluster is created, because that is when the parts of
    // it that cannot be changed later are decided.
    let profile = solution.cluster_profile();

    let (tenant1_ns, tenant1_mapping) = resolve_tenant_config(
        &tenant1.tenant1_short,
        &tenant1.tenant1_ns,
        &tenant1.tenant1_mapping,
    )?;
    let (tenant2_ns, tenant2_mapping) = resolve_tenant_config(
        &tenant2.tenant2_short,
        &tenant2.tenant2_ns,
        &tenant2.tenant2_mapping,
    )?;

    println!(
        "Tenant1: ns={}, port_mapping={{container={}, host={}}}",
        tenant1_ns, tenant1_mapping.0, tenant1_mapping.1
    );
    println!(
        "Tenant2: ns={}, port_mapping={{container={}, host={}}}",
        tenant2_ns, tenant2_mapping.0, tenant2_mapping.1
    );

    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("/tmp"));
    std::fs::create_dir_all(&output_dir).context("Failed to create output directory")?;

    let port_mappings = TenantsPortMapping::from_tuple(tenant1_mapping, tenant2_mapping);
    let using_existing_cluster = existing_cluster_kubeconfig.is_some();
    let cluster_kubeconfig = existing_cluster_kubeconfig
        .unwrap_or_else(|| output_dir.join(format!("{}.kubeconfig", cluster_name)));

    let cluster_name = if using_existing_cluster {
        cluster_kubeconfig
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(cluster_name)
    } else {
        cluster_name
    };

    let base_cluster = match provider {
        ChosenClusterProvider::Kind => {
            if using_existing_cluster {
                println!("Using existing kind cluster '{}'", cluster_name);
                HostClusterType::Kind(
                    KindCluster::load(cluster_name, cluster_kubeconfig.clone()).await?,
                )
            } else {
                println!("Creating new kind cluster '{}'", cluster_name);
                HostClusterType::Kind(
                    KindCluster::create(
                        cluster_name,
                        cluster_kubeconfig.clone(),
                        port_mappings,
                        &profile,
                    )
                    .await?,
                )
            }
        }
        ChosenClusterProvider::K3s => {
            if using_existing_cluster {
                println!("Using existing k3s cluster '{}'", cluster_name);
                HostClusterType::K3s(
                    K3sCluster::load(cluster_name, cluster_kubeconfig.clone()).await?,
                )
            } else {
                println!("Creating new k3s cluster '{}'", cluster_name);
                HostClusterType::K3s(
                    K3sCluster::create(
                        cluster_name,
                        cluster_kubeconfig.clone(),
                        port_mappings,
                        &profile,
                    )
                    .await?,
                )
            }
        }
        ChosenClusterProvider::None => {
            if using_existing_cluster {
                println!("Using existing pre-existing cluster '{}'", cluster_name);
                HostClusterType::PreExisting(
                    PreExistingCluster::load(cluster_name, cluster_kubeconfig.clone()).await?,
                )
            } else {
                println!("Creating new pre-existing cluster '{}'", cluster_name);
                HostClusterType::PreExisting(
                    PreExistingCluster::create(
                        cluster_name,
                        cluster_kubeconfig.clone(),
                        port_mappings,
                        &profile,
                    )
                    .await?,
                )
            }
        }
    };

    // Before any tenant, because a cluster created with `disableDefaultCNI` has
    // no pod networking until this runs — and the control-plane solution's own
    // operator is a pod.
    KubernetesClusterBuilder::install_cni(&base_cluster, solution.cni()?).await?;

    // After the CNI, because publishing the RuntimeClass needs a working API
    // path and the node has no pod network until the CNI is up.
    if let Some(runtime) = solution.sandbox_runtime()? {
        KubernetesClusterBuilder::install_sandbox_runtime(&base_cluster, runtime).await?;
    }

    let t1_cfg = output_dir.join(format!("tenant1-{}.kubeconfig", cluster_name));
    let t2_cfg = output_dir.join(format!("tenant2-{}.kubeconfig", cluster_name));

    let t1_cluster =
        get_or_create_tenant_cluster(&base_cluster, "tenant1", t1_cfg.clone(), solution).await?;
    let t2_cluster =
        get_or_create_tenant_cluster(&base_cluster, "tenant2", t2_cfg.clone(), solution).await?;

    t1_cluster.ensure_cluster_is_ready().await?;
    t2_cluster.ensure_cluster_is_ready().await?;

    println!("Created test clusters:");
    println!("Tenant 1 kubeconfig: {}", t1_cfg.display());
    println!("Tenant 2 kubeconfig: {}", t2_cfg.display());

    Ok(())
}

fn resolve_tenant_config(
    short: &Option<Vec<String>>,
    default_ns: &str,
    default_mapping: &(u16, u16),
) -> anyhow::Result<(String, (u16, u16))> {
    let tenant_ns = short
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| default_ns.to_string());
    let tenant_mapping = if let Some(v) = short {
        if v.len() > 1 {
            parse_mapping(&v[1])?
        } else {
            *default_mapping
        }
    } else {
        *default_mapping
    };
    Ok((tenant_ns, tenant_mapping))
}

pub async fn list_pods(client: Client) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::all(client);
    for p in pods.list(&ListParams::default()).await?.items {
        println!(
            "\t{}: {}",
            p.metadata.namespace.as_deref().unwrap_or("default"),
            p.metadata.name.as_deref().unwrap_or("unnamed")
        );
    }
    Ok(())
}

fn parse_mapping(s: &str) -> anyhow::Result<(u16, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid format, expected 'containerPort:hostPort'"));
    }
    Ok((parts[0].parse()?, parts[1].parse()?))
}

fn setup_logging(verbose: bool) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(if verbose { Level::INFO } else { Level::ERROR })
        .init();
    Ok(())
}

#[cfg(test)]
mod campaign_config_tests {
    use super::*;

    /// The campaign config must land exactly on the rates the paper reports.
    ///
    /// Those figures were previously *intended* values the tool never delivered:
    /// the control plane ran 1.55x over, storage 1.83x over, and the workload
    /// could not physically reach its target at all. Now that the configured
    /// rate is what gets offered, this file is what makes the paper's numbers
    /// true — so pin it. A well-meaning edit to a rate or a multiplier silently
    /// changes what the paper claims.
    fn campaign() -> FairnessConfig {
        FairnessConfigBuilder::new()
            .with_yaml(Some(&PathBuf::from("experiments/campaign.yaml")))
            .expect("campaign config should parse")
            .build()
    }

    /// One escalation factor across every subsystem, so the degradation factors
    /// can be compared between them. The published campaign stressed the control
    /// plane 300x harder than the data plane, which is why Table I's rows are not
    /// comparable as presented.
    /// Escalation is per subsystem, and deliberately unequal.
    ///
    /// It was uniform at 10x, which is tidier to describe but measured the
    /// wrong thing in two of the four. A subsystem saturates at its own load:
    /// on the 16-core benchmark set the network path needs ~30x before the
    /// victim degrades at all — below that the kernel serves more traffic
    /// *faster* and the tenant appears to benefit from being attacked — while
    /// the control plane needs 20x before capsule and vcluster separate.
    #[test]
    fn each_subsystem_is_escalated_enough_to_contend() {
        let config = campaign();

        // Every subsystem escalates by pod count, never by asking one worker
        // for more. A blocked worker cannot exceed 1/latency, and a load
        // generator asked for an impossible rate collapses to near zero rather
        // than degrading to its maximum — measured at loadMultiplier 10, where
        // the network intruder produced 0.1% of target.
        assert_eq!(config.load_multiplier, 1.0);

        // The total is what has to clear a subsystem's contention threshold;
        // how it splits between rate and pods decides what it costs to get
        // there. Assert both, because the split is load-bearing for the
        // network and invisible in the product.
        let escalation = |load: f64, pods: f64| load * pods;

        assert_eq!(config.cp_load_multiplier, 1.0);
        assert_eq!(config.cp_pod_multiplier, 20.0);
        // 10x, which contends or does not depending on the host, so this
        // figure cannot be validated here. Below the host's packet-rate ceiling
        // the kernel path gets *more* efficient with load (NAPI polling) and
        // the victim's latency falls, reporting a degradation under 1.0 — not
        // fairness, but the harness failing to contend. On the 16-core pinned
        // benchmark set the ceiling is ~450k pkt/s and 10x (137.5k one-way,
        // 275k on the wire once the echo is counted) sits under it: measured
        // 0.76x, which is why that host needs 30x. An unpinned developer host
        // saturates far earlier and reports 21.8x at this same 10x.
        //
        // So: check the reported degradation is above 1.0 before trusting a
        // network row, and raise `network.podMultiplier` on any host where it
        // is not.
        // Network: 10x by pods alone. The split is available per subsystem
        // (`loadMultiplier` beside `podMultiplier`) and is the thing to reach
        // for if this row misbehaves: a pod pair is two Python processes
        // sharing the node with the victim's own generator, so past some pod
        // count the victim's latency measures its own CPU starvation rather
        // than network contention. Raising the rate per pod reaches the same
        // wire rate with fewer processes, at the cost of asking more of a
        // single asyncio event loop.
        assert_eq!(config.net_load_multiplier, 1.0);
        assert_eq!(config.net_pod_multiplier, 10.0);
        assert_eq!(
            escalation(config.net_load_multiplier, config.net_pod_multiplier),
            10.0
        );
        assert_eq!(config.st_load_multiplier, 1.0);
        assert_eq!(config.st_pod_multiplier, 10.0);
        assert_eq!(config.wl_load_multiplier, 1.0);
        assert_eq!(config.wl_pod_multiplier, 10.0);

        // Unlimited would make every rate below a no-op.
        assert!(!matches!(
            config.rate_strategy,
            RateLimitStrategy::Unlimited
        ));
    }

    /// 2000 rather than 1500, because 1500 does not separate the solutions.
    ///
    /// Measured back to back on the same clusters, intruder achieving 100% of
    /// target in every cell: at 1500 capsule scored 2.07 and vcluster 1.51, a
    /// separation of 1.37x; at 2000, 3.86 and 1.91 — 2.02x. Capsule shares the
    /// host API server so a heavier neighbour lands on it, while vcluster's
    /// tenant has its own; below 2000 neither is stressed enough to show it.
    #[test]
    fn control_plane_targets_100_to_2000_requests_per_second() {
        let config = campaign();
        assert_eq!(config.cp_rate, 100.0);

        let intruder = config.cp_rate * config.cp_load_multiplier * config.cp_pod_multiplier;
        assert_eq!(intruder, 2000.0);

        // Concurrency must be ample: a worker blocks on each request, so its
        // ceiling is 1/latency. At 20 req/s per worker there is a wide margin
        // even when contention pushes latency into the tens of milliseconds.
        let workers = config.cp_requesters as f64 * config.cp_pod_multiplier;
        assert_eq!(workers, 100.0);
        assert_eq!(intruder / workers, 20.0);
    }

    #[test]
    fn probe_is_burstable_so_it_fits_a_kubevirt_tenant() {
        let yaml = campaign();

        // Guaranteed forces requests == limits, which reserves a full core per
        // probe pod. A KubeVirt tenant is a pair of 2-core VMs, so that shape
        // cannot be scheduled there and the solution drops out of the campaign.
        assert_eq!(
            yaml.probe_qos,
            PodQosClass::Burstable,
            "probe must be Burstable or KubeVirt tenants cannot schedule it"
        );

        // Capping the intruder would cap the interference being measured.
        assert_eq!(
            yaml.intruder_qos,
            PodQosClass::BestEffort,
            "intruder must stay unconstrained"
        );
    }

    #[test]
    fn data_plane_targets_the_published_rates() {
        let config = campaign();
        // Each subsystem escalates by its own multiplier. Using the global one
        // here made this assert a figure the campaign no longer offers: it
        // still passed while claiming the network reached 1.25 Gbps, which it
        // has not done since the network moved to 30x.
        // Both halves are per subsystem now. Using the global load multiplier
        // here would have this assert pass while describing a rate the network
        // has not offered since it moved to 4x.
        let escalate = |per_unit: f64, load: f64, pods: f64| per_unit * load * pods;

        // Storage: 10 -> 100 kreq/s, rate being per pod.
        assert_eq!(config.st_rate, 10_000.0);
        assert_eq!(
            escalate(
                10_000.0,
                config.st_load_multiplier,
                config.st_pod_multiplier
            ),
            100_000.0
        );

        // Network: 150 Mbps -> 1.5 Gbps one-way at a 1000-byte payload. The
        // probe is an echo, so the wire carries twice each figure.
        assert_eq!(config.net_packet_size, 1000);
        let one_way_mbps = |packets: f64| packets * config.net_packet_size as f64 * 8.0 / 1e6;
        assert_eq!(one_way_mbps(config.net_rate), 150.0);
        assert_eq!(
            one_way_mbps(escalate(
                config.net_rate,
                config.net_load_multiplier,
                config.net_pod_multiplier
            )),
            1500.0
        );

        // Workload: 5 -> 50 req/s.
        assert_eq!(config.wl_rate, 5.0);
        assert_eq!(
            escalate(5.0, config.wl_load_multiplier, config.wl_pod_multiplier),
            50.0
        );

        // There was an assertion here requiring `wl_max_prime <= 50_000`, on
        // the reasoning that a sysbench event at maxPrime 500000 takes ~1.9 s
        // and so caps a pod near 0.5 req/s. The published rate is in fact
        // sustained, so the estimate was simply wrong for this hardware — and
        // it never belonged in a config test, because how long an event takes
        // is a property of the host CPU that no unit test can know.
        //
        // The underlying concern is real and now lives where it can be
        // answered: the generator is serial (`--threads=1 --events=1` inside a
        // blocking loop), so on slow enough hardware the achieved rate *would*
        // silently fall short of the target. That is measured per run and
        // reported by `achieved_rate_shortfall` in
        // assessment::workload::fairness, against the machine actually used.
    }

    #[test]
    fn campaign_phases_are_the_published_durations() {
        let config = campaign();
        assert_eq!(config.baseline_duration, Duration::from_secs(30));
        // 30s, halved from 60s to bring a 10-rep 4-solution campaign down from
        // ~7.5h. It halves the samples behind each run's latency figure.
        assert_eq!(config.test_duration, Duration::from_secs(30));
    }
}

#[cfg(test)]
mod cluster_profile_tests {
    use super::*;

    fn solution(data_plane: Vec<DataPlaneTechnology>) -> SolutionUnderTest {
        SolutionUnderTest {
            control_plane: ClusterEnvironmentType::Native,
            data_plane,
        }
    }

    /// Every cluster is built for a real CNI, never kind's default.
    ///
    /// kindnet fails silently in two unrelated ways: it ignores NetworkPolicy,
    /// so a policy row on it measures a policy nobody enforces; and it
    /// addresses pods `/24`, a netmask a KubeVirt guest inherits through its
    /// `bridge` binding, which left two tenants' VMs on one node ARPing for
    /// each other and never answered. Neither announces itself in a result, so
    /// the default is pinned here rather than left to whichever technology
    /// happens to ask for something.
    #[test]
    fn the_default_profile_disables_kindnet_and_takes_the_cni_subnet() {
        let profile = solution(vec![]).cluster_profile();

        assert!(profile.disable_default_cni, "kindnet must never be the CNI");
        assert_eq!(
            profile.pod_subnet.as_deref(),
            Some(CniPlugin::DEFAULT.pod_subnet())
        );
    }

    /// A technology that names its own CNI still gets it.
    #[test]
    fn a_technology_that_needs_its_own_cni_overrides_the_default() {
        let solution = solution(vec![DataPlaneTechnology::KubeOvnVpc]);

        assert_eq!(solution.cni().unwrap(), CniPlugin::KubeOvn);
        assert_eq!(
            solution.cluster_profile().pod_subnet.as_deref(),
            Some(CniPlugin::KubeOvn.pod_subnet()),
            "the cluster must be created with the subnet its CNI expects"
        );
    }

    /// Technologies that compose all name the same CNI, and that is agreement.
    ///
    /// `kubeovn`, `kubeovn-subnet` and `kubeovn-vpc` are layers on one CNI, so
    /// selecting them together must not read as two CNIs fighting.
    #[test]
    fn technologies_sharing_one_cni_compose() {
        assert_eq!(
            solution(vec![
                DataPlaneTechnology::KubeOvn,
                DataPlaneTechnology::KubeOvnVpc,
            ])
            .cni()
            .unwrap(),
            CniPlugin::KubeOvn
        );
    }
}
