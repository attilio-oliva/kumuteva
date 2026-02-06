mod assessment;
mod cluster;
mod external_crds;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use assessment::TenantClusterConfig;
use clap::{Parser, Subcommand, ValueEnum};
use cluster::TenantsPortMapping;
use cluster::{ControlPlaneIsolation, KindCluster, KubernetesClient, KubernetesClusterBuilder};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};
use serde::Deserialize;
use tracing::Level;

use crate::assessment::{
    // New clean assessors
    fairness_assessor::{FairnessRunnerBuilder, RateLimitStrategy as FairnessRateLimitStrategy},
    // Legacy types for isolation assessment
    AssessmentConfig,
};
use crate::assessment::{
    FairnessControlPlaneAssessor, FairnessControlPlaneConfig, FairnessNetworkAssessor,
    FairnessNetworkConfig, FairnessStorageAssessor, FairnessStorageConfig, FairnessStorageScenario,
    FairnessWorkloadAssessor, FairnessWorkloadConfig,
};

use crate::cluster::{HostClusterType, K3sCluster, PreExistingCluster};

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULTS & CONFIGURATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

mod defaults {
    use super::{RateLimitStrategy, StorageScenario};

    // We define STR variants for clap help text (concat! macro requires literals/str constants)
    // and typed variants for actual logic.

    pub const BASELINE_DURATION: u64 = 30;
    pub const TEST_DURATION: u64 = 60;

    pub const RATE_STRATEGY: RateLimitStrategy = RateLimitStrategy::Unlimited;

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
    pub const ST_SCENARIO: StorageScenario = StorageScenario::Random;

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
            ClusterEnvironmentType::CapsuleProxy => "capsule-proxy",
            ClusterEnvironmentType::KubeZoo => "kubezoo",
            ClusterEnvironmentType::VCluster => "vcluster",
            ClusterEnvironmentType::KubeVirt => "kubevirt",
            ClusterEnvironmentType::Kamaji => "kamaji",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ChosenClusterProvider {
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

    pub net_rate: f64,
    pub net_pod_pairs: u32,
    pub net_streams: u32,
    pub net_packet_size: u32,

    pub st_rate: f64,
    pub st_pods: u32,
    pub st_block_size: u32,
    pub st_file_size: u32,
    pub st_scenario: StorageScenario,

    pub wl_rate: f64,
    pub wl_pods: u32,
    pub wl_threads: u32,
    pub wl_max_prime: u32,

    pub export_csv: bool,
    pub output_dir: String,
}

/// Layer 1: YAML Configuration
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct FairnessYamlLayer {
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
#[serde(rename_all = "camelCase")]
struct GlobalConfigYaml {
    baseline_duration_seconds: Option<u64>,
    test_duration_seconds: Option<u64>,
    rate_strategy: Option<String>,
    rate: Option<f64>,
    load_multiplier: Option<f64>,
    pod_multiplier: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ControlPlaneConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    requesters: Option<usize>,
}
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NetworkConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    pod_pairs: Option<u32>,
    streams: Option<u32>,
    packet_size_bytes: Option<u32>,
}
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StorageConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    pods: Option<u32>,
    block_size_kb: Option<u32>,
    file_size_mb: Option<u32>,
    scenario: Option<String>,
}
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WorkloadConfigYaml {
    enabled: Option<bool>,
    rate: Option<f64>,
    pods: Option<u32>,
    threads: Option<u32>,
    max_prime: Option<u32>,
}
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ExportConfigYaml {
    csv: Option<bool>,
    output_dir: Option<String>,
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

    /// Rate strategy [default: unlimited]
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

    // Export
    /// Export results to CSV file(s) [default: false]
    #[clap(long)]
    pub export_csv: bool,

    /// Output directory for CSV export [default: fairness_results]
    #[clap(short = 'o', long)]
    pub output_dir: Option<String>,

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

            net_rate: cli.net_rate.or(yaml.network.rate).unwrap_or(rate_limit),
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

            wl_rate: cli.wl_rate.or(yaml.workload.rate).unwrap_or(rate_limit),
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

            export_csv: cli.export_csv || yaml.export.csv.unwrap_or(false),
            output_dir: cli
                .output_dir
                .or(yaml.export.output_dir)
                .unwrap_or_else(|| defaults::OUTPUT_DIR.to_string()),
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

#[derive(Debug, Subcommand)]
enum Commands {
    /// Setup test environment with two tenants given a cluster environment type
    Setup {
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
    },
    /// Verify isolation between two clusters
    Verify {
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
    },
    /// Run fairness assessment tests between two tenants
    Fairness(FairnessCliLayer),
}

#[derive(Debug, Parser)]
struct Tenant1SetupConfig {
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
struct Tenant2SetupConfig {
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
        Commands::Setup {
            existing_cluster_kubeconfig,
            output_dir,
            cluster_name,
            kind,
            provider,
            tenant1,
            tenant2,
            verbose,
        } => {
            setup_logging(verbose)?;
            println!("Setting up test environment...");
            let cluster_name = format!("{}-{}", cluster_name, kind.as_str());
            setup_test_environment(
                existing_cluster_kubeconfig,
                output_dir,
                &cluster_name,
                kind,
                provider,
                tenant1,
                tenant2,
            )
            .await?;
            println!("Test environment setup complete");
        }
        Commands::Verify {
            verbose,
            tenant1_kubeconfig_path,
            tenant2_kubeconfig_path,
            tenant1_namespace,
            tenant2_namespace,
            control_plane,
            storage,
            network,
            workload,
        } => {
            setup_logging(verbose)?;
            println!("Verifying cluster isolation...");
            let assessment_config =
                AssessmentConfig::from_flags(control_plane, storage, network, workload);
            println!("Assessment config: {}", assessment_config);

            let tenant1_config = Arc::new(TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&tenant1_kubeconfig_path, 5).await?,
                namespace: tenant1_namespace,
            });
            let tenant2_config = Arc::new(TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&tenant2_kubeconfig_path, 5).await?,
                namespace: tenant2_namespace,
            });

            let report =
                assessment::assess_multitenancy(tenant1_config, tenant2_config, &assessment_config)
                    .await
                    .context("Failed to run multitenancy assessment")?;

            println!("\nCluster isolation assessment report:");
            if let Some(cp) = &report.control_plane {
                println!("{}", cp);
            }
            if let Some(storage) = &report.storage {
                println!("{}", storage);
            }
            if let Some(network) = &report.network {
                println!("{}", network);
            }
            if let Some(workload) = &report.workload {
                println!("{}", workload);
            }
            println!("{}", report);
        }
        Commands::Fairness(cli_args) => {
            setup_logging(cli_args.verbose)?;
            println!("Running fairness assessment...\n");

            // Build Configuration (CLI > YAML > Defaults)
            let config_path = cli_args.config_file.clone();

            if let Some(ref path) = config_path {
                println!("Loading configuration from: {}\n", path.display());
            }

            let t1_path = cli_args.tenant1_kubeconfig_path.clone();
            let t2_path = cli_args.tenant2_kubeconfig_path.clone();
            let t1_ns = cli_args.tenant1_namespace.clone();
            let t2_ns = cli_args.tenant2_namespace.clone();

            let config = FairnessConfigBuilder::new()
                .with_yaml(config_path.as_ref())?
                .with_cli(cli_args)
                .build(); // No args passed here, logic is internal to build()

            // Load tenant configurations
            let tenant1_config = Arc::new(TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&t1_path, 5).await?,
                namespace: t1_ns,
            });
            let tenant2_config = Arc::new(TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&t2_path, 5).await?,
                namespace: t2_ns,
            });

            println!("Fairness Test Configuration:");
            println!(
                "  Baseline duration: {} seconds",
                config.baseline_duration.as_secs()
            );
            println!(
                "  Test duration: {} seconds",
                config.test_duration.as_secs()
            );
            println!("  Rate strategy: {:?}", config.rate_strategy);
            if !matches!(config.rate_strategy, RateLimitStrategy::Unlimited) {
                println!("  Rate limit: {} req/s", config.rate_limit);
            }
            println!("  Rate multiplier: {}x", config.load_multiplier);
            println!("  Pod multiplier: {}x", config.pod_multiplier);
            println!();

            let mut results = Vec::new();

            // Helper to build a runner for a specific subsystem
            let create_runner = |rate: f64| {
                let mut builder = FairnessRunnerBuilder::new()
                    .baseline_duration(config.baseline_duration)
                    .test_duration(config.test_duration)
                    .rate(rate)
                    .strategy(config.rate_strategy.into())
                    .malicious_multiplier(config.load_multiplier)
                    .pod_multiplier(config.pod_multiplier);

                if config.export_csv {
                    builder = builder.export_csv(&config.output_dir);
                }
                builder.build()
            };

            // Control Plane
            if config.run_cp {
                println!("═══════════════════════════════════════════════════════════");
                println!("Control Plane Fairness Assessment");
                println!("  Workers: {}", config.cp_requesters);
                if config.cp_rate != config.rate_limit {
                    println!("  Rate limit: {} req/s (custom)", config.cp_rate);
                }
                println!("═══════════════════════════════════════════════════════════");

                let cp_assessor = FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
                    workers: config.cp_requesters,
                });
                let runner = create_runner(config.cp_rate);
                results.push((
                    "Control Plane",
                    runner
                        .run(&cp_assessor, tenant1_config.clone(), tenant2_config.clone())
                        .await?,
                ));
            }

            // Network
            if config.run_network {
                println!("\n═══════════════════════════════════════════════════════════");
                println!("Network Fairness Assessment (TCP Ping)");
                println!(
                    "  Pod pairs: {}, Streams: {}, Pkt byte size: {}",
                    config.net_pod_pairs, config.net_streams, config.net_packet_size
                );
                if config.net_rate != config.rate_limit {
                    println!("  Rate limit: {} req/s (custom)", config.net_rate);
                }
                println!("═══════════════════════════════════════════════════════════");

                let net_assessor = FairnessNetworkAssessor::new(FairnessNetworkConfig {
                    pod_pairs: config.net_pod_pairs,
                    streams: config.net_streams,
                    packet_size: config.net_packet_size,
                });
                let runner = create_runner(config.net_rate);
                results.push((
                    "Network",
                    runner
                        .run(
                            &net_assessor,
                            tenant1_config.clone(),
                            tenant2_config.clone(),
                        )
                        .await?,
                ));
            }

            // Storage
            if config.run_storage {
                println!("\n═══════════════════════════════════════════════════════════");
                println!("Storage Fairness Assessment");
                println!(
                    "  Pods: {}, Block: {}KB, File: {}MB, Scenario: {:?}",
                    config.st_pods, config.st_block_size, config.st_file_size, config.st_scenario
                );
                if config.st_rate != config.rate_limit {
                    println!("  Rate limit: {} req/s (custom)", config.st_rate);
                }
                println!("═══════════════════════════════════════════════════════════");

                let st_assessor = FairnessStorageAssessor::new(FairnessStorageConfig {
                    pods: config.st_pods,
                    block_size_kb: config.st_block_size,
                    file_size_mb: config.st_file_size,
                    scenario: config.st_scenario.into(),
                });
                let runner = create_runner(config.st_rate);
                results.push((
                    "Storage",
                    runner
                        .run(&st_assessor, tenant1_config.clone(), tenant2_config.clone())
                        .await?,
                ));
            }

            // Workload
            if config.run_workload {
                println!("\n═══════════════════════════════════════════════════════════");
                println!("Workload (CPU) Fairness Assessment");
                println!(
                    "  Pods: {}, Threads: {}, Prime: {}",
                    config.wl_pods, config.wl_threads, config.wl_max_prime
                );
                if config.wl_rate != config.rate_limit {
                    println!("  Rate limit: {} req/s (custom)", config.wl_rate);
                }
                println!("═══════════════════════════════════════════════════════════");

                let wl_assessor = FairnessWorkloadAssessor::new(FairnessWorkloadConfig {
                    pods: config.wl_pods,
                    threads: config.wl_threads,
                    max_prime: config.wl_max_prime,
                });
                let runner = create_runner(config.wl_rate);
                results.push((
                    "Workload",
                    runner
                        .run(&wl_assessor, tenant1_config.clone(), tenant2_config.clone())
                        .await?,
                ));
            }

            // Summary
            println!("\n═══════════════════════════════════════════════════════════");
            println!("FAIRNESS ASSESSMENT SUMMARY");
            println!("═══════════════════════════════════════════════════════════\n");

            for (_, result) in &results {
                println!("{}", result);
            }

            if !results.is_empty() {
                let avg_deg: f64 = results
                    .iter()
                    .map(|(_, r)| r.latency_degradation)
                    .sum::<f64>()
                    / results.len() as f64;
                println!("\n───────────────────────────────────────────────────────────");
                println!("Overall Average Latency Degradation: {:.2}x", avg_deg);

                if let Some((worst_name, worst_res)) = results.iter().max_by(|a, b| {
                    a.1.latency_degradation
                        .partial_cmp(&b.1.latency_degradation)
                        .unwrap()
                }) {
                    println!(
                        "Worst Subsystem: {} ({:.2}x degradation, {})",
                        worst_name,
                        worst_res.latency_degradation,
                        worst_res.fairness_level()
                    );
                }
            }

            if config.export_csv {
                println!("\n📁 Results exported to: {}/", config.output_dir);
            }
        }
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
    env_type: ClusterEnvironmentType,
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
    let builder =
        KubernetesClusterBuilder::new(host_cluster.clone()).with_kubeconfig_path(kubeconfig_path);

    let tenant_cluster = match env_type {
        ClusterEnvironmentType::Capsule => {
            builder
                .with_isolation_technology(ControlPlaneIsolation::Capsule(tenant.to_string()))
                .build()
                .await?
        }
        ClusterEnvironmentType::CapsuleProxy => {
            builder
                .with_isolation_technology(ControlPlaneIsolation::CapsuleProxy(tenant.to_string()))
                .build()
                .await?
        }
        ClusterEnvironmentType::VCluster => {
            builder
                .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant.to_string()))
                .build()
                .await?
        }
        ClusterEnvironmentType::KubeVirt => {
            builder
                .with_isolation_technology(ControlPlaneIsolation::KubeVirt(tenant.to_string()))
                .build()
                .await?
        }
        ClusterEnvironmentType::Kamaji => {
            builder
                .with_isolation_technology(ControlPlaneIsolation::Kamaji(tenant.to_string()))
                .build()
                .await?
        }
        ClusterEnvironmentType::Native => {
            builder
                .with_isolation_technology(ControlPlaneIsolation::None(tenant.to_string()))
                .build()
                .await?
        }
        _ => return Err(anyhow!("Unsupported cluster environment type")),
    };

    Ok(tenant_cluster)
}

async fn setup_test_environment(
    existing_cluster_kubeconfig: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    cluster_name: &str,
    env: ClusterEnvironmentType,
    provider: ChosenClusterProvider,
    tenant1: Tenant1SetupConfig,
    tenant2: Tenant2SetupConfig,
) -> anyhow::Result<()> {
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
                    KindCluster::create(cluster_name, cluster_kubeconfig.clone(), port_mappings)
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
                    K3sCluster::create(cluster_name, cluster_kubeconfig.clone(), port_mappings)
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
                    )
                    .await?,
                )
            }
        }
    };

    let t1_cfg = output_dir.join(format!("tenant1-{}.kubeconfig", cluster_name));
    let t2_cfg = output_dir.join(format!("tenant2-{}.kubeconfig", cluster_name));

    let t1_cluster =
        get_or_create_tenant_cluster(&base_cluster, "tenant1", t1_cfg.clone(), env).await?;
    let t2_cluster =
        get_or_create_tenant_cluster(&base_cluster, "tenant2", t2_cfg.clone(), env).await?;

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
