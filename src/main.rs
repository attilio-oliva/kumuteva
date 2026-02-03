mod assessment;
mod cluster;
mod external_crds;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use assessment::TenantClusterConfig;
use clap::{Parser, Subcommand, ValueEnum};
use cluster::TenantsPortMapping;
use cluster::{ControlPlaneIsolation, KindCluster, KubernetesClient, KubernetesClusterBuilder};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};
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

#[derive(Debug, Parser)]
#[clap(name = "multi-tenancy-verifier")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ClusterEnvironmentType {
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

impl ChosenClusterProvider {
    fn as_str(&self) -> &str {
        match self {
            ChosenClusterProvider::Kind => "kind",
            ChosenClusterProvider::K3s => "k3s",
            ChosenClusterProvider::None => "none",
        }
    }
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
        /// If not specified, defaults to /tmp
        #[clap(long = "output", short = 'o')]
        output_dir: Option<PathBuf>,

        /// Name of the cluster to use or create.
        /// It is used as a prefix and followed by the environment type (e.g. test-vcluster).
        #[clap(long, default_value = "kumuteva")]
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
    Fairness {
        /// Path to tenant1 kubeconfig file (regular tenant) [required]
        #[clap(value_name = "tenant1-kubeconfig")]
        tenant1_kubeconfig_path: PathBuf,
        /// Path to tenant2 kubeconfig file (malicious tenant) [required]
        #[clap(value_name = "tenant2-kubeconfig")]
        tenant2_kubeconfig_path: PathBuf,

        /// Namespace for tenant1
        #[clap(long = "tenant1-ns", default_value = "tenant1")]
        tenant1_namespace: String,
        /// Namespace for tenant2
        #[clap(long = "tenant2-ns", default_value = "tenant2")]
        tenant2_namespace: String,

        /// Assess control plane fairness
        #[clap(long = "control-plane", alias = "cp")]
        control_plane: bool,
        /// Assess storage fairness
        #[clap(long = "storage", alias = "st")]
        storage: bool,
        /// Assess network fairness
        #[clap(long = "network", alias = "net")]
        network: bool,
        /// Assess workload (CPU) fairness
        #[clap(long = "workload", alias = "wl")]
        workload: bool,

        /// Duration for baseline measurement in seconds
        #[clap(long, default_value = "30")]
        baseline_duration: u64,
        /// Duration for unbalanced test phase in seconds
        #[clap(long, default_value = "60")]
        test_duration: u64,

        /// Rate limiting strategy for the runner
        #[clap(long, default_value = "unlimited", value_enum)]
        rate_strategy: RateLimitStrategy,
        /// Request rate limit (requests/sec) - only used with non-unlimited strategies
        #[clap(long, default_value = "10.0")]
        rate_limit: f64,
        /// Load multiplier for malicious tenant (e.g., 10.0 = 10x normal load)
        #[clap(long, default_value = "10.0")]
        load_multiplier: f64,

        /// Number of concurrent requesters for control plane tests
        #[clap(long, default_value = "1")]
        cp_requesters: usize,

        /// Number of benchmark pods per tenant for workload tests
        #[clap(long, default_value = "1")]
        wl_pods: u32,
        /// Number of CPU threads per workload benchmark pod
        #[clap(long, default_value = "1")]
        wl_threads: u32,
        /// Max prime number for workload benchmark (higher = longer task)
        #[clap(long, default_value = "500000")]
        wl_max_prime: u32,

        /// Number of iperf3 client-server pod pairs for network tests
        #[clap(long, default_value = "1")]
        net_pod_pairs: u32,

        /// Number of I/O benchmark pods per tenant for storage tests
        #[clap(long, default_value = "1")]
        st_pods: u32,
        /// I/O block size in KB for storage tests
        #[clap(long, default_value = "4")]
        st_block_size: u32,
        /// File size in MB for storage tests
        #[clap(long, default_value = "100")]
        st_file_size: u32,
        /// Storage test scenario: random or sequential
        #[clap(long, default_value = "random", value_parser = parse_storage_scenario)]
        st_scenario: StorageScenario,

        /// Export results to CSV files
        #[clap(long)]
        export_csv: bool,
        /// Output directory for CSV export (default: fairness_results)
        #[clap(long, default_value = "fairness_results")]
        output_dir: String,

        /// Enable verbose output
        #[clap(long, default_value = "false")]
        verbose: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StorageScenario {
    Random,
    Sequential,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RateLimitStrategy {
    /// No rate limiting - run as fast as possible
    Unlimited,
    /// Fixed delay between requests
    FixedDelay,
    /// Adaptive rate adjustment based on feedback
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

fn parse_storage_scenario(s: &str) -> Result<StorageScenario, String> {
    match s.to_lowercase().as_str() {
        "random" => Ok(StorageScenario::Random),
        "sequential" | "seq" => Ok(StorageScenario::Sequential),
        _ => Err(format!(
            "Invalid storage scenario: {}. Use 'random' or 'sequential'",
            s
        )),
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

#[derive(Debug, Parser)]
struct Tenant1SetupConfig {
    /// Short style: Provide tenant namespace and optional mapping.
    /// Example: --tenant1 tenant1-namespace [TENANT1_MAPPING]
    #[clap(
        long = "tenant1",
        name = "tenant1",
        value_names = &["TENANT1_NAMESPACE", "TENANT1_MAPPING"],
        num_args = 1..=2,
        conflicts_with_all = &["tenant1_ns", "tenant1_mapping"]
    )]
    tenant1_short: Option<Vec<String>>,

    /// Long style: Tenant namespace.
    #[clap(
        long = "tenant1-ns",
        default_value = "tenant1",
        conflicts_with = "tenant1"
    )]
    tenant1_ns: String,

    /// Long style: Port mapping in format containerPort:hostPort.
    #[clap(
        long = "tenant1-mapping",
        value_parser = parse_mapping,
        default_value = "30010:30001",
        conflicts_with = "tenant1"
    )]
    tenant1_mapping: (u16, u16),
}

#[derive(Debug, Parser)]
struct Tenant2SetupConfig {
    /// Short style: Provide tenant namespace and optional mapping.
    /// Example: --tenant2 tenant2-namespace [TENANT2_MAPPING]
    #[clap(
        long = "tenant2",
        name = "tenant2",
        value_names = &["TENANT2_NAMESPACE", "TENANT2_MAPPING"],
        num_args = 1..=2,
        conflicts_with_all = &["tenant2_ns", "tenant2_mapping"]
    )]
    tenant2_short: Option<Vec<String>>,

    /// Long style: Tenant namespace.
    #[clap(
        long = "tenant2-ns",
        default_value = "tenant2",
        conflicts_with = "tenant2"
    )]
    tenant2_ns: String,

    /// Long style: Port mapping in format containerPort:hostPort.
    #[clap(
        long = "tenant2-mapping",
        value_parser = parse_mapping,
        default_value = "30020:30002",
        conflicts_with = "tenant2"
    )]
    tenant2_mapping: (u16, u16),
}

fn resolve_tenant_config(
    short: &Option<Vec<String>>,
    default_ns: &str,
    default_mapping: &(u16, u16),
) -> anyhow::Result<(String, (u16, u16))> {
    let tenant_ns = if let Some(short_values) = short {
        short_values
            .first()
            .cloned()
            .unwrap_or_else(|| default_ns.to_string())
    } else {
        String::from(default_ns)
    };

    let tenant_mapping = if let Some(short_values) = short {
        if short_values.len() > 1 {
            parse_mapping(&short_values[1])?
        } else {
            *default_mapping
        }
    } else {
        *default_mapping
    };

    Ok((tenant_ns, tenant_mapping))
}

impl Tenant1SetupConfig {
    fn get_config(&self) -> anyhow::Result<(String, (u16, u16))> {
        resolve_tenant_config(&self.tenant1_short, &self.tenant1_ns, &self.tenant1_mapping)
    }
}

impl Tenant2SetupConfig {
    fn get_config(&self) -> anyhow::Result<(String, (u16, u16))> {
        resolve_tenant_config(&self.tenant2_short, &self.tenant2_ns, &self.tenant2_mapping)
    }
}

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

            // Build assessment config: if no flags specified, run all; otherwise only specified ones
            let assessment_config =
                AssessmentConfig::from_flags(control_plane, storage, network, workload);
            println!("Assessment config: {}", assessment_config);

            let tenant1_config = TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&tenant1_kubeconfig_path, 5).await?,
                namespace: tenant1_namespace,
            };
            let tenant2_config = TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&tenant2_kubeconfig_path, 5).await?,
                namespace: tenant2_namespace,
            };

            let tenant1_config = Arc::new(tenant1_config);
            let tenant2_config = Arc::new(tenant2_config);

            let report = assessment::assess_multitenancy(
                tenant1_config.clone(),
                tenant2_config.clone(),
                &assessment_config,
            )
            .await
            .context("Failed to run multitenancy assessment")?;

            println!();
            println!("Cluster isolation assessment report:");

            // Print individual subsystem reports if available
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
        Commands::Fairness {
            tenant1_kubeconfig_path,
            tenant2_kubeconfig_path,
            tenant1_namespace,
            tenant2_namespace,
            control_plane,
            storage,
            network,
            workload,
            baseline_duration,
            test_duration,
            rate_strategy,
            rate_limit,
            load_multiplier,
            cp_requesters,
            wl_pods,
            wl_threads,
            wl_max_prime,
            net_pod_pairs,
            st_pods,
            st_block_size,
            st_file_size,
            st_scenario,
            export_csv,
            output_dir,
            verbose,
        } => {
            setup_logging(verbose)?;
            println!("Running fairness assessment...\n");

            // Determine which subsystems to test
            let run_all = !control_plane && !storage && !network && !workload;
            let run_cp = control_plane || run_all;
            let run_storage = storage || run_all;
            let run_network = network || run_all;
            let run_workload = workload || run_all;

            // Load tenant configurations
            let tenant1_config = Arc::new(TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&tenant1_kubeconfig_path, 5).await?,
                namespace: tenant1_namespace,
            });
            let tenant2_config = Arc::new(TenantClusterConfig {
                cluster: KubernetesClient::load_with_retry(&tenant2_kubeconfig_path, 5).await?,
                namespace: tenant2_namespace,
            });

            // Build the fairness runner with the specified configuration
            let mut runner_builder = FairnessRunnerBuilder::new()
                .baseline_duration(std::time::Duration::from_secs(baseline_duration))
                .test_duration(std::time::Duration::from_secs(test_duration))
                .rate(rate_limit)
                .strategy(rate_strategy.into())
                .malicious_multiplier(load_multiplier);

            if export_csv {
                runner_builder = runner_builder.export_csv(&output_dir);
            }

            let runner = runner_builder.build();

            println!("Fairness Test Configuration:");
            println!("  Baseline duration: {} seconds", baseline_duration);
            println!("  Test duration: {} seconds", test_duration);
            println!("  Rate strategy: {:?}", rate_strategy);
            if !matches!(rate_strategy, RateLimitStrategy::Unlimited) {
                println!("  Rate limit: {} req/sec", rate_limit);
            }
            println!("  Load multiplier: {}x", load_multiplier);
            println!();

            let mut results = Vec::new();

            // Control Plane fairness
            if run_cp {
                println!("═══════════════════════════════════════════════════════════");
                println!("Control Plane Fairness Assessment");
                println!("  Workers: {}", cp_requesters);
                println!("═══════════════════════════════════════════════════════════");

                let cp_config = FairnessControlPlaneConfig {
                    workers: cp_requesters,
                };
                let cp_assessor = FairnessControlPlaneAssessor::new(cp_config);

                let result = runner
                    .run(&cp_assessor, tenant1_config.clone(), tenant2_config.clone())
                    .await?;
                results.push(("Control Plane", result));
            }

            // Network fairness
            if run_network {
                println!("\n═══════════════════════════════════════════════════════════");
                println!("Network Fairness Assessment");
                println!("  Pod pairs per tenant: {}", net_pod_pairs);
                println!("  Baseline bandwidth: {}Mbps", runner.config().tenant1_rate);
                println!("═══════════════════════════════════════════════════════════");

                let net_config = FairnessNetworkConfig {
                    pod_pairs: net_pod_pairs,
                };
                let net_assessor = FairnessNetworkAssessor::new(net_config);

                let result = runner
                    .run(
                        &net_assessor,
                        tenant1_config.clone(),
                        tenant2_config.clone(),
                    )
                    .await?;
                results.push(("Network", result));
            }

            // Storage fairness
            if run_storage {
                println!("\n═══════════════════════════════════════════════════════════");
                println!("Storage Fairness Assessment");
                println!(
                    "  Pods: {}, Block size: {}KB, File size: {}MB, Scenario: {:?}",
                    st_pods, st_block_size, st_file_size, st_scenario
                );
                println!("═══════════════════════════════════════════════════════════");

                let storage_config = FairnessStorageConfig {
                    pods: st_pods,
                    block_size_kb: st_block_size,
                    file_size_mb: st_file_size,
                    scenario: st_scenario.into(),
                };
                let storage_assessor = FairnessStorageAssessor::new(storage_config);

                let result = runner
                    .run(
                        &storage_assessor,
                        tenant1_config.clone(),
                        tenant2_config.clone(),
                    )
                    .await?;
                results.push(("Storage", result));
            }

            // Workload fairness
            if run_workload {
                println!("\n═══════════════════════════════════════════════════════════");
                println!("Workload (CPU) Fairness Assessment");
                println!(
                    "  Pods: {}, Threads: {}, Max prime: {}",
                    wl_pods, wl_threads, wl_max_prime
                );
                println!("═══════════════════════════════════════════════════════════");

                let wl_config = FairnessWorkloadConfig {
                    pods: wl_pods,
                    threads: wl_threads,
                    max_prime: wl_max_prime,
                };
                let wl_assessor = FairnessWorkloadAssessor::new(wl_config);

                let result = runner
                    .run(&wl_assessor, tenant1_config.clone(), tenant2_config.clone())
                    .await?;
                results.push(("Workload", result));
            }

            // Print summary
            println!("\n═══════════════════════════════════════════════════════════");
            println!("FAIRNESS ASSESSMENT SUMMARY");
            println!("═══════════════════════════════════════════════════════════\n");

            for (_, result) in &results {
                println!("{}", result);
            }

            // Calculate overall degradation
            if !results.is_empty() {
                let avg_degradation: f64 = results
                    .iter()
                    .map(|(_, r)| r.latency_degradation)
                    .sum::<f64>()
                    / results.len() as f64;

                println!("\n───────────────────────────────────────────────────────────");
                println!(
                    "Overall Average Latency Degradation: {:.2}x",
                    avg_degradation
                );

                if let Some((worst_name, worst_result)) = results.iter().max_by(|(_, a), (_, b)| {
                    a.latency_degradation
                        .partial_cmp(&b.latency_degradation)
                        .unwrap()
                }) {
                    println!(
                        "Worst Subsystem: {} ({:.2}x degradation, {})",
                        worst_name,
                        worst_result.latency_degradation,
                        worst_result.fairness_level()
                    );
                }
            }

            if export_csv {
                println!("\n📁 Results exported to: {}/", output_dir);
            }
        }
    }

    Ok(())
}

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

    let tenant_cluster = match env_type {
        ClusterEnvironmentType::Capsule => {
            KubernetesClusterBuilder::new(host_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::Capsule(tenant.to_string()))
                // .with_isolation_technology(NetworkIsolationStrategy::NetworkPolicy(
                //     tenant.to_string(),
                // ))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        ClusterEnvironmentType::CapsuleProxy => {
            KubernetesClusterBuilder::new(host_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::CapsuleProxy(tenant.to_string()))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        ClusterEnvironmentType::VCluster => {
            KubernetesClusterBuilder::new(host_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant.to_string()))
                // .with_isolation_technology(NetworkIsolationStrategy::NetworkPolicy(
                //     tenant.to_string(),
                // ))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        ClusterEnvironmentType::KubeVirt => {
            KubernetesClusterBuilder::new(host_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::KubeVirt(tenant.to_string()))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        ClusterEnvironmentType::Kamaji => {
            KubernetesClusterBuilder::new(host_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::Kamaji(tenant.to_string()))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        ClusterEnvironmentType::Native => {
            KubernetesClusterBuilder::new(host_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::None(tenant.to_string()))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        _ => {
            return Err(anyhow!("Unsupported cluster environment type"));
        }
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
    let (tenant1_ns, tenant1_mapping) = tenant1.get_config()?;
    let (tenant2_ns, tenant2_mapping) = tenant2.get_config()?;
    println!(
        "Tenant1: ns={}, port_mapping={{container={}, host={}}}",
        tenant1_ns, tenant1_mapping.0, tenant1_mapping.1
    );
    println!(
        "Tenant2: ns={}, port_mapping={{container={}, host={}}}",
        tenant2_ns, tenant2_mapping.0, tenant2_mapping.1
    );

    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("/tmp"));
    std::fs::create_dir_all(&output_dir)
        .context("Failed to create output directory for kubeconfig files")?;

    let port_mappings = TenantsPortMapping::from_tuple(tenant1_mapping, tenant2_mapping);
    let using_existing_cluster = existing_cluster_kubeconfig.is_some();
    let cluster_kubeconfig = if let Some(existing_path) = existing_cluster_kubeconfig {
        existing_path
    } else {
        output_dir.join(format!("{}.kubeconfig", cluster_name))
    };

    let cluster_name = if using_existing_cluster {
        // If using existing cluster, try to extract the name from the kubeconfig file path
        cluster_kubeconfig
            .file_stem()
            .and_then(|os_str| os_str.to_str())
            .unwrap_or(cluster_name)
    } else {
        cluster_name
    };

    // Create base cluster based on provider type
    let base_cluster = match provider {
        ChosenClusterProvider::Kind => {
            let cluster = if using_existing_cluster {
                println!("Using existing kind cluster '{}'", cluster_name);
                KindCluster::load(cluster_name, cluster_kubeconfig.clone())
                    .await
                    .context("Failed to load existing kind cluster")?
            } else {
                println!("Creating new kind cluster '{}'", cluster_name);
                KindCluster::create(cluster_name, cluster_kubeconfig.clone(), port_mappings)
                    .await
                    .context("Failed to create new kind cluster")?
            };
            HostClusterType::Kind(cluster)
        }
        ChosenClusterProvider::K3s => {
            let cluster = if using_existing_cluster {
                println!("Using existing k3s cluster '{}'", cluster_name);
                K3sCluster::load(cluster_name, cluster_kubeconfig.clone())
                    .await
                    .context("Failed to load existing k3s cluster")?
            } else {
                println!("Creating new k3s cluster '{}'", cluster_name);
                K3sCluster::create(cluster_name, cluster_kubeconfig.clone(), port_mappings)
                    .await
                    .context("Failed to create new k3s cluster")?
            };
            HostClusterType::K3s(cluster)
        }
        ChosenClusterProvider::None => {
            let cluster = if using_existing_cluster {
                println!("Using existing pre-existing cluster '{}'", cluster_name);
                PreExistingCluster::load(cluster_name, cluster_kubeconfig.clone())
                    .await
                    .context("Failed to load existing pre-existing cluster")?
            } else {
                println!("Creating new pre-existing cluster '{}'", cluster_name);
                PreExistingCluster::create(cluster_name, cluster_kubeconfig.clone(), port_mappings)
                    .await
                    .context("Failed to create new pre-existing cluster")?
            };
            HostClusterType::PreExisting(cluster)
        }
    };

    let tenant1_kubeconfig_name = format!("tenant1-{}", cluster_name);
    let tenant2_kubeconfig_name = format!("tenant2-{}", cluster_name);
    let tenant1_kubeconfig = output_dir.join(format!("{}.kubeconfig", tenant1_kubeconfig_name));
    let tenant2_kubeconfig = output_dir.join(format!("{}.kubeconfig", tenant2_kubeconfig_name));

    let tenant1_cluster =
        get_or_create_tenant_cluster(&base_cluster, "tenant1", tenant1_kubeconfig.clone(), env)
            .await?;
    let tenant2_cluster =
        get_or_create_tenant_cluster(&base_cluster, "tenant2", tenant2_kubeconfig.clone(), env)
            .await?;

    tenant1_cluster.ensure_cluster_is_ready().await?;
    tenant2_cluster.ensure_cluster_is_ready().await?;

    println!("Created test clusters:");
    println!("Tenant 1 kubeconfig: {}", tenant1_kubeconfig.display());
    println!("Tenant 2 kubeconfig: {}", tenant2_kubeconfig.display());

    Ok(())
}

pub async fn list_pods(client: Client) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::all(client);
    let pod = pods.list(&ListParams::default()).await?;
    println!("List of pods:");
    // print namespace and name of each pod
    for p in pod.items {
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
    let container = parts[0].parse().context("Invalid container port")?;
    let host = parts[1].parse().context("Invalid host port")?;
    Ok((container, host))
}

fn setup_logging(verbose: bool) -> anyhow::Result<()> {
    let filter_level = if verbose { Level::INFO } else { Level::ERROR };

    tracing_subscriber::fmt()
        .with_max_level(filter_level)
        .init();

    Ok(())
}
