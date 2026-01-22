mod assessment;
mod cluster;
mod external_crds;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use assessment::TenantClusterConfig;
use clap::{Parser, Subcommand, ValueEnum};
use cluster::TenantsPortMapping;
use cluster::{
    ControlPlaneIsolation, KindCluster, KubernetesClient, KubernetesClusterBuilder,
    NetworkIsolationStrategy,
};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};
use tracing::Level;

use crate::assessment::{
    manual_test_cross_tenant_operation, run_detailed_fairness_assessment, run_fairness_assessment,
    AssessmentConfig, ControlPlaneFairnessAssessor, ControlPlaneFairnessConfig,
    ControlPlaneOperation, ControlPlaneResource, FairnessTestConfig, NetworkFairnessAssessor,
    NetworkFairnessConfig, StorageFairnessAssessor, StorageFairnessConfig,
};

use crate::cluster::{HostCluster, HostClusterType, K3sCluster, K3sProvider, PreExistingCluster};

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
        /// Enable verbose output
        #[clap(long, default_value = "false")]
        verbose: bool,
        /// Use an existing cluster instead of creating a new one
        #[clap(long, short, default_value = "false")]
        existing_cluster: bool,
        /// Name of the cluster to use or create.
        /// It is used as a prefix and followed by the environment type (e.g. test-vcluster).
        #[clap(long, default_value = "test")]
        cluster_name: String,
        #[clap(long = "type", short = 't', default_value = "vcluster")]
        kind: ClusterEnvironmentType,
        /// Host cluster provider to use for the underlying cluster
        #[clap(long = "provider", short = 'p', default_value = "kind")]
        provider: ChosenClusterProvider,
        #[clap(flatten)]
        tenant1: Tenant1SetupConfig,
        #[clap(flatten)]
        tenant2: Tenant2SetupConfig,
    },
    /// Verify isolation between two clusters
    Verify {
        #[clap(long, default_value = "false")]
        verbose: bool,
        #[clap(short = 'f', long = "tenant1-kubeconfig")]
        tenant1_kubeconfig_path: PathBuf,
        #[clap(short = 's', long = "tenant2-kubeconfig")]
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
    },
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
            verbose,
            existing_cluster,
            cluster_name,
            kind,
            provider,
            tenant1,
            tenant2,
        } => {
            setup_logging(verbose)?;

            println!("Setting up test environment...");
            let cluster_name = format!("{}-{}", cluster_name, kind.as_str());
            setup_test_environment(
                existing_cluster,
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
            println!("Multitenancy assessment report:\n{}", report);

            // Common config
            // let config = FairnessTestConfig::default();

            // Control Plane
            // let cp_assessor =
            //     ControlPlaneFairnessAssessor::new(ControlPlaneFairnessConfig::default());
            // let cp_result = run_fairness_assessment(
            //     &cp_assessor,
            //     tenant1_config.clone(),
            //     tenant2_config.clone(),
            //     &config,
            // )
            // .await?;

            // Network
            // let net_assessor = NetworkFairnessAssessor::new(NetworkFairnessConfig::default());
            // let net_result = run_detailed_fairness_assessment(
            //     &net_assessor,
            //     tenant1_config.clone(),
            //     tenant2_config.clone(),
            //     &config,
            //     true,
            //     Some("results/net"),
            // )
            // .await?;

            // Storage
            // let storage_assessor = StorageFairnessAssessor::new(StorageFairnessConfig::default());
            // let storage_result = run_fairness_assessment(
            //     &storage_assessor,
            //     tenant1_config.clone(),
            //     tenant2_config.clone(),
            //     &config,
            // )
            // .await?;

            // println!(
            //     "Control Plane degradation: {:.1}%",
            //     cp_result.latency_degradation * 100.0
            // );
            // println!(
            //     "Network degradation: {:.1}%",
            //     net_result.result.latency_degradation * 100.0
            // );
            // println!(
            //     "Storage degradation: {:.1}%",
            //     storage_result.latency_degradation * 100.0
            // );

            // manual_test_cross_tenant_operation(
            //     &tenant1_config,
            //     &tenant2_config,
            //     &ControlPlaneResource::StorageClass,
            //     &ControlPlaneOperation::Get,
            //     false, // Don't cleanup - leave objects for inspection
            // )
            // .await?;
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
    existing_cluster: bool,
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

    let port_mappings = TenantsPortMapping::from_tuple(tenant1_mapping, tenant2_mapping);
    let test_kubeconfig = PathBuf::from(format!("/tmp/{}.kubeconfig", cluster_name));

    // Create base cluster based on provider type
    let base_cluster = match provider {
        ChosenClusterProvider::Kind => {
            let cluster = if existing_cluster {
                println!("Using existing kind cluster '{}'", cluster_name);
                KindCluster::load(cluster_name, test_kubeconfig.clone())
                    .await
                    .context("Failed to load existing kind cluster")?
            } else {
                println!("Creating new kind cluster '{}'", cluster_name);
                KindCluster::create(cluster_name, test_kubeconfig.clone(), port_mappings)
                    .await
                    .context("Failed to create new kind cluster")?
            };
            HostClusterType::Kind(cluster)
        }
        ChosenClusterProvider::K3s => {
            let cluster = if existing_cluster {
                println!("Using existing k3s cluster '{}'", cluster_name);
                K3sCluster::load(cluster_name, test_kubeconfig.clone())
                    .await
                    .context("Failed to load existing k3s cluster")?
            } else {
                println!("Creating new k3s cluster '{}'", cluster_name);
                K3sCluster::create(cluster_name, test_kubeconfig.clone(), port_mappings)
                    .await
                    .context("Failed to create new k3s cluster")?
            };
            HostClusterType::K3s(cluster)
        }
        ChosenClusterProvider::None => {
            let cluster = if existing_cluster {
                println!("Using existing pre-existing cluster '{}'", cluster_name);
                PreExistingCluster::load(cluster_name, test_kubeconfig.clone())
                    .await
                    .context("Failed to load existing pre-existing cluster")?
            } else {
                println!("Creating new pre-existing cluster '{}'", cluster_name);
                PreExistingCluster::create(cluster_name, test_kubeconfig.clone(), port_mappings)
                    .await
                    .context("Failed to create new pre-existing cluster")?
            };
            HostClusterType::PreExisting(cluster)
        }
    };

    let tenant1_kubeconfig_name = format!("tenant1-{}", cluster_name);
    let tenant2_kubeconfig_name = format!("tenant2-{}", cluster_name);
    let tenant1_kubeconfig = PathBuf::from(format!("/tmp/{}.kubeconfig", tenant1_kubeconfig_name));
    let tenant2_kubeconfig = PathBuf::from(format!("/tmp/{}.kubeconfig", tenant2_kubeconfig_name));

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
