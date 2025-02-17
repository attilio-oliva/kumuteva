mod cluster;
mod external_crds;
mod verifier;

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand, ValueEnum};
use cluster::TenantsPortMapping;
use cluster::{
    ControlPlaneIsolation, KindCluster, KubernetesCluster, KubernetesClusterBuilder,
    NetworkIsolationStrategy,
};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};
use verifier::TenantClusterConfig;

#[derive(Debug, Parser)]
#[clap(name = "multi-tenancy-verifier")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ClusterEnvironmentType {
    #[clap(name = "capsule", alias = "cap", alias = "caps")]
    Capsule,
    #[clap(name = "kcp")]
    Kcp,
    #[clap(name = "vcluster", alias = "vc")]
    VCluster,
    #[clap(name = "kubevirt", alias = "kv")]
    KubeVirt,
}

impl ClusterEnvironmentType {
    fn as_str(&self) -> &str {
        match self {
            ClusterEnvironmentType::Capsule => "capsule",
            ClusterEnvironmentType::Kcp => "kcp",
            ClusterEnvironmentType::VCluster => "vcluster",
            ClusterEnvironmentType::KubeVirt => "kubevirt",
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Setup test environment with two tenants given a cluster environment type
    Setup {
        #[clap(long, short, default_value = "false")]
        existing_cluster: bool,
        /// Name of the cluster to use or create.
        /// It is used as a prefix and followed by the environment type (e.g. test-vcluster).
        #[clap(long, default_value = "test")]
        cluster_name: String,
        #[clap(long = "type", short = 't', default_value = "vcluster")]
        kind: ClusterEnvironmentType,
        #[clap(flatten)]
        tenant1: Tenant1SetupConfig,
        #[clap(flatten)]
        tenant2: Tenant2SetupConfig,
    },
    /// Verify isolation between two clusters
    Verify {
        #[clap(short = 'f', long = "tenant1-kubeconfig")]
        tenant1_kubeconfig_path: PathBuf,
        #[clap(short = 's', long = "tenant2-kubeconfig")]
        tenant2_kubeconfig_path: PathBuf,

        #[clap(long = "tenant1-ns", default_value = "tenant1")]
        tenant1_namespace: String,
        #[clap(long = "tenant2-ns", default_value = "tenant2")]
        tenant2_namespace: String,
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
            existing_cluster,
            cluster_name,
            kind,
            tenant1,
            tenant2,
        } => {
            println!("Setting up test environment...");
            let cluster_name = format!("{}-{}", cluster_name, kind.as_str());
            setup_test_environment(existing_cluster, &cluster_name, kind, tenant1, tenant2).await?;
            println!("Test environment setup complete");
        }
        Commands::Verify {
            tenant1_kubeconfig_path,
            tenant2_kubeconfig_path,
            tenant1_namespace,
            tenant2_namespace,
        } => {
            println!("Verifying cluster isolation...");
            let tenant1_config = TenantClusterConfig {
                cluster: KubernetesCluster::load(&tenant1_kubeconfig_path).await?,
                namespace: tenant1_namespace,
            };
            let tenant2_config = TenantClusterConfig {
                cluster: KubernetesCluster::load(&tenant2_kubeconfig_path).await?,
                namespace: tenant2_namespace,
            };
            /*
            let obj_isolation_result =
                verifier::check_object_isolation(&tenant1_config, &tenant2_config).await;

            match obj_isolation_result {
                Ok(true) => println!("Object isolation test passed"),
                Ok(false) => {
                    println!("Object isolation test failed: tenant2 can access tenant1 objects")
                }
                Err(e) => println!("Object isolation could not be verified: {}", e),
            }

            let transparent_isolation_result = verifier::check_transparent_isolation_level(
                &tenant1_config,
                &tenant2_config,
                TransparentIsolationLevel::Cluster,
            )
            .await;

            match transparent_isolation_result {
                Ok(_) => println!("Transparent isolation test at cluster level passed"),
                Err(e) => println!("Transparent isolation test at cluster level failed: {}", e),
            }

            let transparent_isolation_result = verifier::check_transparent_isolation_level(
                &tenant1_config,
                &tenant2_config,
                TransparentIsolationLevel::Node,
            )
            .await;

            match transparent_isolation_result {
                Ok(_) => println!("Transparent isolation test at node level passed"),
                Err(e) => println!("Transparent isolation test at node level failed: {}", e),
            }

            let transparent_isolation_result = verifier::check_transparent_isolation_level(
                &tenant1_config,
                &tenant2_config,
                TransparentIsolationLevel::Namespace,
            )
            .await;

            match transparent_isolation_result {
                Ok(_) => println!("Transparent isolation test at namespace level passed"),
                Err(e) => println!(
                    "Transparent isolation test at namespace level failed: {}",
                    e
                ),
            }
            */

            /* This will do the same as above, but formatted in a nice way
            let report = verifier::check_control_plane_isolation(&tenant1_config, &tenant2_config)
                .await
                .context("Failed to verify control plane isolation")?;

            println!("Control plane isolation test results:\n{}", report);
            */

            /*

            let is_network_isolated =
                verifier::check_network_isolation(&tenant1_config, &tenant2_config)
                    .await
                    .context("Failed to verify network isolation")?;

            if is_network_isolated {
                println!("Network isolation test passed");
            } else {
                println!("Network isolation test failed");
            }
            */

            let is_storage_isolated =
                verifier::check_storage_isolation(&tenant1_config, &tenant2_config).await;
            is_storage_isolated.unwrap();
        }
    }

    Ok(())
}

async fn get_or_create_tenant_cluster(
    kind_cluster: &KindCluster,
    tenant: &str,
    kubeconfig_path: PathBuf,
    env_type: ClusterEnvironmentType,
) -> anyhow::Result<KubernetesCluster> {
    if let Ok(existing_cluster) = KubernetesCluster::load(&kubeconfig_path).await {
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
            KubernetesClusterBuilder::new(kind_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::Capsule(tenant.to_string()))
                .with_isolation_technology(NetworkIsolationStrategy::NetworkPolicy(
                    tenant.to_string(),
                ))
                .with_kubeconfig_path(kubeconfig_path)
                .build()
                .await?
        }
        ClusterEnvironmentType::VCluster => {
            KubernetesClusterBuilder::new(kind_cluster.clone())
                .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant.to_string()))
                // .with_isolation_technology(NetworkIsolationStrategy::NetworkPolicy(
                //     tenant.to_string(),
                // ))
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

    let kind_cluster = if existing_cluster {
        println!("Using existing kind cluster '{}'", cluster_name);
        KindCluster::load(cluster_name, test_kubeconfig.clone())?
    } else {
        println!("Creating new kind cluster '{}'", cluster_name);
        KindCluster::create(cluster_name, test_kubeconfig.clone(), port_mappings)?
    };

    let tenant1_kubeconfig_name = format!("tenant1-{}", cluster_name);
    let tenant2_kubeconfig_name = format!("tenant2-{}", cluster_name);
    let tenant1_kubeconfig = PathBuf::from(format!("/tmp/{}.kubeconfig", tenant1_kubeconfig_name));
    let tenant2_kubeconfig = PathBuf::from(format!("/tmp/{}.kubeconfig", tenant2_kubeconfig_name));

    let tenant1_cluster =
        get_or_create_tenant_cluster(&kind_cluster, "tenant1", tenant1_kubeconfig.clone(), env)
            .await?;
    let tenant2_cluster =
        get_or_create_tenant_cluster(&kind_cluster, "tenant2", tenant2_kubeconfig.clone(), env)
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
