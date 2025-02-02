mod cluster;
mod verifier;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cluster::{
    ControlPlaneIsolationTechnology, IsolationTechnology, KindCluster, KubernetesCluster,
    KubernetesClusterBuilder, NGINX_POD,
};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

#[derive(Debug, Parser)]
#[clap(name = "multi-tenancy-verifier")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Setup test environment with vclusters
    Setup {
        #[clap(long, short, default_value = "false")]
        existing_cluster: bool,
        #[clap(long, default_value = "test-vcluster")]
        cluster_name: String,
    },
    /// Verify isolation between two clusters
    Verify {
        #[clap(short, long)]
        first_kubeconfig_path: PathBuf,
        #[clap(short, long)]
        second_kubeconfig_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Setup {
            existing_cluster,
            cluster_name,
        } => {
            println!("Setting up test environment...");
            setup_test_environment(existing_cluster, &cluster_name).await?;
            println!("Test environment setup complete");
        }
        Commands::Verify {
            first_kubeconfig_path,
            second_kubeconfig_path,
        } => {
            println!("Verifying cluster isolation...");
            let first_cluster = KubernetesCluster::load(&first_kubeconfig_path).await?;
            let second_cluster = KubernetesCluster::load(&second_kubeconfig_path).await?;

            let obj_isolation_result =
                verifier::check_object_isolation(&first_cluster, &second_cluster).await;

            match obj_isolation_result {
                Ok(_) => {
                    println!("Object isolation test passed");
                }
                Err(e) => {
                    println!("Object isolation test failed: {}", e);
                }
            }
        }
    }

    Ok(())
}

async fn get_or_create_tenant_vcluster(
    kind_cluster: &KindCluster,
    tenant: &str,
    kubeconfig_path: PathBuf,
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

    let tenant_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
        .with_isolation_technology(IsolationTechnology::ControlPlane(
            ControlPlaneIsolationTechnology::VCluster(tenant.to_string()),
        ))
        .with_kubeconfig_path(kubeconfig_path)
        .build()
        .await?;
    tenant_cluster.ensure_cluster_is_ready().await?;
    Ok(tenant_cluster)
}

async fn setup_test_environment(existing_cluster: bool, cluster_name: &str) -> anyhow::Result<()> {
    let test_kubeconfig = PathBuf::from("/tmp/test-vcluster.kubeconfig");

    let kind_cluster = if existing_cluster {
        println!("Using existing kind cluster '{}'", cluster_name);
        KindCluster::load(cluster_name, test_kubeconfig.clone())?
    } else {
        println!("Creating new kind cluster '{}'", cluster_name);
        KindCluster::create(cluster_name, test_kubeconfig.clone())?
    };

    let tenant1_kubeconfig = PathBuf::from("/tmp/tenant1-vcluster.kubeconfig");
    let tenant2_kubeconfig = PathBuf::from("/tmp/tenant2-vcluster.kubeconfig");

    let _tenant1_cluster =
        get_or_create_tenant_vcluster(&kind_cluster, "tenant1", tenant1_kubeconfig.clone()).await?;
    let _tenant2_cluster =
        get_or_create_tenant_vcluster(&kind_cluster, "tenant2", tenant2_kubeconfig.clone()).await?;

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
