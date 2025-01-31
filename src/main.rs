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

async fn setup_test_environment(existing_cluster: bool, cluster_name: &str) -> anyhow::Result<()> {
    let name = "test-vcluster";
    let kubeconfig_path = PathBuf::from("/tmp/test-vcluster.kubeconfig");

    let kind_cluster = if existing_cluster {
        println!("Using existing kind cluster '{}'", cluster_name);
        KindCluster::load(cluster_name, kubeconfig_path.clone())?
    } else {
        println!("Creating new kind cluster '{}'", cluster_name);
        KindCluster::create(cluster_name, kubeconfig_path.clone())?
    };

    let tenant1_kubeconfig_path = PathBuf::from("/tmp/tenant1-vcluster.kubeconfig");
    let tenant2_kubeconfig_path = PathBuf::from("/tmp/tenant2-vcluster.kubeconfig");

    let tenant1_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
        .with_isolation_technology(IsolationTechnology::ControlPlane(
            ControlPlaneIsolationTechnology::VCluster("tenant1".to_string()),
        ))
        .with_kubeconfig_path(tenant1_kubeconfig_path)
        .build()
        .await?;

    tenant1_cluster.ensure_cluster_is_ready().await?;

    let tenant2_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
        .with_isolation_technology(IsolationTechnology::ControlPlane(
            ControlPlaneIsolationTechnology::VCluster("tenant2".to_string()),
        ))
        .with_kubeconfig_path(tenant2_kubeconfig_path)
        .build()
        .await?;

    tenant2_cluster.ensure_cluster_is_ready().await?;

    println!("Created test clusters:");
    println!("Tenant 1 kubeconfig: /tmp/tenant1-vcluster.kubeconfig");
    println!("Tenant 2 kubeconfig: /tmp/tenant2-vcluster.kubeconfig");

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
