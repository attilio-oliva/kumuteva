mod cluster;
mod verifier;

use std::path::PathBuf;

use clap::Parser;
use cluster::{KubernetesCluster, NGINX_POD};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

#[derive(Debug, Clone, Parser)]
pub struct Cli {
    #[clap(short, long)]
    pub first_kubeconfig_path: PathBuf,
    #[clap(short, long)]
    pub second_kubeconfig_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let first_cluster = KubernetesCluster::load(&args.first_kubeconfig_path).await?;
    let second_cluster = KubernetesCluster::load(&args.second_kubeconfig_path).await?;

    let obj_isolation_result =
        verifier::check_object_isolation(&first_cluster, &second_cluster).await?;

    println!("Object isolation test result: {:?}", obj_isolation_result);

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
