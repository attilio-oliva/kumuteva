mod cluster_setup;
mod utils;

use std::path::PathBuf;

use clap::Parser;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::ListParams,
    config::{KubeConfigOptions, Kubeconfig},
    Api, Client, Config,
};
use utils::setup_client;

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
    let first_client = setup_client(&args.first_kubeconfig_path).await?;
    let second_client = setup_client(&args.second_kubeconfig_path).await?;

    list_pods(first_client).await?;
    list_pods(second_client).await?;
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
