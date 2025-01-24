mod cluster_setup;
mod utils;

use std::path::PathBuf;

use clap::Parser;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, config::Kubeconfig, Api, Client, Config};
use utils::{
    create_pod_in_namespace, delete_pod_in_namespace, get_pod_in_namespace, setup_client, NGINX_POD,
};

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

    //list_pods(first_client.clone()).await?;
    //list_pods(second_client.clone()).await?;

    let pod_name = NGINX_POD
        .metadata
        .name
        .clone()
        .unwrap_or(String::from("nginx"));

    // deploy nginx pod in first cluster
    create_pod_in_namespace(first_client.clone(), &NGINX_POD, "t1").await?;
    // check if pod is available in first cluster by the first tenant
    let pod_seen_by_tenant1 = get_pod_in_namespace(first_client.clone(), &pod_name, "t1").await?;

    // check if pod is available in first cluster by the second tenant
    let pod_seen_by_tenant2 = get_pod_in_namespace(second_client.clone(), &pod_name, "t1").await;
    if pod_seen_by_tenant2.is_ok() {
        println!("Pod is visible to tenant2");
    } else {
        println!("Pod is not visible to tenant2");
    }

    // clean up
    delete_pod_in_namespace(first_client.clone(), &pod_name, "t1").await?;

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
