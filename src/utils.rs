use std::{
    cell::LazyCell,
    path::{Path, PathBuf},
};

use k8s_openapi::api::core::v1::{Container, Namespace, Pod, PodSpec};
use kube::{
    api::{ObjectMeta, PostParams},
    config::{KubeConfigOptions, Kubeconfig},
    Api, Client, Config, ResourceExt,
};

pub const NGINX_POD: LazyCell<Pod> = LazyCell::new(|| Pod {
    metadata: ObjectMeta {
        name: Some(String::from("nginx-pod")),
        ..Default::default()
    },
    spec: Some(PodSpec {
        containers: vec![Container {
            name: String::from("nginx-container"),
            image: Some(String::from("nginx")),
            ..Default::default()
        }],
        ..Default::default()
    }),
    ..Default::default()
});

pub async fn setup_client(kubeconfig_path: &Path) -> anyhow::Result<Client> {
    let kubeconfig = Kubeconfig::read_from(kubeconfig_path)?;
    let options = KubeConfigOptions::default();
    let config = Config::from_custom_kubeconfig(kubeconfig, &options).await?;
    let client = Client::try_from(config)?;
    Ok(client)
}

pub async fn create_namespace_if_not_exists(client: Client, namespace: &str) -> anyhow::Result<()> {
    let namespaces_api: Api<Namespace> = Api::all(client);
    let namespace_list = namespaces_api.list(&Default::default()).await?;
    if namespace_list
        .items
        .iter()
        .any(|ns| ns.metadata.name.as_deref() == Some(namespace))
    {
        return Ok(());
    }

    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some(String::from(namespace)),
            ..Default::default()
        },
        ..Default::default()
    };

    namespaces_api
        .create(&PostParams::default(), &namespace)
        .await?;
    Ok(())
}
pub async fn create_pod_in_default_namespace(
    client: Client,
    pod: &Pod,
) -> anyhow::Result<Api<Pod>> {
    create_pod(client, pod, None).await
}

pub async fn create_pod_in_namespace(
    client: Client,
    pod: &Pod,
    namespace: &str,
) -> anyhow::Result<Api<Pod>> {
    create_namespace_if_not_exists(client.clone(), namespace).await?;
    create_pod(client, pod, Some(namespace)).await
}

pub async fn create_pod(
    client: Client,
    pod: &Pod,
    namespace: Option<&str>,
) -> anyhow::Result<Api<Pod>> {
    let pods_api = match namespace {
        Some(namespace) => Api::<Pod>::namespaced(client, namespace),
        None => Api::<Pod>::namespaced(client, "default"),
    };

    pods_api.create(&PostParams::default(), &pod).await?;
    Ok(pods_api)
}

pub async fn get_pod_in_namespace(
    client: Client,
    pod_name: &str,
    namespace: &str,
) -> anyhow::Result<Pod> {
    let pods_api = Api::<Pod>::namespaced(client, namespace);
    let pod = pods_api.get(pod_name).await?;
    Ok(pod)
}

pub async fn delete_pod_in_namespace(
    client: Client,
    pod_name: &str,
    namespace: &str,
) -> anyhow::Result<()> {
    let pods_api = Api::<Pod>::namespaced(client, namespace);
    pods_api.delete(pod_name, &Default::default()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use k8s_openapi::api::core::v1::Pod;
    use kube::{api::ListParams, Api};

    use super::*;

    const TEMP_KUBECONFIG_PATH: LazyCell<PathBuf> = LazyCell::new(|| {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push("kubeconfig");
        path
    });

    #[tokio::test]
    async fn setup_and_use_client() {
        let client = setup_client(&TEMP_KUBECONFIG_PATH).await.unwrap();

        let pod_api: Api<Pod> = Api::all(client);
        let pod_list_operation = pod_api.list(&ListParams::default()).await;
        assert!(
            pod_list_operation.is_ok(),
            "Failed to list pods: {:?}",
            pod_list_operation.err()
        );

        let pods = pod_list_operation.unwrap();
        assert!(!pods.items.is_empty(), "Pod list should not be empty");
    }

    #[tokio::test]
    async fn create_and_delete_pod() {
        let client = setup_client(&TEMP_KUBECONFIG_PATH).await.unwrap();

        let pod_creation = create_pod_in_default_namespace(client, &NGINX_POD).await;
        assert!(
            pod_creation.is_ok(),
            "Failed to create pod: {:?}",
            pod_creation.err()
        );

        let pod_api = pod_creation.unwrap();
        let pod_name = NGINX_POD.metadata.name.clone().unwrap();
        let pod_result = pod_api.get(pod_name.as_str()).await;
        assert!(
            pod_result.is_ok(),
            "Failed to get the created pod: {:?}",
            pod_result.err()
        );

        let delete_result = pod_api.delete(pod_name.as_str(), &Default::default()).await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete the created pod: {:?}",
            delete_result.err()
        );
    }
}
