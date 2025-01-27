use anyhow::Result;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::api::{ListParams, ObjectList, ObjectMeta};
use kube::config::Config;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{api::PostParams, Api, Client};

use std::path::Path;

/// An abstraction over a Kubernetes client.
/// This struct is used to interact with a Kubernetes cluster using `kube` crate.
pub struct KubernetesCluster {
    client: Client,
}

impl KubernetesCluster {
    pub async fn load(kubeconfig_path: &Path) -> Result<Self> {
        let kubeconfig = Kubeconfig::read_from(kubeconfig_path)?;
        let options = KubeConfigOptions::default();
        let config = Config::from_custom_kubeconfig(kubeconfig, &options).await?;
        let client = Client::try_from(config)?;
        Ok(Self { client })
    }

    pub async fn create_namespace_if_not_exists(&self, namespace: &str) -> Result<()> {
        let namespaces_api: Api<Namespace> = Api::all(self.client.clone());
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

    pub async fn get_pod_in_namespace(&self, pod_name: &str, namespace: &str) -> Result<Api<Pod>> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        pods_api.get(pod_name).await?;
        Ok(pods_api)
    }

    pub async fn delete_pod_in_namespace(&self, pod_name: &str, namespace: &str) -> Result<()> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        pods_api.delete(pod_name, &Default::default()).await?;
        Ok(())
    }

    pub async fn create_pod(&self, pod: &Pod, namespace: Option<&str>) -> Result<Api<Pod>> {
        let namespace = namespace.unwrap_or("default");
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        pods_api.create(&PostParams::default(), pod).await?;
        Ok(pods_api)
    }

    pub async fn create_pod_in_default_namespace(&self, pod: &Pod) -> Result<Api<Pod>> {
        self.create_pod(pod, None).await
    }

    pub async fn create_pod_in_namespace(&self, pod: &Pod, namespace: &str) -> Result<Api<Pod>> {
        self.create_pod(pod, Some(namespace)).await
    }

    pub async fn list_all_pods(&self) -> Result<ObjectList<Pod>> {
        let api: Api<Pod> = Api::all(self.client.clone());
        let pods = api.list(&ListParams::default()).await?;
        Ok(pods)
    }
}

impl From<Client> for KubernetesCluster {
    fn from(client: Client) -> Self {
        Self { client }
    }
}
impl From<KubernetesCluster> for Client {
    fn from(cluster: KubernetesCluster) -> Self {
        cluster.client
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::LazyCell, path::PathBuf};

    use crate::cluster::KubernetesCluster;
    use crate::cluster::NGINX_POD;

    const TEMP_KUBECONFIG_PATH: LazyCell<PathBuf> = LazyCell::new(|| {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push("kubeconfig");
        path
    });

    #[tokio::test]
    async fn setup_and_use_client() {
        let cluster = KubernetesCluster::load(&TEMP_KUBECONFIG_PATH).await;

        assert!(
            cluster.is_ok(),
            "Failed to create client: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();

        let pod_list_operation = cluster.list_all_pods().await;
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
        let client = KubernetesCluster::load(&TEMP_KUBECONFIG_PATH).await;
        assert!(
            client.is_ok(),
            "Failed to create client: {:?}",
            client.err()
        );

        let client = client.unwrap();

        let pod_creation = client.create_pod_in_default_namespace(&NGINX_POD).await;
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
