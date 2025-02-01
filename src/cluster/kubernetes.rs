use anyhow::{Error, Result};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Namespace, Pod, Secret, Service, ServiceAccount};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::{Metadata, NamespaceResourceScope, Resource};
use kube::api::{ListParams, ObjectList, ObjectMeta, Patch, PatchParams, WatchEvent, WatchParams};
use kube::config::Config;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::runtime::reflector::Lookup;
use kube::CustomResourceExt;
use kube::{api::PostParams, Api, Client};

use futures::{StreamExt, TryStreamExt};
use tokio::time::sleep;

use std::path::Path;
use std::time::Duration;

use super::{Foo, KindCluster};

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

    pub async fn create_nodeport_service(&self, namespace: &str) -> Result<Service> {
        /*
                // create a NodePort service to access the vcluster
                            let service_name = "vcluster-service";
                            let service_port = 6443;
                            let service_type = "NodePort";
                            let service_manifest = format!(
                                r#"
        apiVersion: v1
        kind: Service
        metadata:
          name: {service_name}
          namespace: {namespace}
        spec:
          selector:
            app: vcluster
            release: {release_name}
          ports:
            - name: https
              port: 443
              targetPort: 8443
              protocol: TCP
          type: NodePort
        "#, */
        let api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let service = Service {
            metadata: ObjectMeta {
                name: Some("vcluster-service".to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
                selector: Some({
                    let mut map = std::collections::BTreeMap::new();
                    map.insert("app".to_string(), "vcluster".to_string());
                    map.insert("release".to_string(), "vcluster-tenant1".to_string());
                    map
                }),
                ports: Some(vec![k8s_openapi::api::core::v1::ServicePort {
                    name: Some("https".to_string()),
                    port: 443,
                    target_port: Some(
                        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443),
                    ),
                    protocol: Some("TCP".to_string()),
                    node_port: Some(30080),
                    ..Default::default()
                }]),
                type_: Some("NodePort".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let service = api.create(&PostParams::default(), &service).await?;
        Ok(service)
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

    pub async fn get_pod_in_namespace(&self, pod_name: &str, namespace: &str) -> Result<Pod> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let pod = pods_api.get(pod_name).await?;
        Ok(pod)
    }

    pub async fn delete_pod_in_namespace(&self, pod_name: &str, namespace: &str) -> Result<()> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        pods_api.delete(pod_name, &Default::default()).await?;
        Ok(())
    }

    pub async fn create_pod(&self, pod: &Pod, namespace: Option<&str>) -> Result<Pod> {
        let namespace = namespace.unwrap_or("default");
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let pod: Pod = pods_api.create(&PostParams::default(), pod).await?;
        Ok(pod)
    }

    pub async fn create_pod_in_default_namespace(&self, pod: &Pod) -> Result<Pod> {
        self.create_pod(pod, None).await
    }

    pub async fn create_pod_in_namespace(&self, pod: &Pod, namespace: &str) -> Result<Pod> {
        self.create_pod(pod, Some(namespace)).await
    }

    pub async fn list_all_pods(&self) -> Result<ObjectList<Pod>> {
        let api: Api<Pod> = Api::all(self.client.clone());
        let pods = api.list(&ListParams::default()).await?;
        Ok(pods)
    }

    pub async fn list_pods_with_label(&self, label: &str) -> Result<ObjectList<Pod>> {
        let api: Api<Pod> = Api::all(self.client.clone());
        let pods = api
            .list(&ListParams {
                label_selector: Some(String::from(label)),
                ..Default::default()
            })
            .await?;
        Ok(pods)
    }

    pub async fn get_secret_in_namespace(
        &self,
        secret_name: &str,
        namespace: &str,
    ) -> Result<Secret> {
        let secrets_api = Api::<Secret>::namespaced(self.client.clone(), namespace);
        let secret = secrets_api.get(secret_name).await?;

        Ok(secret)
    }

    async fn is_pod_ready(&self, pod_name: &str, namespace: &str) -> Result<bool> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let pod = pods_api.get(pod_name).await?;
        let status = pod.status.ok_or(Error::msg("Pod status not found"))?;
        println!("Pod status check: {:?}", status.phase);
        println!(
            "is running: {:?}",
            status.phase == Some("Running".to_string())
        );
        Ok(status.phase == Some("Running".to_string()))
    }

    pub async fn wait_for_pod_to_be_ready(&self, pod_name: &str, namespace: &str) -> Result<()> {
        // use the Job API to wait for the pod to be ready
        let jobs: Api<Job> = Api::namespaced(self.client.clone(), namespace);

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", pod_name))
            .timeout(290); // upper bound of how long we watch for

        let pod_ready = self.is_pod_ready(pod_name, namespace).await?;

        if pod_ready {
            return Ok(());
        }

        let mut stream = jobs.watch(&lp, "0").await?.boxed();

        while let Some(status) = stream.try_next().await? {
            if let WatchEvent::Modified(s) = status {
                println!("Pod modified: {:?}", s.status);
                if s.status.unwrap().ready == Some(1) {
                    return Ok(());
                }
            } else {
                println!("New event on pod: {:?}", status);
                if (self.is_pod_ready(pod_name, namespace)).await? {
                    return Ok(());
                }
            }
        }
        println!("Pod become ready in time");
        Ok(())
    }

    pub async fn publish_namespaced_crd<C>(&self) -> Result<()>
    where
        C: CustomResourceExt + Resource<Scope = NamespaceResourceScope> + Metadata<Ty = ObjectMeta>,
    {
        let crd = C::crd();
        let crd_name = crd.name().unwrap();
        let crds: Api<CustomResourceDefinition> = Api::all(self.client.clone());
        crds.patch(
            &crd_name,
            &PatchParams::apply("myapp"),
            &Patch::Apply(C::crd()),
        )
        .await?;

        Ok(())
    }

    pub async fn ensure_cluster_is_ready(&self) -> anyhow::Result<()> {
        let service_accounts: Api<ServiceAccount> = Api::namespaced(self.client.clone(), "default");

        for _ in 0..10 {
            match service_accounts.get("default").await {
                Ok(_) => {
                    //Cluster is ready
                    return Ok(());
                }
                Err(_) => {
                    //Waiting for cluster to be ready...
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }

        Err(Error::msg("Cluster did not become ready in time"))
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
    use std::path::PathBuf;

    use crate::cluster::KindCluster;
    use crate::cluster::KubernetesCluster;
    use crate::cluster::NGINX_POD;

    const CLUSTER_NAME_PREFIX: &str = "test-k8s";

    fn temp_kubeconfig_path(name: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push(format!("{}.kubeconfig", name));
        path
    }

    fn setup_kind_cluster(name: &str) -> anyhow::Result<KindCluster> {
        let kubeconfig_path = temp_kubeconfig_path(name);
        KindCluster::create(name, kubeconfig_path)
    }

    async fn teardown_kind_cluster(cluster: KindCluster) -> anyhow::Result<()> {
        cluster.delete()
    }

    #[tokio::test]
    async fn setup_and_use_client() {
        let temp_cluster_name = format!("{}-setup", CLUSTER_NAME_PREFIX);
        let setup_temp_cluster = setup_kind_cluster(&temp_cluster_name);
        assert!(
            setup_temp_cluster.is_ok(),
            "Failed to setup kind cluster: {:?}",
            setup_temp_cluster.err()
        );

        let temp_cluster = setup_temp_cluster.unwrap();

        let kubeconfig_path = temp_kubeconfig_path(&temp_cluster_name);
        let cluster = KubernetesCluster::load(&kubeconfig_path).await;
        assert!(
            cluster.is_ok(),
            "Failed to create client: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();
        cluster.ensure_cluster_is_ready().await.unwrap();

        let pod_list_operation = cluster.list_all_pods().await;
        assert!(
            pod_list_operation.is_ok(),
            "Failed to list pods: {:?}",
            pod_list_operation.err()
        );

        let pods = pod_list_operation.unwrap();
        assert!(!pods.items.is_empty(), "Pod list should not be empty");

        let teardown_temp_cluster = teardown_kind_cluster(temp_cluster).await;
        assert!(
            teardown_temp_cluster.is_ok(),
            "Failed to teardown kind cluster: {:?}",
            teardown_temp_cluster.err()
        );
    }

    #[tokio::test]
    async fn create_and_delete_pod() {
        let temp_cluster_name = format!("{}-create-delete", CLUSTER_NAME_PREFIX);
        let setup_temp_cluster = setup_kind_cluster(&temp_cluster_name);

        assert!(
            setup_temp_cluster.is_ok(),
            "Failed to setup kind cluster: {:?}",
            setup_temp_cluster.err()
        );

        let temp_cluster = setup_temp_cluster.unwrap();

        let kubeconfig_path = temp_kubeconfig_path(&temp_cluster_name);
        let client = KubernetesCluster::load(&kubeconfig_path).await;
        assert!(
            client.is_ok(),
            "Failed to create client: {:?}",
            client.err()
        );

        let cluster = client.unwrap();
        cluster.ensure_cluster_is_ready().await.unwrap();

        let pod_creation = cluster.create_pod_in_default_namespace(&NGINX_POD).await;
        assert!(
            pod_creation.is_ok(),
            "Failed to create pod: {:?}",
            pod_creation.err()
        );

        let pod = pod_creation.unwrap();
        let pod_name = pod.metadata.name.as_deref().unwrap_or("unnamed");
        let retrieved_pod = cluster.get_pod_in_namespace(pod_name, "default").await;

        assert!(
            retrieved_pod.is_ok(),
            "Failed to get the created pod: {:?}",
            retrieved_pod.err()
        );

        let delete_result = cluster.delete_pod_in_namespace(pod_name, "default").await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete the created pod: {:?}",
            delete_result.err()
        );

        let teardown_temp_cluster = teardown_kind_cluster(temp_cluster).await;
        assert!(
            teardown_temp_cluster.is_ok(),
            "Failed to teardown kind cluster: {:?}",
            teardown_temp_cluster.err()
        );
    }
}
