use anyhow::{anyhow, Context, Error, Result};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{
    Namespace, Node, Pod, Secret, Service, ServiceAccount, ServicePort, ServiceSpec,
};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::{ClusterResourceScope, Metadata, NamespaceResourceScope, Resource};
use kube::api::{
    AttachParams, AttachedProcess, ListParams, ObjectList, ObjectMeta, Patch, PatchParams,
    WatchEvent, WatchParams,
};
use kube::config::Config;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::core::ErrorResponse;
use kube::runtime::reflector::Lookup;
use kube::runtime::{watcher, WatchStreamExt};
use kube::CustomResourceExt;
use kube::{api::PostParams, Api, Client};

use futures::{StreamExt, TryStreamExt};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::time::sleep;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::pin;
use std::time::Duration;

use super::DummyCRD;

/// An abstraction over a Kubernetes client.
/// This struct is used to interact with a Kubernetes cluster using `kube` crate.
pub struct KubernetesCluster {
    client: Client,
}

impl KubernetesCluster {
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    pub async fn load(kubeconfig_path: &Path) -> Result<Self> {
        let kubeconfig = Kubeconfig::read_from(kubeconfig_path)?;
        let options = KubeConfigOptions::default();
        let config = Config::from_custom_kubeconfig(kubeconfig, &options).await?;
        let client = Client::try_from(config)?;
        Ok(Self { client })
    }

    pub async fn patch_cluster_resource<R, P>(
        &self,
        resource_name: &str,
        patch: &Patch<P>,
    ) -> Result<R>
    where
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
        P: serde::Serialize + std::fmt::Debug,
    {
        let api: Api<R> = Api::all(self.client.clone());
        let resource = api
            .patch(resource_name, &PatchParams::default(), patch)
            .await?;
        Ok(resource)
    }

    pub async fn create_nodeport_service(
        &self,
        namespace: &str,
        selector: Option<BTreeMap<String, String>>,
        chosen_port: Option<i32>,
    ) -> Result<Service> {
        let api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let service = Service {
            metadata: ObjectMeta {
                name: Some("vcluster-service".to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector,
                ports: Some(vec![ServicePort {
                    name: Some("https".to_string()),
                    port: 443,
                    target_port: Some(IntOrString::Int(8443)),
                    protocol: Some("TCP".to_string()),
                    node_port: chosen_port,
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
        let namespaces = self.list_cluster_resources::<Namespace>().await?;
        if namespaces
            .items
            .iter()
            .any(|ns| ns.metadata.name.as_deref() == Some(namespace))
        {
            return Ok(());
        }

        self.create_namespace(namespace).await
    }

    pub async fn create_namespace(&self, namespace: &str) -> Result<()> {
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(String::from(namespace)),
                ..Default::default()
            },
            ..Default::default()
        };

        let namespaces_api: Api<Namespace> = Api::all(self.client.clone());

        namespaces_api
            .create(&PostParams::default(), &namespace)
            .await?;
        Ok(())
    }

    pub async fn delete_cluster_resource<R>(&self, resource_name: &str) -> Result<()>
    where
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::all(self.client.clone());
        api.delete(resource_name, &Default::default()).await?;
        Ok(())
    }

    pub async fn get_cluster_resource<R>(&self, resource_name: &str) -> Result<R>
    where
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::all(self.client.clone());
        let resource = api.get(resource_name).await?;
        Ok(resource)
    }

    pub async fn find_cluster_resources_with_label<R>(&self, label: &str) -> Result<ObjectList<R>>
    where
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::all(self.client.clone());
        let resources = api
            .list(&ListParams {
                label_selector: Some(String::from(label)),
                ..Default::default()
            })
            .await?;
        Ok(resources)
    }

    pub async fn get_resource_in_namespace<R>(
        &self,
        resource_name: &str,
        namespace: &str,
    ) -> Result<R>
    where
        R: Resource<Scope = NamespaceResourceScope>
            + Clone
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);
        let resource = api.get(resource_name).await?;
        Ok(resource)
    }

    pub async fn get_pod_in_namespace(&self, pod_name: &str, namespace: &str) -> Result<Pod> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let pod = pods_api.get(pod_name).await?;
        Ok(pod)
    }

    pub async fn delete_resouce_in_namespace<R>(
        &self,
        resource_name: &str,
        namespace: &str,
    ) -> Result<()>
    where
        R: Resource<Scope = NamespaceResourceScope>
            + Clone
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);
        api.delete(resource_name, &Default::default()).await?;
        Ok(())
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

    pub async fn create_cluster_resource<R>(&self, resource: &R) -> Result<R>
    where
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::all(self.client.clone());
        let created = api.create(&PostParams::default(), resource).await?;
        Ok(created)
    }

    pub async fn create_namespaced_resource<R>(&self, resource: &R, namespace: &str) -> Result<R>
    where
        R: Resource<Scope = NamespaceResourceScope>
            + Clone
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);
        let created = api.create(&PostParams::default(), resource).await?;
        Ok(created)
    }

    pub async fn create_dummy_crd_resource(
        &self,
        namespace: &str,
        resource: DummyCRD,
    ) -> Result<()> {
        let crd_api: Api<DummyCRD> = Api::namespaced(self.client.clone(), namespace);
        let crd_name = resource.name().unwrap();
        let patch_params = PatchParams::apply(&crd_name);
        let patch = Patch::Apply(resource.clone());
        crd_api.patch(&crd_name, &patch_params, &patch).await?;
        Ok(())
    }

    pub async fn list_all_pods(&self) -> Result<ObjectList<Pod>> {
        let api: Api<Pod> = Api::all(self.client.clone());
        let pods = api.list(&ListParams::default()).await?;
        Ok(pods)
    }

    pub async fn list_pods_with_label_in_namespace(
        &self,
        label: &str,
        namespace: &str,
    ) -> Result<ObjectList<Pod>> {
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let pods = api
            .list(&ListParams {
                label_selector: Some(String::from(label)),
                ..Default::default()
            })
            .await?;
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
        //println!("Pod status check: {:?}", status.phase);
        Ok(status.phase == Some("Running".to_string()))
    }

    pub async fn list_namespaced_resources<R>(&self, namespace: &str) -> Result<ObjectList<R>>
    where
        R: Resource<Scope = NamespaceResourceScope>
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);
        let resources = api.list(&ListParams::default()).await?;
        Ok(resources)
    }

    pub async fn list_cluster_resources<R>(&self) -> Result<ObjectList<R>>
    where
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::all(self.client.clone());
        let resources = api.list(&ListParams::default()).await?;
        Ok(resources)
    }

    pub async fn list_nodes(&self) -> Result<ObjectList<Node>> {
        let api: Api<Node> = Api::all(self.client.clone());
        let nodes = api.list(&ListParams::default()).await?;
        Ok(nodes)
    }

    pub async fn get_node(&self, node_name: &str) -> Result<Node> {
        let nodes_api = Api::<Node>::all(self.client.clone());
        let node = nodes_api.get(node_name).await?;
        Ok(node)
    }

    pub async fn set_label_to_node(
        &self,
        node_name: &str,
        label_key: &str,
        label_value: &str,
    ) -> Result<()> {
        let nodes_api = Api::<Node>::all(self.client.clone());
        let patch_params = PatchParams::apply(node_name);
        let patch = Patch::Merge(json!({
            "metadata": {
                "name": node_name,
                "labels": {
                    label_key: label_value
                }
            }
        }));
        let result = nodes_api.patch(node_name, &patch_params, &patch).await;

        // if the requests times out, ignore as it is common to happen in vcluster
        if let Err(e) = result {
            if !e.to_string().contains("context deadline exceeded") {
                return Err(e.into());
            }
        }

        Ok(())
    }

    /*
    pub async fn wait_for_resource_to_be_ready<R>(
        &self,
        resource_name: &str,
        namespace: &str,
    ) -> Result<()>
    where
        R: Resource<Scope = NamespaceResourceScope>
            + Metadata<Ty = ObjectMeta>
            + Clone
            + std::fmt::Debug
            + serde::de::DeserializeOwned,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", resource_name))
            .timeout(290); // upper bound of how long we watch for

        let resource_ready = api.get(resource_name).await.is_ok();

        if resource_ready {
            return Ok(());
        }

        let mut stream = api.watch(&lp, "0").await?.boxed();

        while let Some(status) = stream.try_next().await? {
            if let WatchEvent::Modified(s) = status {
                println!("Resource modified: {:?}", s);
                // Add your custom logic to check if the resource is ready
                // For example, if the resource has a condition field, you can check it here
                if let Some(conditions) =
                    s.metadata().annotations.clone().unwrap().get("conditions")
                {
                    if conditions.contains("Ready") {
                        return Ok(());
                    }
                }
                return Ok(());
            } else {
                println!("New event on resource: {:?}", status);
                if api.get(resource_name).await.is_ok() {
                    return Ok(());
                }
            }
        }
        println!("Resource become ready in time");
        Ok(())
    }
    */

    pub async fn wait_for_resource_to_be_created<R>(
        &self,
        resource_name: &str,
        namespace: &str,
    ) -> Result<()>
    where
        R: Resource<Scope = NamespaceResourceScope>
            + Metadata<Ty = ObjectMeta>
            + Clone
            + std::fmt::Debug
            + serde::de::DeserializeOwned,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", resource_name))
            .timeout(290); // upper bound of how long we watch for

        let resource_created = api.get(resource_name).await.is_ok();

        if resource_created {
            return Ok(());
        }

        let mut stream = api.watch(&lp, "0").await?.boxed();

        while let Some(status) = stream.try_next().await? {
            if let WatchEvent::Added(s) = status {
                //println!("Resource added: {:?}", s.name());
                return Ok(());
            } else {
                //println!("New event on resource: {:?}", status);
                if api.get(resource_name).await.is_ok() {
                    return Ok(());
                }
            }
        }
        Err(anyhow!("Resource was not created in time"))
    }

    pub async fn watch_namespaced_resource_until_condition<R, F, O>(
        &self,
        resource_name: &str,
        namespace: &str,
        timeout_seconds: u32,
        on_event: F,
    ) -> Result<()>
    where
        F: Fn(WatchEvent<R>) -> O,
        O: Future<Output = bool>,
        R: Resource<Scope = NamespaceResourceScope>
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::namespaced(self.client.clone(), namespace);

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", resource_name))
            .timeout(timeout_seconds); // upper bound of how long we watch for

        let mut stream = api.watch(&lp, "0").await?.boxed();

        while let Some(status) = stream.try_next().await? {
            let should_stop = on_event(status).await;
            if should_stop {
                return Ok(());
            }
        }

        Err(Error::msg("Resource watch timed out"))
    }

    pub async fn watch_cluster_resource_until_condition<R, F, O>(
        &self,
        resource_name: &str,
        timeout_seconds: u32,
        on_event: F,
    ) -> Result<()>
    where
        F: Fn(WatchEvent<R>) -> O,
        O: Future<Output = bool>,
        R: Resource<Scope = ClusterResourceScope>
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Metadata<Ty = ObjectMeta>,
    {
        let api: Api<R> = Api::all(self.client.clone());

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", resource_name))
            .timeout(timeout_seconds); // upper bound of how long we watch for

        let mut stream = api.watch(&lp, "0").await?.boxed();

        while let Some(status) = stream.try_next().await? {
            let should_stop = on_event(status).await;
            if should_stop {
                return Ok(());
            }
        }

        Err(Error::msg("Resource watch timed out"))
    }

    pub async fn watch_pod_until_condition<F, O>(
        &self,
        pod_name: &str,
        namespace: &str,
        on_event: F,
    ) -> Result<()>
    where
        F: Fn(WatchEvent<Pod>) -> O,
        O: Future<Output = bool>,
    {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", pod_name))
            .timeout(290); // upper bound of how long we watch for

        let mut stream = pods.watch(&lp, "0").await.unwrap().boxed();

        while let Some(status) = stream.try_next().await? {
            let should_stop = on_event(status).await;
            if should_stop {
                return Ok(());
            }
        }

        Err(Error::msg("Pod watch timed out"))
    }

    pub async fn wait_for_pod_to_be_ready(&self, pod_name: &str, namespace: &str) -> Result<()> {
        // use the Job API to wait for the pod to be ready
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);

        let pod_ready = self.is_pod_ready(pod_name, namespace).await?;

        if pod_ready {
            return Ok(());
        }

        let wc = watcher::Config {
            field_selector: Some(format!("metadata.name={}", pod_name)),
            timeout: Some(290),
            ..Default::default()
        };

        let watch_stream = watcher(api, wc).applied_objects().default_backoff();

        let mut stream = pin!(watch_stream);

        while let Some(pod) = stream.try_next().await? {
            let status = pod.status.ok_or(Error::msg("Pod status not found"))?;
            if status.phase == Some("Running".to_string()) {
                return Ok(());
            }
        }

        println!("Pod did not become ready in time");
        Err(Error::msg("Pod did not become ready in time"))
    }

    pub async fn publish_crd<C>(&self) -> Result<()>
    where
        C: CustomResourceExt,
    {
        let crd_name = C::crd_name();
        let crds: Api<CustomResourceDefinition> = Api::all(self.client.clone());

        let crd_exists = crds.get(crd_name).await.is_ok();

        if crd_exists {
            return Err(Error::msg("CRD already exists"));
        }

        crds.create(&PostParams::default(), &C::crd()).await?;

        Ok(())
    }

    pub async fn unpublish_crd<C>(&self) -> Result<()>
    where
        C: CustomResourceExt,
    {
        let crd_name = C::crd_name();
        let crds: Api<CustomResourceDefinition> = Api::all(self.client.clone());

        let crd_exists = crds.get(crd_name).await.is_ok();

        if !crd_exists {
            return Err(Error::msg("CRD does not exist"));
        }

        crds.delete(crd_name, &Default::default()).await?;

        Ok(())
    }

    pub async fn wait_for_crd_publishing<C>(&self) -> Result<()>
    where
        C: CustomResourceExt,
    {
        let crd_name = C::crd_name();
        let crds: Api<CustomResourceDefinition> = Api::all(self.client.clone());

        // Check if the CRD is already established.
        if let Ok(crd) = crds.get(crd_name).await {
            if Self::is_crd_established(&crd) {
                return Ok(());
            }
        }

        let lp = WatchParams::default()
            .fields(&format!("metadata.name={}", crd_name))
            .timeout(290); // upper bound of how long we watch for

        let mut stream = crds.watch(&lp, "0").await?.boxed();

        while let Some(event) = stream.try_next().await? {
            match event {
                WatchEvent::Added(crd) | WatchEvent::Modified(crd) => {
                    if Self::is_crd_established(&crd) {
                        return Ok(());
                    }
                }
                _ => {
                    // Fallback, check CRD status by fetching the latest version.
                    if let Ok(crd) = crds.get(crd_name).await {
                        if Self::is_crd_established(&crd) {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(Error::msg("CRD was not published in time"))
    }

    fn is_crd_established(crd: &CustomResourceDefinition) -> bool {
        if let Some(status) = &crd.status {
            if let Some(conditions) = &status.conditions {
                return conditions
                    .iter()
                    .any(|cond| cond.type_ == "Established" && cond.status == "True");
            }
        }
        false
    }

    pub async fn ensure_cluster_is_ready(&self) -> anyhow::Result<()> {
        // check if it's possible to list service accounts
        let can_list_sa = self
            .is_authorized_to("get", "serviceaccounts", Some("default"))
            .await;
        if let Ok(false) = can_list_sa {
            println!("Cluster does not allow listing service accounts");
            return Ok(());
        }

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

    /// Check if the current user is authorized to perform an action on a resource in a namespace.
    ///
    /// Namespace set to None means the resource is cluster-scoped.
    ///
    /// This method uses the SelfSubjectAccessReview API to check if the current user is authorized to perform an action on a resource.
    pub async fn is_authorized_to(
        &self,
        verb: &str,
        resource: &str,
        namespace: Option<&str>,
    ) -> Result<bool> {
        let resource_attributes = ResourceAttributes {
            namespace: namespace.map(|ns| ns.to_string()),
            verb: Some(verb.to_string()),
            resource: Some(resource.to_string()),
            ..Default::default()
        };
        let access_attempt = SelfSubjectAccessReview {
            spec: SelfSubjectAccessReviewSpec {
                resource_attributes: Some(resource_attributes),
                ..Default::default()
            },
            ..Default::default()
        };

        let auth = Api::<SelfSubjectAccessReview>::all(self.client.clone());
        let res = auth
            .create(&PostParams::default(), &access_attempt)
            .await
            .context("Failed to check authorization")?;

        let status = res
            .status
            .ok_or_else(|| anyhow!("No status in SelfSubjectAccessReview"))?;

        Ok(status.allowed)
    }

    pub async fn exec_command_in_container(
        &self,
        pod_name: &str,
        namespace: &str,
        command: &str,
    ) -> Result<String> {
        let pods_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let attached_process = pods_api
            .exec(
                pod_name,
                vec!["sh", "-c", command],
                &AttachParams::default().stderr(false),
            )
            .await?;
        let output = get_output(attached_process).await;

        Ok(output)
    }

    pub async fn get_pod_ip(&self, pod_name: &str, namespace: &str) -> Result<String> {
        let pod = self.get_pod_in_namespace(pod_name, namespace).await?;
        let status = pod.status.ok_or(Error::msg("Pod status not found"))?;
        let pod_ip = status.pod_ip.ok_or(Error::msg("Pod IP not found"))?;
        Ok(pod_ip)
    }
}

async fn get_output(mut attached: AttachedProcess) -> String {
    let stdout = tokio_util::io::ReaderStream::new(attached.stdout().unwrap());
    let out = stdout
        .filter_map(|r| async { r.ok().and_then(|v| String::from_utf8(v.to_vec()).ok()) })
        .collect::<Vec<_>>()
        .await
        .join("");
    attached.join().await.unwrap();
    out
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
        KindCluster::create(name, kubeconfig_path, Default::default())
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
