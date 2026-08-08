use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Duration};

use anyhow::{anyhow, Context, Ok};
use k8s_openapi::api::{core::v1::Secret, networking::v1::NetworkPolicy};
use kube::{api::ObjectMeta, runtime::reflector::Lookup};
use tokio::time::sleep;

use crate::{
    cluster::HostClusterType,
    external_crds::{capsule, create_tenant},
};

use super::KubernetesClient;

use serde_json::json;

#[derive(Debug, Clone)]
pub enum IsolationTechnology {
    ControlPlane(ControlPlaneIsolation),
    DataPlane(DataPlaneIsolation),
}

#[derive(Debug, Clone)]
pub enum ControlPlaneIsolation {
    /// Do not isolate the control plane, just create a new namespace
    None(String),
    /// Capsule with a tenant confined in the given namespace
    Capsule(String),
    CapsuleProxy(String),
    /// vCluster virtual control plane in the given namespace
    VCluster(String),
    KubeVirt(String),
    /// Kamaji tenant control plane in the given namespace
    Kamaji(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum DataPlaneIsolation {
    Network(NetworkIsolationStrategy),
    Storage(StorageIsolationStrategy),
    Workload(WorkloadIsolation),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum NetworkIsolationStrategy {
    NetworkPolicy(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum StorageIsolationStrategy {
    SeparateStorageClass,
    ReclaimPolicySetToDelete,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum WorkloadIsolation {
    VM(VirtualMachineSandboxing),
    UserspaceKernel(UserspaceKernelSandboxing),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum VirtualMachineSandboxing {
    KataContainers,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum UserspaceKernelSandboxing {
    GVisor,
}

impl From<ControlPlaneIsolation> for IsolationTechnology {
    fn from(tech: ControlPlaneIsolation) -> Self {
        IsolationTechnology::ControlPlane(tech)
    }
}

impl From<DataPlaneIsolation> for IsolationTechnology {
    fn from(tech: DataPlaneIsolation) -> Self {
        IsolationTechnology::DataPlane(tech)
    }
}

impl From<NetworkIsolationStrategy> for DataPlaneIsolation {
    fn from(tech: NetworkIsolationStrategy) -> Self {
        DataPlaneIsolation::Network(tech)
    }
}

impl From<NetworkIsolationStrategy> for IsolationTechnology {
    fn from(tech: NetworkIsolationStrategy) -> Self {
        DataPlaneIsolation::Network(tech).into()
    }
}

pub struct KubernetesClusterBuilder {
    host_cluster: HostClusterType,
    kubeconfig_path: PathBuf,
    isolation_technologies: Vec<IsolationTechnology>,
}

impl KubernetesClusterBuilder {
    pub fn new(host_cluster: HostClusterType) -> Self {
        Self {
            host_cluster,
            kubeconfig_path: PathBuf::new(),
            isolation_technologies: vec![],
        }
    }

    // A single builder method taking any type that converts into IsolationTechnology.
    pub fn with_isolation_technology<T: Into<IsolationTechnology>>(
        mut self,
        technology: T,
    ) -> Self {
        self.isolation_technologies.push(technology.into());
        self
    }

    pub fn with_kubeconfig_path(mut self, kubeconfig_path: PathBuf) -> Self {
        self.kubeconfig_path = kubeconfig_path;
        self
    }

    pub async fn build(self) -> anyhow::Result<KubernetesClient> {
        let control_plane_isolation_technologies: Vec<ControlPlaneIsolation> = self
            .isolation_technologies
            .iter()
            .filter_map(|isolation_technology| match isolation_technology {
                IsolationTechnology::ControlPlane(control_plane_isolation_technology) => {
                    Some(control_plane_isolation_technology.clone())
                }
                _ => None,
            })
            .collect();

        let data_plane_isolation_technologies: Vec<DataPlaneIsolation> = self
            .isolation_technologies
            .iter()
            .filter_map(|isolation_technology| match isolation_technology {
                IsolationTechnology::DataPlane(data_plane_isolation_technology) => {
                    Some(data_plane_isolation_technology.clone())
                }
                _ => None,
            })
            .collect();

        for control_plane_isolation_technology in control_plane_isolation_technologies {
            self.apply_control_plane_isolation_technology(control_plane_isolation_technology)
                .await?;
        }

        // Ensure that the cluster is ready before applying data plane isolation technologies
        let _ = KubernetesClient::load(self.host_cluster.kubeconfig_path())
            .await?
            .ensure_cluster_is_ready()
            .await;

        for data_plane_isolation_technology in data_plane_isolation_technologies {
            self.apply_data_plane_isolation_technology(data_plane_isolation_technology)
                .await?;
        }

        let kubernetes_cluster = KubernetesClient::load(&self.kubeconfig_path).await?;
        Ok(kubernetes_cluster)
    }

    async fn apply_control_plane_isolation_technology(
        &self,
        control_plane_isolation_technology: ControlPlaneIsolation,
    ) -> anyhow::Result<()> {
        match control_plane_isolation_technology {
            ControlPlaneIsolation::Capsule(namespace) => {
                self.deploy_capsule_tenant(&namespace).await
            }
            ControlPlaneIsolation::CapsuleProxy(namespace) => {
                self.deploy_capsule_proxy(&namespace).await
            }

            ControlPlaneIsolation::VCluster(namespace) => self.deploy_vcluster(&namespace).await,

            ControlPlaneIsolation::None(namespace) => {
                self.dummy_control_plane_isolation(&namespace).await
            }

            ControlPlaneIsolation::KubeVirt(namespace) => {
                println!("Deploying KubeVirt cluster in namespace: {}", namespace);
                self.deploy_kubevirt_cluster(&namespace).await
            }

            ControlPlaneIsolation::Kamaji(namespace) => {
                println!(
                    "Deploying Kamaji tenant control plane in namespace: {}",
                    namespace
                );
                self.deploy_kamaji_cluster(&namespace).await
            }
        }
    }

    async fn apply_data_plane_isolation_technology(
        &self,
        data_plane_isolation_technology: DataPlaneIsolation,
    ) -> anyhow::Result<()> {
        match data_plane_isolation_technology {
            DataPlaneIsolation::Network(network_isolation_strategy) => {
                match network_isolation_strategy {
                    NetworkIsolationStrategy::NetworkPolicy(tenant_namespace) => {
                        self.isolate_network_between_namespaces(&tenant_namespace)
                            .await
                    }
                }
            }
            DataPlaneIsolation::Storage(_storage_isolation_technology) => {
                Err(anyhow!("Storage isolation is not implemented yet"))
            }
            DataPlaneIsolation::Workload(_workload_isolation_technology) => {
                Err(anyhow!("Workload isolation is not implemented yet"))
            }
        }
    }

    async fn isolate_network_between_namespaces(
        &self,
        tenant_namespace: &str,
    ) -> anyhow::Result<()> {
        let admin_cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;
        let deny_all_network_policy = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "deny-other-namespaces",
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {}
                },
                "ingress": [{
                    "from": [{
                        "podSelector": {}
                    }]
                }],
            }
        });

        let allow_dns_network_policy = serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
              "name": "allow-traffic-to-kube-system",
            },
            "spec": {
              "podSelector": {},
              "egress": [
                {
                  "to": [
                    {
                      "podSelector": {
                        "matchLabels": {}
                      },
                      "namespaceSelector": {
                        "matchLabels": {
                          "kubernetes.io/metadata.name": "kube-system"
                        }
                      }
                    }
                  ],
                }
              ]
            }
        });

        let deny_all_network_policy: NetworkPolicy =
            serde_json::from_value(deny_all_network_policy)?;
        let allow_dns_network_policy: NetworkPolicy =
            serde_json::from_value(allow_dns_network_policy)?;

        admin_cluster
            .create_namespaced_resource::<NetworkPolicy>(&deny_all_network_policy, tenant_namespace)
            .await?;
        admin_cluster
            .create_namespaced_resource::<NetworkPolicy>(
                &allow_dns_network_policy,
                tenant_namespace,
            )
            .await?;

        Ok(())
    }

    fn install_capsule() -> anyhow::Result<()> {
        let repo_name = "projectcapsule";
        let repo_url = "https://projectcapsule.github.io/charts";
        let chart = "capsule";
        let chart_path = format!("{repo_name}/{chart}");

        let capsule_namespace = "capsule-system";
        let capsule_version = "0.10.0";

        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg(repo_name)
            .arg(repo_url)
            .output()
            .context("Failed to add capsule helm repo")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        // Check if Capsule is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--filter")
            .arg(chart)
            .output()
            .context("Failed to check if capsule is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if helm_list_output.contains(chart) {
            println!("Capsule is already installed, skipping installation");
            return Ok(());
        }

        let output = Command::new("helm")
            .arg("install")
            .arg(chart)
            .arg(chart_path)
            .arg("--version")
            .arg(capsule_version)
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--create-namespace")
            .output()
            .context("Failed to install capsule helm chart")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    fn install_capsule_proxy(nodeport: u16) -> anyhow::Result<()> {
        let repo_name = "projectcapsule";
        let repo_url = "https://projectcapsule.github.io/charts";
        let chart = "capsule-proxy";
        let chart_path = format!("{repo_name}/{chart}");

        let capsule_namespace = "capsule-system";
        let capsule_version = "0.10.0";

        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg(repo_name)
            .arg(repo_url)
            .output()
            .context("Failed to add capsule helm repo")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        // Check if Capsule Proxy is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--filter")
            .arg(chart)
            .output()
            .context("Failed to check if capsule is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if helm_list_output.contains(chart) {
            println!("Capsule Proxy is already installed, skipping installation");
            return Ok(());
        }

        let output = Command::new("helm")
            .arg("install")
            .arg(chart)
            .arg(chart_path)
            .arg("--version")
            .arg(capsule_version)
            .arg("-n")
            .arg(capsule_namespace)
            .arg("--create-namespace")
            .arg("--set")
            .arg("crds.install=true")
            .arg("--set")
            .arg("service.type=NodePort")
            .arg("--set")
            .arg(format!("service.nodePort={}", nodeport))
            .output()
            .context("Failed to install capsule helm chart")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }
        Ok(())
    }

    async fn deploy_capsule_proxy(&self, tenant_name: &str) -> anyhow::Result<()> {
        // Use tenant1 port mapping: container_port for nodeport, host_port for kubeconfig
        let tenant_mapping = &self.host_cluster.port_mappings().tenant1;
        let nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

        Self::install_capsule()?;
        Self::install_capsule_proxy(nodeport)?;

        // Deploy tenant but skip namespace creation (we'll do it after adjusting kubeconfig)
        self.deploy_capsule_tenant_without_namespace(tenant_name)
            .await?;

        // Modify the kubeconfig to use the correct port and skip TLS verification
        // Only if using kind provider
        if matches!(self.host_cluster, HostClusterType::Kind(_)) {
            self.adjust_capsule_proxy_kubeconfig(host_port)?;
        }

        // Now create the namespace using the adjusted kubeconfig
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 10).await?;
        tenant_cluster.create_namespace(tenant_name).await?;

        Ok(())
    }

    fn adjust_capsule_proxy_kubeconfig(&self, host_port: u16) -> anyhow::Result<()> {
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;

        // Parse the kubeconfig as YAML to modify the server URL and add insecure-skip-tls-verify
        let mut kubeconfig_yaml: serde_yaml::Value = serde_yaml::from_str(&kubeconfig)?;

        if let Some(clusters) = kubeconfig_yaml
            .get_mut("clusters")
            .and_then(|c| c.as_sequence_mut())
        {
            for cluster_entry in clusters.iter_mut() {
                if let Some(cluster) = cluster_entry
                    .get_mut("cluster")
                    .and_then(|c| c.as_mapping_mut())
                {
                    // Get the current server URL and replace the port
                    if let Some(server) = cluster.get_mut("server").and_then(|s| s.as_str()) {
                        // Extract the host part and replace with new port
                        // Server URL format: https://host:port or https://host
                        let new_server = if let Some(idx) = server.rfind(':') {
                            // Check if there's a port after the last colon
                            let after_colon = &server[idx + 1..];
                            if after_colon.chars().all(|c| c.is_ascii_digit()) {
                                format!("{}:{}", &server[..idx], host_port)
                            } else {
                                format!("{}:{}", server, host_port)
                            }
                        } else {
                            format!("{}:{}", server, host_port)
                        };
                        cluster.insert(
                            serde_yaml::Value::String("server".to_string()),
                            serde_yaml::Value::String(new_server),
                        );
                    }

                    // Remove certificate-authority-data and add insecure-skip-tls-verify
                    cluster.remove(&serde_yaml::Value::String(
                        "certificate-authority-data".to_string(),
                    ));
                    cluster.insert(
                        serde_yaml::Value::String("insecure-skip-tls-verify".to_string()),
                        serde_yaml::Value::Bool(true),
                    );
                }
            }
        }

        let modified_kubeconfig = serde_yaml::to_string(&kubeconfig_yaml)?;
        std::fs::write(&self.kubeconfig_path, modified_kubeconfig)?;

        Ok(())
    }

    async fn deploy_capsule_tenant(&self, tenant_name: &str) -> anyhow::Result<()> {
        self.deploy_capsule_tenant_without_namespace(tenant_name)
            .await?;

        // create a namespace for the tenant
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 5).await?;
        tenant_cluster.create_namespace(tenant_name).await?;

        Ok(())
    }

    async fn deploy_capsule_tenant_without_namespace(
        &self,
        tenant_name: &str,
    ) -> anyhow::Result<()> {
        Self::install_capsule()?;

        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        let tenant_admin_user = format!("{}-admin", tenant_name);
        // Create the tenant crd

        let tenant_metadata = ObjectMeta {
            name: Some(String::from(tenant_name)),
            ..Default::default()
        };

        let tenant_spec = capsule::TenantSpec {
            owners: vec![capsule::TenantOwners {
                kind: capsule::TenantOwnersKind::User,
                name: tenant_admin_user.clone(),
                cluster_roles: None,
                proxy_settings: None,
            }],
            ..Default::default()
        };

        let tenant_resource = capsule::Tenant {
            metadata: tenant_metadata,
            spec: tenant_spec,
            ..Default::default()
        };

        // create this crd resource
        create_tenant(&cluster, tenant_resource).await?;

        let output = Command::new("provisioner/capsule/create-user.sh")
            .arg(&tenant_admin_user)
            .arg(tenant_name)
            .output()
            .context("Failed to create capsule user")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        // move all the generated files to the kubeconfig path
        let generated_files_prefix = format!("{}-{}", tenant_admin_user, tenant_name);

        let kubeconfig_files = vec![
            format!("{}.kubeconfig", generated_files_prefix),
            format!("{}.crt", generated_files_prefix),
            format!("{}.key", generated_files_prefix),
        ];

        for file in kubeconfig_files {
            let dest = if file.ends_with(".kubeconfig") {
                self.kubeconfig_path.clone()
            } else {
                self.kubeconfig_path.with_file_name(&file)
            };
            std::fs::copy(&file, dest)?;
            std::fs::remove_file(&file)?;
        }

        Ok(())
    }

    async fn deploy_vcluster(&self, namespace: &str) -> anyhow::Result<()> {
        let vcluster_values_path = "vcluster.yaml";
        save_vcluster_helm_values(vcluster_values_path)?;

        let release_name = format!("vcluster-{}", namespace);
        let chart_name = "vcluster";

        let output = Command::new("helm")
            .arg("upgrade")
            .arg("--install")
            .arg(&release_name)
            .arg(chart_name)
            .arg("--values")
            .arg("vcluster.yaml")
            .arg("--repo")
            .arg("https://charts.loft.sh")
            .arg("--namespace")
            .arg(namespace)
            .arg("--create-namespace")
            .arg("--kubeconfig")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to execute helm upgrade command")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        // Wait for the vcluster api server pod to appear.
        let label = "app=vcluster";
        let mut pods = cluster
            .list_pods_with_label_in_namespace(label, namespace)
            .await?;

        // retry up to 10 times

        for _ in 0..10 {
            if !pods.items.is_empty() {
                break;
            }
            sleep(Duration::from_secs(5)).await;
            pods = cluster.list_pods_with_label(label).await?;
        }

        let pod_name = pods
            .items
            .first()
            .and_then(|pod| pod.name())
            .ok_or_else(|| anyhow!("vcluster pod name not found"))?;

        println!("Waiting for vcluster pod to be ready: {:?}", pod_name);
        cluster
            .wait_for_pod_to_be_ready(&pod_name, namespace)
            .await?;

        let vcluster_kubeconfig: String =
            Self::get_vcluster_kubeconfig(&cluster, namespace, &release_name).await?;
        // save new kubeconfig
        std::fs::write(&self.kubeconfig_path, vcluster_kubeconfig)?;

        // kind cluster exposes the api server on a different port
        // We need to force the API server port to be on a specific port
        // because the kind mapping takes it and maps it to a different host port
        let tenant_mapping = match namespace {
            "tenant1" => &self.host_cluster.port_mappings().tenant1,
            "tenant2" => &self.host_cluster.port_mappings().tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        let mut nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

        // if the cluster is not kind the nodeport = host_port
        match self.host_cluster {
            HostClusterType::Kind(_) => {
                // For kind, we need to create a NodePort service to expose the vcluster API server
                println!(
                    "Creating NodePort service for vcluster in namespace {} on port {}",
                    namespace, nodeport
                );
            }
            _ => {
                // For other clusters, we assume the host_port is already set correctly
                println!(
                    "Using host port {} for vcluster in namespace {}",
                    host_port, namespace
                );
                nodeport = host_port;
            }
        }

        let selector = Some({
            let mut map = BTreeMap::new();
            map.insert("app".to_string(), "vcluster".to_string());
            map.insert(
                "release".to_string(),
                format!("vcluster-{}", namespace).to_string(),
            );
            map
        });
        let service = cluster
            .create_nodeport_service(namespace, selector, Some(nodeport.into()))
            .await?;

        //get the nodeport
        let _nodeport = service
            .spec
            .and_then(|spec| spec.ports)
            .and_then(|ports| ports.first().and_then(|port| port.node_port))
            .ok_or_else(|| anyhow!("Nodeport not found"))?;

        // adjust kubeconfig to use the new port (8443 is the default one)
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;
        let kubeconfig = kubeconfig.replace("8443", &host_port.to_string());
        std::fs::write(&self.kubeconfig_path, kubeconfig)?;

        // create a namespace to deploy workloads
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 10).await?;
        tenant_cluster.ensure_cluster_is_ready().await?;
        tenant_cluster.create_namespace(namespace).await?;

        Ok(())
    }

    async fn get_vcluster_kubeconfig(
        cluster: &KubernetesClient,
        namespace: &str,
        vcluster_name: &str,
    ) -> anyhow::Result<String> {
        let secret_name = format!("vc-{}", vcluster_name);

        cluster
            .wait_for_resource_creation::<Secret>(&secret_name, namespace)
            .await?;

        let secret = cluster
            .get_secret_in_namespace(&secret_name, namespace)
            .await?;

        // Extract and decode config
        let config_b64 = secret
            .data
            .and_then(|data| data.get("config").cloned())
            .ok_or_else(|| anyhow::anyhow!("Config data not found in secret"))?;

        // Parse as string (kube-rs already decodes from base64)
        let config: String = String::from_utf8(config_b64.0)
            .context("Failed to parse config data from secret as UTF-8 string")?;
        Ok(config)
    }
    async fn dummy_control_plane_isolation(&self, namespace: &str) -> anyhow::Result<()> {
        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;
        cluster.create_namespace(namespace).await?;
        // use the kind kubeconfig as the tenant kubeconfig
        // Basically, we are not isolating the control plane and reusing the same kubeconfig
        let kubeconfig = std::fs::read_to_string(self.host_cluster.kubeconfig_path())?;
        std::fs::write(&self.kubeconfig_path, kubeconfig)?;
        Ok(())
    }

    async fn deploy_kubevirt_cluster(&self, namespace: &str) -> anyhow::Result<()> {
        // sleep for a while to ensure the host cluster is ready
        sleep(Duration::from_secs(10)).await;

        println!("Deploying KubeVirt on host cluster...");
        println!(
            "  Running: provisioner/kubevirt/deploy-kubevirt.sh {}",
            self.host_cluster.kubeconfig_path().to_string_lossy()
        );
        // Use the shell script to deploy KubeVirt
        let output = Command::new("provisioner/kubevirt/deploy-kubevirt.sh")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to execute KubeVirt deployment script")?;
        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        } else {
            println!(
                "Kubevirt deployment output: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        println!("Deploying CAPI provider on host cluster...");
        println!(
            "  Running: provisioner/kubevirt/deploy-capi-provider.sh {}",
            self.host_cluster.kubeconfig_path().to_string_lossy()
        );
        let output = Command::new("provisioner/kubevirt/deploy-capi-provider.sh")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to execute CAPI provider deployment script")?;
        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        } else {
            println!(
                "CAPI provider deployment output: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        let tenant_mapping = match namespace {
            "tenant1" => &self.host_cluster.port_mappings().tenant1,
            "tenant2" => &self.host_cluster.port_mappings().tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        println!(
            "Creating KubeVirt cluster for tenant in namespace: {}",
            namespace
        );
        println!(
            "  Running: provisioner/kubevirt/create-kubevirt-cluster.sh {} {} {} {} {}",
            self.host_cluster.kubeconfig_path().to_string_lossy(),
            self.kubeconfig_path.to_str().unwrap(),
            namespace,
            tenant_mapping.container_port,
            tenant_mapping.host_port,
        );

        // If kind cluster, expose the API server as nodeport
        let should_use_nodeport = matches!(self.host_cluster, HostClusterType::Kind(_))
            .then(|| "y")
            .unwrap_or("n");

        let output = Command::new("provisioner/kubevirt/create-kubevirt-cluster.sh")
            .arg(self.host_cluster.kubeconfig_path())
            .arg(self.kubeconfig_path.to_str().unwrap())
            .arg(namespace)
            .arg(should_use_nodeport)
            .arg(tenant_mapping.container_port.to_string())
            .arg(tenant_mapping.host_port.to_string())
            .output()
            .context("Failed to execute CAPI controller deployment script")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        } else {
            println!(
                "CAPI controller deployment output: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        // Wait for KubeVirt to be ready
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 10).await?;
        tenant_cluster.ensure_cluster_is_ready().await?;
        tenant_cluster.create_namespace(namespace).await?;

        Ok(())
    }

    async fn deploy_kamaji_cluster(&self, namespace: &str) -> anyhow::Result<()> {
        // Get port mappings for the tenant
        let tenant_mapping = match namespace {
            "tenant1" => &self.host_cluster.port_mappings().tenant1,
            "tenant2" => &self.host_cluster.port_mappings().tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        let nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

        // Install dependencies (cert-manager, metallb) and Kamaji
        Self::install_kamaji_dependencies(self.host_cluster.kubeconfig_path().to_str().unwrap())?;
        Self::install_kamaji(self.host_cluster.kubeconfig_path().to_str().unwrap())?;

        // Create the tenant control plane
        self.create_kamaji_tenant_control_plane(namespace, nodeport)
            .await?;

        // Wait for the tenant control plane to be ready and get the kubeconfig
        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;
        self.wait_for_kamaji_tenant_ready(&cluster, namespace)
            .await?;

        // Extract kubeconfig from the secret and save it
        let kubeconfig = self.get_kamaji_kubeconfig(&cluster, namespace).await?;
        std::fs::write(&self.kubeconfig_path, &kubeconfig)?;

        // Adjust kubeconfig to use the correct port (host_port)
        self.adjust_kamaji_kubeconfig(host_port)?;

        // Wait for the tenant cluster to be ready
        let tenant_cluster = KubernetesClient::load_with_retry(&self.kubeconfig_path, 15).await?;
        tenant_cluster.ensure_cluster_is_ready().await?;
        tenant_cluster.create_namespace(namespace).await?;

        Ok(())
    }

    fn install_kamaji_dependencies(kubeconfig_path: &str) -> anyhow::Result<()> {
        // Install cert-manager (required by Kamaji)
        println!("Installing cert-manager...");

        // Add jetstack repo (official cert-manager)
        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg("jetstack")
            .arg("https://charts.jetstack.io")
            .output()
            .context("Failed to add jetstack helm repo")?;

        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("already exists")
        {
            return Err(terminal_stderr_to_error(output));
        }

        // Update helm repos
        let _ = Command::new("helm").arg("repo").arg("update").output();

        // Check if cert-manager is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg("cert-manager")
            .arg("--filter")
            .arg("cert-manager")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .output()
            .context("Failed to check if cert-manager is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if !helm_list_output.contains("cert-manager") {
            let output = Command::new("helm")
                .arg("upgrade")
                .arg("--install")
                .arg("cert-manager")
                .arg("jetstack/cert-manager")
                .arg("--namespace")
                .arg("cert-manager")
                .arg("--create-namespace")
                .arg("--set")
                .arg("crds.enabled=true")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .arg("--wait")
                .arg("--timeout")
                .arg("5m")
                .output()
                .context("Failed to install cert-manager")?;

            if !output.status.success() {
                return Err(terminal_stderr_to_error(output));
            }
            println!("cert-manager installed successfully");
        } else {
            println!("cert-manager is already installed, skipping");
        }

        // Install MetalLB for LoadBalancer support
        println!("Installing MetalLB...");

        let check_output = Command::new("kubectl")
            .arg("get")
            .arg("namespace")
            .arg("metallb-system")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .output()
            .context("Failed to check if metallb is installed")?;

        if !check_output.status.success() {
            let output = Command::new("kubectl")
                .arg("apply")
                .arg("-f")
                .arg("https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output()
                .context("Failed to install metallb")?;

            if !output.status.success() {
                return Err(terminal_stderr_to_error(output));
            }

            // Wait for MetalLB controller to be ready
            println!("Waiting for MetalLB controller to be ready...");
            let _ = Command::new("kubectl")
                .arg("wait")
                .arg("--namespace")
                .arg("metallb-system")
                .arg("--for=condition=ready")
                .arg("pod")
                .arg("--selector=app=metallb,component=controller")
                .arg("--timeout=120s")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output();

            // Wait for MetalLB speaker to be ready
            println!("Waiting for MetalLB speaker to be ready...");
            let _ = Command::new("kubectl")
                .arg("wait")
                .arg("--namespace")
                .arg("metallb-system")
                .arg("--for=condition=ready")
                .arg("pod")
                .arg("--selector=app=metallb,component=speaker")
                .arg("--timeout=120s")
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output();

            // Additional wait for webhook to be fully operational
            std::thread::sleep(std::time::Duration::from_secs(15));

            // Configure MetalLB IP address pool
            Self::configure_metallb_ip_pool(kubeconfig_path)?;

            println!("MetalLB installed successfully");
        } else {
            println!("MetalLB is already installed, skipping");
        }

        Ok(())
    }

    fn configure_metallb_ip_pool(kubeconfig_path: &str) -> anyhow::Result<()> {
        // Get the gateway IP of the kind network
        let output = Command::new("docker")
            .arg("network")
            .arg("inspect")
            .arg("-f")
            .arg("{{range .IPAM.Config}}{{.Gateway}}{{end}}")
            .arg("kind")
            .output()
            .context("Failed to get kind network gateway IP")?;

        if !output.status.success() {
            // If kind network doesn't exist, use a default
            println!("Warning: Could not get kind network gateway, using default IP range");
            return Ok(());
        }

        let gateway_ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if gateway_ip.is_empty() {
            println!("Warning: Empty gateway IP, skipping MetalLB IP pool configuration");
            return Ok(());
        }

        // Extract first two octets and create IP range
        let parts: Vec<&str> = gateway_ip.split('.').collect();
        if parts.len() < 2 {
            println!("Warning: Invalid gateway IP format, skipping MetalLB IP pool configuration");
            return Ok(());
        }

        let net_prefix = format!("{}.{}", parts[0], parts[1]);

        let ip_pool_yaml = format!(
            r#"apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kind-ip-pool
  namespace: metallb-system
spec:
  addresses:
  - {}.255.200-{}.255.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
"#,
            net_prefix, net_prefix
        );

        // Write to temp file and apply
        let temp_path = "/tmp/metallb-config.yaml";
        std::fs::write(temp_path, &ip_pool_yaml)?;

        // Retry applying MetalLB config with backoff (webhook may take time to be ready)
        let mut last_error = String::new();
        for attempt in 1..=5 {
            println!(
                "Applying MetalLB IP pool configuration (attempt {}/5)...",
                attempt
            );

            let output = Command::new("kubectl")
                .arg("apply")
                .arg("-f")
                .arg(temp_path)
                .arg("--kubeconfig")
                .arg(kubeconfig_path)
                .output()
                .context("Failed to apply metallb IP pool configuration")?;

            if output.status.success() {
                println!("MetalLB IP pool configured successfully");
                return Ok(());
            }

            last_error = String::from_utf8_lossy(&output.stderr).to_string();

            // Check if it's a webhook error (need to wait more)
            if last_error.contains("webhook") || last_error.contains("connection refused") {
                println!("MetalLB webhook not ready yet, waiting...");
                std::thread::sleep(std::time::Duration::from_secs(10 * attempt as u64));
            } else {
                // Some other error, might already exist
                break;
            }
        }

        // Don't fail if this doesn't work, it may already exist
        println!(
            "Warning: MetalLB IP pool configuration may have failed: {}",
            last_error
        );

        Ok(())
    }

    fn install_kamaji(kubeconfig_path: &str) -> anyhow::Result<()> {
        println!("Installing Kamaji...");

        // Add clastix repo
        let output = Command::new("helm")
            .arg("repo")
            .arg("add")
            .arg("clastix")
            .arg("https://clastix.github.io/charts")
            .output()
            .context("Failed to add clastix helm repo")?;

        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("already exists")
        {
            return Err(terminal_stderr_to_error(output));
        }

        // Update helm repos
        let _ = Command::new("helm").arg("repo").arg("update").output();

        // Check if Kamaji is already installed
        let check_output = Command::new("helm")
            .arg("list")
            .arg("-n")
            .arg("kamaji-system")
            .arg("--filter")
            .arg("kamaji")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .output()
            .context("Failed to check if kamaji is installed")?;

        let helm_list_output = String::from_utf8_lossy(&check_output.stdout);
        if helm_list_output.contains("kamaji") && !helm_list_output.contains("kamaji-") {
            println!("Kamaji is already installed, skipping");
            return Ok(());
        }

        // Check specifically if kamaji (not kamaji-tenant-*) is installed
        if helm_list_output.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.first() == Some(&"kamaji")
        }) {
            println!("Kamaji is already installed, skipping");
            return Ok(());
        }

        let output = Command::new("helm")
            .arg("upgrade")
            .arg("--install")
            .arg("kamaji")
            .arg("clastix/kamaji")
            .arg("--namespace")
            .arg("kamaji-system")
            .arg("--create-namespace")
            .arg("--set")
            .arg("resources=null")
            .arg("--kubeconfig")
            .arg(kubeconfig_path)
            .arg("--wait")
            .arg("--timeout")
            .arg("5m")
            .output()
            .context("Failed to install kamaji")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        println!("Kamaji installed successfully");
        Ok(())
    }

    async fn create_kamaji_tenant_control_plane(
        &self,
        namespace: &str,
        nodeport: u16,
    ) -> anyhow::Result<()> {
        let cluster = KubernetesClient::load(self.host_cluster.kubeconfig_path()).await?;

        // Create namespace for the tenant control plane
        cluster.create_namespace(namespace).await?;

        // Create the TenantControlPlane resource
        let tcp_name = format!("tcp-{}", namespace);

        let tcp_yaml = format!(
            r#"apiVersion: kamaji.clastix.io/v1alpha1
kind: TenantControlPlane
metadata:
  name: {}
  namespace: {}
spec:
  dataStore: default
  controlPlane:
    deployment:
      replicas: 1
    service:
      serviceType: LoadBalancer
      additionalMetadata:
        labels:
          tenant: {}
  kubernetes:
    version: "v1.30.0"
    kubelet:
      cgroupfs: systemd
    admissionControllers:
      - ResourceQuota
      - LimitRanger
  networkProfile:
    port: {}
  addons:
    coreDNS: {{}}
    kubeProxy: {{}}
    konnectivity:
      server:
        port: 8132
"#,
            tcp_name, namespace, namespace, nodeport
        );

        // Write to temp file and apply
        let temp_path = format!("/tmp/kamaji-tcp-{}.yaml", namespace);
        std::fs::write(&temp_path, &tcp_yaml)?;

        let output = Command::new("kubectl")
            .arg("apply")
            .arg("-f")
            .arg(&temp_path)
            .arg("--kubeconfig")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to create kamaji tenant control plane")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        println!(
            "Created Kamaji TenantControlPlane {} in namespace {}",
            tcp_name, namespace
        );
        Ok(())
    }

    async fn wait_for_kamaji_tenant_ready(
        &self,
        _cluster: &KubernetesClient,
        namespace: &str,
    ) -> anyhow::Result<()> {
        let tcp_name = format!("tcp-{}", namespace);
        println!(
            "Waiting for Kamaji TenantControlPlane {} to be ready...",
            tcp_name
        );

        // Wait for the tenant control plane to be ready by checking the status
        for i in 0..60 {
            let output = Command::new("kubectl")
                .arg("get")
                .arg("tcp")
                .arg(&tcp_name)
                .arg("-n")
                .arg(namespace)
                .arg("-o")
                .arg("jsonpath={.status.kubernetesResources.version.status}")
                .arg("--kubeconfig")
                .arg(self.host_cluster.kubeconfig_path())
                .output()
                .context("Failed to get tcp status")?;

            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "Ready" {
                println!("Kamaji TenantControlPlane {} is ready", tcp_name);
                return Ok(());
            }

            if i % 10 == 0 {
                println!(
                    "Still waiting for TenantControlPlane {} (status: {})...",
                    tcp_name,
                    if status.is_empty() {
                        "pending"
                    } else {
                        &status
                    }
                );
            }
            sleep(Duration::from_secs(5)).await;
        }

        Err(anyhow!(
            "Timeout waiting for Kamaji TenantControlPlane {} to be ready",
            tcp_name
        ))
    }

    async fn get_kamaji_kubeconfig(
        &self,
        cluster: &KubernetesClient,
        namespace: &str,
    ) -> anyhow::Result<String> {
        let tcp_name = format!("tcp-{}", namespace);

        // First, get the secret name from the TCP status
        let output = Command::new("kubectl")
            .arg("get")
            .arg("tcp")
            .arg(&tcp_name)
            .arg("-n")
            .arg(namespace)
            .arg("-o")
            .arg("jsonpath={.status.kubeconfig.admin.secretName}")
            .arg("--kubeconfig")
            .arg(self.host_cluster.kubeconfig_path())
            .output()
            .context("Failed to get kubeconfig secret name")?;

        let secret_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if secret_name.is_empty() {
            // Try default secret name pattern
            let secret_name = format!("{}-admin-kubeconfig", tcp_name);
            return Self::get_kubeconfig_from_secret(cluster, namespace, &secret_name).await;
        }

        Self::get_kubeconfig_from_secret(cluster, namespace, &secret_name).await
    }

    async fn get_kubeconfig_from_secret(
        cluster: &KubernetesClient,
        namespace: &str,
        secret_name: &str,
    ) -> anyhow::Result<String> {
        // Wait for secret to exist
        cluster
            .wait_for_resource_creation::<Secret>(secret_name, namespace)
            .await?;

        let secret = cluster
            .get_secret_in_namespace(secret_name, namespace)
            .await?;

        // Extract and decode the kubeconfig - try different possible key names
        let possible_keys = ["admin.conf", "super-admin.conf", "kubeconfig"];

        for key in possible_keys {
            if let Some(config_b64) = secret.data.as_ref().and_then(|data| data.get(key).cloned()) {
                let config = String::from_utf8(config_b64.0)
                    .context("Failed to parse kubeconfig data as UTF-8 string")?;
                return Ok(config);
            }
        }

        Err(anyhow!(
            "Kubeconfig data not found in secret {}. Available keys: {:?}",
            secret_name,
            secret.data.as_ref().map(|d| d.keys().collect::<Vec<_>>())
        ))
    }

    fn adjust_kamaji_kubeconfig(&self, host_port: u16) -> anyhow::Result<()> {
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;

        // Parse the kubeconfig as YAML to modify the server URL
        let mut kubeconfig_yaml: serde_yaml::Value = serde_yaml::from_str(&kubeconfig)?;

        if let Some(clusters) = kubeconfig_yaml
            .get_mut("clusters")
            .and_then(|c| c.as_sequence_mut())
        {
            for cluster_entry in clusters.iter_mut() {
                if let Some(cluster) = cluster_entry
                    .get_mut("cluster")
                    .and_then(|c| c.as_mapping_mut())
                {
                    // Get the current server URL and replace the port
                    if let Some(server) = cluster.get("server").and_then(|s| s.as_str()) {
                        // Server URL format: https://host:port
                        // Replace the port with host_port and change host to localhost
                        let new_server = if let Some(idx) = server.rfind(':') {
                            let after_colon = &server[idx + 1..];
                            if after_colon.chars().all(|c| c.is_ascii_digit()) {
                                // Replace both host and port for kind clusters
                                format!("https://127.0.0.1:{}", host_port)
                            } else {
                                format!("{}:{}", server, host_port)
                            }
                        } else {
                            format!("{}:{}", server, host_port)
                        };
                        cluster.insert(
                            serde_yaml::Value::String("server".to_string()),
                            serde_yaml::Value::String(new_server),
                        );
                    }

                    // Add insecure-skip-tls-verify for localhost connections
                    cluster.remove(&serde_yaml::Value::String(
                        "certificate-authority-data".to_string(),
                    ));
                    cluster.insert(
                        serde_yaml::Value::String("insecure-skip-tls-verify".to_string()),
                        serde_yaml::Value::Bool(true),
                    );
                }
            }
        }

        let modified_kubeconfig = serde_yaml::to_string(&kubeconfig_yaml)?;
        std::fs::write(&self.kubeconfig_path, modified_kubeconfig)?;

        Ok(())
    }
}

fn terminal_stderr_to_error(output: std::process::Output) -> anyhow::Error {
    anyhow::anyhow!(
        "{}\nCommand failed with exit code: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )
}

fn save_vcluster_helm_values(path: &str) -> anyhow::Result<()> {
    let json_values = json!({
        "controlPlane": {
            "distro": {
                "k8s": {
                    "enabled": true
                },
            },
            "backingStore": {
                "etcd": {
                    "deploy": {
                        "enabled": true
                    }
                }
            },
            /*
            "proxy": {
                "extraSANs": ["localhost", "172.23.0.3"]
            }
            */
        },
        "exportKubeConfig": {
            //"server": "https://172.23.0.3:30080",
            "insecure": true,
        },
        "sync": {
                "fromHost": {
                    "nodes": {
                        //"enabled": true,
                        //"syncBackChanges": true
                    },
                },
                "toHost": {
                    "persistentVolumes": {
                        "enabled": true,
                    },
                    "storageClasses": {
                        "enabled": true
                    },
                }
            }

        // "policies": {
        //     "podSecurityStandard": "baseline",
        //     "resourceQuota": {
        //         "enabled": true
        //     },
        //     "limitRange": {
        //         "enabled": true
        //     }
        // },
        // "exportKubeConfig": {
        //     "context": "vcluster-context",
        //     "secret": {
        //         "name": "vc-kubeconfig"
        //     }
        // }
    });

    let yaml_values = serde_yaml::from_str::<serde_yaml::Value>(&json_values.to_string())?;
    std::fs::write(path, serde_yaml::to_string(&yaml_values)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cluster::KindCluster;

    use super::*;
    use std::path::PathBuf;

    const CLUSTER_NAME_PREFIX: &str = "k8s-env";

    struct TestCluster {
        pub name: String,
        pub kubeconfig_path: PathBuf,
    }

    impl TestCluster {
        async fn create(name: &str) -> anyhow::Result<Self> {
            let kubeconfig_path = temp_kubeconfig_path(name);
            let _ = KindCluster::create(name, kubeconfig_path.clone(), Default::default())
                .await
                .context("Failed to create kind cluster")?;
            Ok(Self {
                name: name.to_string(),
                kubeconfig_path,
            })
        }
    }

    fn temp_kubeconfig_path(name: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push(format!("{}.kubeconfig", name));
        path
    }

    async fn teardown_kind_cluster(cluster: TestCluster) -> anyhow::Result<()> {
        let kind_cluster = KindCluster::load(&cluster.name, cluster.kubeconfig_path).await?;
        kind_cluster.delete().await
    }

    // Provisions a real kind cluster via Docker, so it cannot run on a clean
    // checkout or in CI. Run explicitly with `cargo test -- --ignored`.
    #[ignore]
    #[tokio::test]
    async fn setup_vcluster() {
        let temp_cluster_name = format!("{}-vcluster", CLUSTER_NAME_PREFIX);
        let temp_cluster = TestCluster::create(&temp_cluster_name).await.unwrap();

        let kind_kubeconfig_path = temp_cluster.kubeconfig_path.clone();
        let vcluster_kubeconfig_path =
            temp_kubeconfig_path(format!("{}-inner", temp_cluster_name).as_str());

        let namespace = "tenant1";
        let host_cluster = HostClusterType::Kind(
            KindCluster::load(&temp_cluster_name, kind_kubeconfig_path.clone())
                .await
                .unwrap(),
        );

        let cluster = KubernetesClusterBuilder::new(host_cluster)
            .with_kubeconfig_path(vcluster_kubeconfig_path)
            .with_isolation_technology(ControlPlaneIsolation::VCluster(String::from(namespace)))
            .build()
            .await;
        assert!(
            cluster.is_ok(),
            "Failed to create client: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();
        let pods = cluster.list_all_pods().await;
        assert!(pods.is_ok(), "Failed to get pods: {:?}", pods.err());

        let _ = teardown_kind_cluster(temp_cluster).await;
    }
}
