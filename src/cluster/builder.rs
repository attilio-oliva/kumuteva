use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Duration};

use anyhow::{anyhow, Context, Ok};
use k8s_openapi::{api::core::v1::Secret, Metadata};
use kube::{api::ObjectMeta, runtime::reflector::Lookup};
use tokio::time::sleep;

use crate::external_crds::{capsule, create_tenant};

use super::{KindCluster, KubernetesCluster};

use serde_json::json;

#[derive(Debug, Clone)]
pub enum IsolationTechnology {
    ControlPlane(ControlPlaneIsolation),
    DataPlane(DataPlaneIsolation),
}

#[derive(Debug, Clone)]
pub enum ControlPlaneIsolation {
    /// Capsule with a tenant confined in the given namespace
    Capsule(String),
    /// vCluster virtual control plane in the given namespace
    VCluster(String),
    KubeVirt,
}

#[derive(Debug, Clone)]
pub enum DataPlaneIsolation {
    Network(NetworkIsolationStrategy),
    Storage(StorageIsolationStrategy),
    Workload(WorkloadIsolation),
}

#[derive(Debug, Clone)]
pub enum NetworkIsolationStrategy {
    NetworkPolicy,
}

#[derive(Debug, Clone)]
pub enum StorageIsolationStrategy {
    SeparateStorageClass,
    ReclaimPolicySetToDelete,
}

#[derive(Debug, Clone)]
pub enum WorkloadIsolation {
    VM(VirtualMachineSandboxing),
    UserspaceKernel(UserspaceKernelSandboxing),
}

#[derive(Debug, Clone)]
pub enum VirtualMachineSandboxing {
    KataContainers,
}

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

pub struct KubernetesClusterBuilder {
    kind_cluster: KindCluster,
    kubeconfig_path: PathBuf,
    isolation_technologies: Vec<IsolationTechnology>,
}

impl KubernetesClusterBuilder {
    pub fn new(kind_cluster: KindCluster) -> Self {
        Self {
            kind_cluster,
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

    pub async fn build(self) -> anyhow::Result<KubernetesCluster> {
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

        for data_plane_isolation_technology in data_plane_isolation_technologies {
            self.apply_data_plane_isolation_technology(data_plane_isolation_technology)?;
        }

        let kubernetes_cluster = KubernetesCluster::load(&self.kubeconfig_path).await?;
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
            ControlPlaneIsolation::VCluster(namespace) => self.deploy_vcluster(&namespace).await,

            ControlPlaneIsolation::KubeVirt => {
                Err(anyhow!("KubeVirt isolation is not implemented yet"))
            }
        }
    }

    fn apply_data_plane_isolation_technology(
        &self,
        data_plane_isolation_technology: DataPlaneIsolation,
    ) -> anyhow::Result<()> {
        match data_plane_isolation_technology {
            DataPlaneIsolation::Network(network_isolation_strategy) => {
                Err(anyhow!("Network isolation is not implemented yet"))
            }
            DataPlaneIsolation::Storage(storage_isolation_technology) => {
                Err(anyhow!("Storage isolation is not implemented yet"))
            }
            DataPlaneIsolation::Workload(workload_isolation_technology) => {
                Err(anyhow!("Workload isolation is not implemented yet"))
            }
        }
    }

    fn install_capsule() -> anyhow::Result<()> {
        let repo_name = "projectcapsule";
        let repo_url = "https://projectcapsule.github.io/charts";
        let chart = "capsule";
        let chart_path = format!("{repo_name}/{chart}");

        let capsule_namespace = "capsule-system";
        let capsule_version = "0.7.0";

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

    async fn deploy_capsule_tenant(&self, tenant_name: &str) -> anyhow::Result<()> {
        Self::install_capsule()?;

        let cluster = KubernetesCluster::load(&self.kind_cluster.kubeconfig_path).await?;

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

        let output = Command::new("capsule/create-user.sh")
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
            .arg(&self.kind_cluster.kubeconfig_path)
            .output()
            .context("Failed to execute helm upgrade command")?;

        if !output.status.success() {
            return Err(terminal_stderr_to_error(output));
        }

        let cluster = KubernetesCluster::load(&self.kind_cluster.kubeconfig_path).await?;

        // Wait for the vcluster api server pod to appear.
        let label = "app=vcluster";
        let mut pods = cluster
            .list_pods_with_label_in_namespace(label, namespace)
            .await?;

        // retry up to 5 times

        for _ in 0..5 {
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
            "tenant1" => &self.kind_cluster.port_mappings.tenant1,
            "tenant2" => &self.kind_cluster.port_mappings.tenant2,
            _ => return Err(anyhow!("No port mapping for namespace {}", namespace)),
        };

        let nodeport = tenant_mapping.container_port;
        let host_port = tenant_mapping.host_port;

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
        let nodeport = service
            .spec
            .and_then(|spec| spec.ports)
            .and_then(|ports| ports.first().and_then(|port| port.node_port))
            .ok_or_else(|| anyhow!("Nodeport not found"))?;

        // adjust kubeconfig to use the new port (8443 is the default one)
        let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;
        let kubeconfig = kubeconfig.replace("8443", &host_port.to_string());
        std::fs::write(&self.kubeconfig_path, kubeconfig)?;
        Ok(())
    }

    async fn get_vcluster_kubeconfig(
        cluster: &KubernetesCluster,
        namespace: &str,
        vcluster_name: &str,
    ) -> anyhow::Result<String> {
        let secret_name = format!("vc-{}", vcluster_name);

        cluster
            .wait_for_resource_to_be_created::<Secret>(&secret_name, namespace)
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
}

fn terminal_stderr_to_error(output: std::process::Output) -> anyhow::Error {
    anyhow::anyhow!(
        "Command failed with exit code: {}\nstderr: {}",
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
                        "enabled": true,
                        "syncBackChanges": true
                    }
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
            let _ = KindCluster::create(name, kubeconfig_path.clone(), Default::default())?;
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
        let kind_cluster = KindCluster::load(&cluster.name, cluster.kubeconfig_path)?;
        kind_cluster.delete()
    }

    #[tokio::test]
    async fn setup_vcluster() {
        let temp_cluster_name = format!("{}-vcluster", CLUSTER_NAME_PREFIX);
        let temp_cluster = TestCluster::create(&temp_cluster_name).await.unwrap();

        let kind_kubeconfig_path = temp_cluster.kubeconfig_path.clone();
        let vcluster_kubeconfig_path =
            temp_kubeconfig_path(format!("{}-inner", temp_cluster_name).as_str());

        let namespace = "tenant1";
        let cluster = KubernetesClusterBuilder::new(
            KindCluster::load(&temp_cluster_name, kind_kubeconfig_path).unwrap(),
        )
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
