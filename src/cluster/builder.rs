use std::{path::PathBuf, process::Command, time::Duration};

use anyhow::{Context, Ok};
use tokio::time::sleep;

use super::{KindCluster, KubernetesCluster};

use serde_json::json;

#[derive(Debug, Clone)]
pub enum IsolationTechnology {
    ControlPlane(ControlPlaneIsolationTechnology),
    DataPlane(DataPlaneIsolationTechnology),
}

#[derive(Debug, Clone)]
pub enum ControlPlaneIsolationTechnology {
    None,
    Capsule,
    /// vCluster virtual control plane in the given namespace
    VCluster(String),
    KubeVirt,
}

#[derive(Debug, Clone)]
pub enum DataPlaneIsolationTechnology {
    None,
    Network(NetworkIsolationStrategy),
    Storage(StorageIsolationTechnology),
    Workload(WorkloadIsolationTechnology),
}

#[derive(Debug, Clone)]
pub enum NetworkIsolationStrategy {
    None,
    NetworkPolicy,
}

#[derive(Debug, Clone)]
pub enum StorageIsolationTechnology {
    None,
    SeparateStorageClass,
    ReclaimPolicySetToDelete,
}

#[derive(Debug, Clone)]
pub enum WorkloadIsolationTechnology {
    None,
    VM(VirtualMachineSandboxing),
    UserspaceKernel(UserspaceKernelSandboxing),
}

#[derive(Debug, Clone)]
pub enum VirtualMachineSandboxing {
    None,
    KataContainers,
}

#[derive(Debug, Clone)]
pub enum UserspaceKernelSandboxing {
    None,
    GVisor,
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

    pub fn with_isolation_technology(mut self, isolation_technology: IsolationTechnology) -> Self {
        self.isolation_technologies.push(isolation_technology);
        self
    }

    pub fn with_kubeconfig_path(mut self, kubeconfig_path: PathBuf) -> Self {
        self.kubeconfig_path = kubeconfig_path;
        self
    }

    pub async fn build(self) -> anyhow::Result<KubernetesCluster> {
        // for each isolation technology, apply the necessary configuration

        // take first the control plane isolation technologies
        let control_plane_isolation_technologies: Vec<ControlPlaneIsolationTechnology> = self
            .isolation_technologies
            .iter()
            .filter_map(|isolation_technology| match isolation_technology {
                IsolationTechnology::ControlPlane(control_plane_isolation_technology) => {
                    Some(control_plane_isolation_technology.clone())
                }
                _ => None,
            })
            .collect();

        let data_plane_isolation_technologies: Vec<DataPlaneIsolationTechnology> = self
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
        control_plane_isolation_technology: ControlPlaneIsolationTechnology,
    ) -> anyhow::Result<()> {
        match control_plane_isolation_technology {
            ControlPlaneIsolationTechnology::None => Ok(()),
            ControlPlaneIsolationTechnology::Capsule => {
                // apply capsule isolation
                Err(anyhow::anyhow!("Capsule isolation is not implemented yet"))
            }
            ControlPlaneIsolationTechnology::VCluster(namespace) => {
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
                    .arg(&namespace)
                    .arg("--create-namespace")
                    .arg("--kubeconfig")
                    .arg(&self.kind_cluster.kubeconfig_path)
                    .output()
                    .context("Failed to execute helm upgrade command")?;

                if output.status.success() {
                    let cluster =
                        KubernetesCluster::load(&self.kind_cluster.kubeconfig_path).await?;
                    // wait for vcluster to be ready
                    // watch the pod with label app=vcluster
                    //use the watch api to watch the pod
                    let label = "app=vcluster";
                    let mut pods = cluster.list_pods_with_label(label).await?;

                    // retry up to 5 times

                    for _ in 0..5 {
                        if !pods.items.is_empty() {
                            break;
                        }
                        sleep(Duration::from_secs(5)).await;
                        pods = cluster.list_pods_with_label(label).await?;
                    }

                    println!(
                        "Waiting for vcluster pod to be ready {:?}",
                        pods.items[0].metadata.name
                    );

                    let pod_name = pods.items[0]
                        .metadata
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Pod name not found"))?;
                    cluster
                        .wait_for_pod_to_be_ready(pod_name, &namespace)
                        .await?;

                    let vcluster_kubeconfig: String =
                        Self::get_vcluster_kubeconfig(&cluster, &namespace, &release_name).await?;
                    // save new kubeconfig
                    std::fs::write(&self.kubeconfig_path, vcluster_kubeconfig)?;

                    let service = cluster.create_nodeport_service(&namespace).await?;

                    // adjust kubeconfig to use the new port
                    let kubeconfig = std::fs::read_to_string(&self.kubeconfig_path)?;
                    //get the nodeport
                    let ports = service.spec.and_then(|spec| spec.ports.clone());
                    let nodeport = ports
                        .and_then(|ports| ports.first().cloned())
                        .and_then(|port| port.node_port)
                        .ok_or_else(|| anyhow::anyhow!("Nodeport not found"))?;
                    println!("Nodeport: {}", nodeport);
                    let kubeconfig = kubeconfig.replace("8443", &nodeport.to_string());
                    std::fs::write(&self.kubeconfig_path, kubeconfig)?;
                    Ok(())
                } else {
                    Err(terminal_stderr_to_error(output))
                }
            }

            ControlPlaneIsolationTechnology::KubeVirt => {
                // apply kubevirt isolation
                return Err(anyhow::anyhow!("KubeVirt isolation is not implemented yet"));
            }
        }
    }

    fn apply_data_plane_isolation_technology(
        &self,
        data_plane_isolation_technology: DataPlaneIsolationTechnology,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn get_vcluster_kubeconfig(
        cluster: &KubernetesCluster,
        namespace: &str,
        vcluster_name: &str,
    ) -> anyhow::Result<String> {
        let secret_name = format!("vc-{}", vcluster_name);

        // Wait for secret to be created up to 5 times
        let mut tries = 0;
        let secret = loop {
            let secret = cluster
                .get_secret_in_namespace(&secret_name, namespace)
                .await;
            if secret.is_ok() {
                break secret;
            } else if tries >= 5 {
                return Err(anyhow::anyhow!(
                    "Secret {} not found in namespace {}",
                    secret_name,
                    namespace
                ));
            }
            sleep(Duration::from_secs(5)).await;
            tries += 1;
        }?;
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
                }
            },
            "backingStore": {
                "etcd": {
                    "deploy": {
                        "enabled": true
                    }
                }
            }
        },
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
    use tokio::runtime::Handle;

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
            let _ = KindCluster::create(name, kubeconfig_path.clone())?;
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
        .with_isolation_technology(IsolationTechnology::ControlPlane(
            ControlPlaneIsolationTechnology::VCluster(String::from(namespace)),
        ))
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
