use std::{
    path::{self, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Ok};
use yaml_rust2::YamlLoader;

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
            self.apply_control_plane_isolation_technology(control_plane_isolation_technology)?;
        }

        for data_plane_isolation_technology in data_plane_isolation_technologies {
            self.apply_data_plane_isolation_technology(data_plane_isolation_technology)?;
        }

        let kubernetes_cluster = KubernetesCluster::load(&self.kubeconfig_path).await?;
        Ok(kubernetes_cluster)
    }

    fn apply_control_plane_isolation_technology(
        &self,
        control_plane_isolation_technology: ControlPlaneIsolationTechnology,
    ) -> anyhow::Result<()> {
        match control_plane_isolation_technology {
            ControlPlaneIsolationTechnology::None => Ok(()),
            ControlPlaneIsolationTechnology::Capsule => {
                // apply capsule isolation
                return Err(anyhow::anyhow!("Capsule isolation is not implemented yet"));
            }
            ControlPlaneIsolationTechnology::VCluster(namespace) => {
                let vcluster_values_path = "vcluster.yaml";
                save_vcluster_helm_values(vcluster_values_path)?;

                let output = Command::new("helm")
                    .arg("upgrade")
                    .arg("--install")
                    .arg(&format!("vcluster-{}", namespace))
                    .arg("vcluster")
                    .arg("--values")
                    .arg("vcluster.yaml")
                    .arg("--repo")
                    .arg("https://charts.loft.sh")
                    .arg("--namespace")
                    .arg(namespace)
                    .arg("--repository-config=")
                    .arg("")
                    .arg("--create-namespace")
                    .output()
                    .context("Failed to execute helm upgrade command")?;

                if output.status.success() {
                    return Ok(());
                } else {
                    return Err(terminal_stderr_to_error(output));
                };
            }
            ControlPlaneIsolationTechnology::KubeVirt => {
                // apply kubevirt isolation
                return Err(anyhow::anyhow!("KubeVirt isolation is not implemented yet"));
            }
        };
        Ok(())
    }

    fn apply_data_plane_isolation_technology(
        &self,
        data_plane_isolation_technology: DataPlaneIsolationTechnology,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

fn terminal_stderr_to_error(output: std::process::Output) -> anyhow::Error {
    anyhow::anyhow!(
        "Command failed with exit code: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )
}
/*
controlPlane:
  # Distro holds virtual cluster related distro options. A distro cannot be changed after vCluster is deployed.
  distro:
    k8s:
      # Enabled specifies if the K8s distro should be enabled. Only one distro can be enabled at the same time.
      enabled: true
  backingStore:
    etcd:
      deploy:
          # Enabled defines if a dedicated etcd cluster should be deployed.
        enabled: true
policies:
  # empty, baseline, restricted can be used here
  podSecurityStandard: baseline

  # TODO: customize the following policies
  resourceQuota:
    enabled: true

  limitRange:
    enabled: true
# This does not work with deployed etcd because it blocks all traffic to local service and pod cidr
#  networkPolicy:
#    enabled: true
*/
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
        "policies": {
            "podSecurityStandard": "baseline",
            "resourceQuota": {
                "enabled": true
            },
            "limitRange": {
                "enabled": true
            }
        }
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

    fn temp_kubeconfig_path(name: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push(format!("{}.kubeconfig", name));
        path
    }

    fn setup_kind_cluster(name: &str) -> anyhow::Result<()> {
        let kubeconfig_path = temp_kubeconfig_path(name);
        let kind_cluster = KindCluster::create(name)?;
        kind_cluster.export_kubeconfig(&kubeconfig_path)
    }

    async fn teardown_kind_cluster(name: &str) -> anyhow::Result<()> {
        let kind_cluster = KindCluster::load(name)?;
        kind_cluster.delete()
    }

    #[tokio::test]
    async fn setup_vcluster() {
        let temp_cluster_name = format!("{}-vcluster", CLUSTER_NAME_PREFIX);
        let setup_temp_cluster = setup_kind_cluster(&temp_cluster_name);
        assert!(
            setup_temp_cluster.is_ok(),
            "Failed to setup kind cluster: {:?}",
            setup_temp_cluster.err()
        );
        let namespace = "tenant1";
        let kubeconfig_path = temp_kubeconfig_path(&temp_cluster_name);
        let cluster = KubernetesClusterBuilder::new(KindCluster::load(&temp_cluster_name).unwrap())
            .with_kubeconfig_path(kubeconfig_path.clone())
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

        let teardown_temp_cluster = teardown_kind_cluster(&temp_cluster_name).await;
        assert!(
            teardown_temp_cluster.is_ok(),
            "Failed to teardown kind cluster: {:?}",
            teardown_temp_cluster.err()
        );
    }
}
