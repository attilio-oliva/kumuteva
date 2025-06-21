use std::{fs::File, io::Write, path::Path, process::Command, str};

use anyhow::Context;
use serde_json::json;

use crate::cluster::{terminal_stderr_to_error, ClusterProvider, HostCluster, TenantsPortMapping};

pub type KindCluster = HostCluster<KindProvider>;

#[derive(Debug, Clone)]
pub struct KindProvider;

impl ClusterProvider for KindProvider {
    async fn create(
        name: &str,
        kubeconfig_path: &Path,
        tenants_port_mapping: TenantsPortMapping,
    ) -> anyhow::Result<()> {
        let (tenant1_mapping, tenant2_mapping) =
            (&tenants_port_mapping.tenant1, &tenants_port_mapping.tenant2);

        let config_json = json!({
            "kind": "Cluster",
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "name": name,
            "nodes": [{
                "role": "control-plane",
                "extraPortMappings": [
                    {
                        "containerPort": tenant1_mapping.container_port,
                        "hostPort": tenant1_mapping.host_port
                    },
                    {
                        "containerPort": tenant2_mapping.container_port,
                        "hostPort": tenant2_mapping.host_port
                    }
                ]
            }]
        });

        let yaml_config =
            serde_yaml::to_string(&config_json).context("Failed to convert JSON config to YAML")?;

        let config_path = Path::new("/tmp/kind-config.yaml");
        let mut file = File::create(config_path).context("Failed to create kind config file")?;
        file.write_all(yaml_config.as_bytes())
            .context("Failed to write kind config to file")?;

        let output = Command::new("kind")
            .arg("create")
            .arg("cluster")
            .arg("--name")
            .arg(name)
            .arg("--config")
            .arg(config_path)
            .output()
            .context("Failed to execute kind create command")?;

        if output.status.success() {
            Self::export_kubeconfig(name, kubeconfig_path).await?;
            Ok(())
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    async fn exists(name: &str) -> anyhow::Result<bool> {
        let output = Command::new("kind")
            .arg("get")
            .arg("clusters")
            .output()
            .context("Failed to execute kind get clusters command")?;

        if output.status.success() {
            let clusters = str::from_utf8(&output.stdout)
                .context("Failed to parse kind get clusters output")?;
            Ok(clusters.contains(name))
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    async fn export_kubeconfig(name: &str, path: &Path) -> anyhow::Result<()> {
        let output = Command::new("kind")
            .arg("get")
            .arg("kubeconfig")
            .arg("--name")
            .arg(name)
            .output()
            .context("Failed to execute kind get kubeconfig command")?;

        if output.status.success() {
            let mut file = File::create(path).context("Failed to create kubeconfig file")?;
            file.write_all(&output.stdout)
                .context("Failed to write kubeconfig to file")?;
            Ok(())
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    async fn delete_cluster(name: &str) -> anyhow::Result<()> {
        let output = Command::new("kind")
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(name)
            .output()
            .context("Failed to execute kind delete command")?;

        if output.status.success() {
            println!("Kind cluster deleted successfully");
            Ok(())
        } else {
            println!("Failed to delete Kind cluster");
            Err(terminal_stderr_to_error(output))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::cluster::PortMapping;

    use super::*;

    const CLUSTER_NAME: &str = "test-cluster";
    const TEMP_KUBECONFIG_PATH: &str = "/tmp/kubeconfig";

    #[tokio::test]
    async fn test_create_and_delete_kind_cluster() {
        let dummy_port_mapping = TenantsPortMapping {
            tenant1: PortMapping {
                container_port: 31111,
                host_port: 32222,
            },
            tenant2: PortMapping {
                container_port: 33333,
                host_port: 34444,
            },
        };
        let cluster = KindCluster::create(
            CLUSTER_NAME,
            PathBuf::from(TEMP_KUBECONFIG_PATH),
            dummy_port_mapping,
        )
        .await;

        assert!(
            cluster.is_ok(),
            "Failed to create a Kind cluster: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();

        // check if the new cluster exists and can be loaded
        let load_cluster =
            KindCluster::load(CLUSTER_NAME, PathBuf::from(TEMP_KUBECONFIG_PATH)).await;
        assert!(
            load_cluster.is_ok(),
            "Failed to load Kind cluster: {:?}",
            load_cluster.err()
        );

        let deletion = cluster.delete().await;
        assert!(
            deletion.is_ok(),
            "Failed to delete Kind cluster: {:?}",
            deletion.err()
        );
    }
}
