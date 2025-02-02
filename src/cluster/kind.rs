use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{self, Command},
    str,
};

use anyhow::{Context, Error, Result};

#[derive(Debug, Clone)]
pub struct KindCluster {
    pub name: String,
    pub kubeconfig_path: PathBuf,
}

impl KindCluster {
    pub fn create(name: &str, kubeconfig_path: PathBuf) -> Result<Self> {
        let config = format!(
            r#"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: {cluster_name}
nodes:
  - role: control-plane
    extraPortMappings:
    - containerPort: {api_server_port1}
      hostPort: 30000
    - containerPort: {api_server_port2}
      hostPort: 30001
"#,
            cluster_name = name,
            api_server_port1 = 30080,
            api_server_port2 = 30443
        );

        let config_path = Path::new("/tmp/kind-config.yaml");
        let mut file = File::create(config_path).context("Failed to create kind config file")?;
        file.write_all(config.as_bytes())
            .context("Failed to write kind config to file")?;

        let output = Command::new("kind")
            .arg("create")
            .arg("cluster")
            .arg("--config")
            .arg(config_path)
            .output()
            .context("Failed to execute kind create command")?;

        if output.status.success() {
            let name = String::from(name);
            Self::export_kubeconfig(&name, &kubeconfig_path)?;
            Ok(Self {
                name,
                kubeconfig_path,
            })
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }
    pub fn exists(name: &str) -> Result<bool> {
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

    pub fn load(name: &str, kubeconfig_path: PathBuf) -> Result<Self> {
        // Check if the cluster exists
        let output = Command::new("kind")
            .arg("get")
            .arg("clusters")
            .output()
            .context("Failed to execute kind get clusters command")?;

        if output.status.success() {
            let clusters = str::from_utf8(&output.stdout)
                .context("Failed to parse kind get clusters output")?;
            if clusters.contains(name) {
                let name = String::from(name);
                Self::export_kubeconfig(&name, &kubeconfig_path)?;
                Ok(Self {
                    name,
                    kubeconfig_path,
                })
            } else {
                Err(Error::msg("Cluster does not exist"))
            }
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    fn export_kubeconfig(name: &str, path: &Path) -> Result<()> {
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

    pub fn delete(&self) -> Result<()> {
        let output = Command::new("kind")
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(&self.name)
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

fn terminal_stderr_to_error(output: process::Output) -> Error {
    let stderr = str::from_utf8(&output.stderr)
        .unwrap_or("Non utf-8 characters in stderr")
        .to_string();
    Error::msg(stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER_NAME: &str = "test-cluster";
    const TEMP_KUBECONFIG_PATH: &str = "/tmp/kubeconfig";

    #[test]
    fn test_create_and_delete_kind_cluster() {
        let cluster = KindCluster::create(CLUSTER_NAME, PathBuf::from(TEMP_KUBECONFIG_PATH));
        assert!(
            cluster.is_ok(),
            "Failed to create a Kind cluster: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();

        // check if the new cluster exists and can be loaded
        let load_cluster = KindCluster::load(CLUSTER_NAME, PathBuf::from(TEMP_KUBECONFIG_PATH));
        assert!(
            load_cluster.is_ok(),
            "Failed to load Kind cluster: {:?}",
            load_cluster.err()
        );

        let deletion = cluster.delete();
        assert!(
            deletion.is_ok(),
            "Failed to delete Kind cluster: {:?}",
            deletion.err()
        );
    }
}
