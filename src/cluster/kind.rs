use std::{
    fs::File,
    io::Write,
    path::Path,
    process::{self, Command},
    str,
};

use anyhow::{Context, Error, Result};

pub struct KindCluster {
    name: String,
}

impl KindCluster {
    pub fn create(name: &str) -> Result<Self> {
        let output = Command::new("kind")
            .arg("create")
            .arg("cluster")
            .arg("--name")
            .arg(name)
            .output()
            .context("Failed to execute kind create command")?;

        if output.status.success() {
            let name = String::from(name);
            Ok(Self { name })
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    pub fn load(name: &str) -> Result<Self> {
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
                Ok(Self { name })
            } else {
                Err(Error::msg("Cluster does not exist"))
            }
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    pub fn export_kubeconfig(&self, path: &Path) -> Result<()> {
        let output = Command::new("kind")
            .arg("get")
            .arg("kubeconfig")
            .arg("--name")
            .arg(&self.name)
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
        let cluster = KindCluster::create(CLUSTER_NAME);
        assert!(
            cluster.is_ok(),
            "Failed to create a Kind cluster: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();

        // check if the new cluster exists
        let loaded_cluster = KindCluster::load(CLUSTER_NAME);
        assert!(
            loaded_cluster.is_ok(),
            "Failed to load Kind cluster: {:?}",
            loaded_cluster.err()
        );

        let kubeconfig_extraction = cluster.export_kubeconfig(Path::new(TEMP_KUBECONFIG_PATH));
        assert!(
            kubeconfig_extraction.is_ok(),
            "Failed to extract kubeconfig: {:?}",
            kubeconfig_extraction.err()
        );

        let deletion = cluster.delete();
        assert!(
            deletion.is_ok(),
            "Failed to delete Kind cluster: {:?}",
            deletion.err()
        );
    }
}
