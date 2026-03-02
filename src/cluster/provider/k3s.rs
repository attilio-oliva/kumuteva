use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    str, thread,
    time::Duration,
};

use super::{ClusterProvider, HostCluster, TenantsPortMapping};
use anyhow::Context;

// Type alias for backward compatibility
pub type K3sCluster = HostCluster<K3sProvider>;

#[derive(Debug, Clone)]
pub struct K3sProvider;

impl ClusterProvider for K3sProvider {
    async fn create(
        name: &str,
        kubeconfig_path: &Path,
        tenants_port_mapping: TenantsPortMapping,
    ) -> anyhow::Result<()> {
        let (_tenant1_mapping, _tenant2_mapping) =
            (&tenants_port_mapping.tenant1, &tenants_port_mapping.tenant2);

        // Create k3s data directory
        let data_dir = format!("/tmp/k3s-{}", name);
        fs::create_dir_all(&data_dir).context("Failed to create k3s data directory")?;

        // Start k3s server
        let mut cmd = Command::new("k3s");
        cmd.arg("server")
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--write-kubeconfig")
            .arg(kubeconfig_path)
            .arg("--write-kubeconfig-mode")
            .arg("644")
            .arg("--https-listen-port")
            .arg("6443")
            .arg("--disable")
            .arg("traefik") // Disable default ingress controller
            .arg("--cluster-init")
            .env("K3S_CLUSTER_SECRET", format!("secret-{}", name))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // Add port mappings through service configuration
        // Note: Direct port mapping in k3s requires external load balancer setup
        // This is a simplified approach - you may need additional configuration

        let _child = cmd.spawn().context("Failed to start k3s server")?;

        // Wait for k3s to be ready
        thread::sleep(Duration::from_secs(10));

        // Check if kubeconfig was created
        if kubeconfig_path.exists() {
            println!("K3s cluster '{}' created successfully", name);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "K3s cluster creation failed - kubeconfig not found"
            ))
        }
    }

    async fn exists(name: &str) -> anyhow::Result<bool> {
        // Check if k3s process is running for this cluster
        let output = Command::new("pgrep")
            .arg("-f")
            .arg(format!("k3s.*{}", name))
            .output()
            .context("Failed to check k3s process")?;

        Ok(output.status.success() && !output.stdout.is_empty())
    }

    async fn export_kubeconfig(name: &str, path: &Path) -> anyhow::Result<()> {
        // For direct k3s, kubeconfig is already written during server start
        let data_dir = format!("/tmp/k3s-{}", name);
        let k3s_kubeconfig = format!("{}/server/cred/admin.kubeconfig", data_dir);

        if Path::new(&k3s_kubeconfig).exists() {
            fs::copy(&k3s_kubeconfig, path).context("Failed to copy kubeconfig")?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("K3s kubeconfig not found"))
        }
    }

    async fn delete_cluster(name: &str) -> anyhow::Result<()> {
        // Kill k3s processes for this cluster
        let _output = Command::new("pkill")
            .arg("-f")
            .arg(format!("k3s.*{}", name))
            .output()
            .context("Failed to kill k3s processes")?;

        // Clean up data directory
        let data_dir = format!("/tmp/k3s-{}", name);
        if Path::new(&data_dir).exists() {
            fs::remove_dir_all(&data_dir).context("Failed to remove k3s data directory")?;
        }

        println!("K3s cluster '{}' deleted successfully", name);
        Ok(())
    }
}
