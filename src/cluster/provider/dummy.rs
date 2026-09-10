use anyhow::{Context, Result};
use std::path::Path;

use crate::cluster::KubernetesClient;

use super::{ClusterProfile, ClusterProvider, HostCluster, TenantsPortMapping};

pub type PreExistingCluster = HostCluster<DummyProvider>;

/// A dummy provider that assumes Kubernetes is already installed and running.
/// It validates cluster connectivity using the Kubernetes API rather than
/// managing cluster lifecycle. Perfect for existing clusters or cloud-managed clusters.
#[derive(Debug, Clone)]
pub struct DummyProvider;

impl ClusterProvider for DummyProvider {
    async fn create(
        _name: &str,
        kubeconfig_path: &Path,
        _tenants_port_mapping: TenantsPortMapping,
        // A pre-existing cluster was built by someone else; its CNI and
        // containerd configuration are facts to be measured, not settings to
        // apply. Whether it matches the profile is the operator's business.
        _profile: &ClusterProfile,
    ) -> Result<()> {
        // For dummy provider, we verify the cluster is accessible
        println!("Verifying existing Kubernetes cluster accessibility...");

        // Check if kubeconfig exists
        if !kubeconfig_path.exists() {
            return Err(anyhow::anyhow!(
                "Kubeconfig file not found at {}. If no provider is chosen a valid kubeconfig must be provided.",
                kubeconfig_path.display()
            ));
        }

        // Verify cluster connectivity by trying to connect
        Self::verify_cluster_connectivity(kubeconfig_path)
            .await
            .context("Failed to verify cluster connectivity using kubeconfig")?;

        println!(
            "Successfully verified cluster connectivity with kubeconfig: {}",
            kubeconfig_path.display()
        );
        Ok(())
    }

    async fn exists(name: &str) -> Result<bool> {
        // For dummy provider, we check if we can connect to any cluster
        // Since we don't manage cluster names, we'll try with default kubeconfig
        println!("Checking if Kubernetes cluster '{}' is accessible...", name);

        // Try to use default kubeconfig or in-cluster config
        match Self::verify_default_cluster_connectivity().await {
            Ok(_) => {
                println!("Cluster '{}' is accessible", name);
                Ok(true)
            }
            Err(_) => {
                println!("Cluster '{}' is not accessible or doesn't exist", name);
                Ok(false)
            }
        }
    }

    async fn export_kubeconfig(_name: &str, _kubeconfig_path: &Path) -> Result<()> {
        // For dummy provider, we don't export anything since we're using an existing kubeconfig
        // This method is essentially a no-op
        println!("Dummy provider: Using existing kubeconfig (no export needed)");
        Ok(())
    }

    async fn delete_cluster(name: &str) -> Result<()> {
        // For dummy provider, we don't delete anything since we don't manage the cluster
        println!(
            "Dummy provider: Not deleting cluster '{}' (external cluster management)",
            name
        );
        Ok(())
    }
}

impl DummyProvider {
    /// Verify cluster connectivity using a specific kubeconfig file
    async fn verify_cluster_connectivity(kubeconfig_path: &Path) -> Result<()> {
        // Load config from specific kubeconfig file
        let client = KubernetesClient::load(kubeconfig_path)
            .await
            .context("Failed to create Kubernetes client from kubeconfig")?;

        // Try to list nodes as a connectivity test
        let is_healthy = client.is_healthy().await;

        if is_healthy {
            println!("Cluster is healthy and accessible.");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to connect to the cluster using kubeconfig: {}",
                kubeconfig_path.display()
            ))
        }
    }

    /// Verify cluster connectivity using default kubeconfig resolution
    async fn verify_default_cluster_connectivity() -> Result<()> {
        let client = KubernetesClient::infer()
            .await
            .context("Failed to infer Kubernetes client from default config")?;

        let is_healthy = client.is_healthy().await;

        if is_healthy {
            println!("Default cluster is healthy and accessible.");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to connect to the default cluster"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    #[tokio::test]
    async fn test_dummy_provider_with_missing_kubeconfig() {
        let non_existent_path = PathBuf::from("/tmp/non-existent-kubeconfig-dummy.yaml");
        let port_mappings = TenantsPortMapping::default();

        let result = PreExistingCluster::create(
            "test-dummy",
            non_existent_path,
            port_mappings,
            &Default::default(),
        )
        .await;
        assert!(result.is_err(), "Should fail when kubeconfig doesn't exist");
    }

    #[tokio::test]
    async fn test_dummy_provider_exists_method() {
        // This test will pass if there's any accessible k8s cluster
        // In CI/testing environments, this might fail - that's expected
        let exists_result = DummyProvider::exists("test-cluster").await;
        assert!(exists_result.is_ok(), "exists() method should not panic");
    }

    #[tokio::test]
    async fn test_dummy_provider_delete_is_noop() {
        let port_mappings = TenantsPortMapping::default();
        // Create a dummy kubeconfig file for the test
        let kubeconfig_path = PathBuf::from("/tmp/dummy-kubeconfig.yaml");
        fs::write(
            &kubeconfig_path,
            "apiVersion: v1\nkind: Config\nclusters: []\nusers: []\ncontexts: []",
        )
        .unwrap();

        // Even if creation fails due to no real cluster, delete should work
        if let Ok(cluster) =
            PreExistingCluster::create("test", kubeconfig_path, port_mappings, &Default::default())
                .await
        {
            assert!(
                cluster.delete().await.is_ok(),
                "Delete should always succeed for dummy provider"
            );
        }
    }
}
