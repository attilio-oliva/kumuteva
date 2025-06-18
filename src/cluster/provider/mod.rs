mod dummy;
mod k3s;
mod kind;

use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    process::{self},
    str,
};

use anyhow::{Context, Error};

pub use dummy::*;
pub use k3s::*;
pub use kind::*;

#[derive(Debug, Clone)]
pub struct TenantsPortMapping {
    pub tenant1: PortMapping,
    pub tenant2: PortMapping,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: u16,
}

// Generic cluster that works with any provider implementation
#[derive(Debug, Clone)]
pub struct HostCluster<T: ClusterProvider> {
    pub name: String,
    pub kubeconfig_path: PathBuf,
    pub port_mappings: TenantsPortMapping,
    _provider: PhantomData<T>,
}

#[derive(Debug, Clone)]
pub enum HostClusterType {
    Kind(KindCluster),
    K3s(K3sCluster),
    PreExisting(PreExistingCluster),
}

impl Default for TenantsPortMapping {
    fn default() -> Self {
        Self {
            tenant1: PortMapping {
                container_port: 30010,
                host_port: 30001,
            },
            tenant2: PortMapping {
                container_port: 30020,
                host_port: 30002,
            },
        }
    }
}

impl TenantsPortMapping {
    pub fn new(tenant1: PortMapping, tenant2: PortMapping) -> Self {
        Self { tenant1, tenant2 }
    }

    pub fn from_tuple(tenant1: (u16, u16), tenant2: (u16, u16)) -> Self {
        Self {
            tenant1: PortMapping {
                container_port: tenant1.0,
                host_port: tenant1.1,
            },
            tenant2: PortMapping {
                container_port: tenant2.0,
                host_port: tenant2.1,
            },
        }
    }
}

pub trait ClusterProvider {
    async fn create(
        name: &str,
        kubeconfig_path: &Path,
        tenants_port_mapping: TenantsPortMapping,
    ) -> anyhow::Result<()>;

    async fn exists(name: &str) -> anyhow::Result<bool>;

    async fn export_kubeconfig(name: &str, kubeconfig_path: &Path) -> anyhow::Result<()>;

    async fn delete_cluster(name: &str) -> anyhow::Result<()>;
}

impl<T: ClusterProvider> HostCluster<T> {
    pub async fn create(
        name: &str,
        kubeconfig_path: PathBuf,
        tenants_port_mapping: TenantsPortMapping,
    ) -> anyhow::Result<Self> {
        T::create(name, &kubeconfig_path, tenants_port_mapping.clone())
            .await
            .context("Failed to create cluster")?;
        Ok(Self {
            name: name.to_string(),
            kubeconfig_path,
            port_mappings: tenants_port_mapping,
            _provider: PhantomData,
        })
    }

    pub async fn exists(name: &str) -> anyhow::Result<bool> {
        T::exists(name)
            .await
            .context("Failed to check if cluster exists")
    }

    pub async fn load(name: &str, kubeconfig_path: PathBuf) -> anyhow::Result<Self> {
        if !Self::exists(name).await? {
            return Err(anyhow::Error::msg("Cluster does not exist"));
        }

        T::export_kubeconfig(name, &kubeconfig_path)
            .await
            .context("Failed to export kubeconfig")?;

        Ok(Self {
            name: name.to_string(),
            kubeconfig_path,
            port_mappings: TenantsPortMapping::default(),
            _provider: PhantomData,
        })
    }

    pub async fn delete(&self) -> anyhow::Result<()> {
        T::delete_cluster(&self.name)
            .await
            .context("Failed to delete cluster")?;
        Ok(())
    }
}

pub fn terminal_stderr_to_error(output: process::Output) -> Error {
    let stderr = str::from_utf8(&output.stderr)
        .unwrap_or("Non utf-8 characters in stderr")
        .to_string();
    Error::msg(stderr)
}

impl HostClusterType {
    pub fn name(&self) -> &str {
        match self {
            HostClusterType::Kind(c) => &c.name,
            HostClusterType::K3s(c) => &c.name,
            HostClusterType::PreExisting(c) => &c.name,
        }
    }

    pub fn kubeconfig_path(&self) -> &PathBuf {
        match self {
            HostClusterType::Kind(c) => &c.kubeconfig_path,
            HostClusterType::K3s(c) => &c.kubeconfig_path,
            HostClusterType::PreExisting(c) => &c.kubeconfig_path,
        }
    }

    pub fn port_mappings(&self) -> &TenantsPortMapping {
        match self {
            HostClusterType::Kind(c) => &c.port_mappings,
            HostClusterType::K3s(c) => &c.port_mappings,
            HostClusterType::PreExisting(c) => &c.port_mappings,
        }
    }
}
