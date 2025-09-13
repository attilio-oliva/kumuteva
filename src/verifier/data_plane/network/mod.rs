mod autonomy;
mod isolation;

pub use autonomy::*;
pub use isolation::*;

use anyhow::Result;
use k8s_openapi::api::core::v1::{Pod, Service};
use std::{fmt::Display, sync::LazyLock};

use crate::verifier::TenantClusterConfig;

pub struct NetworkReport {
    pub isolation: NetworkIsolationReport,
    pub autonomy: NetworkAutonomyReport,
}

pub struct NetworkIsolationReport {
    pub pod_isolation: bool,
    pub service_isolation: bool,
    pub dns_isolation: bool,
    pub success: bool,
}

pub struct NetworkAutonomyReport {
    pub service_exposure: bool,
    pub success: bool,
}

const NETWORK_MULTITOOL_IMAGE: &str = "wbitt/network-multitool";
const NETWORK_MULTITOOL_POD_NAME: &str = "network-multitool";
static NETWORK_MULTITOOL_POD: LazyLock<Pod> = LazyLock::new(|| {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": NETWORK_MULTITOOL_POD_NAME,
        },
        "spec": {
            "containers": [
                {
                    "name": NETWORK_MULTITOOL_POD_NAME,
                    "image": NETWORK_MULTITOOL_IMAGE,
                    "ports": [
                        {
                            "containerPort": 80,
                        }
                    ],
                }
            ]
        }
    }
    ))
    .unwrap()
});

static WEBSERVER_SERVICE: LazyLock<Service> = LazyLock::new(|| {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "tenant-service",
        },
        "spec": {
            "selector": {
                "app": "tenant-service",
            },
            "ports": [
                {
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 80,
                }
            ],
            "type": "ClusterIP",
        }
    }
    ))
    .unwrap()
});

// Comprehensive network multi-tenancy check including both isolation and autonomy
pub async fn check_network_multitenancy(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<NetworkReport> {
    let autonomy = check_network_autonomy(tenant1, tenant2).await?;
    let isolation = check_network_isolation(tenant1, tenant2).await?;

    Ok(NetworkReport {
        isolation,
        autonomy,
    })
}

impl Display for NetworkReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Multi-tenancy Data Plane - Network Report")?;
        writeln!(f, "========================================")?;

        // Isolation summary
        writeln!(
            f,
            "🔒 Isolation: {}",
            if self.isolation.success {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        if !self.isolation.success {
            writeln!(f, "  • ❌ Failing isolation:")?;
            if !self.isolation.pod_isolation {
                writeln!(f, "    - Cross-Tenant Pod Communication: Failed")?;
            }
            if !self.isolation.service_isolation {
                writeln!(f, "    - Cross-Tenant Service Communication: Failed")?;
            }
            if !self.isolation.dns_isolation {
                writeln!(f, "    - Cross-Tenant DNS Resolution: Failed")?;
            }
        }

        writeln!(f)?; // Empty line

        // Autonomy summary
        writeln!(
            f,
            "🔧 Autonomy: {}",
            if self.autonomy.success {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        writeln!(
            f,
            "  • Service Exposure Autonomy: {}",
            if self.autonomy.service_exposure {
                "✅"
            } else {
                "❌"
            }
        )?;

        if !self.autonomy.success {
            writeln!(f, "  • ❌ Issues:")?;
            writeln!(
                f,
                "    - Tenants cannot independently expose services on same ports (using NodePort)"
            )?;
        }

        Ok(())
    }
}
