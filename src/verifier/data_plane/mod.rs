mod network;
mod storage_isolation;

use std::fmt::Display;

pub use network_isolation::*;
pub use storage_isolation::*;

pub struct DataPlaneIsolationReport {
    pub network_isolation: NetworkIsolationReport,
    pub storage_isolation: StorageIsolationReport,
}

pub struct NetworkIsolationReport {
    pub pod_isolation: bool,
    pub service_isolation: bool,
    pub dns_isolation: bool,
    pub success: bool,
}

pub struct StorageIsolationReport {
    pub check_strategy: StorageIsolationCheckStrategy,
    pub success: bool,
}

impl Display for NetworkIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Multi-tenancy Data Plane - Network Report")?;
        writeln!(f, "==================================")?;

        writeln!(
            f,
            "🔒 Isolation: {}",
            if self.success {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        if !self.success {
            writeln!(f, "  • ❌ Failing isolation:")?;
            writeln!(
                f,
                "    - Cross-Tenant Pod Communication Isolation: {}",
                self.pod_isolation
            )?;
            writeln!(
                f,
                "    - Cross-Tenant Service Communication Isolation: {}",
                self.service_isolation
            )?;
            writeln!(
                f,
                "    - Cross-Tenant DNS Resolution Isolation: {}",
                self.dns_isolation
            )?;
        }

        Ok(())
    }
}

impl Display for StorageIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Multi-tenancy Data Plane - Storage Report")?;
        writeln!(f, "==================================")?;

        writeln!(
            f,
            "🔒 Isolation: {}",
            if self.success {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        if !self.success {
            writeln!(f, "  • ❌ Failing isolation:")?;
            writeln!(f, "    - Check Strategy Failed: {:?}", self.check_strategy)?;
        }

        Ok(())
    }
}
