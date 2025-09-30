mod network;
mod storage_isolation;
mod workload;

use std::fmt::Display;

pub use network::*;
pub use storage_isolation::*;
pub use workload::*;

pub struct DataPlaneReport {
    pub network: NetworkReport,
    pub storage_isolation: StorageIsolationReport,
}

pub struct StorageIsolationReport {
    pub check_strategy: StorageIsolationCheckStrategy,
    pub success: bool,
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
