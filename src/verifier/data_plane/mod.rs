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
