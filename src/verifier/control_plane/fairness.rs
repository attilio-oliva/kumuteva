use crate::verifier::TenantClusterConfig;
use anyhow::Result;

pub async fn check_fairness(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<bool> {
    //todo!("Implement fairness test")
    Ok(true)
}
