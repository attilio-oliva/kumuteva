use crate::cluster::KubernetesCluster;

pub mod capsule;

use capsule::Tenant;
use kube::{
    api::{Patch, PatchParams},
    Api,
};

pub async fn create_tenant(cluster: &KubernetesCluster, tenant: Tenant) -> Result<(), kube::Error> {
    let tenant_name = tenant.metadata.name.clone().unwrap();
    let patch_params = PatchParams::apply(&tenant_name);
    let patch = Patch::Apply(tenant);

    let tenants: Api<Tenant> = Api::all(cluster.client());
    tenants.patch(&tenant_name, &patch_params, &patch).await?;
    Ok(())
}
