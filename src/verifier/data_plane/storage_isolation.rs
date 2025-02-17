use std::fmt::Result;

use k8s_openapi::api::{core::v1::PersistentVolume, storage::v1::StorageClass};

use crate::verifier::TenantClusterConfig;

/// Check if the storage is isolated between two tenants.
///
/// It's isolated if the StorageClass object has reclaimPolicy set to Delete.
/// Otherwise each tenant must have its own storage class.
pub async fn check_storage_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    if !tenant1
        .cluster
        .is_authorized_to("get", "StorageClass", None)
        .await?
    {
        return Err(anyhow::anyhow!(
            "Tenant1 does not have permission to list StorageClass objects"
        ));
    }

    if !tenant2
        .cluster
        .is_authorized_to("get", "StorageClass", None)
        .await?
    {
        return Err(anyhow::anyhow!(
            "Tenant2 does not have permission to list StorageClass objects"
        ));
    }

    let tenant1_storage_classes = tenant1
        .cluster
        .list_cluster_resources::<StorageClass>()
        .await?;
    let tenant2_storage_classes = tenant2
        .cluster
        .list_cluster_resources::<StorageClass>()
        .await?;

    if !tenant1_storage_classes.items.is_empty() && !tenant2_storage_classes.items.is_empty() {
        return check_storage_class_isolation(
            &tenant1_storage_classes.items,
            &tenant2_storage_classes.items,
        );
    }

    // If we can't check storage classes, we can try by creating  a PVC and checking if it's isolated
    // first attempt to check PV persistentVolumeReclaimPolicy field as it's set by the StorageClass
    // if the tenant doesn't have permission to list PVs, we can't check this

    attempt_other_tenant_file_access(tenant1, tenant2).await?;

    Ok(())
}

async fn attempt_other_tenant_file_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    let persistent_volume_name = "kumuteva-pv-storage";
    let persistent_volume_claim_name = "kumuteva-pv-claim";
    let pod_name = "persistent-pod";

    let pod = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "containers": [
                {
                    "name": "nginx-persistent",
                    "image": "nginx",
                    "volumeMounts": [
                        {
                            "mountPath": "/usr/share/nginx/html",
                            "name": persistent_volume_name,
                        },
                    ],
                },
            ],
            "volumes": [
                {
                    "name": persistent_volume_name,
                    "persistentVolumeClaim": {
                        "claimName": persistent_volume_claim_name,
                    },
                },
            ],
        }
    }))?;

    tenant1
        .cluster
        .create_pod_in_namespace(&pod, &tenant1.namespace)
        .await?;

    tenant1
        .cluster
        .wait_for_pod_to_be_ready(pod_name, &tenant1.namespace)
        .await?;

    // check if authorized to list PVs
    if tenant1
        .cluster
        .is_authorized_to("get", "PersistentVolume", None)
        .await?
    {
        let pv = tenant1
            .cluster
            .get_cluster_resource::<PersistentVolume>(persistent_volume_name)
            .await?;

        if let Some(reclaim_policy) = pv
            .spec
            .as_ref()
            .and_then(|spec| spec.persistent_volume_reclaim_policy.as_deref())
        {
            if reclaim_policy != "Delete" {
                return Err(anyhow::anyhow!(
                    "PersistentVolume {:?} is not isolated between tenants, it must have reclaimPolicy set to Delete",
                    persistent_volume_name
                ));
            }
        }
    }

    // if we can't check PVs, we can try by checking by creating a PVC in the other tenant
    // and check if it can see the file created by the first tenant

    // first create a file in the volume
    let file_name = "index.html";
    let file_content = "Hello, this is a tenant1 using Kumuteva!";
    let file_path = format!("/usr/share/nginx/html/{}", file_name);

    tenant1
        .cluster
        .exec_command_in_container(
            pod_name,
            &tenant1.namespace,
            &format!("sh -c 'echo {} > {}'", file_content, file_path),
        )
        .await?;

    // Now delete the pod and create the same pod in the other tenant
    tenant1
        .cluster
        .delete_pod_in_namespace(pod_name, &tenant1.namespace)
        .await?;

    tenant2
        .cluster
        .create_pod_in_namespace(&pod, &tenant2.namespace)
        .await?;

    tenant2
        .cluster
        .wait_for_pod_to_be_ready(pod_name, &tenant2.namespace)
        .await?;

    // check if the file is accessible
    let file_content2 = tenant2
        .cluster
        .exec_command_in_container(pod_name, &tenant2.namespace, &format!("cat {}", file_path))
        .await?;

    if file_content2.trim() == file_content {
        return Err(anyhow::anyhow!(
            "Tenant2 can access the file created by Tenant1, storage is not isolated"
        ));
    }

    Ok(())
}

fn check_storage_class_isolation(
    tenant1_storage_classes: &[StorageClass],
    tenant2_storage_classes: &[StorageClass],
) -> anyhow::Result<()> {
    let shared_storage_classes = tenant1_storage_classes
        .iter()
        .filter(|sc| {
            tenant2_storage_classes
                .iter()
                .any(|sc2| sc2.metadata.uid == sc.metadata.uid)
        })
        .collect::<Vec<_>>();

    // If there are no shared storage classes, then the storage is isolated between tenants
    if shared_storage_classes.is_empty() {
        return Ok(());
    }

    let shared_storage_classes_without_delete_policy = shared_storage_classes
        .iter()
        .filter(|sc| sc.reclaim_policy != Some("Delete".to_string()))
        .collect::<Vec<_>>();

    if !shared_storage_classes_without_delete_policy.is_empty() {
        return Err(anyhow::anyhow!(
            "Storage classes {:?} are not isolated between tenants, they must have reclaimPolicy set to Delete if StorageClass is shared",
            shared_storage_classes_without_delete_policy
                .iter()
                .map(|sc| sc.metadata.name.as_deref().unwrap_or_default())
                .collect::<Vec<_>>()
        ));
    }

    Ok(())
}
/*
async fn test_volume_access_after_deletion() -> Result<()> {
    // Create a Kubernetes client
    let client = Client::try_default().await?;

    // Create a volume and attach it to a test pod.
    let volume = create_volume(&client).await?;
    attach_volume_to_pod(&client, &volume).await?;

    // Confirm the volume is accessible while in use.
    check_volume_access(&client, &volume).await?;

    // Destroy the volume (simulate deletion while in use).
    delete_volume(&client, &volume).await?;

    // Wait for changes to propagate.
    sleep(Duration::from_secs(5)).await;

    // Attempt to access the now-destroyed volume, expecting a failure.
    if check_volume_access(&client, &volume).await.is_ok() {
        return Err(anyhow::anyhow!(
            "Volume access succeeded after deletion, isolation test failed"
        ));
    }

    Ok(())
}
*/
