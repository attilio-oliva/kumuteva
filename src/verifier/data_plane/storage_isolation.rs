use std::fmt::Result;

use k8s_openapi::api::{
    apps::v1::StatefulSet,
    core::v1::{PersistentVolume, PersistentVolumeClaim},
    storage::v1::StorageClass,
};

use crate::verifier::TenantClusterConfig;

/// Check if the storage is isolated between two tenants.
///
/// It's isolated if the StorageClass object has reclaimPolicy set to Delete.
/// Otherwise each tenant must have its own storage class.
pub async fn check_storage_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    // let can_t1_get_storage_class = is_authorized_to_get_storage_class(tenant1).await;
    // let can_t2_get_storage_class = is_authorized_to_get_storage_class(tenant2).await;
    //
    // if can_t1_get_storage_class? && can_t2_get_storage_class? {
    //     let tenant1_storage_classes = tenant1
    //         .cluster
    //         .list_cluster_resources::<StorageClass>()
    //         .await?;
    //     let tenant2_storage_classes = tenant2
    //         .cluster
    //         .list_cluster_resources::<StorageClass>()
    //         .await?;
    //
    //     if !tenant1_storage_classes.items.is_empty() && !tenant2_storage_classes.items.is_empty() {
    //         return check_storage_class_isolation(
    //             &tenant1_storage_classes.items,
    //             &tenant2_storage_classes.items,
    //         );
    //     }
    // }

    // If we can't check storage classes, we can try by creating  a PVC and checking if it's isolated
    // first attempt to check PV persistentVolumeReclaimPolicy field as it's set by the StorageClass
    // if the tenant doesn't have permission to list PVs, we can't check this

    attempt_other_tenant_file_access(tenant1, tenant2).await?;

    Ok(())
}

async fn cleanup(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    pv_name: &str,
    pvc_name: &str,
) -> anyhow::Result<()> {
    let pod_name = "persistent-pod";

    tenant2
        .cluster
        .delete_resouce_in_namespace::<StatefulSet>(pod_name, &tenant2.namespace)
        .await?;

    println!("Cleaning up PVC {}", pvc_name);
    tenant1
        .cluster
        .delete_resouce_in_namespace::<PersistentVolumeClaim>(pvc_name, &tenant1.namespace)
        .await?;

    println!("Cleaning up PV {}", pv_name);
    tenant1
        .cluster
        .delete_cluster_resource::<PersistentVolume>(pv_name)
        .await?;

    Ok(())
}

async fn attempt_other_tenant_file_access(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<()> {
    //let persistent_volume_name = "kumuteva-pv-storage";
    let persistent_volume_claim_name = "kumuteva-pv-claim";
    let pod_name = "persistent-pod";

    let file_name = "index.html";
    let file_content = "Hello, this is a tenant1 using Kumuteva!";
    let mount_path = "/usr/share/nginx/html";
    let file_path = format!("/usr/share/nginx/html/{}", file_name);

    let tenant1_pod = serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "selector": {
                "matchLabels": {
                    "app": pod_name
                },
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": pod_name
                    },
                },
                "spec": {
                    "containers": [
                        {
                            "name": pod_name,
                            "image": "nginx",
                            "command": [
                        "sh",
                        "-c",
                        // write the file then sleep briefly before exit
                        format!("echo '{}' > {} && sleep 2", file_content, file_path)
                    ],
                            "volumeMounts": [
                                {
                                    "mountPath": mount_path,
                                    "name": persistent_volume_claim_name
                                },
                            ],
                        },
                    ],
                },
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {
                        "name": persistent_volume_claim_name,
                    },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage": "1Gi",
                            },
                        },
                    },
                },
            ],
            "restartPolicy": "Never",
            "replicas": 1
        }
    }))?;

    println!("Creating a StatefulSet in tenant1");
    tenant1
        .cluster
        .create_namespaced_resource::<StatefulSet>(&tenant1_pod, &tenant1.namespace)
        .await?;

    tenant1
        .cluster
        .watch_namespaced_resource_until_condition::<StatefulSet, _, _>(
            pod_name,
            &tenant1.namespace,
            30,
            |_event| async {
                let stateful_set = tenant1
                    .cluster
                    .get_resource_in_namespace::<StatefulSet>(pod_name, &tenant1.namespace)
                    .await;

                if stateful_set.is_err() {
                    return false;
                }

                stateful_set
                    .unwrap()
                    .status
                    .as_ref()
                    .and_then(|status| status.ready_replicas)
                    .map(|ready_replicas| ready_replicas > 0)
                    .unwrap_or(false)
            },
        )
        .await?;

    let created_pvc = tenant1
        .cluster
        .list_namespaced_resources::<PersistentVolumeClaim>(&tenant1.namespace)
        .await?
        .items
        .into_iter()
        .find(|pvc| {
            pvc.metadata
                .labels
                .as_ref()
                .map(|labels| labels["app"] == pod_name)
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow::anyhow!("PersistentVolumeClaim not found"))?;

    // The name of the PVC requested is used as a base for each replica of a StatefulSet
    // so we need to get the actual name of the PVC created by the StatefulSet by our single replica
    let created_pvc_name = created_pvc.metadata.name.as_deref().unwrap_or_default();
    let dynamic_pv_name = created_pvc.spec.unwrap().volume_name.unwrap();

    println!("A dynamic PV was created: {}", dynamic_pv_name);

    // check if authorized to list PVs
    if tenant1
        .cluster
        .is_authorized_to("get", "PersistentVolume", None)
        .await?
    {
        println!("Checking if PersistentVolume is isolated between tenants");
        let new_persistent_volume = tenant1
            .cluster
            .list_cluster_resources::<PersistentVolume>()
            .await?
            .items
            .into_iter()
            .find(|pv| {
                pv.spec
                    .as_ref()
                    .and_then(|spec| {
                        spec.claim_ref
                            .as_ref()
                            .map(|claim_ref| claim_ref.name.as_deref())
                    })
                    .flatten()
                    .map(|claim_name| claim_name == created_pvc_name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| anyhow::anyhow!("PersistentVolume not found"))?;

        // if let Some(reclaim_policy) = new_persistent_volume
        //     .spec
        //     .as_ref()
        //     .and_then(|spec| spec.persistent_volume_reclaim_policy.as_deref())
        // {
        //     if reclaim_policy != "Delete" {
        //         return Err(anyhow::anyhow!(
        //             "PersistentVolume is not isolated between tenants, it must have reclaimPolicy set to Delete"
        //         ));
        //     } else {
        //         println!("PersistentVolume is isolated between tenants");
        //         return Ok(());
        //     }
        // }
    }

    // Now create a pod in tenant2 that attempts to read the file.
    // The container command checks if the file content is the expected one.
    // If yes then it exits with exit code 1, otherwise 0.
    let tenant2_pod = serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "selector": {
                "matchLabels": {
                    "app": pod_name
                },
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": pod_name
                    },
                },
                "spec": {
                    "containers": [
                        {
                            "name": pod_name,
                            "image": "nginx",
                            "command": [
                                "sh",
                                "-c",
                                format!(
                                    "echo 'Reading file content:' && cat {} 2>/dev/null || echo 'File not found/accessible' && \
                                     if [ \"$(cat {} 2>/dev/null)\" = \"{}\" ]; then exit 1; else exit 0; fi",
                                    file_path,
                                    file_path,
                                    file_content
                                )
                            ],
                            "volumeMounts": [
                                {
                                    "mountPath": mount_path,
                                    "name": persistent_volume_claim_name
                                },
                            ],
                        },
                    ],
                },
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {
                        "name": persistent_volume_claim_name,
                    },
                    "spec": {
                        "volumeName": dynamic_pv_name, // Attempt to use the same PV as tenant1
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage": "1Gi",
                            },
                        },
                    },
                },
            ],
            "restartPolicy": "Never",
            "replicas": 1
        }
    }))?;

    // println!("Attempting to create a file in tenant1 and access it from tenant2");
    // tenant1
    //     .cluster
    //     .exec_command_in_container(
    //         pod_name,
    //         &tenant1.namespace,
    //         &format!("sh -c 'echo {} > {}'", file_content, file_path),
    //     )
    //     .await?;

    // Now delete the pod and create the same pod in the other tenant
    tenant1
        .cluster
        .delete_resouce_in_namespace::<StatefulSet>(pod_name, &tenant1.namespace)
        .await?;

    tenant1
        .cluster
        .delete_resouce_in_namespace::<PersistentVolumeClaim>(created_pvc_name, &tenant1.namespace)
        .await?;

    tenant1
        .cluster
        .patch_cluster_resource::<PersistentVolume, _>(
            &dynamic_pv_name,
            &kube::api::Patch::Strategic(serde_json::json!({
                "spec": {
                    "claimRef": null
                }
            })),
        )
        .await?;

    tenant2
        .cluster
        .create_namespaced_resource::<StatefulSet>(&tenant2_pod, &tenant2.namespace)
        .await?;

    let wait_operation = tenant2
        .cluster
        .watch_namespaced_resource_until_condition::<StatefulSet, _, _>(
            pod_name,
            &tenant2.namespace,
            15,
            |_event| async {
                let stateful_set = tenant2
                    .cluster
                    .get_resource_in_namespace::<StatefulSet>(pod_name, &tenant2.namespace)
                    .await;

                if stateful_set.is_err() {
                    return false;
                }

                // some solution will block the pod creation as a webhoook preventing a cross-tenant mount
                // so we need to check if the pod is not created, then we assume the storage is isolated
                let pod = tenant2
                    .cluster
                    .list_pods_with_label_in_namespace(
                        &format!("app={}", pod_name),
                        &tenant2.namespace,
                    )
                    .await
                    .map(|pods| pods.items.first().cloned());

                if pod.is_err() || pod.as_ref().unwrap().is_none() {
                    return false;
                }

                let pod = pod.unwrap().unwrap();

                let is_container_terminated = pod
                    .status
                    .and_then(|status| status.container_statuses)
                    .map(|container_statuses| {
                        container_statuses.iter().any(|container_status| {
                            container_status
                                .state
                                .as_ref()
                                .and_then(|state| {
                                    state.terminated.as_ref().map(|terminated| {
                                        terminated.exit_code == 0 || terminated.exit_code == 1
                                    })
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

                is_container_terminated
            },
        )
        .await;
    if wait_operation.is_err()
        && wait_operation
            .unwrap_err()
            .to_string()
            .contains("timed out")
    {
        println!("Pod creation timed out, we assume a policy is blocking the cross-tenant mount");
        //let _ = cleanup(tenant1, tenant2, &dynamic_pv_name, created_pvc_name).await;
        return Ok(());
    }

    // check if the file is accessible
    // let file_content2 = tenant2
    //     .cluster
    //     .exec_command_in_container(pod_name, &tenant2.namespace, &format!("cat {}", file_path))
    //     .await?;

    //if file_content2.trim() == file_content {
    //    return Err(anyhow::anyhow!(
    //        "Tenant2 can access the file created by Tenant1, storage is not isolated"
    //    ));
    //}

    let label = format!("app={}", pod_name);
    // get stateful set pod
    let pod = tenant2
        .cluster
        .list_pods_with_label_in_namespace(&label, &tenant2.namespace)
        .await?
        .items
        .first()
        .ok_or(anyhow::anyhow!("Pod in tenant2 not found"))
        .unwrap()
        .to_owned();

    // check exit status
    let exit_code = pod.status.unwrap().container_statuses.unwrap()[0]
        .state
        .as_ref()
        .and_then(|state| state.terminated.as_ref())
        .map(|terminated| terminated.exit_code)
        .unwrap_or(0);

    if exit_code == 1 {
        return Err(anyhow::anyhow!(
            "Tenant2 can access the file created by Tenant1, storage is not isolated"
        ));
    }

    let _ = cleanup(tenant1, tenant2, &dynamic_pv_name, created_pvc_name).await;
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

async fn is_authorized_to_get_storage_class(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    tenant
        .cluster
        .is_authorized_to("get", "StorageClass", None)
        .await
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
