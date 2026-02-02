use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use tracing::info;

use crate::assessment::control_plane::{
    cleanup_test_resource, create_dynamic_object, create_minimal_object,
    get_existing_object_for_testing, get_namespace_param, is_authorization_error,
    is_valid_get_result, requires_existing_object, KubernetesObject, TenantClusterConfig,
};

/// Test if tenant can actually CREATE a resource by attempting the operation
pub(super) async fn test_autonomy_create(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // We try to create a resource even though requires_existing_object may be true

    let test_name = format!(
        "autonomy-create-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant.namespace);
    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    // Cleanup regardless of result
    if create_result.is_ok() {
        cleanup_test_resource(tenant, object_kind, &test_name, namespace).await;
    }

    Ok(create_result.is_ok())
}

/// Test if tenant can actually GET a resource by attempting the operation
pub(super) async fn test_autonomy_get(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        // Try to get an existing resource
        let existing_name = get_existing_object_for_testing(tenant, object_kind).await;
        if let Ok(name) = existing_name {
            let get_result = tenant
                .cluster
                .get_resource_dyn(object_kind, &name, None)
                .await;
            // Validate that the returned object is actually valid
            return Ok(get_result
                .map(|obj| is_valid_get_result(&obj, &name))
                .unwrap_or(false));
        }

        info!(
            "No existing resource found for {:?} to test GET {:?}",
            object_kind, existing_name
        );

        return Ok(false);
    }

    let namespace = get_namespace_param(object_kind, &tenant.namespace);

    // No existing resources - try to create one to test GET
    let test_name = format!(
        "autonomy-get-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        // Check if the LIST is authorized and use it instead to get an object name
        let list_result = tenant
            .cluster
            .list_resources_dyn(object_kind, namespace)
            .await;

        if let Ok(list) = list_result {
            // If there are existing resources, try to GET one of them
            if let Some(item) = list.items.first() {
                if let Some(name) = &item.metadata.name {
                    let get_result = tenant
                        .cluster
                        .get_resource_dyn(object_kind, name, namespace)
                        .await;
                    // Validate that the returned object is actually valid
                    return Ok(get_result
                        .map(|obj| is_valid_get_result(&obj, name))
                        .unwrap_or(false));
                }
            }
        }
    }

    // Try to GET the resource we created
    let get_result = tenant
        .cluster
        .get_resource_dyn(object_kind, &test_name, namespace)
        .await;

    // Cleanup
    cleanup_test_resource(tenant, object_kind, &test_name, namespace).await;

    // Validate that the returned object is actually valid
    Ok(get_result
        .map(|obj| is_valid_get_result(&obj, &test_name))
        .unwrap_or(false))
}

/// Test if tenant can actually LIST resources by attempting the operation
pub(super) async fn test_autonomy_list(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    let namespace = get_namespace_param(object_kind, &tenant.namespace);

    let list_result = tenant
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await;

    Ok(list_result.is_ok())
}

/// Test if tenant can actually UPDATE a resource by attempting the operation
pub(super) async fn test_autonomy_update(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        let existing_name = get_existing_object_for_testing(tenant, object_kind).await;
        if let Ok(name) = existing_name {
            let test_label_key = "kumuteva-autonomy-test";
            let test_label_value = "update-test";

            let patch = kube::api::Patch::Merge(serde_json::json!({
                "metadata": {
                    "labels": {
                        test_label_key: test_label_value
                    }
                }
            }));

            let update_result = tenant
                .cluster
                .patch_resource_dyn(object_kind, &name, &patch, None)
                .await;

            // Try to revert if successful
            if update_result.is_ok() {
                let revert_patch = kube::api::Patch::Merge(serde_json::json!({
                    "metadata": {
                        "labels": {
                            test_label_key: null
                        }
                    }
                }));
                let _ = tenant
                    .cluster
                    .patch_resource_dyn(object_kind, &name, &revert_patch, None)
                    .await;
            }

            return Ok(update_result.is_ok());
        }
        return Ok(false);
    }

    let namespace = get_namespace_param(object_kind, &tenant.namespace);

    // No existing resources - create one to test UPDATE
    let test_name = format!(
        "autonomy-update-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        let list_result = tenant
            .cluster
            .list_resources_dyn(object_kind, namespace)
            .await;

        if let Ok(list) = list_result {
            if let Some(item) = list.items.first() {
                if let Some(name) = &item.metadata.name {
                    // Try to update an existing resource
                    let patch = kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": {
                                "kumuteva-autonomy-update-test": "true"
                            }
                        }
                    }));

                    let update_result = tenant
                        .cluster
                        .patch_resource_dyn(object_kind, name, &patch, namespace)
                        .await;

                    // Try to revert if successful
                    if update_result.is_ok() {
                        let revert_patch = kube::api::Patch::Merge(serde_json::json!({
                            "metadata": {
                                "labels": {
                                    "kumuteva-autonomy-update-test": null
                                }
                            }
                        }));
                        let _ = tenant
                            .cluster
                            .patch_resource_dyn(object_kind, name, &revert_patch, namespace)
                            .await;
                    }

                    return Ok(update_result.is_ok());
                }
            }
        }

        // Can't create and no existing resources to test with
        return Ok(false);
    }

    // Wait a moment for the resource to be ready
    let _ = tenant
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Try to UPDATE the resource
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "autonomy-update-test": "true"
            }
        }
    }));

    let update_result = tenant
        .cluster
        .patch_resource_dyn(object_kind, &test_name, &patch, namespace)
        .await;

    // Cleanup
    cleanup_test_resource(tenant, object_kind, &test_name, namespace).await;

    Ok(update_result.is_ok())
}

/// Test if tenant can actually DELETE a resource by attempting the operation
pub(super) async fn test_autonomy_delete(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<bool> {
    // Special handling for resources that can't be created
    // if requires_existing_object(object_kind) {

    // }

    // For DELETE, we MUST create a resource to delete - we can't delete existing resources
    // as that would be destructive to the user's environment
    let test_name = format!(
        "autonomy-delete-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant.namespace);
    let obj = create_minimal_object(object_kind, &test_name, &tenant.namespace)?;

    let create_result = tenant
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "autonomy-test"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        // Can't create a resource to test DELETE with
        // If we can't create, we likely can't delete either
        return Ok(false);
    }

    // Wait a moment for the resource to be ready
    let _ = tenant
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Try to DELETE the resource
    let delete_result = tenant
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    // For StatefulSets, also clean up the PVC (even if delete failed, PVC might exist)
    if *object_kind == KubernetesObject::StatefulSet {
        if let Some(ns) = namespace {
            let pvc_name = format!("{}-{}-0", test_name, test_name);
            let _ = tenant
                .cluster
                .delete_resource_in_namespace::<PersistentVolumeClaim>(&pvc_name, ns)
                .await;
        }
    }

    Ok(delete_result.is_ok())
}
