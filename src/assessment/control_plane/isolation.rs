use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use kube::ResourceExt;

use crate::{
    assessment::{
        control_plane::{
            cleanup_test_resource, create_dynamic_object, create_minimal_object,
            get_existing_object_for_testing, get_namespace_param, infer_isolation_from_error,
            is_valid_get_result, requires_existing_object,
        },
        CrossTenantResult, IsolationLevel, KubernetesObject,
    },
    TenantClusterConfig,
};

/// Test cross-tenant CREATE isolation
pub(super) async fn test_cross_tenant_create(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    let test_name = format!(
        "create-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let t1_namespace = get_namespace_param(object_kind, &tenant1.namespace);

    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;

    // Step 1: Tenant1 creates the resource
    let t1_create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj.clone(), "tenant1"),
            t1_namespace,
        )
        .await;

    if t1_create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Unknown,
            details: format!(
                "Cannot verify CREATE isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Step 2: Tenant2 attempts to create with the same name in tenant1's namespace
    let t2_create_result = tenant2
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant2"),
            t1_namespace, // Attempting in tenant1's namespace
        )
        .await;

    // Step 3: Analyze the result
    let result = match t2_create_result {
        Ok(_) => {
            // Tenant2 succeeded - check if it overwrote tenant1's object
            let current_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &test_name, t1_namespace)
                .await;

            if let Ok(obj) = current_obj {
                if obj.annotations().get("kumuteva.io/created-by-tenant")
                    == Some(&"tenant2".to_string())
                {
                    // Tenant2 overwrote tenant1's object - no isolation
                    CrossTenantResult {
                        autonomy: true,
                        isolation: IsolationLevel::None,
                        details: format!(
                            "Cross-tenant CREATE breach: {} overwritten by other tenant",
                            object_kind.kind()
                        ),
                    }
                } else {
                    // Object still belongs to tenant1 - tenant2 created in different scope
                    // This is hard isolation - each tenant has their own namespace
                    CrossTenantResult {
                        autonomy: true,
                        isolation: IsolationLevel::Hard,
                        details: format!(
                            "CREATE has hard isolation for {} - tenants have separate scopes",
                            object_kind.kind()
                        ),
                    }
                }
            } else {
                CrossTenantResult {
                    autonomy: false,
                    isolation: IsolationLevel::Unknown,
                    details: format!(
                        "Cannot verify CREATE isolation for {} - object state unclear",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant CREATE blocked for {}: {}",
                    object_kind.kind(),
                    error_msg
                ),
            }
        }
    };

    // Cleanup
    cleanup_test_resource(tenant1, object_kind, &test_name, t1_namespace).await;

    Ok(result)
}

/// Test cross-tenant UPDATE isolation
pub(super) async fn test_cross_tenant_update(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_update_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "update-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;

    // Step 1: Create object in tenant1 with a known marker label
    let initial_label_value = "tenant1-original";
    let mut dynamic_obj = create_dynamic_object(object_kind, &test_name, obj, "tenant1");
    dynamic_obj.metadata.labels = Some(BTreeMap::from([(
        "update-test-marker".to_string(),
        initial_label_value.to_string(),
    )]));

    let create_result = tenant1
        .cluster
        .create_resource_dyn(object_kind, &dynamic_obj, namespace)
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify UPDATE isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Wait for the resource to be created
    let _ = tenant1
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Step 2: Tenant2 attempts to update the object
    let malicious_label_value = "tenant2-modified";
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "update-test-marker": malicious_label_value
            }
        }
    }));

    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, &test_name, &patch, namespace)
        .await;

    // Step 3: Verify the actual state
    let result = match update_result {
        Ok(_) => {
            // Update call succeeded - verify if it actually modified the object
            let current_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &test_name, namespace)
                .await;

            match current_obj {
                Ok(obj) => {
                    let current_label = obj
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get("update-test-marker"));

                    if current_label == Some(&malicious_label_value.to_string()) {
                        // Update took effect - no isolation
                        CrossTenantResult {
                            autonomy: true,
                            isolation: IsolationLevel::None,
                            details: format!(
                                "Cross-tenant UPDATE breach: {} modified by other tenant",
                                object_kind.kind()
                            ),
                        }
                    } else if current_label == Some(&initial_label_value.to_string()) {
                        // Label unchanged - update was blocked but succeeded (soft isolation)
                        CrossTenantResult {
                            autonomy: true,
                            isolation: IsolationLevel::Soft(
                                "Update succeeded but did not modify resource".to_string(),
                            ),
                            details: format!(
                                "UPDATE has soft isolation for {} - modification blocked",
                                object_kind.kind()
                            ),
                        }
                    } else {
                        CrossTenantResult {
                            autonomy: true,
                            isolation: IsolationLevel::Soft(format!(
                                "Unexpected label value: {:?}",
                                current_label
                            )),
                            details: format!(
                                "UPDATE isolation unclear for {} - unexpected state",
                                object_kind.kind()
                            ),
                        }
                    }
                }
                Err(e) => CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(format!("Could not verify: {}", e)),
                    details: format!(
                        "Cannot verify UPDATE isolation for {} - read failed",
                        object_kind.kind()
                    ),
                },
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant UPDATE blocked for {}: {}",
                    object_kind.kind(),
                    error_msg
                ),
            }
        }
    };

    // Cleanup
    cleanup_test_resource(tenant1, object_kind, &test_name, namespace).await;

    Ok(result)
}

/// Test UPDATE for resources that can't be created (like Node)
pub(super) async fn test_cross_tenant_update_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Get an existing object
    let existing_name = match get_existing_object_for_testing(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            return Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot test {} UPDATE - no existing object available: {}",
                    object_kind.kind(),
                    e
                ),
            });
        }
    };

    tracing::info!(
        "Testing UPDATE isolation for {} using existing object: {}",
        object_kind.kind(),
        existing_name
    );

    // Get the current state (to restore later if needed)
    let current_obj = tenant1
        .cluster
        .get_resource_dyn(object_kind, &existing_name, None)
        .await;

    let original_labels = current_obj
        .as_ref()
        .ok()
        .and_then(|obj| obj.metadata.labels.clone());

    // Tenant2 attempts to update the existing object
    let test_label_key = "kumuteva-update-test";
    let test_label_value = "tenant2-attempted-modification";

    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                test_label_key: test_label_value
            }
        }
    }));

    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, &existing_name, &patch, None)
        .await;

    let result = match update_result {
        Ok(_) => {
            // Update succeeded - verify if it took effect
            let updated_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &existing_name, None)
                .await;

            let was_modified = updated_obj
                .as_ref()
                .ok()
                .and_then(|obj| obj.metadata.labels.as_ref())
                .and_then(|labels| labels.get(test_label_key))
                == Some(&test_label_value.to_string());

            if was_modified {
                // Revert the modification
                let revert_patch = if let Some(ref orig) = original_labels {
                    kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": orig
                        }
                    }))
                } else {
                    kube::api::Patch::Merge(serde_json::json!({
                        "metadata": {
                            "labels": {
                                test_label_key: null
                            }
                        }
                    }))
                };

                let _ = tenant1
                    .cluster
                    .patch_resource_dyn(object_kind, &existing_name, &revert_patch, None)
                    .await;

                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant UPDATE breach: {} '{}' modified by other tenant",
                        object_kind.kind(),
                        existing_name
                    ),
                }
            } else {
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(
                        "Update succeeded but modification not visible".to_string(),
                    ),
                    details: format!(
                        "UPDATE has soft isolation for {} - modification not effective",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true, // Tenant1 can see the node, so there's autonomy
                isolation,
                details: format!(
                    "Cross-tenant UPDATE blocked for {} '{}': {}",
                    object_kind.kind(),
                    existing_name,
                    error_msg
                ),
            }
        }
    };

    Ok(result)
}

/// Test cross-tenant GET isolation
pub(super) async fn test_cross_tenant_get(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_get_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "get-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    // Create test object in tenant1
    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;
    let create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant1"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify GET isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Tenant2 attempts to GET the object
    let get_result = tenant2
        .cluster
        .get_resource_dyn(object_kind, &test_name, namespace)
        .await;

    let result = match get_result {
        Ok(obj) => {
            // Check if the returned object is actually valid (has the expected name)
            // Some proxies return Ok with empty objects instead of errors
            if is_valid_get_result(&obj, &test_name) {
                // Tenant2 can actually read tenant1's object - no isolation
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant GET breach: {} readable by other tenant",
                        object_kind.kind()
                    ),
                }
            } else {
                // GET returned Ok but with empty/invalid object - this is hard isolation
                // The proxy is hiding the resource from tenant2
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "Cross-tenant GET blocked for {} - proxy returned empty object",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!("Cross-tenant GET blocked for {}", object_kind.kind()),
            }
        }
    };

    // Cleanup
    cleanup_test_resource(tenant1, object_kind, &test_name, namespace).await;

    Ok(result)
}

/// Test GET for resources that can't be created (like Node)
pub(super) async fn test_cross_tenant_get_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Get an existing object visible to tenant1
    let existing_name = match get_existing_object_for_testing(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            return Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot test {} GET - no existing object available: {}",
                    object_kind.kind(),
                    e
                ),
            });
        }
    };

    tracing::info!(
        "Testing GET isolation for {} using existing object: {}",
        object_kind.kind(),
        existing_name
    );

    // Tenant2 attempts to GET the same object
    let t2_get_result = tenant2
        .cluster
        .get_resource_dyn(object_kind, &existing_name, None)
        .await;

    match t2_get_result {
        Ok(t2_obj) => {
            // Check if the returned object is actually valid
            // Some proxies return Ok with empty objects instead of errors
            if !is_valid_get_result(&t2_obj, &existing_name) {
                return Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "Cross-tenant GET blocked for {} - proxy returned empty object",
                        object_kind.kind()
                    ),
                });
            }

            // Both tenants can see the same resource
            // For cluster-scoped resources like nodes, this is expected
            // We need to check if it is the same object or not

            let t1_obj = tenant1
                .cluster
                .get_resource_dyn(object_kind, &existing_name, None)
                .await?;

            if t1_obj.metadata == t2_obj.metadata {
                // Same view
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "{} GET retrieve the same object named '{}'",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            } else {
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "{} GET retrieve different objects named '{}'",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            Ok(CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant GET blocked for {} '{}': {}",
                    object_kind.kind(),
                    existing_name,
                    error_msg
                ),
            })
        }
    }
}

/// Test cross-tenant LIST isolation
pub(super) async fn test_cross_tenant_list(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_list_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "list-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    // Create test object in tenant1 with unique annotation
    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;
    let create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant1"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify LIST isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Tenant2 attempts to LIST in tenant1's namespace
    let t2_list = tenant2
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await;

    let result = match t2_list {
        Ok(resources) => {
            // Check if tenant1's object is visible
            let can_see_tenant1_resource = resources
                .items
                .iter()
                .any(|item| item.metadata.name.as_deref() == Some(&test_name));

            if can_see_tenant1_resource {
                // Tenant2 can see tenant1's resources - no isolation
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant LIST breach: {} visible to other tenant",
                        object_kind.kind()
                    ),
                }
            } else {
                // Resources are filtered - hard isolation
                // Tenant2 sees an empty/filtered list as if resource doesn't exist
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "LIST has hard isolation for {} - tenant1's resources not visible",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!("Cross-tenant LIST blocked for {}", object_kind.kind()),
            }
        }
    };

    // Cleanup
    cleanup_test_resource(tenant1, object_kind, &test_name, namespace).await;

    Ok(result)
}

/// Test LIST for resources that can't be created (like Node)
pub(super) async fn test_cross_tenant_list_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Ensure at least one object exists (trigger node sync in vCluster)
    let _ = get_existing_object_for_testing(tenant1, object_kind).await;

    // List from both tenants
    let tenant1_list = tenant1.cluster.list_resources_dyn(object_kind, None).await;

    let tenant2_list = tenant2.cluster.list_resources_dyn(object_kind, None).await;

    match (tenant1_list, tenant2_list) {
        (Ok(t1_items), Ok(t2_items)) => {
            let t1_names: std::collections::HashSet<_> = t1_items
                .items
                .iter()
                .filter_map(|n| n.metadata.name.clone())
                .collect();

            let t2_names: std::collections::HashSet<_> = t2_items
                .items
                .iter()
                .filter_map(|n| n.metadata.name.clone())
                .collect();

            // If both lists are empty, we cannot verify isolation
            // (can't tell if they share the same empty view or have separate empty views)
            if t1_names.is_empty() && t2_names.is_empty() {
                return Ok(CrossTenantResult {
                    autonomy: true, // Both can LIST (just returns empty)
                    isolation: IsolationLevel::Unknown,
                    details: format!(
                        "Cannot verify {} LIST isolation - both tenants see 0 items and cannot create test resources",
                        object_kind.kind()
                    ),
                });
            }

            if t1_names == t2_names {
                // Identical non-empty view - this is a shared view (no isolation)
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "LIST shows shared {} view - both tenants see same {} items",
                        object_kind.kind(),
                        t1_names.len()
                    ),
                })
            } else {
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Hard,
                    details: format!(
                        "LIST has hard isolation for {} - different views (tenant1: {}, tenant2: {})",
                        object_kind.kind(),
                        t1_names.len(),
                        t2_names.len()
                    ),
                })
            }
        }
        (Ok(t1_items), Err(e)) => {
            // Tenant1 can list, tenant2 cannot
            Ok(CrossTenantResult {
                autonomy: true,
                isolation: IsolationLevel::Hard,
                details: format!(
                    "LIST has asymmetric isolation for {} - tenant1 sees {} items, tenant2 blocked: {}",
                    object_kind.kind(),
                    t1_items.items.len(),
                    e
                ),
            })
        }
        (Err(e), Ok(t2_items)) => {
            // Tenant2 can list, tenant1 cannot
            Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot verify {} LIST isolation - tenant1 blocked: {}, tenant2 sees {} items",
                    object_kind.kind(),
                    e,
                    t2_items.items.len()
                ),
            })
        }
        (Err(e1), Err(_e2)) => {
            // Neither can list
            Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot verify {} LIST isolation - both tenants blocked: {}",
                    object_kind.kind(),
                    e1
                ),
            })
        }
    }
}

/// Test cross-tenant DELETE isolation
pub(super) async fn test_cross_tenant_delete(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Special handling for resources that can't be created
    if requires_existing_object(object_kind) {
        return test_cross_tenant_delete_for_existing_resource(tenant1, tenant2, object_kind).await;
    }

    let test_name = format!(
        "delete-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let namespace = get_namespace_param(object_kind, &tenant1.namespace);

    // Create test object in tenant1
    let obj = create_minimal_object(object_kind, &test_name, &tenant1.namespace)?;
    let create_result = tenant1
        .cluster
        .create_resource_dyn(
            object_kind,
            &create_dynamic_object(object_kind, &test_name, obj, "tenant1"),
            namespace,
        )
        .await;

    if create_result.is_err() {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(format!(
                "Could not create test object: {}",
                create_result.unwrap_err()
            )),
            details: format!(
                "Cannot verify DELETE isolation for {} - tenant1 creation failed",
                object_kind.kind()
            ),
        });
    }

    // Wait for resource to be created
    let _ = tenant1
        .cluster
        .wait_for_dyn_resource_creation(object_kind, &test_name, namespace)
        .await;

    // Tenant2 attempts to DELETE the object
    let delete_result = tenant2
        .cluster
        .delete_resource_dyn(object_kind, &test_name, namespace)
        .await;

    let result = match delete_result {
        Ok(_) => {
            // Delete succeeded - verify if object is actually gone
            let exists = tenant1
                .cluster
                .dyn_object_exists(object_kind, &test_name, namespace)
                .await
                .unwrap_or(true);

            if !exists {
                // Object was deleted - no isolation
                // Still need to clean up PVC if it was a StatefulSet
                if *object_kind == KubernetesObject::StatefulSet {
                    if let Some(ns) = namespace {
                        let pvc_name = format!("{}-{}-0", test_name, test_name);
                        let _ = tenant1
                            .cluster
                            .delete_resource_in_namespace::<PersistentVolumeClaim>(&pvc_name, ns)
                            .await;
                    }
                }
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant DELETE breach: {} deleted by other tenant",
                        object_kind.kind()
                    ),
                }
            } else {
                // Object still exists - delete was silently ignored (soft isolation)
                // Clean up the object since it wasn't actually deleted
                cleanup_test_resource(tenant1, object_kind, &test_name, namespace).await;
                CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(
                        "Delete succeeded but object still exists".to_string(),
                    ),
                    details: format!(
                        "DELETE has soft isolation for {} - object preserved",
                        object_kind.kind()
                    ),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            // Cleanup since delete failed
            cleanup_test_resource(tenant1, object_kind, &test_name, namespace).await;

            CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!("Cross-tenant DELETE blocked for {}", object_kind.kind()),
            }
        }
    };

    Ok(result)
}

/// Test DELETE for resources that can't be created (like Node)
pub(super) async fn test_cross_tenant_delete_for_existing_resource(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> anyhow::Result<CrossTenantResult> {
    // Get an existing object name
    let existing_name = match get_existing_object_for_testing(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            return Ok(CrossTenantResult {
                autonomy: false,
                isolation: IsolationLevel::Unknown,
                details: format!(
                    "Cannot test {} DELETE - no existing object available: {}",
                    object_kind.kind(),
                    e
                ),
            });
        }
    };

    // Check if tenant2 is authorized to delete (don't actually delete!)
    let t2_can_delete = tenant2
        .cluster
        .is_authorized_to("delete", &object_kind.plural_kind(), None)
        .await
        .unwrap_or(false);

    if !t2_can_delete {
        return Ok(CrossTenantResult {
            autonomy: false,
            isolation: IsolationLevel::Soft(
                "Tenant2 not authorized to delete resource".to_string(),
            ),
            details: format!(
                "Cannot verify DELETE isolation for {} - tenant2 lacks delete permission",
                object_kind.kind()
            ),
        });
    }

    // let's try deleting and chech if is still existing
    let delete_result = tenant2
        .cluster
        .delete_resource_dyn(object_kind, &existing_name, None)
        .await;

    match delete_result {
        Ok(_) => {
            // Delete succeeded - verify if object is actually gone
            let exists = tenant1
                .cluster
                .dyn_object_exists(object_kind, &existing_name, None)
                .await
                .unwrap_or(true);

            if !exists {
                // Object was deleted - no isolation
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::None,
                    details: format!(
                        "Cross-tenant DELETE breach: {} '{}' deleted by other tenant",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            } else {
                // Object still exists - delete was silently ignored
                Ok(CrossTenantResult {
                    autonomy: true,
                    isolation: IsolationLevel::Soft(
                        "Delete succeeded but object still exists".to_string(),
                    ),
                    details: format!(
                        "DELETE has soft isolation for {} - object '{}' preserved",
                        object_kind.kind(),
                        existing_name
                    ),
                })
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let isolation = infer_isolation_from_error(&error_msg);

            Ok(CrossTenantResult {
                autonomy: true,
                isolation,
                details: format!(
                    "Cross-tenant DELETE blocked for {} '{}': {}",
                    object_kind.kind(),
                    existing_name,
                    error_msg
                ),
            })
        }
    }
}
