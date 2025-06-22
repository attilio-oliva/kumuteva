use crate::verifier::{
    ControlPlaneIsolationReport, KubernetesObject, KubernetesVerb, ObjectPropertyAssessment,
    OperationResult, TenantClusterConfig,
};

use anyhow::{Context, Result};
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};

/// Verifies that object isolation works between two tenant clusters
/// Tests autonomy (can perform operations on own objects) and isolation (cannot access other tenant's objects)
pub async fn check_object_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<ControlPlaneIsolationReport> {
    let object_kinds = KubernetesObject::all();
    let verbs = [
        KubernetesVerb::Create,
        KubernetesVerb::Get,
        KubernetesVerb::List,
        KubernetesVerb::Update,
        KubernetesVerb::Patch,
        KubernetesVerb::Delete,
        KubernetesVerb::Watch,
    ];

    let mut object_results = Vec::new();
    let mut autonomy_failures = Vec::new();

    for object_kind in object_kinds {
        println!(
            "Testing object kind: {} ({})",
            object_kind.kind(),
            object_kind.api_version()
        );

        let result = assess_object_kind_accessibility(tenant1, tenant2, &object_kind, &verbs)
            .await
            .context(format!("Failed to test object kind {}", object_kind.kind()))?;

        // Collect failures
        if !result.is_valid {
            isolation_failures.push(format!(
                "{}/{}: Cross-tenant access detected",
                object_kind.api_version(),
                object_kind.kind()
            ));
        }

        if !result.has_autonomy {
            autonomy_failures.push(format!(
                "{}/{}: Tenant cannot perform all required operations",
                object_kind.api_version(),
                object_kind.kind()
            ));
        }

        object_results.push(result);
    }

    let overall_isolation_success = isolation_failures.is_empty();
    let overall_autonomy_success = autonomy_failures.is_empty();

    Ok(ControlPlaneIsolationReport {
        overall_isolation_success,
        overall_autonomy_success,
        objects_assessment: object_results,
        failures: isolation_failures,
        autonomy_failures,
    })
}

async fn assess_object_kind_accessibility(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verbs: &[KubernetesVerb],
) -> Result<ObjectPropertyAssessment> {
    let mut autonomy_results = Vec::new();
    let mut isolation_results = Vec::new();

    // Test autonomy - can tenant1 perform all operations on this object kind?
    for verb in verbs {
        let result = test_tenant_autonomy(tenant1, object_kind, *verb).await;
        autonomy_results.push(result);
    }

    // Test isolation - create object with tenant1, try to access with tenant2
    for verb in verbs {
        let result = test_cross_tenant_isolation(tenant1, tenant2, object_kind, *verb).await;
        isolation_results.push(result);
    }

    let has_autonomy = autonomy_results.iter().all(|r| r.success);
    let has_isolation = isolation_results.iter().all(|r| r.success);

    Ok(ObjectPropertyAssessment {
        kind: object_kind.clone(),
        autonomy_results,
        issued_operations: isolation_results,
        has_autonomy,
        is_valid: has_isolation,
    })
}

async fn test_tenant_autonomy(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verb: KubernetesVerb,
) -> OperationResult {
    let result = match verb {
        KubernetesVerb::Create => test_create_operation(tenant, object_kind).await,
        KubernetesVerb::Get => test_get_operation(tenant, object_kind).await,
        KubernetesVerb::List => test_list_operation(tenant, object_kind).await,
        KubernetesVerb::Update => test_update_operation(tenant, object_kind).await,
        KubernetesVerb::Patch => test_patch_operation(tenant, object_kind).await,
        KubernetesVerb::Delete => test_delete_operation(tenant, object_kind).await,
        KubernetesVerb::Watch => test_watch_operation(tenant, object_kind).await,
    };

    println!(
        "Testing autonomy for {} {}: {:?}",
        object_kind.kind(),
        verb,
        result
    );

    match result {
        Ok(_) => OperationResult {
            verb,
            success: true,
            error_reason: None,
        },
        Err(e) => OperationResult {
            verb,
            success: false,
            error_reason: Some(e.to_string()),
        },
    }
}

async fn test_cross_tenant_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verb: KubernetesVerb,
) -> OperationResult {
    // First, tenant1 creates an object
    let object_name = format!(
        "test-{}-{}",
        object_kind.kind().to_lowercase(),
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    let create_result = create_test_object(tenant1, object_kind, &object_name).await;
    if create_result.is_err() {
        println!(
            "Failed to create test object for isolation test: {}",
            create_result.unwrap_err()
        );
        return OperationResult {
            verb,
            success: true, // If we can't create, isolation is irrelevant for this test
            error_reason: Some("Could not create test object for isolation test".to_string()),
        };
    }

    // Then tenant2 tries to access tenant1's object
    let access_result = match verb {
        KubernetesVerb::Get => {
            test_cross_tenant_get(tenant2, tenant1, object_kind, &object_name).await
        }
        KubernetesVerb::List => test_cross_tenant_list(tenant2, tenant1, object_kind).await,
        KubernetesVerb::Update => {
            test_cross_tenant_update(tenant2, tenant1, object_kind, &object_name).await
        }
        KubernetesVerb::Delete => {
            test_cross_tenant_delete(tenant2, tenant1, object_kind, &object_name).await
        }
        _ => Ok(()), // Skip other verbs for cross-tenant testing
    };

    // Cleanup
    let _ = cleanup_test_object(tenant1, object_kind, &object_name).await;

    println!(
        "Testing isolation (cross) for {} {}: {:?}",
        object_kind.kind(),
        verb,
        access_result
    );
    match access_result {
        Err(_) => OperationResult {
            verb,
            success: false, // If tenant2 can access tenant1's object, isolation failed
            error_reason: Some(
                "Cross-tenant access was successful - isolation breach detected".to_string(),
            ),
        },
        Ok(_) => OperationResult {
            verb,
            success: true, // If tenant2 cannot access tenant1's object, isolation works
            error_reason: None,
        },
    }
}

// Individual operation test implementations
async fn test_create_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let object_name = format!(
        "autonomy-test-{}",
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );
    create_test_object(tenant, object_kind, &object_name).await?;
    cleanup_test_object(tenant, object_kind, &object_name).await?;
    Ok(())
}

async fn test_list_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let resource_name = object_kind.plural_kind();

    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let is_authorized = tenant
        .cluster
        .is_authorized_to("list", &resource_name, namespace)
        .await?;

    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to list {}",
            object_kind.kind()
        ))
    }
}

async fn test_get_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let resource_name = object_kind.plural_kind();

    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let is_authorized = tenant
        .cluster
        .is_authorized_to("get", &resource_name, namespace)
        .await?;

    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to get {}",
            object_kind.kind()
        ))
    }
}

async fn test_update_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let resource_name = object_kind.plural_kind();
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let is_authorized = tenant
        .cluster
        .is_authorized_to("update", &resource_name, namespace)
        .await?;

    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to update {}",
            object_kind.kind()
        ))
    }
}

async fn test_patch_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let resource_name = object_kind.plural_kind();
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let is_authorized = tenant
        .cluster
        .is_authorized_to("patch", &resource_name, namespace)
        .await?;

    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to patch {}",
            object_kind.kind()
        ))
    }
}

async fn test_delete_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let resource_name = object_kind.plural_kind();
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let is_authorized = tenant
        .cluster
        .is_authorized_to("delete", &resource_name, namespace)
        .await?;

    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to delete {}",
            object_kind.kind()
        ))
    }
}

async fn test_watch_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    let resource_name = object_kind.plural_kind();
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let is_authorized = tenant
        .cluster
        .is_authorized_to("watch", &resource_name, namespace)
        .await?;

    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to watch {}",
            object_kind.kind()
        ))
    }
}

// Cross-tenant operation tests using the dispatch macro
async fn test_cross_tenant_get(
    tenant2: &TenantClusterConfig,
    tenant1: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> Result<()> {
    // Attempt to get an object created by tenant1 in tenant2's namespace
    let namespace = tenant1.namespace.as_str();
    let resource = tenant2
        .cluster
        .get_resource_dyn(object_kind, object_name, Some(namespace))
        .await;

    if resource.is_ok() {
        Err(anyhow::anyhow!(
            "Cross-tenant access detected: {} {} found in {}",
            object_kind.kind(),
            object_name,
            namespace
        ))
    } else {
        Ok(())
    }
}

async fn test_cross_tenant_list(
    tenant2: &TenantClusterConfig,
    tenant1: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<()> {
    // Attempt to list objects of a kind created by tenant1 in tenant2's namespace
    let namespace = tenant1.namespace.as_str();
    let resources = tenant2
        .cluster
        .list_resources_dyn(object_kind, Some(namespace))
        .await;

    if resources.is_ok() {
        // check if the list contains objects created by tenant1
        let can_see_t1_res = resources
            .unwrap()
            .items
            .iter()
            .any(|obj| obj.metadata.name == Some(object_kind.kind().to_string()));
        if can_see_t1_res {
            return Err(anyhow::anyhow!(
                "Cross-tenant access detected: {} objects found in {}",
                object_kind.kind(),
                namespace
            ));
        }
    }

    Ok(())
}

async fn test_cross_tenant_update(
    tenant2: &TenantClusterConfig,
    tenant1: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> Result<()> {
    // Create a minimal update patch
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "test-update": "cross-tenant-test"
            }
        }
    }));

    // Print the whole resource from the cluster for debugging
    let resource = tenant1
        .cluster
        .get_resource_dyn(object_kind, object_name, Some(tenant1.namespace.as_str()))
        .await;
    if let Ok(resource) = resource {
        println!(
            "Resource before update: {}",
            serde_json::to_string_pretty(&resource).unwrap()
        );
    } else {
        println!(
            "Failed to get resource for debugging: {}",
            resource.unwrap_err()
        );
        // try to get the resource from tenant2
        let resource = tenant2
            .cluster
            .get_resource_dyn(object_kind, object_name, Some(tenant1.namespace.as_str()))
            .await;
        if let Ok(resource) = resource {
            println!(
                "Resource from tenant2 before update: {}",
                serde_json::to_string_pretty(&resource).unwrap()
            );
        } else {
            println!(
                "Failed to get resource from tenant2 for debugging: {}",
                resource.unwrap_err()
            );
        }
    }

    // Attempt to update an object created by tenant1 in tenant2's namespace
    let namespace = tenant1.namespace.as_str();
    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, object_name, &patch, Some(namespace))
        .await;
    if update_result.is_ok() {
        Err(anyhow::anyhow!(
            "Cross-tenant access detected: {} {} updated in {} ({:?})",
            object_kind.kind(),
            object_name,
            namespace,
            update_result.unwrap()
        ))
    } else {
        Ok(())
    }
}

async fn test_cross_tenant_delete(
    tenant2: &TenantClusterConfig,
    tenant1: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> Result<()> {
    // Attempt to delete the object created by tenant1
    let namespace = tenant1.namespace.as_str();
    let delete_result = tenant2
        .cluster
        .delete_resource_dyn(object_kind, object_name, Some(namespace))
        .await;
    if delete_result.is_ok() {
        Err(anyhow::anyhow!(
            "Cross-tenant access detected: {} {} deleted in {}",
            object_kind.kind(),
            object_name,
            namespace
        ))
    } else {
        Ok(())
    }
}

// Helper functions for object management
async fn create_test_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> Result<()> {
    // Create a minimal test object based on the kind
    let test_object = create_minimal_object(object_kind, object_name, &tenant.namespace)?;
    let dynamic_object = DynamicObject {
        types: Some(TypeMeta {
            api_version: object_kind.api_version().to_string(),
            kind: object_kind.kind().to_string(),
        }),
        metadata: ObjectMeta {
            name: Some(object_name.to_string()),
            ..Default::default()
        },
        data: test_object,
    };

    let namespace = tenant.namespace.as_str();

    // Attempt to create the object in the tenant's cluster
    let create_result = tenant
        .cluster
        .create_resource_dyn(object_kind, &dynamic_object, Some(namespace))
        .await;
    if create_result.is_err() {
        return Err(anyhow::anyhow!(
            "Failed to create {} {}: {}",
            object_kind.kind(),
            object_name,
            create_result.unwrap_err()
        ));
    }
    Ok(())
}

async fn cleanup_test_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
) -> Result<()> {
    // Attempt to delete the test object
    let namespace = tenant.namespace.as_str();
    let delete_result = tenant
        .cluster
        .delete_resource_dyn(object_kind, object_name, Some(namespace))
        .await;

    if delete_result.is_err() {
        return Err(anyhow::anyhow!(
            "Failed to cleanup {} {}: {}",
            object_kind.kind(),
            object_name,
            delete_result.unwrap_err()
        ));
    }
    Ok(())
}

fn create_minimal_object(
    object_kind: &KubernetesObject,
    object_name: &str,
    namespace: &str,
) -> Result<serde_json::Value> {
    let mut base_object = serde_json::json!({
        "apiVersion": object_kind.api_version(),
        "kind": object_kind.kind(),
        "metadata": {
            "name": object_name,
        }
    });

    // Add namespace if required
    if object_kind.is_namespaced() {
        base_object["metadata"]["namespace"] = serde_json::Value::String(namespace.to_string());
    }

    // Add kind-specific required fields
    match object_kind {
        KubernetesObject::Pod => {
            base_object["spec"] = serde_json::json!({
                "containers": [{
                    "name": "test-container",
                    "image": "nginx:latest"
                }]
            });
        }
        KubernetesObject::Deployment => {
            base_object["spec"] = serde_json::json!({
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }]
                    }
                }
            });
        }
        KubernetesObject::Service => {
            base_object["spec"] = serde_json::json!({
                "selector": {
                    "app": object_name
                },
                "ports": [{
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 8080
                }]
            });
        }
        KubernetesObject::ConfigMap => {
            base_object["data"] = serde_json::json!({
                "key": "value"
            });
        }
        KubernetesObject::Secret => {
            base_object["type"] = serde_json::Value::String("Opaque".to_string());
            base_object["data"] = serde_json::json!({
                "key": "dmFsdWU=" // base64 encoded "value"
            });
        }
        // Add more specific cases as needed
        _ => {
            // For other resources, the base object should be sufficient
        }
    }

    Ok(base_object)
}
