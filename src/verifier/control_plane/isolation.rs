use crate::verifier::{
    control_plane::autonomy, AssessmentResult, ControlPlaneIsolationReport, KubernetesObject,
    KubernetesVerb, ObjectPropertyAssessment, OperationResult, TenantClusterConfig,
};

use anyhow::{Context, Result};
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};

/// Verifies that object isolation works between two tenant clusters
/// Tests that one tenant cannot access other tenant's objects
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
    let mut isolation_failures = Vec::new();

    for object_kind in object_kinds {
        // println!(
        //     "Testing object kind: {} ({})",
        //     object_kind.kind(),
        //     object_kind.api_version()
        // );

        let result = assess_object_isolation(tenant1, tenant2, &object_kind, &verbs)
            .await
            .context(format!("Failed to test object kind {}", object_kind.kind()))?;

        // Collect failures
        if !result.is_valid() {
            isolation_failures.push(format!(
                "{}/{}: Cross-tenant access detected",
                object_kind.api_version(),
                object_kind.kind()
            ));
        }
        object_results.push(result);
    }

    let overall_isolation_success = isolation_failures.is_empty();

    Ok(ControlPlaneIsolationReport {
        overall_isolation_success,
        objects_assessment: object_results,
        failures: isolation_failures,
    })
}

async fn assess_object_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verbs: &[KubernetesVerb],
) -> Result<ObjectPropertyAssessment> {
    // Try to get or create a test object for isolation testing
    let object_name = match setup_test_object(tenant1, object_kind).await {
        Ok(name) => name,
        Err(e) => {
            // If we can't create/find an object, fall back to autonomy testing
            return fallback_to_autonomy_testing(tenant1, object_kind, e).await;
        }
    };

    // println!(
    //     "Created or found object {} {} for isolation tests",
    //     object_kind.kind(),
    //     object_name
    // );

    // Test cross-tenant isolation for each verb
    let isolation_results =
        test_cross_tenant_operations(tenant1, tenant2, object_kind, &object_name, verbs).await;

    // Cleanup the test object
    let _ = cleanup_test_object(tenant1, object_kind, &object_name).await;

    let has_isolation = isolation_results.iter().all(|r| r.success);
    let result = if has_isolation {
        AssessmentResult::Success
    } else {
        AssessmentResult::Unsuccessful(format!(
            "Cross-tenant access detected for {}: [{}]",
            object_kind.kind(),
            isolation_results
                .iter()
                .filter(|r| !r.success)
                .map(|r| r.verb.to_string().to_uppercase())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    };

    Ok(ObjectPropertyAssessment {
        kind: object_kind.clone(),
        issued_operations: isolation_results,
        result,
    })
}

async fn setup_test_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
) -> Result<String> {
    let random_object_name = format!(
        "test-{}-{}",
        object_kind.kind().to_lowercase(),
        uuid::Uuid::new_v4().to_string()[0..8].to_lowercase()
    );

    // Try to create a new test object
    match create_test_object(tenant, object_kind, &random_object_name).await {
        Ok(_) => Ok(random_object_name),
        Err(creation_error) => {
            // If creation fails, try to find an existing object
            find_existing_object(tenant, object_kind, creation_error).await
        }
    }
}

pub async fn find_existing_object(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    creation_error: anyhow::Error,
) -> Result<String> {
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };

    let resources = tenant
        .cluster
        .list_resources_dyn(object_kind, namespace)
        .await
        .context("Failed to list existing resources for isolation test")?;

    if resources.items.is_empty() {
        return Err(anyhow::anyhow!(
            "No existing objects found for isolation test on {}: {}",
            object_kind.kind(),
            creation_error
        ));
    }

    let first_resource = resources.items.first().unwrap();
    let object_name = first_resource.metadata.name.clone().unwrap_or_default();

    // println!("Using existing object {} for isolation test", object_name);

    Ok(object_name)
}

async fn fallback_to_autonomy_testing(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    error: anyhow::Error,
) -> Result<ObjectPropertyAssessment> {
    let error_reason = format!(
        "Could not test this allowed operation because CREATE is forbidden and no existing object to test was found {}",
        error
    );

    // Test basic operations to determine if tenant has permissions
    let operations = [
        (
            KubernetesVerb::Create,
            autonomy::test_operation(tenant, object_kind, KubernetesVerb::Create).await,
        ),
        (
            KubernetesVerb::Get,
            autonomy::test_operation(tenant, object_kind, KubernetesVerb::Get).await,
        ),
        (
            KubernetesVerb::List,
            autonomy::test_operation(tenant, object_kind, KubernetesVerb::List).await,
        ),
        (
            KubernetesVerb::Update,
            autonomy::test_operation(tenant, object_kind, KubernetesVerb::Update).await,
        ),
        (
            KubernetesVerb::Delete,
            autonomy::test_operation(tenant, object_kind, KubernetesVerb::Delete).await,
        ),
    ];

    let operation_results: Vec<OperationResult> = operations
        .into_iter()
        .map(|(verb, result)| OperationResult {
            verb,
            success: result.is_err(), // Success means operation was denied (no permissions)
            error_reason: if result.is_ok() {
                Some(format!("{}: {}", verb, error_reason))
            } else {
                None
            },
        })
        .collect();

    let no_operation_is_allowed = operation_results.iter().all(|r| r.success);
    let result = if no_operation_is_allowed {
        AssessmentResult::Success
    } else {
        AssessmentResult::NotEvaluated(
            format!("Operations [{}] are allowed, but not [CREATE] and there are no existing object to test isolation",
                    operation_results
                        .iter()
                        .filter(|r| r.success)
                        .map(|r| r.verb.to_string().to_uppercase())
                        .collect::<Vec<_>>()
                        .join(", ")
        )
        )
    };

    Ok(ObjectPropertyAssessment {
        kind: object_kind.clone(),
        issued_operations: operation_results,
        result,
    })
}

async fn test_cross_tenant_operations(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    object_name: &str,
    verbs: &[KubernetesVerb],
) -> Vec<OperationResult> {
    let mut results = Vec::new();

    for verb in verbs {
        let test_result = match verb {
            KubernetesVerb::Get => {
                test_cross_tenant_get(tenant2, tenant1, object_kind, object_name).await
            }
            KubernetesVerb::List => test_cross_tenant_list(tenant2, tenant1, object_kind).await,
            KubernetesVerb::Update => {
                test_cross_tenant_update(tenant2, tenant1, object_kind, object_name).await
            }
            KubernetesVerb::Delete => {
                test_cross_tenant_delete(tenant2, tenant1, object_kind, object_name).await
            }
            _ => Ok(()), // Skip other verbs for cross-tenant testing
        };

        // println!(
        //     "Testing isolation (cross) for {} {}: {:?}",
        //     object_kind.kind(),
        //     verb,
        //     test_result
        // );

        let operation_result = match test_result {
            Ok(_) => OperationResult {
                verb: *verb,
                success: true, // If tenant2 cannot access tenant1's object, isolation works
                error_reason: None,
            },
            Err(_) => OperationResult {
                verb: *verb,
                success: false, // If tenant2 can access tenant1's object, isolation failed
                error_reason: Some(
                    "Cross-tenant access was successful - isolation breach detected".to_string(),
                ),
            },
        };

        results.push(operation_result);
    }

    results
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

    if resource.is_err() {
        // println!(
        //     "The object to update did not exist: {}",
        //     resource.unwrap_err()
        // );
        return Ok(());
    }

    // Attempt to update an object created by tenant1 by tenant2
    let namespace = tenant1.namespace.as_str();
    let update_result = tenant2
        .cluster
        .patch_resource_dyn(object_kind, object_name, &patch, Some(namespace))
        .await;
    if update_result.is_ok() {
        // Check if the update was successful
        let updated_resource = tenant1
            .cluster
            .get_resource_dyn(object_kind, object_name, Some(namespace))
            .await;
        if let Ok(updated_resource) = updated_resource {
            if updated_resource
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("test-update"))
                == Some(&"cross-tenant-test".to_string())
            {
                return Err(anyhow::anyhow!(
                    "Cross-tenant access detected: {} {} updated in {} ({:?})",
                    object_kind.kind(),
                    object_name,
                    namespace,
                    update_result.unwrap()
                ));
            }
        } else {
            println!(
                "Failed to get updated resource for verification: {}",
                updated_resource.unwrap_err()
            );
        }
    }
    Ok(())
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

pub fn create_minimal_object(
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

        KubernetesObject::DaemonSet => {
            base_object["spec"] = serde_json::json!({
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

        KubernetesObject::PersistentVolumeClaim => {
            base_object["spec"] = serde_json::json!({
                "accessModes": ["ReadWriteOnce"],
                "resources": {
                    "requests": {
                        "storage": "1Gi"
                    }
                },

            });
        }

        KubernetesObject::PersistentVolume => {
            // Use hostPath type - the path doesn't need to exist on the API server
            // as we're just testing authorization, not actually mounting volumes
            base_object["spec"] = serde_json::json!({
                "capacity": {
                    "storage": "1Gi"
                },
                "accessModes": ["ReadWriteOnce"],
                "persistentVolumeReclaimPolicy": "Retain",
                "hostPath": {
                    "path": format!("/tmp/test-pv-{}", object_name)
                }
            });
        }

        KubernetesObject::ReplicaSet => {
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

        KubernetesObject::StatefulSet => {
            base_object["spec"] = serde_json::json!({
                "serviceName": object_name,
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
                },
                "volumeClaimTemplates": [{
                    "metadata": {
                        "name": object_name
                    },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage": "1Gi"
                            }
                        }
                    }
                }]
            });
        }

        KubernetesObject::Ingress => {
            base_object["spec"] = serde_json::json!({
                "rules": [{
                    "host": format!("{}.example.com", object_name),
                    "http": {
                        "paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": object_name,
                                    "port": {
                                        "number": 80
                                    }
                                }
                            }
                        }]
                    }
                }]
            });
        }

        KubernetesObject::HorizontalPodAutoscaler => {
            base_object["spec"] = serde_json::json!({
                "scaleTargetRef": {
                    "apiVersion": object_kind.api_version(),
                    "kind": object_kind.kind(),
                    "name": object_name
                },
                "minReplicas": 1,
                "maxReplicas": 2,
                "targetCPUUtilizationPercentage": 50
            });
        }

        KubernetesObject::RoleBinding => {
            base_object["roleRef"] = serde_json::json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": object_name
            });
            base_object["subjects"] = serde_json::json!([{
                "kind": "User",
                "name": "test-user",
                "apiGroup": "rbac.authorization.k8s.io"
            }]);
        }

        KubernetesObject::ClusterRoleBinding => {
            base_object["roleRef"] = serde_json::json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": object_name
            });
            base_object["subjects"] = serde_json::json!([{
                "kind": "User",
                "name": "test-user",
                "apiGroup": "rbac.authorization.k8s.io"
            }]);
        }

        KubernetesObject::Job => {
            base_object["spec"] = serde_json::json!({
                "template": {
                    "metadata": {
                        "labels": {
                            "job-name": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }],
                        "restartPolicy": "Never"
                    }
                }
            });
        }

        KubernetesObject::CronJob => {
            base_object["spec"] = serde_json::json!({
                "schedule": "*/5 * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "metadata": {
                                "labels": {
                                    "job-name": object_name
                                }
                            },
                            "spec": {
                                "containers": [{
                                    "name": "test-container",
                                    "image": "nginx:latest"
                                }],
                                "restartPolicy": "Never"
                            }
                        }
                    }
                }
            });
        }

        KubernetesObject::StorageClass => {
            base_object["provisioner"] =
                serde_json::Value::String("kubernetes.io/no-provisioner".to_string());
            // no-provisioner doesn't require any parameters
            base_object["volumeBindingMode"] =
                serde_json::Value::String("WaitForFirstConsumer".to_string());
        }

        KubernetesObject::IngressClass => {
            // IngressClass only requires controller field
            base_object["spec"] = serde_json::json!({
                "controller": "k8s.io/ingress-nginx"
            });
        }

        KubernetesObject::NetworkPolicy => {
            base_object["spec"] = serde_json::json!({
                "podSelector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{
                    "from": [{
                        "podSelector": {
                            "matchLabels": {
                                "app": object_name
                            }
                        }
                    }]
                }],
                "egress": [{
                    "to": [{
                        "podSelector": {
                            "matchLabels": {
                                "app": object_name
                            }
                        }
                    }]
                }]
            });
        }

        // Add more specific cases as needed
        _ => {
            // For other resources, the base object should be sufficient
        }
    }

    Ok(base_object)
}
