use crate::verifier::{
    create_minimal_object, AssessmentResult, ControlPlaneAutonomy, ControlPlaneAutonomyReport,
    KubernetesObject, KubernetesVerb, ObjectPropertyAssessment, OperationResult,
    TenantClusterConfig,
};

use anyhow::{Context, Result};
use kube::{
    api::{DynamicObject, ObjectMeta, TypeMeta},
    core::object,
};

/// Tests autonomy (allowed operations on objects)
pub async fn check_control_plane_autonomy(
    tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> Result<ControlPlaneAutonomyReport> {
    let object_kinds = KubernetesObject::all();
    let verbs = [
        KubernetesVerb::Create,
        KubernetesVerb::Get,
        KubernetesVerb::List,
        KubernetesVerb::Patch,
        KubernetesVerb::Delete,
        KubernetesVerb::Watch,
    ];

    let mut object_results = Vec::new();
    let mut autonomy_failures = Vec::new();

    for object_kind in object_kinds {
        // println!(
        //     "Testing object kind: {} ({})",
        //     object_kind.kind(),
        //     object_kind.api_version()
        // );

        let object_autonomy = assess_object_kind_accessibility(tenant1, &object_kind, &verbs)
            .await
            .context(format!("Failed to test object kind {}", object_kind.kind()))?;

        if !object_autonomy.is_valid() {
            autonomy_failures.push(format!(
                "{}/{}: Tenant cannot perform all required operations",
                object_kind.api_version(),
                object_kind.kind()
            ));
        }

        object_results.push(object_autonomy);
    }

    let autonomy_level = ControlPlaneAutonomy::from(object_results.as_slice());

    Ok(ControlPlaneAutonomyReport {
        autonomy_level,
        objects_assessment: object_results,
        failures: autonomy_failures,
    })
}

async fn assess_object_kind_accessibility(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verbs: &[KubernetesVerb],
) -> Result<ObjectPropertyAssessment> {
    let mut autonomy_results = Vec::new();

    // Test autonomy - can tenant1 perform all operations on this object kind?
    for verb in verbs {
        let result = test_tenant_autonomy(tenant, object_kind, *verb).await;
        autonomy_results.push(result);
    }

    let has_autonomy = autonomy_results.iter().all(|r| r.success);
    let result = if has_autonomy {
        AssessmentResult::Success
    } else {
        AssessmentResult::Unsuccessful(
            autonomy_results
                .iter()
                .filter_map(|r| r.error_reason.clone())
                .collect::<Vec<String>>()
                .join("; "),
        )
    };

    Ok(ObjectPropertyAssessment {
        kind: object_kind.clone(),
        issued_operations: autonomy_results,
        result,
    })
}

async fn test_tenant_autonomy(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verb: KubernetesVerb,
) -> OperationResult {
    let result = test_operation(tenant, object_kind, verb).await;

    // println!(
    //     "Tested autonomy for {} {}: {:?}",
    //     object_kind.kind(),
    //     verb,
    //     result
    // );

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

// Generic operation test function
// This function will call the specific operation test functions based on the verb
pub async fn test_operation(
    tenant: &TenantClusterConfig,
    object_kind: &KubernetesObject,
    verb: KubernetesVerb,
) -> Result<()> {
    let verb_string = verb.to_string().to_lowercase();

    let resource_name = object_kind.plural_kind();
    let namespace = if object_kind.is_namespaced() {
        Some(tenant.namespace.as_str())
    } else {
        None
    };
    let object_name = format!("{}-{}", object_kind.kind().to_lowercase(), "autonomy-test");

    let test_object = create_minimal_object(object_kind, &object_name, &tenant.namespace)?;
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

    // Create a minimal update patch
    let patch = kube::api::Patch::Merge(serde_json::json!({
        "metadata": {
            "labels": {
                "test-update": "cross-tenant-test"
            }
        }
    }));

    let is_authorized = tenant
        .cluster
        .is_authorized_to(&verb_string, &resource_name, namespace)
        .await?;
    if is_authorized {
        // attempt the operation
        match verb {
            KubernetesVerb::Create => {
                tenant
                    .cluster
                    .create_resource_dyn(object_kind, &dynamic_object, namespace)
                    .await?;
                //wait for the object to be created
                tenant
                    .cluster
                    .wait_for_dyn_resource_creation(object_kind, &object_name, namespace)
                    .await?;

                let exists = tenant
                    .cluster
                    .dyn_object_exists(object_kind, &object_name, namespace)
                    .await?;
                if !exists {
                    Err(anyhow::anyhow!(
                        "Operation {} on {} {} was not successful (object does not exist)",
                        verb_string,
                        object_kind.kind(),
                        namespace.unwrap_or("cluster")
                    ))
                } else {
                    // Creation was successful
                    Ok(())
                }
            }
            KubernetesVerb::Update | KubernetesVerb::Patch => {
                // first create the object if it does not exist
                let created_res = tenant
                    .cluster
                    .create_resource_dyn(object_kind, &dynamic_object, namespace)
                    .await;
                let created_res = match created_res {
                    Ok(_) => {
                        tenant
                            .cluster
                            .wait_for_dyn_resource_creation(object_kind, &object_name, namespace)
                            .await?;
                        tenant
                            .cluster
                            .get_resource_dyn(object_kind, &object_name, namespace)
                            .await?
                    }
                    Err(_) => {
                        // If creation fails, we can still try to patch an existing object
                        let existing_objects = tenant
                            .cluster
                            .list_resources_dyn(object_kind, namespace)
                            .await;
                        if existing_objects.is_err() {
                            return Err(anyhow::anyhow!(
                                "Failed to create or update {} {} in namespace {}",
                                object_kind.kind(),
                                object_name,
                                namespace.unwrap_or("cluster")
                            ));
                        }
                        let existing_objects = existing_objects.unwrap();
                        if existing_objects.items.is_empty() {
                            return Err(anyhow::anyhow!(
                                "No existing {} {} found to patch in namespace {}",
                                object_kind.kind(),
                                object_name,
                                namespace.unwrap_or("cluster")
                            ));
                        }
                        existing_objects.items[0].clone() // Take the first existing object to patch
                    }
                };

                let resource_name = created_res.metadata.name.clone().unwrap_or(object_name);
                // Now patch the object
                tenant
                    .cluster
                    .patch_resource_dyn(object_kind, &resource_name, &patch, namespace)
                    .await?;

                // If the patch was successful, we can check the updated object
                let updated_object = tenant
                    .cluster
                    .get_resource_dyn(object_kind, &resource_name, namespace)
                    .await;

                if let Ok(updated_object) = updated_object {
                    let labels = updated_object.metadata.labels.unwrap_or_default();
                    if labels.get("test-update") != Some(&"cross-tenant-test".to_string()) {
                        return Err(anyhow::anyhow!(
                            "Patch operation on {} {} was not successful (update not applied)",
                            object_kind.kind(),
                            namespace.unwrap_or("cluster")
                        ));
                    }
                    // Patch was successful
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "Patch operation on {} {} was not successful (object not found after patch)",
                        object_kind.kind(),
                        namespace.unwrap_or("cluster")
                    ))
                }
            }
            KubernetesVerb::Delete => {
                tenant
                    .cluster
                    .delete_resource_dyn(object_kind, &object_name, namespace)
                    .await?;

                // Wait for the object to be deleted
                tenant
                    .cluster
                    .wait_for_dyn_resource_deletion(object_kind, &object_name, namespace)
                    .await?;

                let exists = tenant
                    .cluster
                    .dyn_object_exists(object_kind, &object_name, namespace)
                    .await?;
                if exists {
                    Err(anyhow::anyhow!(
                        "Operation {} on {} {} was not successful (object still exists)",
                        verb_string,
                        object_kind.kind(),
                        namespace.unwrap_or("cluster")
                    ))
                } else {
                    // Deletion was successful
                    Ok(())
                }
            }
            _ => Ok(()), // Get, List, Watch do not modify state
        }
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to {} {}",
            verb_string,
            object_kind.kind()
        ))
    }
}
