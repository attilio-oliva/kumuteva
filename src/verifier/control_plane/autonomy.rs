use crate::verifier::{
    AssessmentResult, ControlPlaneAutonomy, ControlPlaneAutonomyReport, KubernetesObject,
    KubernetesVerb, ObjectPropertyAssessment, OperationResult, TenantClusterConfig,
};

use anyhow::{Context, Result};

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
        KubernetesVerb::Update,
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
                .collect(),
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

    let is_authorized = tenant
        .cluster
        .is_authorized_to(&verb_string, &resource_name, namespace)
        .await?;
    if is_authorized {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Not authorized to {} {}",
            verb_string,
            object_kind.kind()
        ))
    }
}
