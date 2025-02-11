use std::collections::BTreeMap;

use crate::{
    cluster::{DummyCRD, DummyCRDSpec, NGINX_POD},
    verifier::TransparentIsolationLevel,
};
use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{Namespace, Node, Pod, PodSpec};
use kube::runtime::reflector::Lookup;

use super::get_example_pod_name;
use crate::TenantClusterConfig;

pub async fn check_transparent_isolation_level(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    level: TransparentIsolationLevel,
) -> Result<()> {
    match level {
        TransparentIsolationLevel::Namespace => {
            check_namespace_level_isolation(tenant1, tenant2).await
        }
        TransparentIsolationLevel::Node => check_node_level_isolation(tenant1, tenant2).await,
        TransparentIsolationLevel::Cluster => check_cluster_level_isolation(tenant1, tenant2).await,
    }
}

/// Verifies that the solution is transparently isolated at namespace level
/// Also, verify that the tenant can list their namespaces and ensure that they can't list other tenants' namespaces.
async fn check_namespace_level_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<()> {
    // List tenant1 namespaces and fetch tenant1's namespace UID.
    let tenant1_namespaces = tenant1
        .cluster
        .list_cluster_resources::<Namespace>()
        .await?;

    // List tenant2 namespaces.
    let tenant2_namespaces = tenant2
        .cluster
        .list_cluster_resources::<Namespace>()
        .await?;

    // Check if any tenant2 namespace (excluding system namespaces) has the same UID as tenant1's namespace.
    let t2_can_see_t1_ns = tenant2_namespaces
        .iter()
        .filter(|ns| {
            !["kube-system", "kube-public", "kube-node-lease", "default"]
                .contains(&ns.name().unwrap_or_default().as_ref())
        })
        .any(|t2_ns| {
            tenant1_namespaces.iter().any(|t1_ns| {
                if t1_ns.metadata.uid == t2_ns.metadata.uid {
                    println!(
                        "Tenant2 can see namespace \"{}\" that has the same UID as tenant1 namespace \"{}\"",
                        t2_ns.name().unwrap_or_default(),
                        t1_ns.name().unwrap_or_default()
                    );
                    return true;
                }
                false
            })
        });

    if t2_can_see_t1_ns {
        anyhow::bail!("Namespaces are not isolated, tenant2 can see tenant1's namespace");
    }

    // attempt to create a new namespace in tenant1
    let new_namespace_name = tenant1.namespace.clone() + "-new";

    tenant1
        .cluster
        .create_namespace(&new_namespace_name)
        .await
        .context("Failed to create a new namespace in tenant1")?;

    // attempt to get the new namespace in tenant2
    let tenant2_namespaces = tenant2
        .cluster
        .list_cluster_resources::<Namespace>()
        .await?;

    let is_namespace_available_in_tenant2 = tenant2_namespaces
        .iter()
        .any(|ns| ns.name().unwrap_or_default() == new_namespace_name);

    if is_namespace_available_in_tenant2 {
        anyhow::bail!("Namespaces are not isolated, tenant2 can see tenant1's new namespace");
    }

    // attempt to delete the new namespace in tenant1
    tenant1
        .cluster
        .delete_cluster_resource::<Namespace>(&new_namespace_name)
        .await
        .context("Failed to delete the new namespace in tenant1")?;

    // attempt to create a new namespace in tenant1 with the same name of an existing tenant2 namespace
    tenant1
        .cluster
        .create_namespace(&tenant2.namespace)
        .await
        .context("Failed to create a new namespace in tenant1 with the same name of an existing tenant2 namespace")?;

    // cleanup the new namespace in tenant1
    tenant1
        .cluster
        .delete_cluster_resource::<Namespace>(&tenant2.namespace)
        .await
        .context("Failed to delete the new namespace in tenant1 with the same name of an existing tenant2 namespace")?;

    Ok(())
}

/// Verifies that the solution is transparently isolated at node level
/// Verify if the tenant can edit the node resources and other tenants will not be able to see the changes.
/// The example imagine a new node label is added to the node by Tenant1 and then create a pod to be scheduled on that node using this label.
/// Tenant2 should not be able to see the new label on the node nor be affected by the new label.
async fn check_node_level_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<()> {
    let nodes = tenant1.cluster.list_nodes().await?;
    let picked_node = nodes.items.first().context("No nodes found")?;
    let node_name = picked_node.name().context("Node name not found")?;

    let new_label = "tenant1-custom";
    let new_label_value = "true";
    tenant1
        .cluster
        .set_label_to_node(&node_name, new_label, new_label_value)
        .await
        .context("Failed to set label to node")?;

    // wait for the node to be updated
    tenant1
        .cluster
        .watch_cluster_resource_until_condition::<Node, _, _>(&node_name, 10, |_event| async {
            let node = tenant1.cluster.get_node(&node_name).await;
            if node.is_err() {
                return false;
            }
            let node = node.unwrap();
            if node.clone().metadata.labels.is_none() {
                return false;
            }

            let labels = node.metadata.labels.unwrap();
            let label_value = labels.get(new_label);
            label_value.is_some() && label_value.unwrap() == new_label_value
        })
        .await
        .context("Failed to watch node")?;

    let updated_node = tenant1.cluster.get_node(&node_name).await;

    match updated_node {
        Ok(node) => {
            let labels = node.metadata.labels.unwrap_or_default();
            let label_value = labels.get(new_label).context("Applied label not found")?;
            if label_value != new_label_value {
                anyhow::bail!(
                    "Failed to set label to node. Expected: {}, Actual: {}",
                    new_label_value,
                    label_value
                );
            }
        }
        Err(e) => {
            anyhow::bail!("Failed to get updated node: {}", e);
        }
    }

    let pod_name = get_example_pod_name();
    let pod = NGINX_POD.clone();

    let pod_with_node_selector = Pod {
        spec: Some(PodSpec {
            node_selector: Some(BTreeMap::from_iter(vec![(
                new_label.to_string(),
                new_label_value.to_string(),
            )])),
            ..pod.spec.unwrap()
        }),
        ..pod
    };

    tenant1
        .cluster
        .create_pod_in_namespace(&pod_with_node_selector, &tenant1.namespace)
        .await?;

    // watch the pod and if it is scheduled on the node
    tenant1.cluster
        .watch_pod_until_condition(&pod_name, &tenant1.namespace, |_| async {
            let pod_update = tenant1.cluster
                .get_pod_in_namespace(&pod_name, &tenant1.namespace)
                .await;
            if pod_update.is_err() {
                return false;
            }

            let pod = pod_update.unwrap();
            // check if pod is running
            if let Some(status) = &pod.status {
                if let Some(phase) = &status.phase {
                    if phase == "Running" {
                        return true;
                    }
                }
            }

            // or if pod is unschedulable
            if let Some(status) = &pod.status {
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.reason == Some("Unschedulable".to_string()) {
                            println!("Pod is unschedulable, maybe because the label is not actually set on the node");
                            return true;
                        }
                    }
                }
            }

            false
        })
        .await
        .context("Failed to watch pod")?;

    let pod = tenant1
        .cluster
        .get_pod_in_namespace(&pod_name, &tenant1.namespace)
        .await?;

    // if the pod is not running, then it is unschedulable
    if let Some(status) = &pod.status {
        if let Some(phase) = &status.phase {
            if phase != "Running" {
                anyhow::bail!("Pod is not running. Phase: {:?}", phase);
            }
        }
    }

    // Cleanup the pod
    tenant1
        .cluster
        .delete_pod_in_namespace(&pod_name, &tenant1.namespace)
        .await
        .context("Failed to cleanup tenant pod")?;

    // Verify tenant2 cannot access tenant1's node label
    let is_isolated = tenant2
        .cluster
        .get_node(&node_name)
        .await
        .map(|node| {
            let labels = node.metadata.labels.unwrap_or_default();
            let label_value = labels.get(new_label);
            label_value.is_none() || label_value.unwrap() != new_label_value
        })
        .unwrap_or(true);

    if !is_isolated {
        anyhow::bail!("Nodes labels are not isolated, tenant2 can see tenant1's node label");
    }

    Ok(())
}

/// Verifies that the solution is transparently isolated at cluster level.
/// Creates a CRD in each tenant cluster and verifying that it's possible
async fn check_cluster_level_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<()> {
    tenant1
        .cluster
        .publish_crd::<DummyCRD>()
        .await
        .context("Failed to publish a CRD in tenant1")?;

    tenant2
        .cluster
        .publish_crd::<DummyCRD>()
        .await
        .context("Failed to publish a CRD in tenant2")?;

    tenant1
        .cluster
        .wait_for_crd_publishing::<DummyCRD>()
        .await?;
    tenant2
        .cluster
        .wait_for_crd_publishing::<DummyCRD>()
        .await?;

    let spec = DummyCRDSpec {
        info: "test".to_string(),
    };

    let metadata: kube::api::ObjectMeta = kube::api::ObjectMeta {
        name: Some("mycrd".to_string()),
        ..Default::default()
    };

    let crd_resource = DummyCRD { metadata, spec };

    tenant1
        .cluster
        .create_dummy_crd_resource(&tenant1.namespace, crd_resource.clone())
        .await
        .context("Failed to create a CRD resource in tenant1")?;

    tenant2
        .cluster
        .create_dummy_crd_resource(&tenant2.namespace, crd_resource)
        .await
        .context("Failed to create a CRD resource in tenant2")?;

    tenant1.cluster.unpublish_crd::<DummyCRD>().await?;
    tenant2.cluster.unpublish_crd::<DummyCRD>().await?;

    anyhow::Ok(())
}
