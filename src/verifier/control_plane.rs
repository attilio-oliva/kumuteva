use std::collections::BTreeMap;

use crate::cluster::{DummyCRD, DummyCRDSpec, KubernetesCluster, NGINX_POD};
use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{Pod, PodSpec};
use kube::runtime::reflector::Lookup;

use super::{TenantClusterConfig, TransparentIsolationLevel};

const POD_DEFAULT_NAME: &str = "nginx";

/// Verifies that object isolation works between two tenant clusters
pub async fn check_object_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<bool> {
    let pod_name = get_pod_name();

    // Deploy and verify pod for tenant1
    deploy_tenant_pod(&tenant1.cluster, &pod_name, &tenant1.namespace).await?;

    // Verify tenant2 cannot access tenant1's pod
    let is_isolated = assert_pod_isolation(&tenant2.cluster, &pod_name, &tenant1.namespace).await;

    // Cleanup
    cleanup_tenant_pod(&tenant1.cluster, &pod_name, &tenant1.namespace).await?;

    Ok(is_isolated)
}

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

async fn check_namespace_level_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> Result<()> {
    unimplemented!("Namespace isolation test is not implemented")
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

    let pod_name = get_pod_name();
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

fn get_pod_name() -> String {
    NGINX_POD
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| POD_DEFAULT_NAME.to_string())
}

async fn deploy_tenant_pod(
    cluster: &KubernetesCluster,
    pod_name: &str,
    namespace: &str,
) -> Result<()> {
    cluster
        .create_pod_in_namespace(&NGINX_POD, namespace)
        .await
        .context("Failed to create tenant pod")?;

    cluster
        .get_pod_in_namespace(pod_name, namespace)
        .await
        .context("Failed to verify tenant pod creation")?;

    Ok(())
}

async fn assert_pod_isolation(
    other_cluster: &KubernetesCluster,
    pod_name: &str,
    namespace: &str,
) -> bool {
    other_cluster
        .get_pod_in_namespace(pod_name, namespace)
        .await
        .is_err() // Expect an error if the pod is not found, meaning isolation is working
}

async fn cleanup_tenant_pod(
    cluster: &KubernetesCluster,
    pod_name: &str,
    namespace: &str,
) -> Result<()> {
    cluster
        .delete_pod_in_namespace(pod_name, namespace)
        .await
        .context("Failed to cleanup tenant pod")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{ControlPlaneIsolation, KindCluster, KubernetesClusterBuilder};
    use std::path::PathBuf;

    const TENANT1_NS: &str = "t1";
    const CLUSTER_NAME_PREFIX: &str = "cp";

    struct TestClusterConfig {
        name: String,
        kubeconfig_path: PathBuf,
    }

    impl TestClusterConfig {
        fn new(name: &str) -> Self {
            let name = name.to_string();
            let kubeconfig_path = temp_kubeconfig_path(&name);
            Self {
                name,
                kubeconfig_path,
            }
        }
    }

    fn temp_kubeconfig_path(cluster_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}.kubeconfig", cluster_name))
    }

    async fn setup_test_cluster(config: &TestClusterConfig) -> Result<KubernetesCluster> {
        let cluster = KubernetesCluster::load(&config.kubeconfig_path).await?;
        cluster.ensure_cluster_is_ready().await?;
        Ok(cluster)
    }

    #[tokio::test]
    async fn test_native_object_isolation() {
        let config =
            TestClusterConfig::new(&format!("{}-obj-isolation-native", CLUSTER_NAME_PREFIX));

        let kind_cluster = KindCluster::create(
            &config.name,
            config.kubeconfig_path.clone(),
            Default::default(),
        )
        .unwrap();

        let tenant1_cluster = setup_test_cluster(&config).await.unwrap();
        let tenant2_cluster = setup_test_cluster(&config).await.unwrap();

        let tenant1_config = TenantClusterConfig {
            cluster: tenant1_cluster,
            namespace: TENANT1_NS.to_string(),
        };

        let tenant2_config = TenantClusterConfig {
            cluster: tenant2_cluster,
            namespace: "t2".to_string(),
        };

        let result = check_object_isolation(&tenant1_config, &tenant2_config).await;
        assert!(result.is_err(), "Native cluster should fail isolation test");

        kind_cluster.delete().unwrap();
    }

    #[tokio::test]
    async fn test_vcluster_object_isolation() {
        let base_config =
            TestClusterConfig::new(&format!("{}-obj-isolation-vcluster", CLUSTER_NAME_PREFIX));
        let kind_cluster = KindCluster::create(
            &base_config.name,
            base_config.kubeconfig_path.clone(),
            Default::default(),
        )
        .unwrap();

        let tenant1_config = TestClusterConfig::new(&format!("tenant1-{}", base_config.name));
        let tenant2_config = TestClusterConfig::new(&format!("tenant2-{}", base_config.name));

        let tenant1_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
            .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant1_config.name.clone()))
            .with_kubeconfig_path(tenant1_config.kubeconfig_path)
            .build()
            .await
            .unwrap();

        tenant1_cluster.ensure_cluster_is_ready().await.unwrap();

        let tenant2_cluster = KubernetesClusterBuilder::new(kind_cluster.clone())
            .with_isolation_technology(ControlPlaneIsolation::VCluster(tenant2_config.name.clone()))
            .with_kubeconfig_path(tenant2_config.kubeconfig_path)
            .build()
            .await
            .unwrap();

        tenant2_cluster.ensure_cluster_is_ready().await.unwrap();

        let tenant1_config = TenantClusterConfig {
            cluster: tenant1_cluster,
            namespace: TENANT1_NS.to_string(),
        };

        let tenant2_config = TenantClusterConfig {
            cluster: tenant2_cluster,
            namespace: "t2".to_string(),
        };

        let result = check_object_isolation(&tenant1_config, &tenant2_config).await;
        assert!(result.is_ok(), "VCluster should pass isolation test");

        kind_cluster.delete().unwrap();
    }
}
