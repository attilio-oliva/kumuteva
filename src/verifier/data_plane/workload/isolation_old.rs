use std::fmt::Display;

use k8s_openapi::api::core::v1::Pod;

use crate::verifier::TenantClusterConfig;

pub struct WorkloadIsolationReport {
    pub success: bool,
    pub message: String,
}

pub async fn check_workload_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<WorkloadIsolationReport> {
    println!("Testing workload isolation - process visibility between tenants...");

    // Step 1: Create tenant2 pod with a recognizable process
    let tenant2_pod_name = "workload-test-target";
    let tenant2_pod = create_regular_pod(tenant2_pod_name);

    tenant2
        .cluster
        .create_pod_in_namespace(&tenant2_pod, &tenant2.namespace)
        .await?;

    // Wait for tenant2 pod to be ready and get its node
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(tenant2_pod_name, &tenant2.namespace)
        .await?;

    // Get the node where tenant2 pod was scheduled
    let tenant2_pod_info = tenant2
        .cluster
        .get_pod_in_namespace(tenant2_pod_name, &tenant2.namespace)
        .await?;

    let node_name = tenant2_pod_info
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Could not determine node for tenant2 pod"))?;

    println!("Tenant2 pod scheduled on node: {}", node_name);

    // Step 2: Create tenant1 malicious pod with hostPID on the same node
    let tenant1_pod_name = "workload-test-malicious";
    let tenant1_pod = create_malicious_pod(tenant1_pod_name, node_name, tenant2_pod_name);

    tenant1
        .cluster
        .create_pod_in_namespace(&tenant1_pod, &tenant1.namespace)
        .await?;

    // Wait for tenant1 pod to be ready or complete
    tenant1
        .cluster
        .watch_pod_until_condition(
            tenant1_pod_name,
            &tenant1.namespace,
            |watch_event| async move {
                match watch_event {
                    kube::core::WatchEvent::Modified(pod) => {
                        if let Some(status) = &pod.status {
                            if let Some(phase) = &status.phase {
                                return phase == "Succeeded" || phase == "Failed";
                            }
                        }
                        false
                    }
                    _ => false,
                }
            },
        )
        .await?;

    let logs = tenant1
        .cluster
        .get_pod_logs(tenant1_pod_name, &tenant1.namespace)
        .await?;

    // Step 4: Cleanup pods
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(tenant1_pod_name, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(tenant2_pod_name, &tenant2.namespace)
        .await;

    // Step 5: Analyze results
    let can_see_processes = logs.contains("TENANT2_PROCESS_FOUND");

    if can_see_processes {
        Ok(WorkloadIsolationReport {
            success: false,
            message: "Workload isolation failed: tenant1 can view tenant2's processes via hostPID"
                .to_string(),
        })
    } else {
        Ok(WorkloadIsolationReport {
            success: true,
            message: "Workload isolation successful: tenant1 cannot view tenant2's processes"
                .to_string(),
        })
    }
}

/// Create a target pod for tenant2 that runs a recognizable process
fn create_regular_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "regular-process",
                "workload-test": "target"
            }
        },
        "spec": {
            "containers": [{
                "name": "regular-process",
                "image": "alpine:latest",
                "command": [
                    "sh", "-c",
                    "echo 'Starting regular process with unique marker...'; \
                     while true; do \
                       echo 'TENANT2_UNIQUE_MARKER: Running...'; \
                       sleep 30; \
                     done"
                ],
                "ports": [{
                    "containerPort": 80
                }]
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

/// Create a malicious pod for tenant1 that tries to interfere with tenant2's workload
fn create_malicious_pod(pod_name: &str, node_name: &str, target_pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "nodeName": node_name,
            "hostPID": true, // This allows the pod to see host processes
            "containers": [{
                "name": "malicious-process",
                "image": "alpine:latest",
                "securityContext": {
                    "privileged": true
                },
                "command": [
                    "sh", "-c",
                    format!(
                        "echo 'Searching for tenant2 processes...' && \
                         for i in $(seq 1 30); do \
                           if ps aux | grep -i 'TENANT2_UNIQUE_MARKER\\|{}' | grep -v grep | grep -v malicious-process; then \
                             echo 'TENANT2_PROCESS_FOUND: Isolation breach detected!'; \
                             ps aux | grep -i 'TENANT2_UNIQUE_MARKER\\|{}' | grep -v grep | grep -v malicious-process; \
                             break; \
                           fi; \
                           echo \"Attempt $i: No tenant2 processes visible\"; \
                           sleep 2; \
                         done; \
                         echo 'Process visibility check completed'",
                        target_pod_name, target_pod_name
                    )
                ],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

/*
/// Create a spy pod for tenant1 with hostPID: true
fn create_spy_pod(pod_name: &str, node_name: &str) -> Pod {
    Pod {
        metadata: ObjectMeta {
            name: Some(pod_name.to_string()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            node_name: Some(node_name.to_string()),
            host_pid: Some(true), // This allows the pod to see host processes
            containers: vec![Container {
                name: "spy-process".to_string(),
                image: Some("alpine:latest".to_string()),
                command: Some(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    // Keep the pod running so we can exec into it
                    "while true; do sleep 30; done".to_string(),
                ]),
                ..Default::default()
            }],
            restart_policy: Some("Never".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

*/

impl Display for WorkloadIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Workload Isolation Report:\n  Success: {}\n  Message: {}",
            self.success, self.message
        )
    }
}
