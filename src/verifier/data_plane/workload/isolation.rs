use std::collections::HashMap;
use std::fmt::Display;

use k8s_openapi::api::core::v1::Pod;

use crate::verifier::TenantClusterConfig;

#[derive(Debug, Clone)]
pub struct WorkloadIsolationReport {
    pub resources_assessment: Vec<WorkloadResourceAssessment>,
    pub overall_autonomy: bool,
    pub overall_isolation: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WorkloadResourceAssessment {
    pub resource: WorkloadResource,
    pub operations_assessment: HashMap<WorkloadOperation, OperationAssessment>,
    pub is_autonomous: bool,
    pub is_isolated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WorkloadResource {
    ProcessNamespace, // Process visibility/isolation
    NetworkNamespace, // Network namespace isolation
    UserNamespace,    // User namespace isolation
    IPCNamespace,     // Inter-process communication
    UTSNamespace,     // Hostname/domain isolation
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WorkloadOperation {
    ViewProcesses,     // Can view processes
    CreateNetworkConn, // Can create network connections
    ModifyHostname,    // Can modify hostname
    AccessIPC,         // Can access IPC resources
}

#[derive(Debug, Clone)]
pub struct OperationAssessment {
    pub authorized: bool,
    pub safe: SafetyLevel,
    pub test_details: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SafetyLevel {
    Safe,    // Operation doesn't affect other tenants
    Unsafe,  // Operation affects other tenants
    Unknown, // Cannot determine if operation affects other tenants
}

impl WorkloadResource {
    fn all() -> Vec<Self> {
        vec![
            WorkloadResource::ProcessNamespace,
            WorkloadResource::NetworkNamespace,
            WorkloadResource::UserNamespace,
            WorkloadResource::IPCNamespace,
            WorkloadResource::UTSNamespace,
        ]
    }

    fn applicable_operations(&self) -> Vec<WorkloadOperation> {
        match self {
            WorkloadResource::ProcessNamespace => vec![WorkloadOperation::ViewProcesses],
            WorkloadResource::NetworkNamespace => vec![WorkloadOperation::CreateNetworkConn],
            WorkloadResource::UserNamespace => vec![
                // User namespace operations are typically handled at creation time
            ],
            WorkloadResource::IPCNamespace => vec![WorkloadOperation::AccessIPC],
            WorkloadResource::UTSNamespace => vec![WorkloadOperation::ModifyHostname],
        }
    }
}

pub async fn check_workload_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<WorkloadIsolationReport> {
    println!("Assessing workload isolation systematically...");

    let resources = WorkloadResource::all();
    let mut resources_assessment = Vec::new();
    let mut warnings = Vec::new();

    for resource in resources {
        let operations = resource.applicable_operations();
        if operations.is_empty() {
            continue; // Skip resources with no applicable operations
        }

        let mut operations_assessment = HashMap::new();

        for operation in operations {
            let assessment = assess_operation(tenant1, tenant2, &resource, &operation).await?;
            operations_assessment.insert(operation, assessment);
        }

        // Determine autonomy: all operations are authorized
        let is_autonomous = operations_assessment
            .values()
            .all(|assessment| assessment.authorized);

        // Determine isolation: no operation is unsafe
        let is_isolated = !operations_assessment
            .values()
            .any(|assessment| assessment.safe == SafetyLevel::Unsafe);

        // Generate warning if autonomous but not isolated
        if is_autonomous && !is_isolated {
            warnings.push(format!(
                "Warning: {} is autonomous but not isolated - potential security risk",
                resource
            ));
        }

        resources_assessment.push(WorkloadResourceAssessment {
            resource,
            operations_assessment,
            is_autonomous,
            is_isolated,
        });
    }

    // Overall assessment
    let overall_autonomy = resources_assessment.iter().all(|r| r.is_autonomous);

    let overall_isolation = resources_assessment.iter().all(|r| r.is_isolated);

    Ok(WorkloadIsolationReport {
        resources_assessment,
        overall_autonomy,
        overall_isolation,
        warnings,
    })
}

async fn assess_operation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    resource: &WorkloadResource,
    operation: &WorkloadOperation,
) -> anyhow::Result<OperationAssessment> {
    // First, check if the operation is authorized
    let authorized = is_authorized_to(tenant1, resource, operation).await?;

    if !authorized {
        return Ok(OperationAssessment {
            authorized: false,
            safe: SafetyLevel::Safe, // If not authorized, it's safe by definition
            test_details: Some("Operation not authorized - access denied".to_string()),
        });
    }

    // If authorized, test if it affects other tenants
    let (safe, test_details) =
        does_affect_other_tenant(tenant1, tenant2, resource, operation).await?;

    Ok(OperationAssessment {
        authorized: true,
        safe,
        test_details: Some(test_details),
    })
}

async fn is_authorized_to(
    tenant: &TenantClusterConfig,
    resource: &WorkloadResource,
    operation: &WorkloadOperation,
) -> anyhow::Result<bool> {
    match (resource, operation) {
        (WorkloadResource::ProcessNamespace, WorkloadOperation::ViewProcesses) => {
            // Test if tenant can create a pod with hostPID: true
            test_host_pid_authorization(tenant).await
        }
        (WorkloadResource::NetworkNamespace, WorkloadOperation::CreateNetworkConn) => {
            // Test if tenant can use hostNetwork
            test_host_network_authorization(tenant).await
        }
        (WorkloadResource::UTSNamespace, WorkloadOperation::ModifyHostname) => {
            // Test if tenant can create pods with hostNetwork (which includes UTS)
            test_host_network_authorization(tenant).await
        }
        (WorkloadResource::IPCNamespace, WorkloadOperation::AccessIPC) => {
            // Test if tenant can use hostIPC
            test_host_ipc_authorization(tenant).await
        }
        _ => Ok(false), // Default to not authorized for unhandled combinations
    }
}

async fn does_affect_other_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
    resource: &WorkloadResource,
    operation: &WorkloadOperation,
) -> anyhow::Result<(SafetyLevel, String)> {
    match (resource, operation) {
        (WorkloadResource::ProcessNamespace, WorkloadOperation::ViewProcesses) => {
            test_process_visibility_cross_tenant(tenant1, tenant2).await
        }
        (WorkloadResource::NetworkNamespace, WorkloadOperation::CreateNetworkConn) => {
            test_network_cross_tenant(tenant1, tenant2).await
        }
        (WorkloadResource::UTSNamespace, WorkloadOperation::ModifyHostname) => {
            test_hostname_cross_tenant(tenant1, tenant2).await
        }
        (WorkloadResource::IPCNamespace, WorkloadOperation::AccessIPC) => {
            test_ipc_cross_tenant(tenant1, tenant2).await
        }
        _ => Ok((SafetyLevel::Unknown, "Test not implemented".to_string())),
    }
}

// Authorization test functions
async fn test_host_pid_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod_name = "hostpid-auth-test";
    let test_pod = create_host_pid_test_pod(test_pod_name);

    let result = tenant
        .cluster
        .create_pod_in_namespace(&test_pod, &tenant.namespace)
        .await;

    // Cleanup regardless of success/failure
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(test_pod_name, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_privileged_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod_name = "privileged-auth-test";
    let test_pod = create_privileged_test_pod(test_pod_name);

    let result = tenant
        .cluster
        .create_pod_in_namespace(&test_pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(test_pod_name, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_host_network_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod_name = "hostnet-auth-test";
    let test_pod = create_host_network_test_pod(test_pod_name);

    let result = tenant
        .cluster
        .create_pod_in_namespace(&test_pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(test_pod_name, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

async fn test_host_ipc_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod_name = "hostipc-auth-test";
    let test_pod = create_host_ipc_test_pod(test_pod_name);

    let result = tenant
        .cluster
        .create_pod_in_namespace(&test_pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(test_pod_name, &tenant.namespace)
        .await;

    Ok(result.is_ok())
}

// Cross-tenant effect test functions
async fn test_process_visibility_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Create target pod in tenant2
    let target_pod_name = "process-target";
    let target_pod = create_target_process_pod(target_pod_name);

    tenant2
        .cluster
        .create_pod_in_namespace(&target_pod, &tenant2.namespace)
        .await?;

    // Wait for target pod to be ready
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(target_pod_name, &tenant2.namespace)
        .await?;

    // Get the node where target pod is running
    let target_pod_info = tenant2
        .cluster
        .get_pod_in_namespace(target_pod_name, &tenant2.namespace)
        .await?;

    let node_name = target_pod_info
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Could not determine target pod node"))?;

    // Create spy pod in tenant1 on the same node
    let spy_pod_name = "process-spy";
    let spy_pod = create_process_spy_pod(spy_pod_name, node_name, target_pod_name);

    let spy_result = tenant1
        .cluster
        .create_pod_in_namespace(&spy_pod, &tenant1.namespace)
        .await;

    let (safety_level, details) = if spy_result.is_err() {
        (
            SafetyLevel::Safe,
            "Cannot create hostPID pod - processes isolated".to_string(),
        )
    } else {
        // Wait for spy pod to complete
        tenant1
            .cluster
            .watch_pod_until_condition(spy_pod_name, &tenant1.namespace, |watch_event| async move {
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
            })
            .await
            .unwrap_or(());

        // Get logs to check if cross-tenant processes were visible
        let logs = tenant1
            .cluster
            .get_pod_logs(spy_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        if logs.contains("TENANT2_PROCESS_FOUND") {
            (
                SafetyLevel::Unsafe,
                "Cross-tenant process visibility detected".to_string(),
            )
        } else {
            (
                SafetyLevel::Safe,
                "No cross-tenant process visibility".to_string(),
            )
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(spy_pod_name, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(target_pod_name, &tenant2.namespace)
        .await;

    Ok((safety_level, details))
}

async fn test_network_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Create a target pod in tenant2 that listens on a specific port
    let target_pod_name = "network-target";
    let target_pod = create_network_target_pod(target_pod_name);

    tenant2
        .cluster
        .create_pod_in_namespace(&target_pod, &tenant2.namespace)
        .await?;

    // Wait for target pod to be ready
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(target_pod_name, &tenant2.namespace)
        .await?;

    // Get the target pod's IP address
    let target_pod_ip = tenant2
        .cluster
        .get_pod_ip(target_pod_name, &tenant2.namespace)
        .await?;

    // Create a network test pod in tenant1 with hostNetwork to test cross-tenant network access
    let spy_pod_name = "network-spy";
    let spy_pod = create_network_spy_pod(spy_pod_name, &target_pod_ip);

    let spy_result = tenant1
        .cluster
        .create_pod_in_namespace(&spy_pod, &tenant1.namespace)
        .await;

    let (safety_level, details) = if spy_result.is_err() {
        (
            SafetyLevel::Safe,
            "Cannot create hostNetwork pod - network isolated".to_string(),
        )
    } else {
        // Wait for spy pod to complete
        tenant1
            .cluster
            .watch_pod_until_condition(spy_pod_name, &tenant1.namespace, |watch_event| async move {
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
            })
            .await
            .unwrap_or(());

        // Get logs to check if cross-tenant network access was successful
        let logs = tenant1
            .cluster
            .get_pod_logs(spy_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        if logs.contains("NETWORK_ACCESS_SUCCESS") {
            (
                SafetyLevel::Unsafe,
                "Cross-tenant network access detected - hostNetwork bypass".to_string(),
            )
        } else {
            (
                SafetyLevel::Safe,
                "No cross-tenant network access detected".to_string(),
            )
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(spy_pod_name, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(target_pod_name, &tenant2.namespace)
        .await;

    Ok((safety_level, details))
}

async fn test_hostname_cross_tenant(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    Ok((
        SafetyLevel::Unknown,
        "Hostname cross-tenant test not implemented".to_string(),
    ))
}

async fn test_ipc_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // Create IPC target pod in tenant2 that creates shared memory
    let target_pod_name = "ipc-target";
    let target_pod = create_ipc_target_pod(target_pod_name);

    tenant2
        .cluster
        .create_pod_in_namespace(&target_pod, &tenant2.namespace)
        .await?;

    // Wait for target pod to be ready
    tenant2
        .cluster
        .wait_for_pod_to_be_ready(target_pod_name, &tenant2.namespace)
        .await?;

    // Get the node where target pod is running
    let target_pod_info = tenant2
        .cluster
        .get_pod_in_namespace(target_pod_name, &tenant2.namespace)
        .await?;

    let node_name = target_pod_info
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Could not determine target pod node"))?;

    // Create spy pod in tenant1 on the same node with hostIPC
    let spy_pod_name = "ipc-spy";
    let spy_pod = create_ipc_spy_pod(spy_pod_name, node_name);

    let spy_result = tenant1
        .cluster
        .create_pod_in_namespace(&spy_pod, &tenant1.namespace)
        .await;

    let (safety_level, details) = if spy_result.is_err() {
        (
            SafetyLevel::Safe,
            "Cannot create hostIPC pod - IPC isolated".to_string(),
        )
    } else {
        // Wait for spy pod to complete
        tenant1
            .cluster
            .watch_pod_until_condition(spy_pod_name, &tenant1.namespace, |watch_event| async move {
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
            })
            .await
            .unwrap_or(());

        // Get logs to check if cross-tenant IPC resources were accessible
        let spy_logs = tenant1
            .cluster
            .get_pod_logs(spy_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        let target_logs = tenant2
            .cluster
            .get_pod_logs(target_pod_name, &tenant2.namespace)
            .await
            .unwrap_or_default();

        // Extract fingerprints from logs
        let target_fingerprint = target_logs
            .lines()
            .find(|line| line.contains("Fingerprint:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("");

        if spy_logs.contains(target_fingerprint) && !target_fingerprint.is_empty() {
            (
                SafetyLevel::Unsafe,
                format!(
                    "Cross-tenant IPC access detected - fingerprint {} found",
                    target_fingerprint
                ),
            )
        } else {
            (
                SafetyLevel::Safe,
                "No cross-tenant IPC access detected".to_string(),
            )
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(spy_pod_name, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(target_pod_name, &tenant2.namespace)
        .await;

    Ok((safety_level, details))
}

// Pod creation helper functions
fn create_host_pid_test_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "hostPID": true,
            "containers": [{
                "name": "test",
                "image": "alpine:latest",
                "command": ["sleep", "1"],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_privileged_test_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "containers": [{
                "name": "test",
                "image": "alpine:latest",
                "command": ["sleep", "1"],
                "securityContext": {
                    "privileged": true
                }
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_host_path_test_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "volumes": [{
                "name": "host-vol",
                "hostPath": {
                    "path": "/tmp"
                }
            }],
            "containers": [{
                "name": "test",
                "image": "alpine:latest",
                "command": ["sleep", "1"],
                "volumeMounts": [{
                    "name": "host-vol",
                    "mountPath": "/host-tmp"
                }]
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_host_network_test_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "hostNetwork": true,
            "containers": [{
                "name": "test",
                "image": "alpine:latest",
                "command": ["sleep", "1"],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_host_ipc_test_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "hostIPC": true,
            "containers": [{
                "name": "test",
                "image": "alpine:latest",
                "command": ["sleep", "1"],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_ipc_target_pod(pod_name: &str) -> Pod {
    let script = [
        "echo 'Creating IPC resources...'",
        "ipcmk -M 64",
        "ipcmk -S 1",
        "ipcmk -Q",
        // concat all the ipcs commands and then pass to sha1sum to get a fingerprint
        "fingerprint=`(ipcs -m; ipcs -s; ipcs -q) | sha1sum | cut -d' ' -f1`",
        "echo 'Fingerprint: ' $fingerprint",
        "while true; do sleep 30; done",
    ]
    .join(" && ");

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "ipc-target",
                "workload-test": "target"
            }
        },
        "spec": {
            "hostIPC": true,
            "containers": [{
                "name": "ipc-target",
                "image": "ubuntu:latest",
                "command": [
                    "sh", "-c",
                    script
                ]
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_ipc_spy_pod(pod_name: &str, node_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "nodeName": node_name,
            "hostIPC": true,
            "containers": [{
                "name": "ipc-spy",
                "image": "ubuntu:latest",
                "command": [
                    "sh", "-c",
                    "sleep 10 && \
                     fingerprint=`(ipcs -m; ipcs -s; ipcs -q) | sha1sum | cut -d' ' -f1` && \
                     echo 'Fingerprint: ' $fingerprint",
                ],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_target_process_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "target-process",
                "workload-test": "target"
            }
        },
        "spec": {
            "containers": [{
                "name": "target-process",
                "image": "alpine:latest",
                "command": [
                    "sh", "-c",
                    "echo 'Starting target process with unique marker...'; \
                     while true; do \
                       echo 'TENANT2_UNIQUE_MARKER: Running...'; \
                       sleep 30; \
                     done"
                ],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_process_spy_pod(pod_name: &str, node_name: &str, target_pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "nodeName": node_name,
            "hostPID": true,
            "containers": [{
                "name": "spy-process",
                "image": "alpine:latest",
                "securityContext": {
                    "privileged": true
                },
                "command": [
                    "sh", "-c",
                    format!(
                        "echo 'Searching for tenant2 processes...' && \
                         for i in $(seq 1 30); do \
                           if ps aux | grep -i 'TENANT2_UNIQUE_MARKER\\|{}' | grep -v grep | grep -v spy-process; then \
                             echo 'TENANT2_PROCESS_FOUND: Isolation breach detected!'; \
                             ps aux | grep -i 'TENANT2_UNIQUE_MARKER\\|{}' | grep -v grep | grep -v spy-process; \
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

fn create_network_target_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "network-target",
                "workload-test": "target"
            }
        },
        "spec": {
            "containers": [{
                "name": "network-target",
                "image": "nginx:alpine",
                "ports": [{
                    "containerPort": 80
                }],
                "command": [
                    "sh", "-c",
                    "echo 'Starting network target server...' && \
                     echo '<h1>TENANT2_NETWORK_TARGET</h1>' > /usr/share/nginx/html/index.html && \
                     nginx -g 'daemon off;'"
                ]
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_network_spy_pod(pod_name: &str, target_ip: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "hostNetwork": true,
            "containers": [{
                "name": "network-spy",
                "image": "alpine/curl:latest",
                "command": [
                    "sh", "-c",
                    format!(
                        "echo 'Testing cross-tenant network access...' && \
                         for i in $(seq 1 10); do \
                           echo \"Attempt $i: Trying to connect to {}:80\" && \
                           if curl -s --connect-timeout 5 {}:80 | grep -q 'TENANT2_NETWORK_TARGET'; then \
                             echo 'NETWORK_ACCESS_SUCCESS: Cross-tenant network access detected!'; \
                             break; \
                           fi; \
                           sleep 2; \
                         done; \
                         echo 'Network access test completed'",
                        target_ip, target_ip
                    )
                ],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

impl Display for WorkloadResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkloadResource::ProcessNamespace => write!(f, "Process Namespace"),
            WorkloadResource::NetworkNamespace => write!(f, "Network Namespace"),
            WorkloadResource::UserNamespace => write!(f, "User Namespace"),
            WorkloadResource::IPCNamespace => write!(f, "IPC Namespace"),
            WorkloadResource::UTSNamespace => write!(f, "UTS Namespace"),
        }
    }
}

impl Display for WorkloadOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkloadOperation::ViewProcesses => write!(f, "View Processes"),
            WorkloadOperation::CreateNetworkConn => write!(f, "Create Network Connections"),
            WorkloadOperation::ModifyHostname => write!(f, "Modify Hostname"),
            WorkloadOperation::AccessIPC => write!(f, "Access IPC Resources"),
        }
    }
}

impl Display for SafetyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyLevel::Safe => write!(f, "Safe"),
            SafetyLevel::Unsafe => write!(f, "Unsafe"),
            SafetyLevel::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Display for WorkloadIsolationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Multi-tenancy Data Plane - Workload Report")?;
        writeln!(f, "==========================================")?;

        writeln!(
            f,
            "🔒 Overall Isolation: {}",
            if self.overall_isolation {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        writeln!(
            f,
            "🔧 Overall Autonomy: {}",
            if self.overall_autonomy {
                "✅ VERIFIED"
            } else {
                "❌ NOT VERIFIED"
            }
        )?;

        if !self.warnings.is_empty() {
            writeln!(f)?;
            writeln!(f, "⚠️  Security Warnings:")?;
            for warning in &self.warnings {
                writeln!(f, "  • {}", warning)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "📋 Detailed Assessment by Resource:")?;

        for resource_assessment in &self.resources_assessment {
            writeln!(f, "  • {}:", resource_assessment.resource)?;
            writeln!(
                f,
                "    - Autonomy: {} | Isolation: {}",
                if resource_assessment.is_autonomous {
                    "✅"
                } else {
                    "❌"
                },
                if resource_assessment.is_isolated {
                    "✅"
                } else {
                    "❌"
                }
            )?;

            for (operation, assessment) in &resource_assessment.operations_assessment {
                let safety_icon = match assessment.safe {
                    SafetyLevel::Safe => "✅",
                    SafetyLevel::Unsafe => "❌",
                    SafetyLevel::Unknown => "❓",
                };

                writeln!(
                    f,
                    "      {} {}: Auth={} Safety={}",
                    safety_icon,
                    operation,
                    if assessment.authorized { "✅" } else { "❌" },
                    assessment.safe
                )?;

                if let Some(details) = &assessment.test_details {
                    writeln!(f, "        Details: {}", details)?;
                }
            }
            writeln!(f)?;
        }

        Ok(())
    }
}
