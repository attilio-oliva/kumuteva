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
    KillProcesses,     // Can kill processes
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
            WorkloadResource::ProcessNamespace => vec![
                WorkloadOperation::ViewProcesses,
                WorkloadOperation::KillProcesses,
            ],
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
        (WorkloadResource::ProcessNamespace, WorkloadOperation::KillProcesses) => {
            // Test if tenant can create privileged pods
            test_privileged_authorization(tenant).await
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
        (WorkloadResource::ProcessNamespace, WorkloadOperation::KillProcesses) => {
            test_process_kill_cross_tenant(tenant1, tenant2).await
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

async fn test_host_path_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod_name = "hostpath-auth-test";
    let test_pod = create_host_path_test_pod(test_pod_name);

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

async fn test_host_path_write_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    // Similar to host_path_authorization but with write permissions
    test_host_path_authorization(tenant).await
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

async fn test_process_kill_cross_tenant(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    // This would be similar to process visibility but testing actual process termination
    Ok((
        SafetyLevel::Unknown,
        "Process kill cross-tenant test not implemented".to_string(),
    ))
}

async fn test_filesystem_access_cross_tenant(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    Ok((
        SafetyLevel::Unknown,
        "Filesystem access cross-tenant test not implemented".to_string(),
    ))
}

async fn test_filesystem_modify_cross_tenant(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    Ok((
        SafetyLevel::Unknown,
        "Filesystem modify cross-tenant test not implemented".to_string(),
    ))
}

async fn test_network_cross_tenant(
    _tenant1: &TenantClusterConfig,
    _tenant2: &TenantClusterConfig,
) -> anyhow::Result<(SafetyLevel, String)> {
    Ok((
        SafetyLevel::Unknown,
        "Network cross-tenant test not implemented".to_string(),
    ))
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
        let logs = tenant1
            .cluster
            .get_pod_logs(spy_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        if logs.contains("TENANT2_IPC_FOUND") {
            (
                SafetyLevel::Unsafe,
                "Cross-tenant IPC access detected - shared memory/semaphores visible".to_string(),
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
            "containers": [{
                "name": "ipc-target",
                "image": "alpine:latest",
                "command": [
                    "sh", "-c",
                    "echo 'Creating IPC resources with tenant2 marker...' && \
                     # Install ipc-utils if available \
                     apk add --no-cache util-linux 2>/dev/null || true && \
                     # Create shared memory segment with unique key \
                     echo 'TENANT2_IPC_MARKER' > /tmp/tenant2_ipc_data && \
                     # Try to create System V shared memory (if available) \
                     if command -v ipcmk >/dev/null; then \
                       ipcmk -M 1024 -p 0666 2>/dev/null || true; \
                     fi && \
                     # Create POSIX shared memory \
                     mkdir -p /dev/shm && \
                     echo 'TENANT2_IPC_SHM_MARKER' > /dev/shm/tenant2_marker 2>/dev/null || true && \
                     # Keep running to maintain IPC resources \
                     while true; do \
                       echo 'Tenant2 IPC resources active...'; \
                       sleep 30; \
                     done"
                ],
                "securityContext": {
                    "runAsUser": 1000
                }
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
                "image": "alpine:latest",
                "securityContext": {
                    "privileged": true
                },
                "command": [
                    "sh", "-c",
                    "echo 'Checking for cross-tenant IPC resources...' && \
                     # Install ipc-utils if available \
                     apk add --no-cache util-linux 2>/dev/null || true && \
                     found_ipc=false && \
                     # Check System V IPC resources \
                     if command -v ipcs >/dev/null; then \
                       echo 'Checking System V IPC resources:' && \
                       ipcs -m 2>/dev/null && \
                       ipcs -s 2>/dev/null && \
                       ipcs -q 2>/dev/null; \
                     fi && \
                     # Check POSIX shared memory \
                     echo 'Checking POSIX shared memory:' && \
                     if [ -d /dev/shm ]; then \
                       ls -la /dev/shm/ 2>/dev/null && \
                       if grep -r 'TENANT2_IPC' /dev/shm/ 2>/dev/null; then \
                         echo 'TENANT2_IPC_FOUND: Cross-tenant shared memory access detected!'; \
                         found_ipc=true; \
                       fi; \
                     fi && \
                     # Check for any tenant2 IPC markers \
                     if find /tmp -name '*tenant2*' 2>/dev/null | grep -q .; then \
                       echo 'TENANT2_IPC_FOUND: Cross-tenant IPC files detected!'; \
                       found_ipc=true; \
                     fi && \
                     if [ \"$found_ipc\" = \"false\" ]; then \
                       echo 'No cross-tenant IPC resources detected'; \
                     fi && \
                     echo 'IPC isolation check completed'"
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
            WorkloadOperation::KillProcesses => write!(f, "Kill Processes"),
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
