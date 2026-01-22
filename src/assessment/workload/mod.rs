use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use std::fmt::Display;
use tracing::info;

use crate::assessment::{
    run_assessment, AssessableResource, CrossTenantResult, IsolationLevel, MultitenancyAssessor,
    SubsystemReport,
};
use crate::assessment::TenantClusterConfig;

// Re-export for backward compatibility
pub type WorkloadIsolationReport = SubsystemReport<WorkloadResource>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WorkloadResource {
    ProcessNamespace,
    NetworkNamespace,
    UserNamespace,
    IPCNamespace,
    PrivilegedSyscalls,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WorkloadOperation {
    ViewProcesses,
    CreateNetworkConn,
    AccessHostUser,
    AccessIPC,
    UsePrivilegedSyscalls,
}

impl AssessableResource for WorkloadResource {
    type Operation = WorkloadOperation;

    fn all() -> Vec<Self> {
        vec![
            Self::ProcessNamespace,
            Self::NetworkNamespace,
            Self::UserNamespace,
            Self::IPCNamespace,
            Self::PrivilegedSyscalls,
        ]
    }

    fn applicable_operations(&self) -> Vec<Self::Operation> {
        match self {
            Self::ProcessNamespace => vec![WorkloadOperation::ViewProcesses],
            Self::NetworkNamespace => vec![WorkloadOperation::CreateNetworkConn],
            Self::UserNamespace => vec![WorkloadOperation::AccessHostUser],
            Self::IPCNamespace => vec![WorkloadOperation::AccessIPC],
            Self::PrivilegedSyscalls => vec![WorkloadOperation::UsePrivilegedSyscalls],
        }
    }
}

pub struct WorkloadAssessor;

#[async_trait]
impl MultitenancyAssessor for WorkloadAssessor {
    type Resource = WorkloadResource;

    fn name(&self) -> &'static str {
        "Workload"
    }

    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &WorkloadResource,
        operation: &WorkloadOperation,
    ) -> anyhow::Result<bool> {
        match (resource, operation) {
            (WorkloadResource::ProcessNamespace, WorkloadOperation::ViewProcesses) => {
                test_host_pid_authorization(tenant).await
            }
            (WorkloadResource::NetworkNamespace, WorkloadOperation::CreateNetworkConn) => {
                test_host_network_authorization(tenant).await
            }
            (WorkloadResource::UserNamespace, WorkloadOperation::AccessHostUser) => {
                test_host_user_authorization(tenant).await
            }
            (WorkloadResource::IPCNamespace, WorkloadOperation::AccessIPC) => {
                test_host_ipc_authorization(tenant).await
            }
            (WorkloadResource::PrivilegedSyscalls, WorkloadOperation::UsePrivilegedSyscalls) => {
                test_privileged_authorization(tenant).await
            }
            _ => Ok(false),
        }
    }

    async fn check_cross_tenant_effect(
        &self,
        tenant1: &TenantClusterConfig,
        tenant2: &TenantClusterConfig,
        resource: &WorkloadResource,
        operation: &WorkloadOperation,
    ) -> anyhow::Result<CrossTenantResult> {
        match (resource, operation) {
            (WorkloadResource::ProcessNamespace, WorkloadOperation::ViewProcesses) => {
                test_process_visibility_cross_tenant(tenant1, tenant2).await
            }
            (WorkloadResource::NetworkNamespace, WorkloadOperation::CreateNetworkConn) => {
                test_network_cross_tenant(tenant1, tenant2).await
            }
            (WorkloadResource::UserNamespace, WorkloadOperation::AccessHostUser) => {
                test_user_namespace_cross_tenant(tenant1, tenant2).await
            }
            (WorkloadResource::IPCNamespace, WorkloadOperation::AccessIPC) => {
                test_ipc_cross_tenant(tenant1, tenant2).await
            }
            (WorkloadResource::PrivilegedSyscalls, WorkloadOperation::UsePrivilegedSyscalls) => {
                test_privileged_syscalls_cross_tenant(tenant1, tenant2).await
            }
            _ => Ok(CrossTenantResult {
                isolation: IsolationLevel::Unknown,
                autonomy: true,
                details: "Test not implemented".to_string(),
            }),
        }
    }
}

/// Public API - maintains backward compatibility
pub async fn check_workload_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<WorkloadIsolationReport> {
    run_assessment(&WorkloadAssessor, tenant1, tenant2).await
}

// =============================================================================
// AUTHORIZATION TESTS
// =============================================================================

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

async fn test_host_user_authorization(tenant: &TenantClusterConfig) -> anyhow::Result<bool> {
    let test_pod_name = "hostuser-auth-test";
    let test_pod = create_host_user_test_pod(test_pod_name);

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

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

async fn test_process_visibility_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
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

    let result = if spy_result.is_err() {
        CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false, // Cannot create hostPID pod
            details: "Cannot create hostPID pod - processes isolated by policy".to_string(),
        }
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
            CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: "Cross-tenant process visibility detected - hostPID allows seeing other tenant's processes".to_string(),
            }
        } else {
            CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: "No cross-tenant process visibility - processes properly isolated"
                    .to_string(),
            }
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

    Ok(result)
}

async fn test_network_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
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

    let result = if spy_result.is_err() {
        CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false, // Cannot create hostNetwork pod
            details: "Cannot create hostNetwork pod - network isolated by policy".to_string(),
        }
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
            CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: "Cross-tenant network access detected - hostNetwork bypass allows reaching other tenant's pods".to_string(),
            }
        } else {
            CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: "No cross-tenant network access - network properly isolated".to_string(),
            }
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

    Ok(result)
}

async fn test_ipc_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
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

    let result = if spy_result.is_err() {
        CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false, // Cannot create hostIPC pod
            details: "Cannot create hostIPC pod - IPC isolated by policy".to_string(),
        }
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
            CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: format!(
                    "Cross-tenant IPC access detected - fingerprint {} visible to other tenant",
                    target_fingerprint
                ),
            }
        } else {
            CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: "No cross-tenant IPC access - IPC properly isolated".to_string(),
            }
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

    Ok(result)
}

async fn test_user_namespace_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Create target pod in tenant2 with specific user
    let target_pod_name = "user-target";
    let target_pod = create_user_target_pod(target_pod_name);

    tenant2
        .cluster
        .create_pod_in_namespace(&target_pod, &tenant2.namespace)
        .await?;

    tenant2
        .cluster
        .wait_for_pod_to_be_ready(target_pod_name, &tenant2.namespace)
        .await?;

    // Create spy pod in tenant1 with hostUser to test cross-tenant user access
    let spy_pod_name = "user-spy";
    let spy_pod = create_user_spy_pod(spy_pod_name);

    let spy_result = tenant1
        .cluster
        .create_pod_in_namespace(&spy_pod, &tenant1.namespace)
        .await;

    let result = if spy_result.is_err() {
        CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false, // Cannot create hostUser pod
            details: "Cannot create hostUser pod - user namespace isolated by policy".to_string(),
        }
    } else {
        // Wait for spy pod to complete and analyze results
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

        let logs = tenant1
            .cluster
            .get_pod_logs(spy_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        if logs.contains("USER_NAMESPACE_BREACH") {
            CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: "Cross-tenant user namespace access detected - host user namespace shared"
                    .to_string(),
            }
        } else {
            CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: "No cross-tenant user namespace access - user namespace properly isolated"
                    .to_string(),
            }
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

    Ok(result)
}

async fn test_privileged_syscalls_cross_tenant(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    info!("Testing privileged syscalls cross-tenant isolation'");

    // Create target pod in tenant2 with sensitive data (NON-PRIVILEGED)
    let target_pod_name = "privileged-target";
    let target_pod = create_non_privileged_target_pod(target_pod_name);

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

    info!(
        "Target pod '{}' with sensitive data is running on node '{}'",
        target_pod_name, node_name
    );

    // Create escape pod in tenant1 on the same node with ONLY privileged flag
    let escape_pod_name = "privileged-escape";
    let escape_pod = create_privileged_escape_pod(escape_pod_name, node_name);

    info!(
        "Malicious escape pod '{}' created on the same node as target pod in tenant",
        escape_pod_name
    );

    let escape_result = tenant1
        .cluster
        .create_pod_in_namespace(&escape_pod, &tenant1.namespace)
        .await;

    let result = if escape_result.is_err() {
        CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: false, // Cannot create privileged pod
            details: "Cannot create privileged pod - privileged syscalls isolated by policy"
                .to_string(),
        }
    } else {
        // Wait for escape pod to complete
        tenant1
            .cluster
            .watch_pod_until_condition(
                escape_pod_name,
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
            .await
            .unwrap_or(());

        // Get logs to check if container escape was successful
        let escape_logs = tenant1
            .cluster
            .get_pod_logs(escape_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        let mut breaches = Vec::new();

        // Check for various container escape indicators
        if escape_logs.contains("KERNEL_MODULE_LOADED")
            && escape_logs.contains("TENANT2_PROCESS_FOUND")
        {
            breaches.push("kernel module loaded and found tenant2 processes");
        }
        if escape_logs.contains("CONTAINER_ESCAPE_SUCCESS") {
            breaches.push("successful container escape to host");
        }
        if escape_logs.contains("TENANT2_PROCESS_VISIBLE") {
            breaches.push("tenant2 processes visible from privileged container");
        }

        info!(
            "Privileged escape pod logs analyzed, breaches found: {:?}",
            breaches
        );

        if !breaches.is_empty() {
            CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: format!(
                    "Container escape successful with cross-tenant access: {}",
                    breaches.join(", ")
                ),
            }
        } else if escape_logs.contains("KERNEL_MODULE_BLOCKED") {
            // Soft isolation - privileged pod created but kernel module loading blocked
            CrossTenantResult {
                isolation: IsolationLevel::Soft("Kernel module loading blocked".to_string()),
                autonomy: true,
                details:
                    "Privileged pod created but kernel module loading blocked - partial isolation"
                        .to_string(),
            }
        } else {
            CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: "No container escape or cross-tenant access detected - privileged syscalls properly isolated".to_string(),
            }
        }
    };

    // Cleanup
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(escape_pod_name, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(target_pod_name, &tenant2.namespace)
        .await;

    Ok(result)
}

// =============================================================================
// MANIFEST CREATION HELPERS
// =============================================================================

fn create_privileged_escape_pod(pod_name: &str, node_name: &str) -> Pod {
    let script = [
        "echo 'Testing container escape using custom kernel module...'",
        "apt update && apt install -y make gcc build-essential linux-headers-$(uname -r) kmod",
        "# Check if we have the necessary tools",
        "if ! command -v make >/dev/null 2>&1; then",
        "  echo 'Build tools not available, cannot create kernel module'",
        "  exit 0",
        "fi",
        "# Create a simple kernel module that can access all processes",
        "mkdir -p /tmp/kmod_test",
        "cd /tmp/kmod_test",
        "# Create the kernel module source",
        "cat > tenant_spy.c << 'EOF'",
        "#include <linux/init.h>",
        "#include <linux/module.h>",
        "#include <linux/kernel.h>",
        "#include <linux/proc_fs.h>",
        "#include <linux/uaccess.h>",
        "#include <linux/sched/signal.h>",
        "#include <linux/sched.h>",
        "#include <linux/fs.h>",
        "#include <linux/slab.h>",
        "#include <linux/mm.h>",
        "",
        "MODULE_LICENSE(\"GPL\");",
        "MODULE_DESCRIPTION(\"Tenant isolation test module\");",
        "MODULE_VERSION(\"1.0\");",
        "",
        "static struct proc_dir_entry *proc_entry;",
        "",
        "// Function to read process cmdline",
        "static int get_process_cmdline(struct task_struct *task, char *buffer, int buf_size) {",
        "    struct mm_struct *mm;",
        "    char *cmdline;",
        "    int len = 0;",
        "    unsigned long arg_start, arg_end;",
        "    ",
        "    if (!task || !buffer || buf_size <= 0)",
        "        return 0;",
        "    ",
        "    mm = get_task_mm(task);",
        "    if (!mm)",
        "        return 0;",
        "    ",
        "    arg_start = mm->arg_start;",
        "    arg_end = mm->arg_end;",
        "    ",
        "    if (arg_start >= arg_end) {",
        "        mmput(mm);",
        "        return 0;",
        "    }",
        "    ",
        "    len = arg_end - arg_start;",
        "    if (len > buf_size - 1)",
        "        len = buf_size - 1;",
        "    ",
        "    cmdline = kmalloc(len + 1, GFP_KERNEL);",
        "    if (!cmdline) {",
        "        mmput(mm);",
        "        return 0;",
        "    }",
        "    ",
        "    if (access_process_vm(task, arg_start, cmdline, len, FOLL_FORCE) == len) {",
        "        cmdline[len] = '\\0';",
        "        // Replace null bytes with spaces for readability",
        "        int i;",
        "        for (i = 0; i < len; i++) {",
        "            if (cmdline[i] == '\\0')",
        "                cmdline[i] = ' ';",
        "        }",
        "        strncpy(buffer, cmdline, buf_size - 1);",
        "        buffer[buf_size - 1] = '\\0';",
        "        len = strlen(buffer);",
        "    } else {",
        "        len = 0;",
        "    }",
        "    ",
        "    kfree(cmdline);",
        "    mmput(mm);",
        "    return len;",
        "}",
        "",
        "static ssize_t tenant_spy_read(struct file *file, char __user *buffer, size_t count, loff_t *pos) {",
        "    struct task_struct *task;",
        "    char *output;",
        "    char cmdline_buf[256];",
        "    int len = 0;",
        "    int process_count = 0;",
        "    int found_tenant2 = 0;",
        "    size_t output_size = 32768; // Even larger buffer",
        "    ssize_t ret;",
        "    ",
        "    if (*pos > 0) return 0;",
        "    ",
        "    // Allocate kernel memory for output buffer",
        "    output = kmalloc(output_size, GFP_KERNEL);",
        "    if (!output) {",
        "        return -ENOMEM;",
        "    }",
        "    ",
        "    len += snprintf(output + len, output_size - len, \"KERNEL_MODULE_LOADED: Scanning all processes...\\n\");",
        "    ",
        "    rcu_read_lock();",
        "    for_each_process(task) {",
        "        // Check if we have enough space left",
        "        if (len >= output_size - 1000) {",
        "            len += snprintf(output + len, output_size - len, \"... (truncated due to buffer limit)\\n\");",
        "            break;",
        "        }",
        "        ",
        "        // Get process cmdline",
        "        memset(cmdline_buf, 0, sizeof(cmdline_buf));",
        "        get_process_cmdline(task, cmdline_buf, sizeof(cmdline_buf));",
        "        ",
        "        process_count++;",
        "        ",
        "        // Check for tenant2 in both comm and cmdline",
        "        if (strstr(task->comm, \"tenant2\") || strstr(cmdline_buf, \"tenant2\") || ",
        "            strstr(task->comm, \"target\") || strstr(cmdline_buf, \"echo tenant2\")) {",
        "            len += snprintf(output + len, output_size - len, ",
        "                          \"TENANT2_PROCESS_FOUND: PID=%d COMM=%.16s CMDLINE=%s\\n\", ",
        "                          task->pid, task->comm, cmdline_buf);",
        "            found_tenant2 = 1;",
        "        }",
        "    }",
        "    rcu_read_unlock();",
        "    ",
        "    len += snprintf(output + len, output_size - len, \"TOTAL_PROCESSES_VISIBLE: %d\\n\", process_count);",
        "    ",
        "    if (found_tenant2) {",
        "        len += snprintf(output + len, output_size - len, \"CONTAINER_ESCAPE_SUCCESS: Kernel module can see tenant2 processes!\\n\");",
        "    } else {",
        "        len += snprintf(output + len, output_size - len, \"No tenant2 processes found from kernel space\\n\");",
        "    }",
        "    ",
        "    if (process_count > 20) {",
        "        len += snprintf(output + len, output_size - len, \"HOST_PROCESS_VISIBLE: Can see %d processes - possible container escape\\n\", process_count);",
        "    }",
        "    ",
        "    if (len > count) {",
        "        len = count;",
        "    }",
        "    ",
        "    if (copy_to_user(buffer, output, len)) {",
        "        ret = -EFAULT;",
        "    } else {",
        "        *pos += len;",
        "        ret = len;",
        "    }",
        "    ",
        "    kfree(output);",
        "    return ret;",
        "}",
        "",
        "static const struct proc_ops tenant_spy_ops = {",
        "    .proc_read = tenant_spy_read,",
        "};",
        "",
        "static int __init tenant_spy_init(void) {",
        "    proc_entry = proc_create(\"tenant_spy\", 0444, NULL, &tenant_spy_ops);",
        "    if (!proc_entry) {",
        "        printk(KERN_ERR \"Failed to create /proc/tenant_spy\\n\");",
        "        return -ENOMEM;",
        "    }",
        "    printk(KERN_INFO \"Tenant spy module loaded\\n\");",
        "    return 0;",
        "}",
        "",
        "static void __exit tenant_spy_exit(void) {",
        "    if (proc_entry) {",
        "        proc_remove(proc_entry);",
        "    }",
        "    printk(KERN_INFO \"Tenant spy module unloaded\\n\");",
        "}",
        "",
        "module_init(tenant_spy_init);",
        "module_exit(tenant_spy_exit);",
        "EOF",
        "",
        "# Create Makefile with proper TAB characters",
        "printf '%s\\n' 'obj-m := tenant_spy.o' '' 'all:' '\\t@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules' '' 'clean:' '\\t@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean' > Makefile",
        "# Try to compile the kernel module",
        "echo 'Compiling kernel module...'",
        "if make; then",
        "  echo 'Kernel module compiled successfully'",
        "  # Try to load the kernel module",
        "  echo 'Loading kernel module...'",
        "  if insmod tenant_spy.ko; then",
        "    echo 'KERNEL_MODULE_LOADED: Module loaded successfully'",
        "    # Wait a moment for target processes to start",
        "    sleep 10",
        "    # Read from the proc entry to get process information",
        "    if [ -f /proc/tenant_spy ]; then",
        "      echo 'Reading process information from kernel module...'",
        "      cat /proc/tenant_spy",
        "    else",
        "      echo 'Proc entry not created'",
        "    fi",
        "    # Cleanup - remove the module",
        "    rmmod tenant_spy 2>/dev/null || echo 'Failed to remove module'",
        "  else",
        "    echo 'KERNEL_MODULE_BLOCKED: Cannot load kernel module - isolation working'",
        "  fi",
        "else",
        "  echo 'Kernel module compilation failed'",
        "  # Fallback to basic process check",
        "  echo 'Falling back to basic process visibility check...'",
        "  process_count=$(ps aux | wc -l)",
        "  echo \"Total visible processes: $process_count\"",
        "  if [ \"$process_count\" -gt 15 ]; then",
        "    echo 'HOST_PROCESS_VISIBLE: Can see many processes - possible container escape'",
        "  fi",
        "  # Look for tenant2 processes specifically",
        "  tenant2_processes=$(ps aux | grep -i 'tenant2\\|privileged-target' | grep -v 'privileged-escape' | grep -v grep)",
        "  if [ -n \"$tenant2_processes\" ]; then",
        "    echo 'TENANT2_PROCESS_VISIBLE: Found tenant2 processes!'",
        "    echo \"$tenant2_processes\"",
        "  else",
        "    echo 'No tenant2 processes visible - isolation working or target not ready'",
        "  fi",
        "fi",
        "echo 'Kernel module container escape test completed'",
        "sleep 3600",
    ].join("\n");

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "nodeName": node_name,
            "containers": [{
                "name": "kernel-escape",
                "image": "ubuntu:24.04",
                "securityContext": {
                    "privileged": true,
                    "capabilities": {
                        "add": ["ALL"]
                    }
                },
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

fn create_non_privileged_target_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "privileged-target",
                "workload-test": "target",
                "tenant": "tenant2"
            }
        },
        "spec": {
            "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 1000,
                "fsGroup": 1000
            },
            "containers": [{
                "name": "tenant2-app",
                "image": "ubuntu:latest",
                "securityContext": {
                    "allowPrivilegeEscalation": false,
                    "capabilities": {
                        "drop": ["ALL"]
                    },
                    "runAsNonRoot": true,
                    "runAsUser": 1000
                },
                "command": [
                    "sh", "-c",
                    "echo 'TENANT2_TARGET_STARTED' && \
                     secret_data=$(date +%s | sha256sum | cut -d' ' -f1 | head -c 16) && \
                    echo \"SECRET_DATA: $secret_data\" && \
                    mkdir -p /tmp/tenant2_marker && \
                    echo \"tenant2\" > /tmp/tenant2_marker/$secret_data && tail -f /tmp/tenant2_marker/$secret_data"
                ]
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_host_user_test_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "hostUsers": true,
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

fn create_user_target_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "user-target",
                "workload-test": "target"
            }
        },
        "spec": {
            "containers": [{
                "name": "user-target",
                "image": "alpine:latest",
                "command": [
                    "sleep", "3600"
                ],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_user_spy_pod(pod_name: &str) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "hostUsers": true,
            "securityContext": {
                "runAsUser": 0
            },
            "containers": [{
                "name": "user-spy",
                "image": "alpine:latest",
                "command": [
                    "sh", "-c",
                    "echo 'Testing user namespace isolation...' && \
                     echo 'Current UID mapping:' && \
                     cat /proc/self/uid_map && \
                     uid_map=$(cat /proc/self/uid_map | head -1) && \
                     first_uid=$(echo $uid_map | awk '{print $1}') && \
                     second_uid=$(echo $uid_map | awk '{print $2}') && \
                     echo \"First UID: $first_uid, Second UID: $second_uid\" && \
                     if [ \"$first_uid\" = \"0\" ] && [ \"$second_uid\" = \"0\" ]; then \
                       echo 'USER_NAMESPACE_BREACH: Using host user namespace (0->0 mapping)'; \
                     else \
                       echo 'User namespace properly isolated (non-host mapping)'; \
                     fi"
                ],
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

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

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for WorkloadResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkloadResource::ProcessNamespace => write!(f, "Process Namespace"),
            WorkloadResource::NetworkNamespace => write!(f, "Network Namespace"),
            WorkloadResource::UserNamespace => write!(f, "User Namespace"),
            WorkloadResource::IPCNamespace => write!(f, "IPC Namespace"),
            WorkloadResource::PrivilegedSyscalls => write!(f, "Privileged Syscalls"),
        }
    }
}

impl Display for WorkloadOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkloadOperation::ViewProcesses => write!(f, "View Processes"),
            WorkloadOperation::CreateNetworkConn => write!(f, "Create Network Connections"),
            WorkloadOperation::AccessHostUser => write!(f, "Access Host User Namespace"),
            WorkloadOperation::AccessIPC => write!(f, "Access IPC Resources"),
            WorkloadOperation::UsePrivilegedSyscalls => write!(f, "Use Privileged Syscalls"),
        }
    }
}
