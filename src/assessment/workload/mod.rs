mod fairness;

pub use fairness::*;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use std::fmt::Display;
use tracing::info;

use crate::assessment::TenantClusterConfig;
use crate::assessment::{
    run_assessment, AssessableResource, CrossTenantResult, IsolationLevel, MultitenancyAssessor,
    SubsystemReport,
};

#[allow(dead_code)]
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

/// Simple Public API
#[allow(dead_code)]
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

/// What the escape pod's kernel-module attempt actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivilegedBreach {
    /// Module loaded and the global task list held another tenant's process.
    SawOtherTenant,
    /// Module loaded but no other tenant was visible.
    LoadedOwnOnly,
    /// A privileged operation was refused despite the capabilities (EPERM).
    DeniedEperm,
    /// The kernel demanded a signed module (EKEYREJECTED).
    SignatureRequired,
    /// Could not build or load for environmental reasons — no isolation signal.
    ToolingFailed,
}

/// Decide the privileged-syscall verdict from what the escape pod reported.
///
/// Pure, so every row of the design's verdict table is unit-tested without a
/// cluster. The ordering encodes the author's rule: an operation blocked because
/// it was *unauthorized* (admission refusal, stripped capabilities, a denied
/// syscall) is `Soft` — blocked, but revealing a shared environment — while a
/// breach that could not be *executed* for tooling reasons is `Unknown`, never
/// the flattering `Hard` the old code produced on a build failure.
///
/// `target_running` distinguishes "the module saw nobody because the kernel is
/// not shared" (a real `Hard`, VM or sandbox) from "saw nobody because the
/// target was not up" (inconclusive).
fn privileged_verdict(
    admission_refused: bool,
    caps_full: bool,
    breach: PrivilegedBreach,
    target_running: bool,
) -> CrossTenantResult {
    if admission_refused {
        return CrossTenantResult {
            isolation: IsolationLevel::Soft("Privileged pod refused at admission".to_string()),
            autonomy: false,
            details: "Platform refused to create a privileged pod - blocked by policy".to_string(),
        };
    }

    if !caps_full {
        return CrossTenantResult {
            isolation: IsolationLevel::Soft("Requested capabilities were stripped".to_string()),
            autonomy: false,
            details: "Container did not receive CAP_SYS_ADMIN/CAP_SYS_MODULE - the platform \
                      confined its capabilities"
                .to_string(),
        };
    }

    match breach {
        PrivilegedBreach::SawOtherTenant => CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "Privileged container loaded a kernel module and read another tenant's \
                      processes - shared kernel, no isolation"
                .to_string(),
        },
        PrivilegedBreach::LoadedOwnOnly => {
            if target_running {
                CrossTenantResult {
                    isolation: IsolationLevel::Hard,
                    autonomy: true,
                    details: "Privileged module loaded but saw no other tenant's processes - \
                              the kernel is not shared (VM or sandbox runtime)"
                        .to_string(),
                }
            } else {
                CrossTenantResult {
                    isolation: IsolationLevel::Unknown,
                    autonomy: true,
                    details: "Privileged module loaded but the tenant2 target was not confirmed \
                              running - cannot conclude"
                        .to_string(),
                }
            }
        }
        PrivilegedBreach::DeniedEperm => CrossTenantResult {
            isolation: IsolationLevel::Soft("Privileged syscall denied (EPERM)".to_string()),
            autonomy: true,
            details: "Container held the capabilities but the privileged operation was refused - \
                      seccomp, an LSM, or kernel lockdown"
                .to_string(),
        },
        PrivilegedBreach::SignatureRequired => CrossTenantResult {
            isolation: IsolationLevel::Soft("Kernel requires signed modules".to_string()),
            autonomy: true,
            details: "Module load rejected for want of a signature (Secure Boot / module \
                      signing) - host hardening rather than tenant isolation"
                .to_string(),
        },
        PrivilegedBreach::ToolingFailed => CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: "Kernel module could not be built or loaded in this environment - \
                      isolation not determined"
                .to_string(),
        },
    }
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

    // Read the host kernel identity the target printed, and pick a matching
    // image for the escape pod so its package manager can install a buildable
    // kernel tree for the exact running kernel.
    let target_logs = tenant2
        .cluster
        .get_pod_logs(target_pod_name, &tenant2.namespace)
        .await
        .unwrap_or_default();
    let proc_version = extract_log_value(&target_logs, "PROC_VERSION=");
    let uname_r = extract_log_value(&target_logs, "UNAME_R=");
    let distro = detect_host_distro(&proc_version, &uname_r);
    info!("Detected host distro {:?} (uname {})", distro, uname_r);

    // Create escape pod in tenant1 on the same node with ONLY privileged flag
    let escape_pod_name = "privileged-escape";
    let escape_pod = create_privileged_escape_pod(escape_pod_name, node_name, distro);

    info!(
        "Malicious escape pod '{}' created on the same node as target pod in tenant",
        escape_pod_name
    );

    let escape_result = tenant1
        .cluster
        .create_pod_in_namespace(&escape_pod, &tenant1.namespace)
        .await;

    let result = if escape_result.is_err() {
        // The platform would not even create a privileged pod.
        privileged_verdict(true, false, PrivilegedBreach::ToolingFailed, true)
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

        let escape_logs = tenant1
            .cluster
            .get_pod_logs(escape_pod_name, &tenant1.namespace)
            .await
            .unwrap_or_default();

        // The capability line is the backbone: if the pod never printed one it
        // did not really run, and that is a tooling failure, not stripped caps.
        let caps_reported =
            escape_logs.contains("CAPS_FULL") || escape_logs.contains("CAPS_DROPPED");
        let caps_full = !caps_reported || escape_logs.contains("CAPS_FULL");

        let breach = if !caps_reported {
            PrivilegedBreach::ToolingFailed
        } else if escape_logs.contains("TENANT2_PROCESS_FOUND") {
            PrivilegedBreach::SawOtherTenant
        } else if escape_logs.contains("MODULE_SIG_REQUIRED") {
            PrivilegedBreach::SignatureRequired
        } else if escape_logs.contains("MODULE_DENIED_EPERM") {
            PrivilegedBreach::DeniedEperm
        } else if escape_logs.contains("MODULE_LOADED") {
            PrivilegedBreach::LoadedOwnOnly
        } else {
            // BUILD_FAILED, HEADERS_UNAVAILABLE, MODULE_LOAD_FAILED_TOOLING.
            PrivilegedBreach::ToolingFailed
        };

        info!(
            "Privileged escape: caps_full={}, breach={:?}",
            caps_full, breach
        );

        // The target pod was waited on above (via `?`), so it is running.
        privileged_verdict(false, caps_full, breach, true)
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

/// The host distribution, inferred from the running kernel it shares with the
/// pod. It decides which image and package manager can install a *buildable*
/// kernel tree for that exact kernel.
///
/// A container shares the host kernel, so the only reliable in-container source
/// of a build tree is the host distro's own `-devel`/`-headers` package. The
/// probe therefore runs the escape pod on an image of the detected distro. Scope
/// is Ubuntu and Fedora; anything else defaults to Ubuntu, whose failure mode is
/// a clean `HEADERS_UNAVAILABLE` rather than a wrong verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostDistro {
    Ubuntu {
        /// The Ubuntu series (e.g. `"22.04"`) parsed from the kernel's ABI tag.
        /// An HWE/vendor kernel such as `6.8.0-1023-oracle` runs on an *older*
        /// series than the native one, and its `linux-headers-<krel>` package
        /// lives only in that series' archive — so the escape image must match
        /// it. `None` for a native kernel, where the current release image is
        /// right.
        release: Option<String>,
    },
    /// `release` is the Fedora version parsed from `.fcNN`, used to line the
    /// image's repos up with the running kernel.
    Fedora { release: Option<u32> },
}

/// Infer the host distro from the running kernel's identity — both readable in
/// any pod with no mount and no privilege, and not namespaced.
///
/// `uname -r` carries `.fcNN` on Fedora and a flavour suffix (`-generic`,
/// `-aws`, …) on Ubuntu; `/proc/version` is the kernel build string and names
/// the builder ("Ubuntu …" or "… Red Hat …"). `.fcNN` is checked first because
/// it also yields the Fedora release for the image tag.
/// First value in `logs` on a line beginning with `prefix`, trimmed.
fn extract_log_value(logs: &str, prefix: &str) -> String {
    logs.lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn detect_host_distro(proc_version: &str, uname_r: &str) -> HostDistro {
    if let Some(idx) = uname_r.find(".fc") {
        let digits: String = uname_r[idx + 3..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        return HostDistro::Fedora {
            release: digits.parse().ok(),
        };
    }
    if proc_version.contains("Fedora") || proc_version.contains("Red Hat") {
        return HostDistro::Fedora { release: None };
    }
    // "Ubuntu" in the build string, an Ubuntu flavour in uname, or anything
    // unrecognised: default to Ubuntu. An HWE/vendor kernel carries the series
    // it was built for in the ABI tag ("#23~22.04.1-Ubuntu"); a native kernel
    // ("#45-Ubuntu") does not, and `None` means "use the image's own release".
    HostDistro::Ubuntu {
        release: extract_ubuntu_series(proc_version),
    }
}

/// The Ubuntu series from a kernel build string's ABI tag, e.g. `"22.04"` from
/// `"#23~22.04.1-Ubuntu"`. The series sits right before `-Ubuntu`, so parse
/// backward from there — a `~NN.NN` elsewhere (e.g. the embedded gcc version)
/// cannot mislead it. `None` for a native kernel whose tag carries no `~NN.NN`.
fn extract_ubuntu_series(proc_version: &str) -> Option<String> {
    let before = &proc_version[..proc_version.find("-Ubuntu")?];
    let after = &before[before.rfind('~')? + 1..];
    let major: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    let rest = &after[major.len()..];
    if major.is_empty() || !rest.starts_with('.') {
        return None;
    }
    let minor: String = rest[1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if minor.is_empty() {
        return None;
    }
    Some(format!("{major}.{minor}"))
}

impl HostDistro {
    /// The image the escape pod runs, matched to the host so its package manager
    /// can install headers for the running kernel.
    fn escape_image(&self) -> String {
        match self {
            HostDistro::Ubuntu { release: Some(r) } => format!("ubuntu:{r}"),
            HostDistro::Ubuntu { release: None } => "ubuntu:24.04".to_string(),
            HostDistro::Fedora { release: Some(n) } => format!("fedora:{n}"),
            HostDistro::Fedora { release: None } => "fedora:latest".to_string(),
        }
    }

    /// Shell lines that install the toolchain and the running kernel's build
    /// tree, set `KDIR`, and emit `HEADERS_DISTRO_PKG` or `HEADERS_UNAVAILABLE`.
    /// The rest of the script (module source, build, load) is distro-agnostic
    /// and consumes `$KDIR`.
    fn header_setup_lines(&self) -> Vec<String> {
        let mut lines: Vec<&str> = vec![
            "",
            "# Toolchain + the running kernel's build tree, from the host's own",
            "# distro. A container shares the host kernel, so only that distro's",
            "# -devel/-headers package carries a tree that `make modules` accepts;",
            "# kheaders in sysfs is headers-only and cannot (it has no Makefile or",
            "# scripts/). Nothing is mounted from the host — image packages only.",
            "krel=$(uname -r)",
            "",
            "# Toolchain and kernel headers are installed SEPARATELY on purpose.",
            "# A single transaction aborts wholesale if the exact kernel-devel /",
            "# linux-headers cannot be resolved (common on Fedora when the running",
            "# kernel is older than the mirror's newest), which used to take make",
            "# down with it and read as 'toolchain unavailable'. Split, a missing",
            "# header package is reported accurately as HEADERS_UNAVAILABLE.",
        ];
        lines.push("hdr_err=''");
        match self {
            HostDistro::Ubuntu { .. } => lines.extend([
                "export DEBIAN_FRONTEND=noninteractive",
                "apt-get update >/dev/null 2>&1 || true",
                // dwarves provides pahole, used for module BTF generation; absent
                // it is only a warning, but installing it keeps the build clean.
                "apt-get install -y make gcc kmod binutils libelf-dev dwarves curl \
                 >/dev/null 2>&1 || true",
            ]),
            HostDistro::Fedora { .. } => lines.extend([
                "dnf install -y --setopt=install_weak_deps=False make gcc kmod \
                 binutils elfutils-libelf-devel dwarves curl >/dev/null 2>&1 || true",
            ]),
        }
        lines.extend([
            "if ! command -v make >/dev/null 2>&1; then",
            "  echo 'BUILD_FAILED: toolchain unavailable'",
            "  exit 0",
            "fi",
        ]);
        // Header package as its own step; capture the error so a resolution
        // failure is visible rather than a silent empty build tree.
        match self {
            HostDistro::Ubuntu { .. } => {
                lines.extend(["hdr_err=$(apt-get install -y linux-headers-$krel 2>&1)"])
            }
            HostDistro::Fedora { .. } => lines.extend([
                "hdr_err=$(dnf install -y kernel-devel-$krel 2>&1)",
                "if [ ! -f \"/usr/src/kernels/$krel/Makefile\" ]; then",
                "  hdr_err=$(dnf install -y \"kernel-devel-uname-r == $krel\" 2>&1)",
                "fi",
                "# Koji fallback: the exact kernel-devel is often gone from the",
                "# mirrors once the host is even slightly behind the latest, but",
                "# every Fedora build is archived in Koji by NVR forever. Fetch it",
                "# directly, so the host need not be on the newest kernel.",
                "if [ ! -f \"/usr/src/kernels/$krel/Makefile\" ]; then",
                "  ver=${krel%%-*}",
                "  arch=${krel##*.}",
                "  rest=${krel#*-}",
                "  rel=${rest%.$arch}",
                "  koji=\"https://kojipkgs.fedoraproject.org/packages/kernel/$ver/$rel/$arch/kernel-devel-$ver-$rel.$arch.rpm\"",
                "  echo \"KOJI_FETCH: $koji\"",
                "  if curl -sfL -o /tmp/kernel-devel.rpm \"$koji\"; then",
                "    hdr_err=$(dnf install -y /tmp/kernel-devel.rpm 2>&1)",
                "  else",
                "    hdr_err=\"koji download failed: $koji\"",
                "  fi",
                "fi",
            ]),
        }
        // A container that installed only -devel has the tree under /usr/src but
        // may lack the /lib/modules/$krel/build symlink (created by the kernel
        // package, absent here). Accept any candidate that actually has a
        // top-level Makefile — that is what `make -C` needs.
        lines.extend([
            "KDIR=''",
            "for cand in \"/lib/modules/$krel/build\" \"/usr/src/kernels/$krel\" \
             \"/usr/src/linux-headers-$krel\"; do",
            "  if [ -f \"$cand/Makefile\" ]; then KDIR=\"$cand\"; break; fi",
            "done",
            "if [ -n \"$KDIR\" ]; then",
            "  echo \"HEADERS_DISTRO_PKG: build tree for $krel at $KDIR\"",
            "else",
            "  echo 'HEADERS_UNAVAILABLE: no build tree for '$krel' in this image'",
            "  echo \"HEADER_INSTALL_ERROR: $(printf '%s' \"$hdr_err\" | tail -n 3)\"",
            "  exit 0",
            "fi",
        ]);
        lines.into_iter().map(str::to_string).collect()
    }

    /// Portable breach (primary): a CO-RE eBPF task iterator that walks the same
    /// global task list as the kernel module, but needs no per-kernel headers —
    /// only the host's BTF (`/sys/kernel/btf/vmlinux`, shipped by modern cloud
    /// kernels). This is what makes the probe conclude on vendor kernels
    /// (Oracle/AWS/Azure/GKE-COS) where `linux-headers-<krel>` is unavailable.
    ///
    /// It emits the *same* markers the module path does (`TENANT2_PROCESS_FOUND`
    /// / `MODULE_LOADED` / `MODULE_DENIED_EPERM`) so the verdict parser is
    /// unchanged. On a conclusive result it sleeps and exits before the module
    /// build runs; otherwise it prints a fall-through marker and lets
    /// `header_setup_lines()` + the module build take over (no BTF, or a
    /// bpftrace too old for `iter:task`).
    fn bpftrace_breach_lines(&self) -> Vec<String> {
        let install: &[&str] = match self {
            HostDistro::Ubuntu { .. } => &[
                "  export DEBIAN_FRONTEND=noninteractive",
                "  apt-get update >/dev/null 2>&1 || true",
                "  apt-get install -y bpftrace >/dev/null 2>&1 || true",
            ],
            HostDistro::Fedora { .. } => &["  dnf install -y bpftrace >/dev/null 2>&1 || true"],
        };
        let mut lines: Vec<&str> = vec![
            "",
            "# --- Portable eBPF breach (primary) ---------------------------------",
            "# Header-free via BTF. We do NOT use a BPF task iterator: it is",
            "# PID-namespace-scoped on modern kernels, so from a pod it only sees the",
            "# pod's own tasks (never other tenants). Instead we attach the global",
            "# sched:sched_switch tracepoint, which fires for EVERY context switch on",
            "# EVERY CPU host-wide, regardless of namespace — the same cross-tenant",
            "# visibility the kernel module's for_each_process() has. Seeing the",
            "# tenant2 sentinel, or many distinct host comms, means a shared kernel.",
            "if [ -r /sys/kernel/btf/vmlinux ]; then",
        ];
        lines.extend(install.iter().copied());
        lines.extend([
            "  if command -v bpftrace >/dev/null 2>&1; then",
            "    # bpftrace attaches tracepoints through tracefs; a privileged",
            "    # container can mount it even when the runtime did not expose it.",
            "    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true",
            "    mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true",
            "    # Let the tenant2 sentinel be scheduled a few times first.",
            "    sleep 5",
            // Aggregate the comm of every task switched-to over a 15s window into
            // a map; bpftrace prints the map on exit as "@c[<comm>]: <n>" lines.
            "    bt=$(timeout 30 bpftrace -e 'tracepoint:sched:sched_switch { @c[args->next_comm] = count(); } interval:s:15 { exit(); }' 2>&1)",
            "    bpf_verdict=''",
            // Distinct host comms observed = the cross-namespace visibility signal.
            // A sandbox/VM would surface only this pod's own handful; a shared
            // kernel surfaces the whole node (kubelet, kworkers, other tenants).
            "    bpf_comms=$(printf '%s' \"$bt\" | grep -cF '@c[')",
            "    echo \"BPF_DISTINCT_COMMS: $bpf_comms\"",
            "    if printf '%s' \"$bt\" | grep -qF '@c[__SENTINEL__]'; then",
            "      echo 'TENANT2_PROCESS_FOUND: scheduler tracepoint observed the tenant2 sentinel running on a shared kernel'",
            "      bpf_verdict=done",
            "    elif [ \"$bpf_comms\" -gt 10 ]; then",
            "      echo 'TENANT2_PROCESS_FOUND: scheduler tracepoint observed many host processes across namespaces - shared kernel, no isolation'",
            "      bpf_verdict=done",
            "    elif [ \"$bpf_comms\" -ge 1 ]; then",
            // Only this pod's own comms scheduled: the kernel view is scoped to
            // the pod (an isolating runtime — sandbox/VM). Same signal the
            // module's "loaded, saw nobody" produces.
            "      echo 'MODULE_LOADED: scheduler tracepoint saw only this pod - kernel view is isolated (sandbox/VM)'",
            "      bpf_verdict=done",
            "    else",
            // No events at all: a clear permission/lockdown denial is confinement
            // (Soft); anything else (attach/BTF/tracefs error) is inconclusive and
            // falls through to the module build.
            "      case \"$bt\" in",
            "        *'Operation not permitted'*|*'Permission denied'*|*lockdown*|*'Operation not supported'*|*'Error attaching'*)",
            "          echo 'MODULE_DENIED_EPERM: eBPF/tracepoint attach refused despite capabilities (lockdown or stripped bpf)'",
            "          bpf_verdict=done ;;",
            "        *)",
            "          echo \"BPFTRACE_INCONCLUSIVE: $(printf '%s' \"$bt\" | tail -n 2 | tr '\\n' ' ')\" ;;",
            "      esac",
            "    fi",
            "    if [ \"$bpf_verdict\" = done ]; then",
            "      echo 'Kernel module container escape test completed'",
            "      exit 0",
            "    fi",
            "  fi",
            "fi",
            "echo 'BTF_UNAVAILABLE_OR_BPFTRACE_MISSING: falling back to kernel-module build'",
        ]);
        lines
            .into_iter()
            .map(|l| l.replace("__SENTINEL__", TENANT2_SENTINEL_COMM))
            .collect()
    }
}

/// argv[0]/comm of the tenant2 sentinel process the target pod launches. Both
/// the eBPF task iterator and the kernel module look for this token in the
/// global task list. Kept within `TASK_COMM_LEN` (16) so it is fully visible in
/// `task->comm`, and it contains "tenant2" so the module's existing comm/cmdline
/// match finds it too.
const TENANT2_SENTINEL_COMM: &str = "tenant2-probe";

fn create_privileged_escape_pod(pod_name: &str, node_name: &str, distro: HostDistro) -> Pod {
    // Capability backbone (distro-agnostic): report the granted set before any
    // build. A plain file read, so it never fails for kernel-version reasons;
    // the verdict leans on it so a build failure cannot masquerade as isolation.
    let head = [
        "echo 'Testing container escape using custom kernel module...'",
        "capeff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)",
        "capbnd=$(sed -n 's/^CapBnd:[[:space:]]*//p' /proc/self/status)",
        "echo \"CAPEFF=${capeff}\"",
        "echo \"CAPBND=${capbnd}\"",
        "cap=$((0x${capeff:-0}))",
        "# CAP_SYS_ADMIN (bit 21, 0x200000) is the capability BOTH breaches need:",
        "# the eBPF loader and the module loader alike. CAP_SYS_MODULE (bit 16,",
        "# 0x10000) and CAP_BPF (bit 39, 0x8000000000) are reported for context",
        "# only, so a platform that strips just CAP_SYS_MODULE — leaving the eBPF",
        "# breach open — is not misread as fully confined.",
        "has_admin=$(( (cap & 0x200000) != 0 ))",
        "has_module=$(( (cap & 0x10000) != 0 ))",
        "has_bpf=$(( (cap & 0x8000000000) != 0 ))",
        "echo \"CAP_DETAIL: sys_admin=$has_admin sys_module=$has_module bpf=$has_bpf\"",
        "if [ \"$has_admin\" -ne 0 ]; then",
        "  echo 'CAPS_FULL: CAP_SYS_ADMIN present - privileged breach is possible'",
        "else",
        "  echo 'CAPS_DROPPED: CAP_SYS_ADMIN missing - capabilities confined'",
        "fi",
    ];

    // Module source, build, and load (distro-agnostic): consumes $KDIR.
    let tail = [
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
        "# Build against the host distro's kernel build tree ($KDIR).",
        "# kbuild reads obj-m from a Kbuild/Makefile in the module directory (M=),",
        "# not from the command line, so write one next to the source. Without it",
        "# kbuild tries to include a Makefile in M= and fails 'No rule to make",
        "# target Makefile'.",
        "echo 'obj-m := tenant_spy.o' > Kbuild",
        "echo 'Compiling kernel module...'",
        "if make -C \"$KDIR\" M=\"$PWD\" modules; then",
        "  echo 'BUILD_OK'",
        "  # Strip symbol-version CRCs. The headers are the running kernel's own,",
        "  # so the ABI already matches; only the Module.symvers bookkeeping is",
        "  # missing, which makes the CRC check redundant. This lets the module",
        "  # load on CONFIG_MODVERSIONS=y kernels, the common case.",
        "  objcopy -R __versions tenant_spy.ko 2>/dev/null || true",
        "  echo 'Loading kernel module...'",
        "  insmod_err=$(insmod tenant_spy.ko 2>&1)",
        "  insmod_rc=$?",
        "  if [ $insmod_rc -eq 0 ]; then",
        "    echo 'MODULE_LOADED: Module loaded successfully'",
        "    # Give the target pod a moment, then read the global task list.",
        "    sleep 10",
        "    if [ -f /proc/tenant_spy ]; then",
        "      cat /proc/tenant_spy",
        "    else",
        "      echo 'Proc entry not created'",
        "    fi",
        "    rmmod tenant_spy 2>/dev/null || true",
        "  else",
        "    echo \"insmod failed: $insmod_err\"",
        "    # Why the load was refused decides the verdict, so report the host's",
        "    # module-gating state rather than guessing. EPERM here is almost",
        "    # always kernel lockdown (Secure Boot: lockdown=integrity), which",
        "    # refuses unsigned modules in-kernel no matter the capabilities — a",
        "    # host protection, not tenant isolation, and uniform across every",
        "    # solution on that host.",
        "    ld=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo n/a)",
        "    se=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo n/a)",
        "    md=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo n/a)",
        "    echo \"LOCKDOWN_STATE: lockdown=$ld sig_enforce=$se modules_disabled=$md\"",
        "    # A user namespace is the other EPERM cause when lockdown is off:",
        "    # module loading needs CAP_SYS_MODULE in the INIT userns, but a mapped",
        "    # container holds it only within its own, so CapEff reads full yet the",
        "    # load is refused. An identity map is '0 0 4294967295'; anything else",
        "    # is a userns (typically a rootless runtime, or the platform remapping",
        "    # capabilities as a deliberate isolation mechanism).",
        "    um=$(tr -s ' ' < /proc/self/uid_map 2>/dev/null | tr '\\n' ';')",
        "    echo \"USERNS_UID_MAP: ${um:-unavailable}\"",
        "    # The reason decides the verdict, so classify it rather than lumping",
        "    # every failure together. A denied privileged op is confinement; a",
        "    # build/load artefact is inconclusive.",
        "    case \"$insmod_err\" in",
        "      *'Required key'*|*'Key was rejected'*)",
        "        echo 'MODULE_SIG_REQUIRED: kernel demands a signed module' ;;",
        "      *'not permitted'*)",
        "        echo 'MODULE_DENIED_EPERM: privileged module load refused despite capabilities' ;;",
        "      *)",
        "        echo 'MODULE_LOAD_FAILED_TOOLING: could not load the compiled module' ;;",
        "    esac",
        "  fi",
        "else",
        "  echo 'BUILD_FAILED: module compilation failed'",
        "fi",
        "echo 'Kernel module container escape test completed'",
        "exit 0",
    ];

    // head (capabilities) -> eBPF breach (primary, header-free; exits on a
    // conclusive result) -> distro-specific header setup -> tail (module
    // build/load, the fallback reached only when the eBPF stage was inconclusive).
    let script = head
        .iter()
        .map(|s| s.to_string())
        .chain(distro.bpftrace_breach_lines())
        .chain(distro.header_setup_lines())
        .chain(tail.iter().map(|s| s.to_string()))
        .collect::<Vec<_>>()
        .join("\n");

    let image = distro.escape_image();

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
                "image": image,
                "securityContext": {
                    "privileged": true,
                    "capabilities": {
                        "add": ["ALL"]
                    }
                },
                "command": [
                    "sh", "-c",
                    script
                ],
                // Building a module means installing a toolchain and kernel
                // headers (dnf/apt use hundreds of MB) and running cc1 against
                // the kernel headers (hundreds more). The old 128Mi limit
                // OOM-killed the container mid-install, before any build marker
                // printed — which reads downstream as ToolingFailed / Unknown.
                // These limits are the build's needs, not part of any fairness
                // measurement.
                "resources": {
                    "requests": {
                        "memory": "256Mi",
                        "cpu": "500m"
                    },
                    "limits": {
                        "memory": "2Gi",
                        "cpu": "2000m"
                    }
                }
            }],
            "restartPolicy": "Never",
        }
    }))
    .unwrap()
}

fn create_non_privileged_target_pod(pod_name: &str) -> Pod {
    // task->comm follows the executable's basename, not argv[0] (so `exec -a`
    // cannot set it) — copy a binary to a tenant2-named path and run it in the
    // background. It MUST be a standalone binary: /bin/sleep on modern distros is
    // the coreutils multi-call binary, which dispatches on argv[0] and refuses an
    // unknown name ("coreutils: unknown program 'tenant2-probe'"). A shell has no
    // such dispatch, so copy bash (sh as fallback) and loop. That process is what
    // the eBPF iterator matches on `comm`; the foreground `tail -f` keeps the pod
    // alive and its cmdline still carries the "tenant2_marker" token the
    // kernel-module fallback matches on.
    let target_cmd = format!(
        "echo \"PROC_VERSION=$(cat /proc/version)\" && \
         echo \"UNAME_R=$(uname -r)\" && \
         echo 'TENANT2_TARGET_STARTED' && \
         secret_data=$(date +%s | sha256sum | cut -d' ' -f1 | head -c 16) && \
         echo \"SECRET_DATA: $secret_data\" && \
         mkdir -p /tmp/tenant2_marker && \
         echo \"tenant2\" > /tmp/tenant2_marker/$secret_data && \
         (cp /bin/bash /tmp/{sentinel} 2>/dev/null || cp /bin/sh /tmp/{sentinel}) && \
         {{ /tmp/{sentinel} -c 'while true; do sleep 0.1; done' & }} && \
         tail -f /tmp/tenant2_marker/$secret_data",
        sentinel = TENANT2_SENTINEL_COMM,
    );
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
                // PROC_VERSION and UNAME_R identify the host kernel this pod
                // shares, so the tool can pick a matching image for the escape
                // pod's module build. Both are readable by any user, not
                // namespaced, and need no mount. The sentinel process makes the
                // tenant visible to the escape pod's eBPF task iterator.
                "command": [
                    "sh", "-c",
                    target_cmd
                ],
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                },
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                ],
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
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
                "image": "ubuntu:latest",
                "command": [
                    "sh", "-c",
                    "sleep 10 && \
                     fingerprint=`(ipcs -m; ipcs -s; ipcs -q) | sha1sum | cut -d' ' -f1` && \
                     echo 'Fingerprint: ' $fingerprint",
                ],
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                ],
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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
                "resources": {
                    "requests": {
                        "memory": "64Mi",
                        "cpu": "250m"
                    },
                    "limits": {
                        "memory": "128Mi",
                        "cpu": "500m"
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    // One test per row of the plan's verdict table. The point is that a probe
    // that could not run never reads as isolation, and that "unauthorized" and
    // "stripped capabilities" read as Soft rather than Hard.

    // detect_host_distro over real /proc/version and uname -r strings.

    #[test]
    fn detects_ubuntu_from_the_kernel_build_string() {
        let proc = "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-045) \
                    (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, \
                    GNU ld (GNU Binutils for Ubuntu) 2.42) #45-Ubuntu SMP";
        // A native kernel's ABI tag has no "~NN.NN", so no series is pinned.
        assert_eq!(
            detect_host_distro(proc, "6.8.0-45-generic"),
            HostDistro::Ubuntu { release: None }
        );
    }

    #[test]
    fn detects_ubuntu_hwe_series_from_the_abi_tag() {
        // An Oracle HWE kernel: uname is "-oracle", and the build string pins the
        // series it was built for. That series must drive the escape image so the
        // header package resolves.
        let proc = "Linux version 6.8.0-1023-oracle (buildd@lcy02-amd64-021) \
                    (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0, \
                    GNU ld (GNU Binutils for Ubuntu) 2.38) #23~22.04.1-Ubuntu SMP";
        assert_eq!(
            detect_host_distro(proc, "6.8.0-1023-oracle"),
            HostDistro::Ubuntu {
                release: Some("22.04".to_string())
            }
        );
    }

    #[test]
    fn detects_fedora_and_its_release_from_uname() {
        let proc = "Linux version 6.11.5-300.fc41.x86_64 (mockbuild@…) \
                    (gcc (GCC) 14.2.1 20240912 (Red Hat 14.2.1-3), GNU ld …)";
        assert_eq!(
            detect_host_distro(proc, "6.11.5-300.fc41.x86_64"),
            HostDistro::Fedora { release: Some(41) }
        );
    }

    #[test]
    fn fedora_release_falls_back_to_the_build_string_without_fc_in_uname() {
        // A contrived uname without .fc, but a Red Hat build string.
        let proc = "Linux version 6.11.5 (mockbuild) (gcc (GCC) 14 (Red Hat 14))";
        assert_eq!(
            detect_host_distro(proc, "6.11.5"),
            HostDistro::Fedora { release: None }
        );
    }

    #[test]
    fn unknown_distro_defaults_to_ubuntu() {
        // A build failure there is a clean HEADERS_UNAVAILABLE, never a wrong
        // verdict — the safe default.
        assert_eq!(
            detect_host_distro("Linux version 6.6.0-x (buildroot)", "6.6.0-x"),
            HostDistro::Ubuntu { release: None }
        );
    }

    #[test]
    fn escape_image_matches_the_detected_distro() {
        assert_eq!(
            HostDistro::Ubuntu { release: None }.escape_image(),
            "ubuntu:24.04"
        );
        assert_eq!(
            HostDistro::Ubuntu {
                release: Some("22.04".to_string())
            }
            .escape_image(),
            "ubuntu:22.04"
        );
        assert_eq!(
            HostDistro::Fedora { release: Some(41) }.escape_image(),
            "fedora:41"
        );
        assert_eq!(
            HostDistro::Fedora { release: None }.escape_image(),
            "fedora:latest"
        );
    }

    #[test]
    fn header_setup_uses_the_right_package_manager() {
        let ubuntu = HostDistro::Ubuntu { release: None }
            .header_setup_lines()
            .join("\n");
        assert!(ubuntu.contains("apt-get install"));
        assert!(ubuntu.contains("linux-headers-$krel"));

        let fedora = HostDistro::Fedora { release: Some(41) }
            .header_setup_lines()
            .join("\n");
        assert!(fedora.contains("dnf install"));
        assert!(fedora.contains("kernel-devel-$krel"));
    }

    fn pod_command_script(pod: &Pod) -> String {
        pod.spec.as_ref().unwrap().containers[0]
            .command
            .as_ref()
            .unwrap()[2]
            .clone()
    }

    #[test]
    fn escape_script_runs_ebpf_first_then_falls_back_to_the_module_build() {
        let script = pod_command_script(&create_privileged_escape_pod(
            "escape",
            "node-1",
            HostDistro::Ubuntu { release: None },
        ));
        // Primary: a header-free eBPF probe gated on the host's BTF. It must use
        // the GLOBAL sched_switch tracepoint, not the namespace-scoped task iter.
        assert!(script.contains("/sys/kernel/btf/vmlinux"));
        assert!(script.contains("tracepoint:sched:sched_switch"));
        assert!(!script.contains("iter:task"));
        assert!(script.contains("apt-get install -y bpftrace"));
        // It identifies the tenant by the sentinel's comm.
        assert!(script.contains(TENANT2_SENTINEL_COMM));
        // Fallback: the kernel-module build still follows the eBPF stage.
        assert!(script.contains("linux-headers-$krel"));
        assert!(script.contains("insmod tenant_spy.ko"));
        // Verdict backbone now keys on CAP_SYS_ADMIN, which both breaches need.
        assert!(script.contains("CAPS_FULL: CAP_SYS_ADMIN present"));
        // eBPF reuses the module marker vocabulary, so the parser is unchanged.
        assert!(script.contains("TENANT2_PROCESS_FOUND"));
        assert!(script.contains("MODULE_DENIED_EPERM"));
    }

    #[test]
    fn escape_script_installs_bpftrace_with_the_host_package_manager() {
        let fedora = pod_command_script(&create_privileged_escape_pod(
            "escape",
            "node-1",
            HostDistro::Fedora { release: Some(41) },
        ));
        assert!(fedora.contains("dnf install -y bpftrace"));
    }

    #[test]
    fn target_pod_launches_a_distinctive_tenant2_sentinel() {
        let cmd = pod_command_script(&create_non_privileged_target_pod("privileged-target"));
        // A sleeper copied to a tenant2-named path so task->comm is the sentinel.
        assert!(cmd.contains(&format!("/tmp/{TENANT2_SENTINEL_COMM}")));
        // Still keeps the marker the kernel-module fallback matches on cmdline.
        assert!(cmd.contains("/tmp/tenant2_marker/"));
    }

    #[test]
    fn extract_log_value_reads_the_marker_line() {
        let logs = "PROC_VERSION=Linux version 6.8.0-45-generic\nUNAME_R=6.8.0-45-generic\n";
        assert_eq!(extract_log_value(logs, "UNAME_R="), "6.8.0-45-generic");
        assert_eq!(extract_log_value(logs, "MISSING="), "");
    }

    #[test]
    fn admission_refusal_is_soft_not_hard() {
        // The platform refused the privileged pod outright. Blocked, but the
        // refusal reveals a guarded shared environment — Soft, per the model's
        // own definition.
        let r = privileged_verdict(true, false, PrivilegedBreach::ToolingFailed, true);
        assert!(matches!(r.isolation, IsolationLevel::Soft(_)));
        assert!(!r.autonomy);
    }

    #[test]
    fn stripped_capabilities_are_soft() {
        // Pod ran but got fewer caps than a privileged container holds. The
        // operations it expected will fail unauthorized, so: Soft.
        let r = privileged_verdict(false, false, PrivilegedBreach::ToolingFailed, true);
        assert!(matches!(r.isolation, IsolationLevel::Soft(_)));
    }

    #[test]
    fn full_caps_seeing_another_tenant_is_none() {
        let r = privileged_verdict(false, true, PrivilegedBreach::SawOtherTenant, true);
        assert_eq!(r.isolation, IsolationLevel::None);
        assert!(r.autonomy);
    }

    #[test]
    fn loaded_but_alone_with_a_running_target_is_hard() {
        // The module ran and the global task list held no other tenant: the
        // kernel is not shared. The one path to Hard.
        let r = privileged_verdict(false, true, PrivilegedBreach::LoadedOwnOnly, true);
        assert_eq!(r.isolation, IsolationLevel::Hard);
    }

    #[test]
    fn loaded_alone_without_a_confirmed_target_is_unknown() {
        // Same module outcome, but the target was not confirmed up, so "saw
        // nobody" cannot be read as isolation.
        let r = privileged_verdict(false, true, PrivilegedBreach::LoadedOwnOnly, false);
        assert_eq!(r.isolation, IsolationLevel::Unknown);
    }

    #[test]
    fn a_denied_privileged_syscall_is_soft() {
        let r = privileged_verdict(false, true, PrivilegedBreach::DeniedEperm, true);
        assert!(matches!(r.isolation, IsolationLevel::Soft(_)));
    }

    #[test]
    fn a_signature_requirement_is_soft() {
        let r = privileged_verdict(false, true, PrivilegedBreach::SignatureRequired, true);
        assert!(matches!(r.isolation, IsolationLevel::Soft(_)));
    }

    #[test]
    fn a_tooling_failure_is_unknown_never_hard() {
        // The regression guard for the bug this change fixes: a build or load
        // failure used to fall through to Hard "properly isolated". It must be
        // Unknown, because the breach was never actually run against the kernel.
        let r = privileged_verdict(false, true, PrivilegedBreach::ToolingFailed, true);
        assert_eq!(r.isolation, IsolationLevel::Unknown);
        assert_ne!(r.isolation, IsolationLevel::Hard);
    }
}
