mod fairness;

pub use fairness::*;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use std::fmt::Display;
use tracing::info;

use crate::assessment::breach::{
    run_breach_experiment, BreachCondition, BreachExperiment, Intruder, Secret,
};
use crate::assessment::probe::{HostAccess, ProbePod};
use crate::assessment::Authorization;
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

    /// The properties are independent, so the order is arbitrary — with one
    /// exception that has to be respected.
    ///
    /// `NetworkNamespace` is last because its probe asks for `hostNetwork`,
    /// and a VM cannot share the node's network namespace. Under Kata the shim
    /// builds its tap in the host's namespace instead: the node is left with
    /// stray `tap0_kata` devices, the API server restarts, and the connection
    /// from outside the cluster never recovers. Every property assessed after
    /// it then reports `Unknown` — not because the technology failed to
    /// isolate anything, but because the harness could no longer reach the
    /// cluster it was measuring.
    ///
    /// Running it last does not make the damage go away; it stops that damage
    /// from erasing four measurements that had nothing to do with it.
    /// (Upstream does not support host networking under Kata either —
    /// `kata-deploy` simply declines to apply Kata to such pods.)
    fn all() -> Vec<Self> {
        vec![
            Self::ProcessNamespace,
            Self::UserNamespace,
            Self::IPCNamespace,
            Self::PrivilegedSyscalls,
            Self::NetworkNamespace,
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
    ) -> anyhow::Result<Authorization> {
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
            // No authorization probe exists for this pair, which is a gap in
            // the harness rather than a policy refusing the tenant.
            _ => Ok(Authorization::Undetermined(
                "no authorization probe is defined for this operation".to_string(),
            )),
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
                run_breach_experiment(&process_namespace_experiment(), tenant1, tenant2).await
            }
            (WorkloadResource::NetworkNamespace, WorkloadOperation::CreateNetworkConn) => {
                run_breach_experiment(&network_namespace_experiment(), tenant1, tenant2).await
            }
            (WorkloadResource::UserNamespace, WorkloadOperation::AccessHostUser) => {
                run_breach_experiment(&user_namespace_experiment(), tenant1, tenant2).await
            }
            (WorkloadResource::IPCNamespace, WorkloadOperation::AccessIPC) => {
                run_breach_experiment(&ipc_namespace_experiment(), tenant1, tenant2).await
            }
            (WorkloadResource::PrivilegedSyscalls, WorkloadOperation::UsePrivilegedSyscalls) => {
                run_breach_experiment(&privileged_syscalls_experiment(), tenant1, tenant2).await
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

async fn test_host_pid_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
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

    Ok(Authorization::from_attempt(result))
}

async fn test_privileged_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
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

    Ok(Authorization::from_attempt(result))
}

async fn test_host_network_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
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

    Ok(Authorization::from_attempt(result))
}

async fn test_host_ipc_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
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

    Ok(Authorization::from_attempt(result))
}

async fn test_host_user_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
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

    Ok(Authorization::from_attempt(result))
}

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

/// tenant2 runs a process carrying a marker string; tenant1 joins the host PID
/// namespace on the same node and looks for it. Seeing another tenant's
/// processes is the breach.
fn process_namespace_experiment() -> BreachExperiment {
    BreachExperiment {
        what: "host PID namespace",
        target: create_target_process_pod("target-process"),
        // The target loops printing this, so its presence proves the process
        // the intruder is hunting actually exists.
        target_service: None,
        secret: Secret::ConfirmedBy("TENANT2_UNIQUE_MARKER".to_string()),
        // PID namespaces are per-node.
        intruder: Intruder::OnTargetNode(|node| {
            create_process_spy_pod("spy-process", node, "target-process")
        }),
        // The intruder decides for itself and says so.
        breach: BreachCondition::IntruderReports("TENANT2_PROCESS_FOUND"),
    }
}

/// tenant2 serves a page; tenant1 joins the host network namespace and tries to
/// fetch it directly by pod IP.
fn network_namespace_experiment() -> BreachExperiment {
    BreachExperiment {
        what: "host network namespace",
        target: create_network_target_pod("network-target"),
        target_service: None,
        secret: Secret::ConfirmedBy("Starting network target server".to_string()),
        // Needs the address rather than the node: the question is reachability.
        intruder: Intruder::AtTargetAddress(|ip| create_network_spy_pod("network-spy", ip)),
        breach: BreachCondition::IntruderReports("NETWORK_ACCESS_SUCCESS"),
    }
}

/// tenant1 reads its own UID map to see whether container root is host root.
///
/// The odd one out: there is nothing to plant. The "target" exists only so the
/// experiment has a victim to name, and the intruder's own `/proc/self/uid_map`
/// is the whole measurement — which is why the control here is only readiness.
fn user_namespace_experiment() -> BreachExperiment {
    BreachExperiment {
        what: "host user namespace",
        target: create_user_target_pod("user-target"),
        target_service: None,
        // The key's name is the secret: unpredictable, and published by the
        // target so the intruder knows what to look for.
        secret: Secret::Published("KEYSTATE:"),
        intruder: Intruder::FromTarget(|target| {
            create_user_spy_pod("user-spy", &target.node, &target.secret)
        }),
        breach: BreachCondition::Decided(classify_user_namespace),
    }
}

/// tenant2 creates System V IPC objects in the host IPC namespace and prints a
/// fingerprint of them; tenant1 joins the same namespace and fingerprints what
/// it can see. Matching fingerprints mean one shared namespace.
fn ipc_namespace_experiment() -> BreachExperiment {
    BreachExperiment {
        what: "host IPC namespace",
        target: create_ipc_target_pod("ipc-target"),
        target_service: None,
        secret: Secret::Published("Fingerprint:"),
        // IPC namespaces do not span machines, so an intruder scheduled
        // elsewhere would fingerprint an unrelated node and see nothing.
        intruder: Intruder::OnTargetNode(|node| create_ipc_spy_pod("ipc-spy", node)),
        breach: BreachCondition::IntruderRepeatsSecret,
    }
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
    /// The pod never really ran, so nothing was attempted — no signal.
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
                    details: "Privileged container reached no other tenant's processes - \
                              the kernel it can act on is not shared"
                        .to_string(),
                }
            } else {
                CrossTenantResult {
                    isolation: IsolationLevel::Unknown,
                    autonomy: true,
                    details: "The tenant2 target was not confirmed running, so finding \
                              nothing proves nothing - cannot conclude"
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

/// tenant1 gets a privileged container and tries to reach tenant2's processes
/// through the kernel — eBPF first, then a hand-built kernel module.
///
/// The one experiment whose verdict is not binary, because the ways it can fail
/// mean different things: denied EPERM is the platform stopping it (`Soft`),
/// a module that loads but sees nobody means a separate kernel (`Hard`), and a
/// toolchain that never built means we learned nothing (`Unknown`). See
/// `BreachCondition::Decided`.
fn privileged_syscalls_experiment() -> BreachExperiment {
    BreachExperiment {
        what: "privileged syscalls",
        target: create_non_privileged_target_pod("tenant2-target"),
        // The target reports the host kernel it shares; without that line the
        // escape pod cannot pick a matching build image, so its absence means
        // the experiment cannot run.
        target_service: None,
        secret: Secret::ConfirmedBy("UNAME_R=".to_string()),
        intruder: Intruder::FromTarget(|target| {
            // A container shares the host kernel but not its distribution, so
            // the only way to learn which headers to install is to ask a pod
            // already running on it.
            let distro = detect_host_distro(
                &extract_log_value(&target.logs, "PROC_VERSION="),
                &extract_log_value(&target.logs, "UNAME_R="),
            );
            create_privileged_escape_pod("kernel-escape", &target.node, distro)
        }),
        breach: BreachCondition::Decided(classify_privileged_escape),
    }
}

/// Turn the escape pod's markers into one of four verdicts.
///
/// The capability line is the backbone: a pod that never printed one did not
/// really run, which is a tooling failure rather than stripped capabilities,
/// and must not be read as isolation.
fn classify_privileged_escape(escape_logs: &str) -> CrossTenantResult {
    let caps_reported = escape_logs.contains("CAPS_FULL") || escape_logs.contains("CAPS_DROPPED");
    let caps_full = !caps_reported || escape_logs.contains("CAPS_FULL");

    let breach = if !caps_reported {
        PrivilegedBreach::ToolingFailed
    } else if escape_logs.contains("TOOLCHAIN_UNREACHABLE")
        && !escape_logs.contains("MODULE_LOADED")
        && !escape_logs.contains("TENANT2_PROCESS_FOUND")
    {
        // Held the capability, never got to use it. Ranked above the
        // build-outcome cases below, which would otherwise read this as a
        // container that tried and reached nothing.
        PrivilegedBreach::ToolingFailed
    } else if escape_logs.contains("TENANT2_PROCESS_FOUND") {
        PrivilegedBreach::SawOtherTenant
    } else if escape_logs.contains("MODULE_SIG_REQUIRED") {
        PrivilegedBreach::SignatureRequired
    } else if escape_logs.contains("MODULE_DENIED_EPERM") {
        PrivilegedBreach::DeniedEperm
    } else {
        // Everything else — the module loaded and saw nobody, or it could not
        // be built at all — is the same answer to the only question this
        // property asks: a container holding CAP_SYS_ADMIN did not reach the
        // other tenant.
        //
        // The build outcome used to decide this, and it made the verdict a
        // fact about the probe rather than about the platform. Under Kata the
        // build always fails, because no distribution ships headers for its
        // guest kernel, and the property reported `Unknown` — as though the
        // runtime's isolation were in doubt, when what was in doubt was our
        // ability to compile. If the breach had been possible it would have
        // shown up as the other tenant's processes; it did not.
        PrivilegedBreach::LoadedOwnOnly
    };

    info!("Privileged escape: caps_full={caps_full}, breach={breach:?}");

    // The executor only reaches here once the target is confirmed running.
    privileged_verdict(false, caps_full, breach, true)
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
        // Can this tenant reach a package repository at all?
        //
        // The build below needs a compiler and kernel headers, and both arrive
        // over the network. A tenant whose egress is restricted — a Kube-OVN
        // VPC or private Subnet, for instance — cannot fetch them, the build
        // fails, and "the build failed" is otherwise indistinguishable from
        // "the container tried the breach and reached nothing". The second is
        // isolation; the first is a probe that never ran, and reporting it as
        // isolation makes the workload verdict a fact about the *network*
        // configuration.
        // Asked of the package manager, not of `curl`.
        //
        // This used to `curl https://deb.debian.org` — but the escape image is a
        // bare `ubuntu:*`, which ships no curl, and curl is installed only by
        // the very step this guards. So the test could not succeed on any
        // Ubuntu host: `curl` was not found, the check reported
        // TOOLCHAIN_UNREACHABLE, and the classifier ranks that above every
        // other outcome — so `Use Privileged Syscalls` returned `Unknown` for
        // every such solution regardless of what the platform does.
        //
        // `apt-get update` / `dnf makecache` need no extra binary and test the
        // repository the build actually fetches from, which is the thing worth
        // knowing.
        lines.extend([
            "",
            "# --- can we fetch a toolchain at all? -------------------------------",
        ]);
        match self {
            HostDistro::Ubuntu { .. } => lines.extend([
                "export DEBIAN_FRONTEND=noninteractive",
                "if ! apt-get update >/dev/null 2>&1; then",
                "  echo 'TOOLCHAIN_UNREACHABLE: no egress to a package repository, so the \\",
                "breach could not be attempted'",
                "fi",
            ]),
            HostDistro::Fedora { .. } => lines.extend([
                "if ! dnf makecache >/dev/null 2>&1; then",
                "  echo 'TOOLCHAIN_UNREACHABLE: no egress to a package repository, so the \\",
                "breach could not be attempted'",
                "fi",
            ]),
        }
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
            "# Header-free via BTF. We read the GLOBAL task-list STATE directly - the",
            "# exact analog of the module's for_each_process(): a BEGIN program walks",
            "# the circular task list from curtask in kernel memory. Unlike a BPF task",
            "# iterator (PID-namespace scoped, sees only the pod) or a scheduler",
            "# tracepoint (perf-based, and restricted/misreported under a nesting",
            "# runtime like Docker/kind), reading state is not namespaced, needs no",
            "# tracefs and no scheduling luck, and enumerates every host task. A",
            "# positive result skips the module build. If injection is REFUSED while",
            "# BPF is advertised and the caps are held, that is Soft confinement and we",
            "# conclude it here; any other quiet/error result falls through to the",
            "# authoritative module build - we never conclude isolation from silence.",
            "if [ -r /sys/kernel/btf/vmlinux ]; then",
        ];
        lines.extend(install.iter().copied());
        lines.extend([
            "  if command -v bpftrace >/dev/null 2>&1; then",
            // Raising memlock helps BPF map creation on hosts that still gate it on
            // RLIMIT_MEMLOCK; harmless where it is already unlimited or unraisable.
            "    ulimit -l unlimited 2>/dev/null || true",
            // Let the tenant2 sentinel finish launching before we snapshot the
            // task list (the target pod is already Ready; this is a safety margin).
            "    sleep 2",
            // Walk the global process list from `curtask` (bpftrace's own task - a
            // real task on the shared host kernel). container_of(t->tasks.next,
            // task_struct, tasks) advances the circular list; stop when we return
            // to the start. curtask avoids kaddr(\"init_task\"), whose address is
            // zeroed by kptr_restrict inside a container. Bounded (4096) for the
            // verifier; BTF gives correct field offsets on any kernel. Single quotes
            // keep the shell from expanding bpftrace's $s/$t/$n variables.
            "    bt=$(timeout 30 bpftrace -e 'BEGIN { $s = curtask; $t = $s; $n = 0; while ($n < 4096) { $t = (struct task_struct *)((uint64)$t->tasks.next - (uint64)offsetof(struct task_struct, tasks)); if ($t == $s) { break; } printf(\"BPFTASK %d %s\\n\", $t->pid, $t->comm); $n = $n + 1; } printf(\"BPFWALK_TOTAL %d\\n\", $n); exit(); }' 2>&1)",
            "    bpf_verdict=''",
            // Reading the tenant2 sentinel, or the whole host process list, from
            // the global task list proves a shared kernel with no isolation.
            "    bpf_tasks=$(printf '%s' \"$bt\" | grep -c '^BPFTASK')",
            "    echo \"BPF_TASKS_WALKED: $bpf_tasks\"",
            "    if printf '%s' \"$bt\" | grep -q '__SENTINEL__'; then",
            "      echo 'TENANT2_PROCESS_FOUND: walked the global task list and read the tenant2 sentinel from kernel space'",
            "      bpf_verdict=done",
            // Walking many tasks is NOT the breach.
            //
            // This used to declare one whenever the walk returned more than
            // twenty tasks, on the reasoning that a container seeing that many
            // must be looking at the host. Inside a VM the tenant is root of
            // its own kernel and sees its own processes — dozens of them — so
            // under KubeVirt the probe reported "read the whole host, shared
            // kernel, no isolation" for two tenants on entirely separate
            // kernels. It went unnoticed only because the pod never used to be
            // scheduled at all.
            //
            // The breach is reading *the other tenant*, and the sentinel above
            // is what identifies it: an unpredictable comm the victim planted.
            // A long task list without it is the intruder looking at its own
            // machine, which is what a lone tenant sees too.
            "    elif [ \"$bpf_tasks\" -gt 20 ]; then",
            "      echo \"MODULE_LOADED: walked $bpf_tasks tasks and none was the other tenant's sentinel\"",
            "      bpf_verdict=done",
            "    else",
            // No task lines. Distinguish two very different reasons. We only reach
            // here because /sys/kernel/btf/vmlinux exists, i.e. the kernel ADVERTISES
            // BPF, and the caps are held (CAPS_FULL above). If BPF program injection
            // is nonetheless REFUSED (EPERM) - a user-namespace remap, an LSM, or
            // kernel lockdown - then a privileged operation we should be able to do
            // was blocked: that is Soft isolation, and the BPF stage concludes it
            // directly (no need to also fail the same way via the module).
            // BTF present (this guard) proves the kernel is modern and BPF-capable,
            // so bpftrace saying \"your kernel is too old / missing BPF_MAP_TYPE_*\"
            // is a FALSE conclusion from a feature-probe bpf() call being EPERM'd -
            // i.e. injection was blocked, not absent. Together with an outright
            // EPERM/lockdown, that is confinement despite held caps => Soft.
            "      case \"$bt\" in",
            "        *'Operation not permitted'*|*'Permission denied'*|*'Creation of the required BPF maps has failed'*|*'not confined'*|*lockdown*|*'too old'*|*'missing the BPF'*|*'BPF_MAP_TYPE_'*)",
            "          echo 'MODULE_DENIED_EPERM: kernel advertises BPF (BTF present) and the caps are held, but BPF program injection was refused/blocked - user-namespace / LSM / lockdown confinement'",
            "          bpf_verdict=done ;;",
            "        *)",
            // A program-level error instead (bpftrace ran but disliked our script,
            // e.g. a version too old for the walk syntax). Not proof of isolation -
            // fall through to the authoritative kernel-module build.
            "          echo \"BPFTRACE_INCONCLUSIVE: walked_tasks=$bpf_tasks - verifying via kernel module ($(printf '%s' \"$bt\" | tail -n 1 | tr '\\n' ' '))\" ;;",
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
    // The capability backbone and eBPF/module breach preamble, in
    // probes/escape_head.sh. Extracted from this Rust array so it can be read,
    // linted and syntax-highlighted as the shell it is; `include_str!` fixes it
    // at compile time, so it cannot drift from what ships.
    let head = include_str!("../probes/escape_head.sh");

    // Module source, build, and load (distro-agnostic): consumes $KDIR.
    // The kernel-module build, load, and /proc/tenant_spy read — the bulk of
    // the script, and all static. In probes/escape_tail.sh.
    let tail = include_str!("../probes/escape_tail.sh");

    // head (capabilities) -> eBPF breach (primary, header-free; exits on a
    // conclusive result) -> distro-specific header setup -> tail (module
    // build/load, the fallback reached only when the eBPF stage was inconclusive).
    // head and tail already carry a trailing newline, so the distro-specific
    // middle slots between them without extra separators. The middle stays in
    // Rust because it is genuinely computed — the escape image's package
    // manager and the eBPF availability check differ per distro.
    let middle: String = distro
        .bpftrace_breach_lines()
        .into_iter()
        .chain(distro.header_setup_lines())
        .map(|line| format!("{line}\n"))
        .collect();
    // The .sh files end with a newline, as text files should; the original
    // `join("\n")` did not. Drop the one trailing newline so the assembled
    // script is byte-identical to what this replaced — a trailing newline is
    // inert to the shell, but exact equality is what makes the extraction
    // provably a no-op.
    let script = format!("{head}{middle}{tail}");
    let script = script.strip_suffix('\n').unwrap_or(&script).to_string();

    let image = distro.escape_image();

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
        },
        "spec": {
            "nodeName": node_name,
            // Stamped explicitly because this manifest predates `ProbePod` and
            // does not inherit its defaults. Without it the probe runs on the
            // node's default runtime whatever `--runtime-class` was asked for,
            // and a sandbox that was never applied reports as a sandbox that
            // failed.
            "runtimeClassName": crate::assessment::probe::runtime_class_for_manifest(),
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

/// The tenant whose processes the escape probe tries to find.
///
/// Deliberately hardened: it asks for nothing, drops every capability and runs
/// as an ordinary user. That is the point — anything the intruder can see of
/// this pod is something the platform failed to hide, not something this pod
/// invited.
///
/// `task->comm` follows the executable's basename, not `argv[0]` (so `exec -a`
/// cannot set it), hence copying a binary to a tenant2-named path and running
/// it in the background. It must be a standalone binary: `/bin/sleep` on modern
/// distros is the coreutils multi-call binary, which dispatches on `argv[0]`
/// and refuses an unknown name. A shell has no such dispatch, so bash is copied
/// (sh as fallback) and loops. That process is what the eBPF iterator matches
/// on `comm`; the foreground `tail -f` keeps the pod alive and its cmdline
/// still carries the `tenant2_marker` token the kernel-module fallback matches.
///
/// `PROC_VERSION` and `UNAME_R` identify the host kernel this pod shares, so
/// the tool can pick a matching image for the escape pod's module build. Both
/// are readable by any user, are not namespaced, and need no mount.
///
/// One deliberate difference from the manifest this replaces: `restricted()`
/// adds a `RuntimeDefault` seccomp profile the original omitted, and drops an
/// `fsGroup: 1000` that was inert here because the pod mounts no volumes. The
/// seccomp profile makes the target admissible under a tenant enforcing the
/// `restricted` standard, where it previously would have been refused — which
/// is a fix, but one whose effect is visible only against a live cluster.
fn create_non_privileged_target_pod(pod_name: &str) -> Pod {
    let script = format!(
        "echo \"PROC_VERSION=$(cat /proc/version)\" && \
         echo \"UNAME_R=$(uname -r)\" && \
         echo 'TENANT2_TARGET_STARTED' && \
         secret_data=$(date +%s | sha256sum | cut -d' ' -f1 | head -c 16) && \
         echo \"SECRET_DATA: $secret_data\" && \
         mkdir -p /tmp/tenant2_marker && \
         echo \"tenant2\" > /tmp/tenant2_marker/$secret_data && \
         (cp /bin/bash /tmp/{sentinel} 2>/dev/null || cp /bin/sh /tmp/{sentinel}) && \
         {{ /tmp/{sentinel} -c 'while true; do sleep 3600; done' & }} && \
         tail -f /tmp/tenant2_marker/$secret_data",
        sentinel = TENANT2_SENTINEL_COMM,
    );

    ProbePod::new(pod_name)
        .container("tenant2-app")
        .image("ubuntu:latest")
        .label("app", "privileged-target")
        .label("workload-test", "target")
        .label("tenant", "tenant2")
        .restricted()
        .shell(script)
        .build()
}

/// Asks to share the host user namespace, so UIDs are not remapped.
///
/// Admission refusing it is the finding; admission allowing it hands the next
/// stage of the probe something to look for.
fn create_host_user_test_pod(pod_name: &str) -> Pod {
    ProbePod::new(pod_name).requests(HostAccess::Users).build()
}

/// An ordinary long-lived pod, owned by the other tenant.
///
/// The control in the user-namespace pairing: it asks for nothing, so anything
/// the spy can see of it is something the platform failed to hide.
fn create_user_target_pod(pod_name: &str) -> Pod {
    ProbePod::new(pod_name)
        .container("user-target")
        .label("app", "user-target")
        .label("workload-test", "target")
        // Enough to install keyutils. Inside a Kata guest the default 128Mi
        // OOM-kills `apk add`, leaving no keyctl and a target that plants
        // nothing — which the harness correctly reported as `Unknown`, and
        // which said nothing whatever about the runtime's isolation.
        .memory_limit("512Mi")
        // The key's name is generated here, so it cannot be guessed and a
        // spurious match is impossible: tenant1 finding *this* name in its own
        // user keyring means the keyring really is shared.
        .shell(
            "apk add --no-cache keyutils >/dev/null 2>&1 || true && \
             name=kumuteva-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \\n') && \
             if keyctl add user \"$name\" tenant2-user-keyring @u >/dev/null 2>&1; then \
               echo \"KEYSTATE: $name\"; \
             else \
               echo 'KEYSTATE: UNAVAILABLE'; \
             fi && \
             sleep 3600",
        )
        .build()
}

/// Searches its own user keyring for a key planted by the other tenant.
///
/// The user keyring `@u` is keyed on `(uid, user namespace)` and on nothing
/// else — not the mount, PID, IPC or network namespace. So two containers find
/// each other's keys exactly when they are the same uid in the same user
/// namespace, which is the question this property asks and the reason this
/// probe needs no other host access.
///
/// It replaces a read of `/proc/self/uid_map`. That inferred a breach from
/// `0 0 4294967295` without ever attempting one, and under a sandbox it was
/// simply wrong: the container really is root, of a machine the other tenant
/// is not on. Here a breach is something the intruder does, not something it
/// concludes.
fn create_user_spy_pod(pod_name: &str, node_name: &str, key_name: &str) -> Pod {
    // Its own key first. If the keyring cannot be used at all — a runtime that
    // does not implement `keyctl`, or a seccomp profile that blocks it — then
    // finding nothing says nothing, and the verdict must not be isolation.
    // When the other tenant could not plant either, search for a name that
    // cannot exist: the point is no longer to find it but to learn what the
    // kernel says when asked, which is the answer this property turns on.
    let wanted = if key_name == "UNAVAILABLE" {
        "kumuteva-cannot-exist"
    } else {
        key_name
    };
    let script = format!(
        "apk add --no-cache keyutils >/dev/null 2>&1 || true && \
         if keyctl add user kumuteva-selftest own @u >/dev/null 2>&1; then \
           echo 'KEYRING_USABLE'; \
         else \
           echo \"KEYRING_SELFTEST_FAILED: $(keyctl add user kumuteva-selftest own @u 2>&1)\"; \
         fi && \
         if keyctl search @u user '{wanted}' >/dev/null 2>&1; then \
           echo 'KEYRING_KEY_FOUND: reached the other tenant through the shared user keyring'; \
         else \
           echo \"KEYRING_SEARCH_FAILED: $(keyctl search @u user '{wanted}' 2>&1)\"; \
         fi"
    );

    ProbePod::new(pod_name)
        .container("user-spy")
        .on_node(node_name)
        // Same reason as the target: it installs keyutils before it can look.
        .memory_limit("512Mi")
        .requests(HostAccess::Users)
        .run_as_user(0)
        .shell(script)
        .build()
}

/// Turn the keyring probe's markers into a verdict.
///
/// The distinction that matters is *what the kernel said when asked*, which is
/// the whole of the soft/hard rule: an operation refused is soft, an operation
/// that does not exist in this context is hard.
///
/// gVisor answers `keyctl search` with `ENOSYS` — the keyring interface is not
/// there at all — so a tenant cannot reach another's keys because there is no
/// keyring to reach. That is hard, and it is why this cannot key on the
/// target having planted successfully: under gVisor neither tenant can plant,
/// and the property would report `Unknown` for a channel that is closed.
///
/// The verdict still rests on the intruder's own evidence, never on the
/// target's failure alone.
fn classify_user_namespace(intruder_output: &str) -> CrossTenantResult {
    let says = |needle: &str| {
        intruder_output
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    };

    if intruder_output.contains("KEYRING_KEY_FOUND") {
        return CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "host user namespace: the intruder found the other tenant's key in its \
                      own user keyring - same uid in the same user namespace"
                .to_string(),
        };
    }

    // ENOSYS. The tenant asked and the kernel it is on has no such facility,
    // which is exactly what a lone tenant on its own machine would be told.
    if says("function not implemented") {
        return CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "host user namespace: the keyring interface does not exist in this \
                      context, so no other tenant's keys are reachable through it"
                .to_string(),
        };
    }

    // It could use its own keyring and the other tenant's key was not in it.
    if intruder_output.contains("KEYRING_USABLE") {
        return CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "host user namespace: the intruder could use its own user keyring and \
                      the other tenant's key was not in it - the user namespace is not shared"
                .to_string(),
        };
    }

    // EPERM. Something refused it, which tells the tenant a restriction
    // exists — soft, not hard.
    if says("permission denied") || says("operation not permitted") {
        return CrossTenantResult {
            isolation: IsolationLevel::Soft(
                "The user keyring was refused to this tenant".to_string(),
            ),
            autonomy: false,
            details: "host user namespace: the platform refused this tenant the user keyring \
                      rather than giving it one of its own"
                .to_string(),
        };
    }

    // The probe installs `keyutils` at run time, so it can arrive without the
    // one tool it needs — and then every branch above misses, because the
    // kernel was never asked anything. Said plainly rather than folded into the
    // generic case below: "the tool is missing" is a fact about this harness,
    // and reading it as a fact about the platform is how a broken probe becomes
    // a verdict.
    if says("not found") || says("no such file") {
        return CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: "host user namespace: `keyctl` was not present in the probe, so the \
                      keyring was never asked anything — this measures the probe's own \
                      tooling, not the platform"
                .to_string(),
        };
    }

    CrossTenantResult {
        isolation: IsolationLevel::Unknown,
        autonomy: true,
        details: format!(
            "host user namespace: the intruder neither reached the other tenant nor \
             reported why, so nothing was established — it said: {}",
            intruder_output.trim().chars().take(160).collect::<String>()
        ),
    }
}

/// Asks to see every process on the node.
///
/// Admission refusing it is the finding; admission allowing it hands the next
/// stage of the probe something to look for.
fn create_host_pid_test_pod(pod_name: &str) -> Pod {
    ProbePod::new(pod_name).requests(HostAccess::Pid).build()
}

/// Asks for full privilege on the node.
fn create_privileged_test_pod(pod_name: &str) -> Pod {
    ProbePod::new(pod_name)
        .requests(HostAccess::Privileged)
        .build()
}

/// Asks to use the node's network stack directly.
///
/// Admission refusing it is the finding; admission allowing it hands the next
/// stage of the probe something to look for.
fn create_host_network_test_pod(pod_name: &str) -> Pod {
    ProbePod::new(pod_name)
        .requests(HostAccess::Network)
        .build()
}

/// Asks to reach the node's System V IPC objects.
///
/// Admission refusing it is the finding; admission allowing it hands the next
/// stage of the probe something to look for.
fn create_host_ipc_test_pod(pod_name: &str) -> Pod {
    ProbePod::new(pod_name).requests(HostAccess::Ipc).build()
}

/// Creates IPC objects in the host namespace for the spy to find.
///
/// Joins the host IPC namespace itself: if it did not, there would be nothing
/// shared to discover and the spy's silence would look like isolation.
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

    ProbePod::new(pod_name)
        .container("ipc-target")
        .image("ubuntu:latest")
        .label("app", "ipc-target")
        .label("workload-test", "target")
        .requests(HostAccess::Ipc)
        .shell(script)
        .build()
}

/// Asks to reach the node's IPC objects, from the target's own node.
///
/// Fingerprints whatever segments, semaphores and queues are visible; the
/// target publishes the same fingerprint, so a match is a breach.
fn create_ipc_spy_pod(pod_name: &str, node_name: &str) -> Pod {
    let script = "sleep 10 && \
                  fingerprint=`(ipcs -m; ipcs -s; ipcs -q) | sha1sum | cut -d' ' -f1` && \
                  echo 'Fingerprint: ' $fingerprint";

    ProbePod::new(pod_name)
        .container("ipc-spy")
        .image("ubuntu:latest")
        .on_node(node_name)
        .requests(HostAccess::Ipc)
        .shell(script)
        .build()
}

/// Runs a process carrying a marker string, for the spy to look for.
///
/// Deliberately unprivileged and in its own namespaces — it is the thing that
/// should stay invisible.
fn create_target_process_pod(pod_name: &str) -> Pod {
    let script = "echo 'Starting target process with unique marker...'; \
                  while true; do \
                    echo 'TENANT2_UNIQUE_MARKER: Running...'; \
                    sleep 30; \
                  done";

    ProbePod::new(pod_name)
        .container("target-process")
        .label("app", "target-process")
        .label("workload-test", "target")
        .shell(script)
        .build()
}

/// Looks for the target's processes from the host PID namespace.
///
/// The container name is preserved deliberately: the script excludes its own
/// `ps` line by matching the literal `spy-process`, so renaming it would make
/// the spy find itself and report a breach that is only its own reflection.
///
/// **Asks for `hostPid` and nothing else, deliberately.** It used to request
/// `privileged` as well, which this property does not need — reading `/proc`
/// from the node's PID namespace requires the namespace, not privilege — and
/// the extra request quietly changed what was being measured. Under gVisor,
/// which refuses to start any privileged container, the pod never ran at all,
/// so the property reported the sandbox declining a privileged request rather
/// than whether the PID namespace was isolated. Each property must stand on
/// its own: privilege is what `privileged_syscalls_experiment` measures.
fn create_process_spy_pod(pod_name: &str, node_name: &str, target_pod_name: &str) -> Pod {
    let script = format!(
        "echo 'Searching for tenant2 processes...' && \
         for i in $(seq 1 30); do \
           if ps aux | grep -i 'TENANT2_UNIQUE_MARKER\\|{target}' | grep -v grep | grep -v spy-process; then \
             echo 'TENANT2_PROCESS_FOUND: Isolation breach detected!'; \
             ps aux | grep -i 'TENANT2_UNIQUE_MARKER\\|{target}' | grep -v grep | grep -v spy-process; \
             break; \
           fi; \
           echo \"Attempt $i: No tenant2 processes visible\"; \
           sleep 2; \
         done; \
         echo 'Process visibility check completed'",
        target = target_pod_name
    );

    ProbePod::new(pod_name)
        .container("spy-process")
        .on_node(node_name)
        .requests(HostAccess::Pid)
        .shell(script)
        .build()
}

/// Serves a marker page for the network spy to fetch.
fn create_network_target_pod(pod_name: &str) -> Pod {
    let script = "echo 'Starting network target server...' && \
                  echo '<h1>TENANT2_NETWORK_TARGET</h1>' > /usr/share/nginx/html/index.html && \
                  nginx -g 'daemon off;'";

    ProbePod::new(pod_name)
        .container("network-target")
        .image("nginx:alpine")
        .label("app", "network-target")
        .label("workload-test", "target")
        .port(80)
        .shell(script)
        .build()
}

/// Tries to reach the other tenant's marker page from the host network.
fn create_network_spy_pod(pod_name: &str, target_ip: &str) -> Pod {
    let script = format!(
        "echo 'Testing cross-tenant network access...' && \
         for i in $(seq 1 10); do \
           echo \"Attempt $i: Trying to connect to {target}:80\" && \
           if curl -s --connect-timeout 5 {target}:80 | grep -q 'TENANT2_NETWORK_TARGET'; then \
             echo 'NETWORK_ACCESS_SUCCESS: Cross-tenant network access detected!'; \
             break; \
           fi; \
           sleep 2; \
         done; \
         echo 'Network access test completed'",
        target = target_ip
    );

    ProbePod::new(pod_name)
        .container("network-spy")
        .image("alpine/curl:latest")
        .requests(HostAccess::Network)
        .shell(script)
        .build()
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

    /// Both keyring probes must have room to install their tool.
    ///
    /// At the shared 128Mi default, `apk add` is OOM-killed inside a Kata
    /// guest; keyctl is then missing, the target plants nothing, and the
    /// property reports `Unknown` — describing the limit rather than the
    /// runtime.
    #[test]
    fn the_keyring_probes_have_room_to_install_keyutils() {
        for pod in [
            create_user_target_pod("user-target"),
            create_user_spy_pod("user-spy", "node-1", "kumuteva-abc123"),
        ] {
            let limit = pod.spec.as_ref().expect("spec").containers[0]
                .resources
                .as_ref()
                .and_then(|resources| resources.limits.as_ref())
                .and_then(|limits| limits.get("memory"))
                .expect("probes always declare limits");
            assert_eq!(limit.0, "512Mi");
        }
    }

    /// Finding the other tenant's key is the breach — nothing is inferred.
    #[test]
    fn a_key_found_in_the_shared_user_keyring_is_a_breach() {
        let result = classify_user_namespace(
            "KEYRING_USABLE\n\
             KEYRING_KEY_FOUND: reached the other tenant through the shared user keyring",
        );
        assert_eq!(result.isolation, IsolationLevel::None);
    }

    /// Looked, and it was not there.
    #[test]
    fn a_usable_keyring_without_the_other_tenants_key_is_isolation() {
        let result = classify_user_namespace(
            "KEYRING_USABLE\nKEYRING_SEARCH_FAILED: keyctl_search: Required key not available",
        );
        assert_eq!(result.isolation, IsolationLevel::Hard);
        assert!(result.autonomy);
    }

    /// gVisor's exact answer. The interface is absent, not forbidden, which is
    /// the same thing a lone tenant on its own machine would be told — hard.
    ///
    /// This reported `Unknown`, because neither tenant could plant a key and
    /// the executor stopped there. The channel is closed, and saying so is not
    /// the same as failing to measure.
    #[test]
    fn a_missing_keyring_interface_is_hard_not_unknown() {
        let result = classify_user_namespace(
            "KEYRING_SELFTEST_FAILED: add_key: Function not implemented\n\
             KEYRING_SEARCH_FAILED: keyctl_search: Function not implemented",
        );
        assert_eq!(result.isolation, IsolationLevel::Hard);
        assert!(result.autonomy);
    }

    /// A refusal is soft, and must not be confused with the interface being
    /// absent — the two arrive as different errno values for a reason.
    #[test]
    fn a_refused_keyring_is_soft() {
        let result = classify_user_namespace(
            "KEYRING_SELFTEST_FAILED: add_key: Permission denied\n\
             KEYRING_SEARCH_FAILED: keyctl_search: Permission denied",
        );
        assert!(
            matches!(result.isolation, IsolationLevel::Soft(_)),
            "{:?}",
            result.isolation
        );
        assert!(!result.autonomy);
    }

    /// Silence still establishes nothing.
    #[test]
    fn an_intruder_that_reported_nothing_concludes_nothing() {
        assert_eq!(
            classify_user_namespace("").isolation,
            IsolationLevel::Unknown
        );
    }

    /// The probe must ask for the host user namespace and nothing else — the
    /// property is independent of every other host namespace, which is why the
    /// keyring is the medium: `@u` is keyed on the user namespace alone.
    #[test]
    fn the_user_spy_asks_only_for_the_user_namespace() {
        let pod = create_user_spy_pod("user-spy", "node-1", "kumuteva-abc123");
        let spec = pod.spec.as_ref().expect("spec");

        assert_eq!(spec.host_users, Some(true));
        assert_eq!(spec.host_pid, None);
        assert_eq!(spec.host_ipc, None);
        assert_eq!(spec.host_network, None);
        assert_ne!(
            spec.containers[0]
                .security_context
                .as_ref()
                .and_then(|context| context.privileged),
            Some(true)
        );
    }

    /// A tenant that could not fetch its toolchain never attempted anything.
    ///
    /// Reported `Hard` on `kubeovn-vpc` and `kubeovn-subnet`, whose egress
    /// restrictions stop `apt-get` reaching a repository. The build then fails
    /// and "the build failed" looks exactly like "tried the breach and reached
    /// nothing" — so the workload verdict became a fact about the network
    /// configuration rather than about privilege.
    #[test]
    fn a_tenant_that_could_not_fetch_a_toolchain_concludes_nothing() {
        let result = classify_privileged_escape(
            "CAPS_FULL: CAP_SYS_ADMIN present\n\
             TOOLCHAIN_UNREACHABLE: no egress to a package repository\n\
             HEADERS_UNAVAILABLE: no build tree in this image",
        );
        assert_eq!(result.isolation, IsolationLevel::Unknown);
    }

    /// But if it got far enough to load a module, no egress later is beside
    /// the point — the breach was attempted and reached nothing.
    #[test]
    fn an_attempted_breach_still_counts_even_if_egress_was_patchy() {
        let result = classify_privileged_escape(
            "CAPS_FULL: CAP_SYS_ADMIN present\n\
             TOOLCHAIN_UNREACHABLE: no egress to a package repository\n\
             MODULE_LOADED: tenant_spy inserted",
        );
        assert_eq!(result.isolation, IsolationLevel::Hard);
    }

    /// No breach means safe, whatever stopped the module from building.
    ///
    /// This read `Unknown` under Kata: the container really did hold
    /// CAP_SYS_ADMIN, but no distribution ships headers for Kata's guest
    /// kernel, so the build failed and the verdict described our compiler
    /// rather than the platform. The question the property asks is whether a
    /// privileged container reached the other tenant. It did not.
    #[test]
    fn a_failed_build_is_still_a_failed_breach() {
        let result = classify_privileged_escape(
            "CAPS_FULL: CAP_SYS_ADMIN present\n\
             TENANT2_TARGET_STARTED\n\
             HEADERS_UNAVAILABLE: no build tree for 6.18.35 in this image",
        );

        assert_eq!(result.isolation, IsolationLevel::Hard);
        assert!(result.autonomy, "the tenant kept the capability");
    }

    /// Reaching the other tenant is the one unsafe outcome.
    #[test]
    fn reaching_the_other_tenant_is_the_breach() {
        let result = classify_privileged_escape(
            "CAPS_FULL: CAP_SYS_ADMIN present\n\
             TENANT2_TARGET_STARTED\n\
             TENANT2_PROCESS_FOUND: saw the other tenant",
        );

        assert_eq!(result.isolation, IsolationLevel::None);
    }

    /// A container that never ran is still no evidence either way — the one
    /// case that must stay `Unknown`, or a dead probe scores as isolation.
    #[test]
    fn a_probe_that_never_reported_its_capabilities_concludes_nothing() {
        let result = classify_privileged_escape("some unrelated output");
        assert_eq!(result.isolation, IsolationLevel::Unknown);
    }

    #[test]
    fn escape_script_runs_ebpf_first_then_falls_back_to_the_module_build() {
        let script = pod_command_script(&create_privileged_escape_pod(
            "escape",
            "node-1",
            HostDistro::Ubuntu { release: None },
        ));
        // Primary: a header-free eBPF probe gated on the host's BTF. It must walk
        // the GLOBAL task list from curtask (kernel-state read), not the
        // namespace-scoped task iterator nor the perf-based scheduler tracepoint.
        assert!(script.contains("/sys/kernel/btf/vmlinux"));
        assert!(script.contains("$s = curtask"));
        assert!(script.contains("BPFTASK"));
        assert!(!script.contains("iter:task"));
        assert!(!script.contains("sched:sched_switch"));
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

    /// The egress test must not need a binary the image lacks.
    ///
    /// It used to `curl` a repository, on a bare `ubuntu:*` image that ships no
    /// curl and installs it only in the step this guards. Every Ubuntu host
    /// therefore reported TOOLCHAIN_UNREACHABLE, which outranks every other
    /// marker, and `Use Privileged Syscalls` came back `Unknown` no matter what
    /// the platform did.
    #[test]
    fn the_toolchain_reachability_test_uses_only_the_package_manager() {
        for distro in [
            HostDistro::Ubuntu { release: None },
            HostDistro::Fedora { release: None },
        ] {
            let script = distro.header_setup_lines().join("\n");
            let guard = script
                .split("can we fetch a toolchain at all?")
                .nth(1)
                .expect("the egress guard is present")
                .split("TOOLCHAIN_UNREACHABLE")
                .next()
                .expect("the guard reports unreachability");
            assert!(
                !guard.contains("curl"),
                "the guard runs before curl is installed: {guard}"
            );
            assert!(
                guard.contains("apt-get update") || guard.contains("dnf makecache"),
                "the guard must ask the package manager: {guard}"
            );
        }
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

#[cfg(test)]
mod probe_requests_what_it_claims {
    //! Every probe must actually ask for the privilege its name promises.
    //!
    //! These probes are written as `serde_json::json!` literals deserialised
    //! into `Pod`, and k8s-openapi's deserialiser *silently discards keys it
    //! does not recognise* — `_ => Field::Other` followed by
    //! `Field::Other => { let _: IgnoredAny = ... }` in its `pod_spec.rs`. So
    //! `"hostPid": true`, with the wrong capitalisation, produces a `PodSpec`
    //! with `host_pid: None`: no error, no panic, no warning.
    //!
    //! The consequence is not a crash but a wrong answer. A probe that fails to
    //! request hostPID sees no other tenant's processes, finds no breach, and
    //! the run reports Hard isolation — a green verdict from a probe that
    //! tested nothing. Nothing downstream can distinguish that from real
    //! isolation.
    //!
    //! Asserting on the *typed* struct rather than the literal is the point:
    //! it checks what the API server will actually receive.

    use super::*;

    /// Each property must be measured by a probe asking for that property and
    /// nothing more.
    ///
    /// `spy-process` asked for `privileged` on top of `hostPid`. Privilege is
    /// irrelevant to reading `/proc` from the node's PID namespace, and the
    /// surplus request changed the answer: gVisor refuses to start any
    /// privileged container, so under a sandbox the pod never ran and the
    /// property reported the refusal instead of whether the PID namespace was
    /// shared. Two independent properties had been welded into one probe.
    #[test]
    fn the_process_spy_asks_for_the_pid_namespace_and_no_privilege() {
        let pod = create_process_spy_pod("spy-process", "node-1", "target-process");
        let spec = pod.spec.as_ref().expect("the probe must have a spec");

        assert_eq!(
            spec.host_pid,
            Some(true),
            "without hostPID the spy sees only its own processes and reports \
             isolation it never tested"
        );

        let privileged = spec.containers[0]
            .security_context
            .as_ref()
            .and_then(|context| context.privileged);
        assert_ne!(
            privileged,
            Some(true),
            "privilege is what the privileged-syscalls property measures; \
             asking for it here makes a sandbox refusing the pod look like a \
             verdict about the PID namespace"
        );
    }

    /// The privileged-syscall probe, by contrast, *must* keep asking for it.
    #[test]
    fn the_privileged_escape_probe_still_asks_for_privilege() {
        let pod = create_privileged_escape_pod(
            "kernel-escape",
            "node-1",
            HostDistro::Ubuntu { release: None },
        );
        let privileged = pod.spec.as_ref().expect("spec").containers[0]
            .security_context
            .as_ref()
            .and_then(|context| context.privileged);
        assert_eq!(privileged, Some(true));
    }

    /// The JSON these probes were built from before the builder existed.
    ///
    /// Kept as the reference for the conversion: if the builder produces the
    /// same `Pod`, the swap cannot have changed what the API server sees, and
    /// no cluster run is needed to establish it. Only the container name
    /// differs — `test` became `probe` — which nothing selects on, since every
    /// probe has exactly one container and `AttachParams::default()` does not
    /// name one.
    fn legacy_json(pod_name: &str, host_field: Option<&str>, privileged: bool) -> Pod {
        let mut spec = serde_json::json!({
            "containers": [{
                "name": "probe",
                "image": "alpine:latest",
                "command": ["sleep", "1"],
                "resources": {
                    "requests": { "memory": "64Mi", "cpu": "250m" },
                    "limits": { "memory": "128Mi", "cpu": "500m" }
                }
            }],
            "restartPolicy": "Never",
        });
        if let Some(field) = host_field {
            spec[field] = serde_json::json!(true);
        }
        if privileged {
            spec["containers"][0]["securityContext"] = serde_json::json!({ "privileged": true });
        }
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": pod_name },
            "spec": spec,
        }))
        .unwrap()
    }

    #[test]
    fn the_builder_reproduces_the_json_it_replaced() {
        assert_eq!(
            create_host_pid_test_pod("p"),
            legacy_json("p", Some("hostPID"), false)
        );
        assert_eq!(
            create_host_ipc_test_pod("p"),
            legacy_json("p", Some("hostIPC"), false)
        );
        assert_eq!(
            create_host_network_test_pod("p"),
            legacy_json("p", Some("hostNetwork"), false)
        );
        assert_eq!(
            create_host_user_test_pod("p"),
            legacy_json("p", Some("hostUsers"), false)
        );
        assert_eq!(
            create_privileged_test_pod("p"),
            legacy_json("p", None, true)
        );
    }

    fn spec(pod: &Pod) -> &k8s_openapi::api::core::v1::PodSpec {
        pod.spec.as_ref().expect("probe pod must have a spec")
    }

    #[test]
    fn the_spy_script_survived_being_moved_into_the_builder() {
        // Shell inside a Rust string inside a JSON literal was three levels of
        // escaping; the builder removes one of them, and getting the remaining
        // two wrong silently changes what the probe greps for. A `\\|`
        // that became `\\\\|` would search for a literal backslash and never
        // match, so the probe would find nothing and report isolation.
        let pod = create_process_spy_pod("spy", "node-1", "victim-pod");
        let script = &pod.spec.as_ref().unwrap().containers[0]
            .command
            .as_ref()
            .expect("the script is the third element of the sh -c command")[2];

        // The alternation must reach the shell as a single backslash-pipe.
        assert!(
            script.contains(r"TENANT2_UNIQUE_MARKER\|victim-pod"),
            "grep alternation mangled: {script}"
        );
        // Self-exclusion, without which the spy matches its own command line.
        assert!(script.contains("grep -v spy-process"));
        // The quoting around the progress message must still be shell quoting.
        assert!(script.contains(r#"echo "Attempt $i"#));
    }

    #[test]
    fn host_namespace_probes_request_their_namespace() {
        assert_eq!(
            spec(&create_host_pid_test_pod("p")).host_pid,
            Some(true),
            "the hostPID probe must request hostPID or it proves nothing"
        );
        assert_eq!(spec(&create_host_ipc_test_pod("p")).host_ipc, Some(true));
        assert_eq!(
            spec(&create_host_network_test_pod("p")).host_network,
            Some(true)
        );
        assert_eq!(
            spec(&create_host_user_test_pod("p")).host_users,
            Some(true),
            "hostUsers is a recent field; a version of k8s-openapi without it \
             would drop this silently"
        );
    }

    #[test]
    fn spy_probes_request_both_the_namespace_and_the_node() {
        // A spy has to land on the same node as its target, or it looks past an
        // empty machine and reports isolation it never tested.
        let ipc = create_ipc_spy_pod("spy", "node-1");
        assert_eq!(spec(&ipc).host_ipc, Some(true));
        assert_eq!(spec(&ipc).node_name.as_deref(), Some("node-1"));

        let process = create_process_spy_pod("spy", "node-1", "target");
        assert_eq!(spec(&process).host_pid, Some(true));
        assert_eq!(spec(&process).node_name.as_deref(), Some("node-1"));

        let network = create_network_spy_pod("spy", "10.0.0.1");
        assert_eq!(spec(&network).host_network, Some(true));

        let user = create_user_spy_pod("spy", "node-1", "kumuteva-abc123");
        assert_eq!(spec(&user).host_users, Some(true));
    }

    #[test]
    fn the_ipc_target_shares_the_host_namespace_it_is_meant_to_be_seen_in() {
        // The target is half the experiment: if it does not join the host IPC
        // namespace there is nothing for the spy to find, and the absence
        // reads as isolation.
        assert_eq!(spec(&create_ipc_target_pod("t")).host_ipc, Some(true));
    }

    #[test]
    fn the_privileged_probes_are_actually_privileged() {
        for pod in [
            create_privileged_test_pod("p"),
            create_privileged_escape_pod("p", "node-1", HostDistro::Ubuntu { release: None }),
        ] {
            let privileged = spec(&pod).containers[0]
                .security_context
                .as_ref()
                .and_then(|c| c.privileged);
            assert_eq!(privileged, Some(true));
        }
    }

    #[test]
    fn the_control_targets_stay_unprivileged() {
        // The other half of the pairing. If a "non-privileged" target quietly
        // gained a host namespace, a breach would be attributed to the wrong
        // cause.
        for pod in [
            create_non_privileged_target_pod("t"),
            create_user_target_pod("t"),
            create_target_process_pod("t"),
            create_network_target_pod("t"),
        ] {
            let s = spec(&pod);
            assert_ne!(s.host_pid, Some(true));
            assert_ne!(s.host_network, Some(true));
            assert_ne!(s.host_users, Some(true));
        }
    }
}
