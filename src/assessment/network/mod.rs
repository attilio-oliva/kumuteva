mod fairness;

pub use fairness::*;

use std::collections::HashMap;
use std::fmt::Display;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Pod, Service};
use tokio::time::sleep;
use tracing::info;

use crate::assessment::breach::{
    run_breach_experiment, BreachCondition, BreachExperiment, Intruder, Secret,
};
use crate::assessment::probe::{HostAccess, ProbePod};
use crate::assessment::TenantClusterConfig;
use crate::assessment::{admission_refusal, Authorization};
use crate::assessment::{
    run_assessment, AssessableResource, CrossTenantResult, IsolationLevel, MultitenancyAssessor,
    SubsystemReport,
};

// =============================================================================
// CONSTANTS
// =============================================================================

const NETWORK_MULTITOOL_POD_NAME: &str = "network-multitool";
const AUTONOMY_TEST_SERVICE_NAME: &str = "autonomy-test-service";
const WEBSERVER_SERVICE_NAME: &str = "webserver-service";
const AUTONOMY_TEST_PORT: i32 = 8080;
const AUTONOMY_TEST_NODE_PORT: i32 = 30080;
/// Unprivileged, so the probe can serve without running as root.
///
/// A port below 1024 needs CAP_NET_BIND_SERVICE, which the `restricted` Pod
/// Security Standard forbids. A tenant configured to that standard — which is
/// the whole point of the `capsule-hardened` target — would refuse the probe
/// pod outright, and the reachability question would go unmeasured for the
/// solutions that are most interesting to measure.
///
/// The port number is not itself under test: the NetworkPolicies this
/// subsystem exercises select on pods and namespaces and carry no `ports`
/// block, so reachability on 8080 asks exactly the question reachability on 80
/// did.
const WEBSERVER_PORT: i32 = 8080;

/// Tenant2's own marker pod, which backs the NodePort it claims so that
/// reaching it can serve as the probe's control.
const TENANT2_MARKER_POD_NAME: &str = "nodeport-marker-pod-t2";

/// How long to wait, in one-second attempts, for a marker pod to report that it
/// is serving.
const MARKER_SERVING_ATTEMPTS: u32 = 60;

/// How many times the NodePort probe asks before concluding nothing answers,
/// and how long it waits between rounds.
///
/// Matched to the reachability probes' own retry window, and for the same
/// reason: the Service was created moments earlier and the node has to be
/// programmed for it.
const NODEPORT_PROBE_ROUNDS: u32 = 12;
const NODEPORT_PROBE_INTERVAL_SECS: u64 = 3;

// Infrastructure network test constants
const NODE_MARKER_POD_NAME: &str = "node-marker-service";
const NODE_MARKER_PORT: i32 = 31337;
const NODE_PROBE_POD_NAME: &str = "node-network-probe";

// =============================================================================
// RESOURCE AND OPERATION DEFINITIONS
// =============================================================================

#[allow(dead_code)]
pub type NetworkIsolationReport = SubsystemReport<NetworkResource>;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkResource {
    /// Pod-to-pod network communication
    PodNetwork,
    /// Service exposure and access
    ServiceNetwork,
    /// Node-to-node network communication
    /// Currently not tested separately, as it overlaps with NodePort tests
    InfrastructureNetwork,
    /// DNS resolution across namespaces
    DnsResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkOperation {
    /// Direct pod-to-pod communication via IP
    ConnectToPod,
    /// Access a service via ClusterIP
    ConnectToService,
    /// Reach a node via its IP
    ConnectToNode,
    /// Expose a service on a NodePort
    ExposeNodePort,
    /// Resolve DNS names across namespaces
    ResolveDns,
}

impl AssessableResource for NetworkResource {
    type Operation = NetworkOperation;

    fn all() -> Vec<Self> {
        vec![
            NetworkResource::PodNetwork,
            NetworkResource::ServiceNetwork,
            // Disabled. The NodePort row asks the question this was reaching
            // for, and it asks it without `hostNetwork` — which no probe here
            // needs, and which drags a capability into the verdict that the
            // property does not name.
            // NetworkResource::InfrastructureNetwork,
            NetworkResource::DnsResolution,
        ]
    }

    fn applicable_operations(&self) -> Vec<NetworkOperation> {
        match self {
            NetworkResource::PodNetwork => vec![NetworkOperation::ConnectToPod],
            NetworkResource::ServiceNetwork => vec![
                NetworkOperation::ConnectToService,
                NetworkOperation::ExposeNodePort,
            ],
            NetworkResource::InfrastructureNetwork => vec![NetworkOperation::ConnectToNode],
            NetworkResource::DnsResolution => vec![NetworkOperation::ResolveDns],
        }
    }
}

// =============================================================================
// ASSESSOR IMPLEMENTATION
// =============================================================================

pub struct NetworkAssessor;

#[async_trait]
impl MultitenancyAssessor for NetworkAssessor {
    type Resource = NetworkResource;

    fn name(&self) -> &'static str {
        "Network"
    }

    async fn is_authorized(
        &self,
        tenant: &TenantClusterConfig,
        resource: &NetworkResource,
        operation: &NetworkOperation,
    ) -> anyhow::Result<Authorization> {
        info!(
            "Checking authorization for {:?} - {:?}",
            resource, operation
        );
        match (resource, operation) {
            (NetworkResource::PodNetwork, NetworkOperation::ConnectToPod) => {
                // Tenants can always create pods that make network connections
                test_pod_network_authorization(tenant).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ConnectToService) => {
                // Tenants can create services
                test_service_creation_authorization(tenant).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ExposeNodePort) => {
                // Test if tenant can create NodePort services
                test_nodeport_authorization(tenant).await
            }
            (NetworkResource::InfrastructureNetwork, NetworkOperation::ConnectToNode) => {
                test_node_network_authorization(tenant).await
            }
            (NetworkResource::DnsResolution, NetworkOperation::ResolveDns) => {
                // DNS resolution is typically always available
                Ok(Authorization::Allowed)
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
        resource: &NetworkResource,
        operation: &NetworkOperation,
    ) -> anyhow::Result<CrossTenantResult> {
        info!(
            "Checking cross-tenant effect for {:?} - {:?}",
            resource, operation
        );
        match (resource, operation) {
            (NetworkResource::PodNetwork, NetworkOperation::ConnectToPod) => {
                run_breach_experiment(&pod_reachability_experiment(), tenant1, tenant2).await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ConnectToService) => {
                run_breach_experiment(
                    &service_reachability_experiment(&tenant2.namespace),
                    tenant1,
                    tenant2,
                )
                .await
            }
            (NetworkResource::ServiceNetwork, NetworkOperation::ExposeNodePort) => {
                test_nodeport_autonomy(tenant1, tenant2).await
            }
            (NetworkResource::DnsResolution, NetworkOperation::ResolveDns) => {
                // The DNS experiment plants in tenant1 and probes from tenant2,
                // the reverse of the reachability ones.
                run_breach_experiment(
                    &dns_resolution_experiment(&tenant1.namespace),
                    tenant2,
                    tenant1,
                )
                .await
            }
            (NetworkResource::InfrastructureNetwork, NetworkOperation::ConnectToNode) => {
                test_node_network_isolation(tenant1, tenant2).await
            }
            _ => Ok(CrossTenantResult {
                isolation: IsolationLevel::Unknown,
                autonomy: true,
                details: "Test not implemented".to_string(),
            }),
        }
    }
}

/// Public API - entry point for network isolation assessment
#[allow(dead_code)]
pub async fn check_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<NetworkIsolationReport> {
    run_assessment(&NetworkAssessor, tenant1, tenant2).await
}

// =============================================================================
// AUTHORIZATION TESTS
// =============================================================================

async fn test_pod_network_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let test_pod = create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME);
    let result = tenant
        .cluster
        .create_pod_in_namespace(&test_pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(NETWORK_MULTITOOL_POD_NAME, &tenant.namespace)
        .await;

    // wait for pod deletion to complete
    let _ = tenant
        .cluster
        .wait_for_pod_deletion(NETWORK_MULTITOOL_POD_NAME, &tenant.namespace)
        .await;

    Ok(Authorization::from_attempt(result))
}

async fn test_service_creation_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let test_service = create_clusterip_service(&tenant.namespace, "auth-test-service");
    let result = tenant
        .cluster
        .create_namespaced_resource::<Service>(&test_service, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<Service>("auth-test-service", &tenant.namespace)
        .await;

    Ok(Authorization::from_attempt(result))
}

async fn test_nodeport_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    // Use auto-assigned nodePort (0 or omit) to test if tenant can create NodePort services at all,
    // rather than testing if a specific port is available
    let test_service = create_nodeport_service_auto_port(&tenant.namespace, "auth-test-nodeport");
    let result = tenant
        .cluster
        .create_namespaced_resource::<Service>(&test_service, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_resource_in_namespace::<Service>("auth-test-nodeport", &tenant.namespace)
        .await;

    // Wait for service deletion to complete
    let _ = tenant
        .cluster
        .wait_for_namespaced_resource_deletion::<Service>("auth-test-nodeport", &tenant.namespace)
        .await;

    Ok(Authorization::from_attempt(result))
}

async fn test_node_network_authorization(
    tenant: &TenantClusterConfig,
) -> anyhow::Result<Authorization> {
    let pod_name = "auth-test-hostnetwork";
    let pod = create_host_network_pod(pod_name);

    let result = tenant
        .cluster
        .create_pod_in_namespace(&pod, &tenant.namespace)
        .await;

    // Cleanup
    let _ = tenant
        .cluster
        .delete_pod_in_namespace(pod_name, &tenant.namespace)
        .await;

    Ok(Authorization::from_attempt(result))
}

// =============================================================================
// CROSS-TENANT EFFECT TESTS
// =============================================================================

/// tenant2 serves a marker on an unprivileged port; tenant1 runs a one-shot pod
/// that curls its address and reports whether it got the marker back.
///
/// Replaces an `exec` into a long-lived multitool pod. The one-shot form is
/// what the workload subsystem already used to ask this same question
/// (`create_network_spy_pod`), so the two subsystems were testing pod-to-pod
/// reachability twice, in two different styles. This deletes one of them.
///
/// The target's `SERVING <marker>` line is used by the intruder to acknowledge
/// an isolation breach: without it, "the intruder got nothing" cannot be told
/// apart from "the server never came up", and the second reads as isolation.
/// Turn the reachability probe's report into a verdict.
///
/// Four outcomes, and the line that matters is between an answer and silence:
///
/// - it reached the other tenant — a breach, `None`;
/// - something answered and rejected it (RST, ICMP port unreachable) — a reply
///   only a shared network can carry, so the intruder learns a rule exists:
///   `Soft`;
/// - nothing answered at all, or the address did not resolve and had no route —
///   exactly what a lone tenant curling an address nobody holds observes, so
///   `Hard`;
/// - anything else — `Unknown`, because a probe that cannot say what happened
///   has not measured isolation.
///
/// Silence used to be folded into the refused case, which is the regression
/// this fixes: under KubeVirt each tenant is a separate cluster on its own
/// network, the other tenant's pod IP belongs to nobody in the intruder's
/// world, the SYN goes unanswered, and curl reports `(28) Connection timeout`.
/// That was scored `Soft` — "a policy forbade it" — for a platform where no
/// policy exists and nothing was there to forbid anything.
///
/// The cost is real and worth naming: a CNI that *drops* cross-tenant packets
/// silently — Calico's deny-all — is indistinguishable from this at the
/// transport layer and now also reads `Hard`. Nothing a tenant can observe
/// separates the two, and the model scores what was observed rather than what
/// we suspect produced it. A rule that answers (REJECT rather than DROP) still
/// reads `Soft`.
fn judge_pod_reachability(output: &str) -> CrossTenantResult {
    judge_reachability("pod-to-pod reachability", output)
}

fn judge_service_reachability(output: &str) -> CrossTenantResult {
    judge_reachability("service reachability", output)
}

fn judge_reachability(what: &str, output: &str) -> CrossTenantResult {
    {
        if output.contains("NETWORK_ACCESS_SUCCESS") {
            return CrossTenantResult {
                isolation: IsolationLevel::None,
                autonomy: true,
                details: format!(
                    "{what}: the intruder observed the other tenant's secret — not isolated"
                ),
            };
        }
        if output.contains("NETWORK_ACCESS_NO_HOST") {
            return CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: format!(
                    "{what}: the other tenant has no route or address from here — {}",
                    first_line(output)
                ),
            };
        }
        if output.contains("NETWORK_ACCESS_NO_ANSWER") {
            return CrossTenantResult {
                isolation: IsolationLevel::Hard,
                autonomy: true,
                details: format!(
                    "{what}: nothing answered at the other tenant's address, which is \
                     what a lone tenant sees — {}",
                    first_line(output)
                ),
            };
        }
        if output.contains("NETWORK_ACCESS_REFUSED") {
            return CrossTenantResult {
                isolation: IsolationLevel::Soft(
                    "The connection was answered and rejected".to_string(),
                ),
                autonomy: true,
                details: format!(
                    "{what}: something answered and rejected the connection, so the \
                     network is shared and a rule forbade the attempt — {}",
                    first_line(output)
                ),
            };
        }
        CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "{what}: the intruder reported nothing usable — {}",
                first_line(output)
            ),
        }
    }
}

/// The probe's own words, trimmed to something a table can carry.
fn first_line(output: &str) -> String {
    output
        .lines()
        .find(|line| line.contains("NETWORK_ACCESS_") || line.contains("DNS_"))
        .unwrap_or(output)
        .chars()
        .take(160)
        .collect()
}

fn pod_reachability_experiment() -> BreachExperiment {
    BreachExperiment {
        what: "pod-to-pod reachability",
        target: create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME),
        target_service: None,
        secret: Secret::ConfirmedBy(format!("SERVING {NETWORK_MULTITOOL_POD_NAME}")),
        intruder: Intruder::AtTargetAddress(|address| {
            create_reachability_probe_pod("network-reach-probe", address)
        }),
        breach: BreachCondition::Decided(judge_pod_reachability),
    }
}

/// A one-shot pod that curls `address` and says whether the marker came back.
///
/// Retries because a Service's endpoints propagate after its backing pod is
/// Ready — the gap that made the old exec-based probe intermittently report
/// isolation it had not measured.
pub(crate) fn create_reachability_probe_pod(name: &str, address: &str) -> Pod {
    // Report *how* the attempt failed, not merely that it did.
    //
    // "Could not reach it" covers findings that carry different verdicts, and
    // curl's exit code separates them where its wording does not — curl 8
    // dropped "Connection refused" from the message that curl 7 printed, so
    // matching on text alone silently reclassifies a result when the base image
    // moves.
    //
    //   6  — the name did not resolve.
    //   7  — the connect failed outright. With `no route to host` or `network
    //         is unreachable` in the message that is the local stack saying the
    //         address is not in this pod's world; otherwise something on the
    //         far side answered with a rejection (RST, ICMP port unreachable),
    //         which only a shared network can deliver.
    //   28 — nothing answered before the timeout. Silence. Identical to what a
    //         lone tenant curling an address nobody holds observes, which is
    //         why it is reported apart from a rejection rather than with it.
    //
    // Anything else is left unclassified rather than assumed: a probe that
    // cannot say what happened must not hand back a verdict.
    let script = format!(
        "last=''; lastcode=0; \
         for i in $(seq 1 15); do \
           out=$(curl -sS --connect-timeout 2 {address}:{WEBSERVER_PORT} 2>&1); \
           code=$?; \
           if [ $code -eq 0 ] && echo \"$out\" | grep -q '{NETWORK_MULTITOOL_POD_NAME}'; then \
             echo 'NETWORK_ACCESS_SUCCESS: reached the other tenant'; \
             exit 0; \
           fi; \
           last=\"$out\"; lastcode=$code; \
           sleep 2; \
         done; \
         if [ \"$lastcode\" = 6 ] || echo \"$last\" | grep -qiE 'no route to host|network is unreachable|could not resolve'; then \
           echo \"NETWORK_ACCESS_NO_HOST: $last\"; \
         elif [ \"$lastcode\" = 7 ]; then \
           echo \"NETWORK_ACCESS_REFUSED: $last\"; \
         elif [ \"$lastcode\" = 28 ]; then \
           echo \"NETWORK_ACCESS_NO_ANSWER: $last\"; \
         else \
           echo \"NETWORK_ACCESS_UNCLEAR: $last\"; \
         fi"
    );

    ProbePod::new(name)
        .container("reach-probe")
        .image("praqma/network-multitool")
        .restricted()
        .shell(script)
        .build()
}

/// tenant2 serves a marker behind a ClusterIP Service; tenant1 curls the
/// Service address.
///
/// Same probe as pod-to-pod reachability, aimed one layer up: the executor
/// hands the intruder the Service's ClusterIP instead of the pod IP because the
/// experiment declares a `target_service`.
fn service_reachability_experiment(victim_namespace: &str) -> BreachExperiment {
    BreachExperiment {
        what: "service reachability",
        target: create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME),
        target_service: Some(create_webserver_service(victim_namespace)),
        secret: Secret::ConfirmedBy(format!("SERVING {NETWORK_MULTITOOL_POD_NAME}")),
        intruder: Intruder::AtTargetAddress(|address| {
            create_reachability_probe_pod("service-reach-probe", address)
        }),
        breach: BreachCondition::Decided(judge_service_reachability),
    }
}

/// tenant1 resolves the DNS name of a Service owned by tenant2.
///
/// Resolution alone is the breach: it discloses that the service exists and
/// where it lives, whether or not the traffic would be allowed. The Service
/// needs no backing pod for this — cluster DNS answers from the ClusterIP — so
/// the target pod exists only to give the experiment something whose readiness
/// proves the namespace is live.
/// Turn the DNS probe's report into a verdict.
///
/// Resolving another tenant's name is a breach whether or not anything is
/// listening behind it — the record itself is the disclosure. `NXDOMAIN` means
/// the server genuinely has nothing for this client, which no configuration
/// change undoes from the tenant's side, so Hard. `REFUSED` means the record
/// exists and access to it is withheld by a rule, so Soft. A server that never
/// answered has told us nothing at all.
fn judge_dns_resolution(output: &str) -> CrossTenantResult {
    if output.contains("DNS_RESOLVED") {
        return CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: "cross-tenant DNS resolution: the other tenant's record resolved here — not isolated".to_string(),
        };
    }
    if output.contains("DNS_NXDOMAIN") {
        return CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: "cross-tenant DNS resolution: the server holds no record of the other tenant for this client".to_string(),
        };
    }
    if output.contains("DNS_REFUSED") {
        return CrossTenantResult {
            isolation: IsolationLevel::Soft("A policy forbade the cross-tenant operation".to_string()),
            autonomy: true,
            details: "cross-tenant DNS resolution: the record exists and the server declined to disclose it".to_string(),
        };
    }
    if output.contains("DNS_SERVER_BROKEN") {
        // SERVFAIL is the server admitting it cannot answer — commonly because
        // it has no route to the API server and so knows of no Services at all.
        // It says nothing about this tenant's records versus another's, and a
        // resolver in that state fails its own tenant's lookups too.
        return CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "cross-tenant DNS resolution: the resolver failed rather than answered — {}",
                first_line(output)
            ),
        };
    }
    CrossTenantResult {
        isolation: IsolationLevel::Unknown,
        autonomy: false,
        details: format!(
            "cross-tenant DNS resolution: no DNS server answered, so nothing was learned — {}",
            first_line(output)
        ),
    }
}

fn dns_resolution_experiment(victim_namespace: &str) -> BreachExperiment {
    let fqdn = format!("{WEBSERVER_SERVICE_NAME}.{victim_namespace}.svc.cluster.local");

    BreachExperiment {
        what: "cross-tenant DNS resolution",
        target: create_network_multitool_pod(NETWORK_MULTITOOL_POD_NAME),
        target_service: Some(create_webserver_service(victim_namespace)),
        secret: Secret::ConfirmedBy(format!("SERVING {NETWORK_MULTITOOL_POD_NAME}")),
        // Needs nothing from the target's placement: the name is known in
        // advance, which is the whole point — the intruder guesses it.
        intruder: Intruder::Anywhere(Box::new(create_dns_probe_pod("dns-probe", &fqdn))),
        breach: BreachCondition::Decided(judge_dns_resolution),
    }
}

/// A one-shot pod that resolves `fqdn` and reports what the server said.
///
/// The distinction is the whole measurement, so the probe reports the server's
/// answer rather than a yes/no:
///
/// - an address came back — the other tenant's record is visible here;
/// - `NXDOMAIN` — the server holds no such record for this client;
/// - `REFUSED` — the server has an answer and declines to give it;
/// - no server answered — nothing was learned, and in particular a tenant with
///   no working DNS at all must not be read as a tenant that was protected.
///
/// That last case is not hypothetical: a Kube-OVN custom VPC has no route to
/// cluster DNS, so `nslookup` times out for *every* name. The old probe scored
/// that as isolation.
pub(crate) fn create_dns_probe_pod(name: &str, fqdn: &str) -> Pod {
    // `nslookup` prints "Name:" followed by "Address:" on success. Requiring
    // both avoids counting the server's own address line, which is present even
    // when the lookup fails.
    let script = format!(
        "out=$(nslookup {fqdn} 2>&1); \
         if echo \"$out\" | grep -A1 'Name:' | grep -q 'Address'; then \
           echo 'DNS_RESOLVED: the name resolves from another tenant'; \
         elif echo \"$out\" | grep -q 'NXDOMAIN'; then \
           echo 'DNS_NXDOMAIN: the server holds no such record for this client'; \
         elif echo \"$out\" | grep -q 'REFUSED'; then \
           echo 'DNS_REFUSED: the server declined to answer'; \
         elif echo \"$out\" | grep -q 'SERVFAIL'; then \
           echo \"DNS_SERVER_BROKEN: $(echo \"$out\" | tr '\\n' ' ' | cut -c1-120)\"; \
         else \
           echo \"DNS_NO_SERVER: $(echo \"$out\" | tr '\\n' ' ' | cut -c1-120)\"; \
         fi"
    );

    ProbePod::new(name)
        .container("dns-probe")
        .image("praqma/network-multitool")
        .restricted()
        .shell(script)
        .build()
}

async fn test_nodeport_autonomy(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    info!("Testing NodePort isolation - can tenant2 reach tenant1's NodePort service?");

    // Generate a unique marker to identify tenant1's service
    let marker = format!("TENANT1_NODEPORT_MARKER_{}", uuid::Uuid::new_v4());
    info!("Generated NodePort marker for tenant1: {}", marker);

    // 1. Create a pod in tenant1 that serves the marker
    let marker_pod = create_nodeport_marker_pod("nodeport-marker-pod", &marker);

    let create_pod_result = tenant1
        .cluster
        .create_pod_in_namespace(&marker_pod, &tenant1.namespace)
        .await;

    if create_pod_result.is_err() {
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Could not create marker pod in tenant1: {:?}",
                create_pod_result.err()
            ),
        });
    }

    // Wait for pod to be ready
    if let Err(e) = tenant1
        .cluster
        .wait_for_pod_to_be_ready("nodeport-marker-pod", &tenant1.namespace)
        .await
    {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!("Tenant1 marker pod failed to start: {}", e),
        });
    }

    // 2. Create NodePort service pointing to the marker pod
    let tenant1_service = create_nodeport_service_with_selector(
        &tenant1.namespace,
        AUTONOMY_TEST_SERVICE_NAME,
        AUTONOMY_TEST_NODE_PORT,
        "nodeport-marker",
    );

    let create_svc_result = tenant1
        .cluster
        .create_namespaced_resource::<Service>(&tenant1_service, &tenant1.namespace)
        .await;

    if create_svc_result.is_err() {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Could not create NodePort service in tenant1: {:?}",
                create_svc_result.err()
            ),
        });
    }

    // 2b. Confirm tenant1 is actually serving the marker before anyone looks
    // for it.
    //
    // Step 2 of the method, and the one this test skipped: a target that never
    // came up leaves the intruder with nothing to find, and "found nothing" is
    // recorded as isolation. Readiness is not enough — the pod is Ready once
    // the shell runs, which is before `httpd` has bound. The marker pod prints
    // `SERVING <marker>` for exactly this purpose.
    if !marker_is_being_served(tenant1, "nodeport-marker-pod", &marker).await {
        cleanup_nodeport_test_resources(tenant1, tenant2).await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: "Tenant1's NodePort service never began serving its marker, so \
                      tenant2 finding nothing proves nothing about isolation"
                .to_string(),
        });
    }

    // 3. Tenant2 claims the same NodePort.
    //
    // Two tenants that cannot both hold port 30080 are sharing one NodePort
    // space, and the collision is itself a disclosure: tenant2 is told the port
    // is taken, which is a restriction it can infer another tenant from.
    //
    // But that is the verdict only if nothing stronger is found. A collision is
    // an inference; reaching tenant1's marker is a breach actually performed,
    // and a performed breach outranks anything inferred — so the probe runs
    // either way and this only decides what to report when the probe finds
    // nothing.
    // Tenant2's own service gets a backend of its own, so that reaching it
    // becomes a control: if tenant2 cannot reach a NodePort it owns, by its own
    // node's address, then this probe cannot see NodePorts here at all and its
    // silence about tenant1 says nothing about isolation.
    let own_marker = format!("TENANT2_NODEPORT_MARKER_{}", uuid::Uuid::new_v4());
    let _ = tenant2
        .cluster
        .create_pod_in_namespace(
            &create_nodeport_marker_pod(TENANT2_MARKER_POD_NAME, &own_marker),
            &tenant2.namespace,
        )
        .await;

    let port_collision = match tenant2
        .cluster
        .create_namespaced_resource::<Service>(
            &create_nodeport_service_with_selector(
                &tenant2.namespace,
                AUTONOMY_TEST_SERVICE_NAME,
                AUTONOMY_TEST_NODE_PORT,
                "nodeport-marker",
            ),
            &tenant2.namespace,
        )
        .await
    {
        Ok(_) => None,
        Err(e) => {
            info!("tenant2 could not claim NodePort {AUTONOMY_TEST_NODE_PORT}: {e}");
            Some(e.to_string())
        }
    };

    // 4. Every address tenant1's NodePort might answer on, rather than the
    // first one that turned up.
    let addresses = candidate_node_addresses(tenant1, "nodeport-marker-pod", false).await;

    if addresses.is_empty() {
        cleanup_nodeport_test_resources(tenant1, tenant2).await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: "Could not determine any node address for the NodePort test".to_string(),
        });
    }

    // 4b. The control: can this probe reach a NodePort at all?
    //
    // Tenant2 owns a NodePort with its own marker behind it, on its own node.
    // If that cannot be reached, "tenant1 did not answer" is a statement about
    // the probe rather than about isolation, and the run has measured nothing.
    //
    // Only meaningful when tenant2 actually got the port — in a shared NodePort
    // space it did not, and the collision is the finding anyway.
    let control = if port_collision.is_none() {
        let own_addresses =
            candidate_node_addresses(tenant2, TENANT2_MARKER_POD_NAME, false).await;
        let reached_own = !own_addresses.is_empty()
            && marker_is_being_served(tenant2, TENANT2_MARKER_POD_NAME, &own_marker).await
            && probe_marker_from(
                tenant2,
                create_network_multitool_pod("nodeport-selftest"),
                "nodeport-selftest",
                "tenant2's own NodePort",
                &own_addresses,
                AUTONOMY_TEST_NODE_PORT,
                &own_marker,
            )
            .await
            .hit
            .is_some();
        Some(reached_own)
    } else {
        None
    };

    // 5. Reach for tenant1's service on tenant1's node address, from an
    // ordinary pod in tenant2 — no host networking, which this test does not
    // need and must not ask for. Getting tenant1's marker back means the two
    // NodePorts are not separate at all, whatever the successful create above
    // suggested.
    let probe = probe_marker_from(
        tenant2,
        create_network_multitool_pod("nodeport-probe"),
        "nodeport-probe",
        "tenant2's pod network",
        &addresses,
        AUTONOMY_TEST_NODE_PORT,
        &marker,
    )
    .await;

    // What was tried and what each attempt said, carried into the verdict. The
    // first version of this logged it and reported only "cannot reach", which
    // left no way to tell a closed route from an untried one when the answer
    // was disputed.
    let trace = probe.trace.join("; ");
    let hit = probe.hit.clone();
    let marker_found = hit.is_some();

    // Nothing was ever asked of the NodePort: the probe pod could not be
    // placed, or it was placed and no command could be run in it. Either way
    // the run failed rather than the NodePort holding — and reporting a broken
    // probe as isolation is how a dead measurement turns into a perfect score.
    //
    // An exec failure only costs the measurement if nothing else answered: one
    // address that could not be reached out to alongside others that were is a
    // gap in the sweep, not a dead probe.
    if !marker_found && (!probe.placed || (probe.exec_failed && !probe.answered)) {
        cleanup_nodeport_test_resources(tenant1, tenant2).await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "The NodePort was never actually probed from tenant2, so nothing was \
                 measured — {trace}"
            ),
        });
    }

    let node_ip = hit.clone().unwrap_or_else(|| addresses[0].1.clone());

    // Something is listening there but it is not tenant1's marker.
    let unexpected = probe.unexpected.clone();

    // 6. Verdict, strongest finding first.
    cleanup_nodeport_test_resources(tenant1, tenant2).await;

    if marker_found {
        // Tenant2 read tenant1's marker. Performed, so it outranks the port
        // collision below however that turned out.
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: format!(
                "Tenant2 read tenant1's marker at {node_ip}:{AUTONOMY_TEST_NODE_PORT} from an \
                ordinary pod on its own network - NodePort traffic is not isolated between \
                tenants. {}",
                match &port_collision {
                    Some(_) => "The tenants also share one NodePort space.",
                    None => "Both tenants hold the same NodePort number independently.",
                }
            ),
        })
    } else if let Some(why) = port_collision {
        // Nothing was reached, so the collision is the finding: tenant2 was
        // told the port is taken, which discloses that another tenant holds it.
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(format!(
                "Tenant2 cannot hold NodePort {AUTONOMY_TEST_NODE_PORT} while tenant1 does"
            )),
            // The tenant may create NodePort services — the authorization gate
            // established that before this ran. What it may not do is have this
            // particular port, which is a collision rather than a prohibition.
            autonomy: true,
            details: format!(
                "Tenants share one NodePort space: tenant2 was refused port \
                 {AUTONOMY_TEST_NODE_PORT} because tenant1 holds it, which tells it another \
                 tenant is there, though it could not reach tenant1's service — {why}. \
                 Attempts: {trace}"
            ),
        })
    } else if let Some(response) = unexpected {
        // Something answered and it was not tenant1's marker. Most likely
        // tenant2's own service on the port it just claimed — but it is not
        // tenant1's marker, so it is not proof of separation either, and it is
        // reported as what it is.
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft(
                "Something other than tenant1's service answered on the shared port number"
                    .to_string(),
            ),
            autonomy: true,
            details: format!(
                "Tenant2 reached an endpoint on port {AUTONOMY_TEST_NODE_PORT} but received \
                an unexpected response: '{}' - a different service or a proxy in between. \
                Attempts: {trace}",
                response.chars().take(100).collect::<String>()
            ),
        })
    } else if control == Some(false) {
        // Tenant2 could not reach a NodePort it owns itself, so it was never in
        // a position to reach tenant1's. Silence here is the probe's, not the
        // platform's, and calling it isolation would be the reassuring answer
        // to a broken measurement.
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: true,
            details: format!(
                "Tenant2 could not reach its own NodePort {AUTONOMY_TEST_NODE_PORT} by its \
                own node's address, so it could not have reached tenant1's either and \
                nothing was measured. Attempts: {trace}"
            ),
        })
    } else {
        // Both tenants hold port 30080, tenant2 can reach its own NodePort, and
        // tenant1's does not answer it: the NodePort spaces are genuinely
        // separate, which is what a lone tenant would see.
        //
        // The attempts are part of the verdict rather than a log line: "cannot
        // reach" is only worth reading alongside which addresses were actually
        // tried.
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: format!(
                "Both tenants hold NodePort {AUTONOMY_TEST_NODE_PORT} independently, tenant2 \
                can reach its own by node address, and tenant1's does not answer it - \
                NodePort traffic is isolated. Attempts: {trace}"
            ),
        })
    }
}

/// What came of pointing one probe pod at every address tenant1 might answer on.
struct NodePortAttempt {
    /// The address that returned the marker, if one did.
    hit: Option<String>,
    /// Whether tenant2 could place this probe pod at all. False means the route
    /// was never taken, which is not a finding about the NodePort.
    placed: bool,
    /// A response that was neither the marker nor a failure to connect —
    /// something else is listening there.
    unexpected: Option<String>,
    /// The probe pod was placed but a command could not be run in it, so the
    /// NodePort was never actually asked. Not isolation.
    exec_failed: bool,
    /// At least one address was actually reached out to and answered for
    /// itself, so an exec failure on some other address did not cost the
    /// measurement.
    answered: bool,
    /// One line per address tried, for the verdict to carry.
    trace: Vec<String>,
}

/// Create `pod` in tenant2, curl every candidate address from it, and take the
/// pod away again.
///
/// Split out because the same question gets asked from two vantage points — the
/// tenant's pod network and the node network — and the second only means
/// anything if a refusal to place the pod is told apart from a connection that
/// failed. `route` names the vantage point for the report.
async fn probe_marker_from(
    tenant2: &TenantClusterConfig,
    pod: Pod,
    pod_name: &str,
    route: &str,
    addresses: &[(String, String)],
    port: i32,
    marker: &str,
) -> NodePortAttempt {
    let mut attempt = NodePortAttempt {
        hit: None,
        placed: false,
        unexpected: None,
        exec_failed: false,
        answered: false,
        trace: Vec::new(),
    };

    if let Err(e) = tenant2
        .cluster
        .create_pod_in_namespace(&pod, &tenant2.namespace)
        .await
    {
        attempt
            .trace
            .push(format!("{route}: probe pod refused ({e})"));
        return attempt;
    }

    if let Err(e) = tenant2
        .cluster
        .wait_for_pod_to_be_ready(pod_name, &tenant2.namespace)
        .await
    {
        let _ = tenant2
            .cluster
            .delete_pod_in_namespace(pod_name, &tenant2.namespace)
            .await;
        attempt
            .trace
            .push(format!("{route}: probe pod never became ready ({e})"));
        return attempt;
    }

    attempt.placed = true;

    // Add the hops on this pod's own way out of its network.
    //
    // The victim's addresses are gathered from the victim's cluster, so they can
    // only ever name nodes that cluster knows about. Under KubeVirt that is the
    // nested node — a virt-launcher pod from the infrastructure's side, whose
    // masquerade forwards nothing — while the address that actually carries the
    // tenants' NodePorts is the infrastructure node, which the victim's cluster
    // has never heard of and which therefore could never appear in that list.
    //
    // The intruder can see it, though: a traceroute out of its own pod walks
    // straight through it. Verified on the KubeVirt testbed — hop 1 is the
    // tenant's own VM, hop 2 the infrastructure node, and `:30010` there answers
    // with the *other* tenant's API server. That is black-box discovery, needs
    // no capability the pod does not already have, and is what a tenant probing
    // by hand finds first.
    let mut targets = addresses.to_vec();
    for hop in escape_route_hops(tenant2, pod_name).await {
        if !targets.iter().any(|(_, a)| *a == hop) {
            targets.push(("hop out of the intruder's own network".to_string(), hop));
        }
    }

    sweep_addresses(
        tenant2, pod_name, route, &targets, port, marker, &mut attempt,
    )
    .await;

    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(pod_name, &tenant2.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(pod_name, &tenant2.namespace)
        .await;

    attempt
}

/// Curl every candidate address from a probe pod that is already running,
/// repeatedly, and record what each one said.
///
/// Separate from pod placement because two properties need the sweep and only
/// one of them wants this function to own the pod: the infrastructure-network
/// probe has to classify its own pod being refused as a finding of its own.
#[allow(clippy::too_many_arguments)]
async fn sweep_addresses(
    tenant2: &TenantClusterConfig,
    pod_name: &str,
    route: &str,
    addresses: &[(String, String)],
    port: i32,
    marker: &str,
    attempt: &mut NodePortAttempt,
) {
    // Ask repeatedly, because the target was created moments ago.
    //
    // A NodePort is not open the instant the API accepts the Service: kube-proxy
    // has to see it and program the node, and the marker pod's endpoint has to
    // propagate. This probe used to curl once, immediately, and read the miss as
    // isolation — the same race the pod and Service reachability probes already
    // retry fifteen times to avoid, documented there as "the gap that made the
    // old exec-based probe intermittently report isolation it had not measured".
    //
    // On a local kind cluster the single shot wins the race, which is why it
    // looked fine. On nested clusters — a tenant per set of VMs, its own
    // kube-proxy inside — it does not, and the platform where the NodePort is
    // most reachable reported it unreachable.
    let mut last: HashMap<&str, String> = HashMap::new();
    'rounds: for round in 0..NODEPORT_PROBE_ROUNDS {
        for (source, address) in addresses {
            // Bounded three ways, because the exec channel gives up after 30s
            // and a command that outlives it is reported as a probe that could
            // not run — which is `Unknown`, not a finding.
            //
            // The `wget` fallback that used to follow the curl is what blew
            // through it: busybox does not take `--timeout` as a long option
            // and retries on its own, so against a CNI that drops packets the
            // pair ran past 30s and `native+calico` scored `Unknown` for a
            // NodePort it had in fact probed. curl alone answers the question,
            // and `timeout` caps whatever curl does with the flags.
            // Report curl's exit code, not just that it failed.
            //
            // Collapsing every failure into one word cost a diagnosis: a
            // NodePort that is *refused* means the address was reached and
            // nothing is listening; one that *times out* means the packets went
            // unanswered; `Host is unreachable` means the sender could not even
            // resolve a route. Those are three different findings about a
            // platform, and this probe reported all of them as "no answer".
            let probe_cmd = format!(
                "out=$(timeout 8 curl -sS --connect-timeout 3 --max-time 6 \
                 http://{address}:{port} 2>&1); code=$?; \
                 if [ $code -eq 0 ]; then echo \"$out\"; \
                 else echo \"CONNECTION_FAILED rc=$code $out\"; fi"
            );

            let output = match tenant2
                .cluster
                .exec_command_in_container(pod_name, &tenant2.namespace, &probe_cmd)
                .await
            {
                Ok(output) => {
                    attempt.answered = true;
                    output
                }
                // The probe never ran, so nothing was asked of the NodePort.
                // Recorded apart from a connection that failed: folding the two
                // together reports a broken harness as isolation.
                Err(e) => {
                    attempt.exec_failed = true;
                    last.insert(source.as_str(), format!("could not run the probe: {e}"));
                    continue;
                }
            };

            info!("probe from {route} to {address}:{port} ({source}), round {round}: {output}");

            if output.contains(marker) {
                attempt
                    .trace
                    .push(format!("{route} → {address} ({source}): reached"));
                attempt.hit = Some(address.clone());
                break 'rounds;
            }

            if output.contains("CONNECTION_FAILED") {
                last.insert(source.as_str(), describe_failure(&output));
            } else {
                last.insert(source.as_str(), "unexpected response".to_string());
                attempt.unexpected.get_or_insert(output);
            }
        }

        if round + 1 < NODEPORT_PROBE_ROUNDS {
            sleep(Duration::from_secs(NODEPORT_PROBE_INTERVAL_SECS)).await;
        }
    }

    if attempt.hit.is_none() {
        for (source, address) in addresses {
            if let Some(outcome) = last.get(source.as_str()) {
                attempt.trace.push(format!(
                    "{route} → {address} ({source}): {outcome}, {NODEPORT_PROBE_ROUNDS} attempts"
                ));
            }
        }
    }
}

/// Every address tenant1's NodePort might answer on, each paired with where it
/// was learnt.
///
/// Plural, and that is the point. The old helper returned the first address it
/// found and stopped, so a cluster whose first node is not the one the tenant
/// can be reached at reported isolation it had never tested. A tenant probing
/// by hand would try each address it can name; so does this.
async fn candidate_node_addresses(
    tenant1: &TenantClusterConfig,
    marker_pod_name: &str,
    marker_on_host_network: bool,
) -> Vec<(String, String)> {
    fn push(found: &mut Vec<(String, String)>, source: String, address: String) {
        if !address.trim().is_empty() && !found.iter().any(|(_, a)| *a == address) {
            found.push((source, address));
        }
    }

    let mut found: Vec<(String, String)> = Vec::new();

    // Every address of every node the tenant can see, not just the first.
    if let Ok(nodes) = tenant1.cluster.list_nodes().await {
        for node in &nodes {
            let name = node
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string());
            let addresses = node
                .status
                .as_ref()
                .and_then(|status| status.addresses.as_ref());
            for address in addresses.into_iter().flatten() {
                if address.type_ == "InternalIP" || address.type_ == "ExternalIP" {
                    push(
                        &mut found,
                        format!("node {name} {}", address.type_),
                        address.address.clone(),
                    );
                }
            }
        }
    }

    // The node the marker actually landed on, which the tenant reads off its
    // own pod and which needs no permission on Node at all.
    if let Ok(pod) = tenant1
        .cluster
        .get_pod_in_namespace(marker_pod_name, &tenant1.namespace)
        .await
    {
        if let Some(host_ip) = pod.status.and_then(|status| status.host_ip) {
            push(&mut found, "marker pod status.hostIP".to_string(), host_ip);
        }
    }

    // The address the node actually sources traffic from, asked of the victim's
    // own pod. Only meaningful when that pod is on the node's network — in an
    // ordinary pod this answers with the pod IP, which is not a node address at
    // all — but where it applies it is the address another tenant would reach
    // the node on, which need not be any address the API reports.
    if marker_on_host_network {
        let source_address = tenant1
            .cluster
            .exec_command_in_container(
                marker_pod_name,
                &tenant1.namespace,
                r#"ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'"#,
            )
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        push(
            &mut found,
            "node's own routable source address".to_string(),
            source_address,
        );
    }

    // Last resort, and the only one available where the API hides both: the
    // gateway the marker pod routes through.
    if found.is_empty() {
        let gateway = tenant1
            .cluster
            .exec_command_in_container(
                marker_pod_name,
                &tenant1.namespace,
                "ip route | grep default | awk '{print $3}'",
            )
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        push(&mut found, "marker pod default gateway".to_string(), gateway);
    }

    info!("candidate node addresses: {found:?}");
    found
}

/// Name the way a connection failed, from curl's own exit code.
///
/// The three that matter are distinct findings, not shades of one: 7 with
/// `unreachable` in the text is the sender having no route to the address at
/// all; 7 otherwise is something answering with a rejection; 28 is silence.
fn describe_failure(output: &str) -> String {
    let code = output
        .split("rc=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("");
    let detail = output
        .split_once("CONNECTION_FAILED")
        .map(|(_, rest)| rest.trim())
        .unwrap_or("")
        .chars()
        .take(90)
        .collect::<String>();

    let named = match code {
        "6" => "the address did not resolve",
        "7" if output.to_lowercase().contains("unreachable") => {
            "no route to the address from here"
        }
        "7" => "the connection was refused — the address was reached and nothing listens",
        "28" => "no answer before the timeout",
        _ => "failed",
    };
    format!("{named} ({detail})")
}

/// The addresses a pod's traffic passes through on its way off the tenant's
/// own network.
///
/// Each hop is a machine the tenant can reach, so each is somewhere another
/// tenant's NodePort could be answering. The victim's own cluster cannot name
/// these — they are on the other side of it — which is why they are discovered
/// from the intruder instead.
async fn escape_route_hops(tenant: &TenantClusterConfig, pod_name: &str) -> Vec<String> {
    let output = tenant
        .cluster
        .exec_command_in_container(
            pod_name,
            &tenant.namespace,
            // A public address is a direction, not a destination: nothing is
            // sent to it beyond the probes the hops themselves answer.
            "traceroute -n -m 4 -w 1 8.8.8.8 2>/dev/null || true",
        )
        .await
        .unwrap_or_default();

    let hops: Vec<String> = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            // "<n>  <address>  <rtt> ms ..."; the first field is the hop number.
            fields.next()?.parse::<u32>().ok()?;
            let address = fields.next()?;
            let is_address = address.split('.').count() == 4
                && address
                    .split('.')
                    .all(|octet| !octet.is_empty() && octet.chars().all(|c| c.is_ascii_digit()));
            is_address.then(|| address.to_string())
        })
        .collect();

    info!("hops out of {}: {hops:?}", tenant.namespace);
    hops
}

/// Wait for a marker pod to say it is actually serving.
///
/// The marker pods print `SERVING <marker>` once `httpd` is bound. Readiness
/// alone is not that: the pod reports Ready as soon as its shell runs, which is
/// before anything is listening, and an intruder that arrives in that window
/// finds nothing — which this test used to record as isolation.
async fn marker_is_being_served(
    tenant: &TenantClusterConfig,
    pod_name: &str,
    marker: &str,
) -> bool {
    let expected = format!("SERVING {marker}");
    for _ in 0..MARKER_SERVING_ATTEMPTS {
        if tenant
            .cluster
            .get_pod_logs(pod_name, &tenant.namespace)
            .await
            .unwrap_or_default()
            .contains(&expected)
        {
            return true;
        }
        sleep(Duration::from_secs(1)).await;
    }
    info!("{pod_name} in {} never reported serving", tenant.namespace);
    false
}

/// Helper to cleanup NodePort test resources
async fn cleanup_nodeport_test_resources(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) {
    let _ = tenant1
        .cluster
        .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant1.namespace)
        .await;
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace("nodeport-marker-pod", &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_resource_in_namespace::<Service>(AUTONOMY_TEST_SERVICE_NAME, &tenant2.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace("nodeport-probe", &tenant2.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(TENANT2_MARKER_POD_NAME, &tenant2.namespace)
        .await;

    // Wait for cleanup
    let _ = tenant1
        .cluster
        .wait_for_namespaced_resource_deletion::<Service>(
            AUTONOMY_TEST_SERVICE_NAME,
            &tenant1.namespace,
        )
        .await;
    let _ = tenant1
        .cluster
        .wait_for_pod_deletion("nodeport-marker-pod", &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion("nodeport-probe", &tenant2.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(TENANT2_MARKER_POD_NAME, &tenant2.namespace)
        .await;
}

/// Tests infrastructure network isolation using a marker-based approach.
///
/// This test verifies if tenant2 can bypass cluster network isolation by accessing
/// a tenant1 service through the underlying node network (using hostNetwork pods).
///
/// Methodology:
/// 1. Tenant1 creates a hostNetwork pod that listens on a specific port and responds
///    with a unique marker string - this is the "observable state" owned by tenant1
/// 2. Tenant2 creates a hostNetwork pod and attempts to reach tenant1's marker service
///    via the node's internal IP
/// 3. If tenant2 can read tenant1's marker, it proves:
///    a) They share the same underlying node infrastructure
///    b) Tenant2 can bypass cluster network isolation via the node network
///
/// This aligns with the assessment methodology: we create a tenant-owned observable
/// state (the marker) and verify if another tenant can observe/access it.
async fn test_node_network_isolation(
    tenant1: &TenantClusterConfig,
    tenant2: &TenantClusterConfig,
) -> anyhow::Result<CrossTenantResult> {
    // Generate a unique marker that identifies tenant1's service
    let marker = format!("TENANT1_NODE_MARKER_{}", uuid::Uuid::new_v4());
    info!("Generated marker for tenant1: {}", marker);

    // 1. Create marker service pod in tenant1 (hostNetwork to bind to node's port)
    let marker_pod = create_node_marker_pod(NODE_MARKER_POD_NAME, &marker, NODE_MARKER_PORT);

    let create_marker_result = tenant1
        .cluster
        .create_pod_in_namespace(&marker_pod, &tenant1.namespace)
        .await;

    if let Err(e) = create_marker_result {
        // The victim could not plant anything, so the intruder finding nothing
        // proves nothing. This read `Hard` — the most reassuring verdict in the
        // table handed out for an experiment that never ran.
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Tenant1 could not place a hostNetwork pod to serve the marker, so \
                 nothing was planted for tenant2 to look for: {e}"
            ),
        });
    }

    // Wait for marker pod to be ready
    if let Err(e) = tenant1
        .cluster
        .wait_for_pod_to_be_ready(NODE_MARKER_POD_NAME, &tenant1.namespace)
        .await
    {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!("Tenant1 marker pod failed to start: {}", e),
        });
    }

    // Every address the node might answer on, not the first one that turned up.
    let addresses = candidate_node_addresses(tenant1, NODE_MARKER_POD_NAME, true).await;

    if addresses.is_empty() {
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: "Could not determine any node address for the infrastructure network test"
                .to_string(),
        });
    }

    info!("Tenant1 marker service reachable at one of: {addresses:?}");

    // 2. Create probe pod in tenant2 (hostNetwork to access node network)
    let probe_pod = create_host_network_pod(NODE_PROBE_POD_NAME);

    let create_probe_result = tenant2
        .cluster
        .create_pod_in_namespace(&probe_pod, &tenant2.namespace)
        .await;

    if let Err(error) = create_probe_result {
        // Cleanup tenant1's marker pod
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;

        // A refusal is soft, never hard. This read `Hard` with the words
        // "isolation enforced by policy" — but the tenant was told a
        // restriction exists, which is the definition of soft, and it never
        // reached the point of attempting the cross-tenant operation. `Hard` is
        // for an operation that runs and returns what a lone tenant would see.
        return Ok(match admission_refusal(&error) {
            Some(why) => CrossTenantResult {
                isolation: IsolationLevel::Soft(format!(
                    "Tenant2 may not place a pod on the node network: {why}"
                )),
                autonomy: false,
                details: format!(
                    "Tenant2 was refused a hostNetwork pod, so it never attempted to \
                     reach tenant1 over the node network — {why}"
                ),
            },
            None => CrossTenantResult {
                isolation: IsolationLevel::Unknown,
                autonomy: false,
                details: format!(
                    "Tenant2's hostNetwork pod could not be created, and not because a \
                     policy refused it: {error}"
                ),
            },
        });
    }

    // Wait for probe pod to be ready
    if let Err(e) = tenant2
        .cluster
        .wait_for_pod_to_be_ready(NODE_PROBE_POD_NAME, &tenant2.namespace)
        .await
    {
        // Cleanup
        let _ = tenant1
            .cluster
            .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
            .await;
        let _ = tenant2
            .cluster
            .delete_pod_in_namespace(NODE_PROBE_POD_NAME, &tenant2.namespace)
            .await;

        // Admitted and then never ran: nothing was asked of tenant1's node.
        return Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Tenant2's hostNetwork pod was admitted but never became ready, so the \
                 node network was never probed: {e}"
            ),
        });
    }

    // 3. Try to read tenant1's marker from tenant2's probe pod, on every
    // address, repeatedly. Single-shot and single-address was how the NodePort
    // probe reported isolation it had not measured.
    let mut attempt = NodePortAttempt {
        hit: None,
        placed: true,
        unexpected: None,
        exec_failed: false,
        answered: false,
        trace: Vec::new(),
    };
    sweep_addresses(
        tenant2,
        NODE_PROBE_POD_NAME,
        "tenant2's node network",
        &addresses,
        NODE_MARKER_PORT,
        &marker,
        &mut attempt,
    )
    .await;

    // Cleanup both pods
    let _ = tenant1
        .cluster
        .delete_pod_in_namespace(NODE_MARKER_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .delete_pod_in_namespace(NODE_PROBE_POD_NAME, &tenant2.namespace)
        .await;
    let _ = tenant1
        .cluster
        .wait_for_pod_deletion(NODE_MARKER_POD_NAME, &tenant1.namespace)
        .await;
    let _ = tenant2
        .cluster
        .wait_for_pod_deletion(NODE_PROBE_POD_NAME, &tenant2.namespace)
        .await;

    let trace = attempt.trace.join("; ");

    if let Some(address) = attempt.hit {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::None,
            autonomy: true,
            details: format!(
                "Tenant2 read tenant1's marker over the node network at {address}:{NODE_MARKER_PORT} - \
                the infrastructure network is shared and can be used to bypass cluster \
                network isolation. Attempts: {trace}"
            ),
        })
    } else if attempt.exec_failed && !attempt.answered {
        // The pod was there and no command could be run in it, so tenant1's
        // node was never asked anything. Reporting that as isolation is how a
        // dead probe turns into a perfect score.
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Unknown,
            autonomy: false,
            details: format!(
                "Tenant2's node-network probe could not be run, so nothing was measured. \
                 Attempts: {trace}"
            ),
        })
    } else if let Some(response) = attempt.unexpected {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Soft("Partial infrastructure sharing detected".to_string()),
            autonomy: true,
            details: format!(
                "Tenant2 reached something on port {NODE_MARKER_PORT} but received an \
                unexpected response: '{}' - may indicate a different service or NAT/proxy \
                in between. Attempts: {trace}",
                response.chars().take(100).collect::<String>()
            ),
        })
    } else {
        Ok(CrossTenantResult {
            isolation: IsolationLevel::Hard,
            autonomy: true,
            details: format!(
                "Tenant2 cannot reach tenant1's node service on port {NODE_MARKER_PORT} from \
                the node network - the infrastructure network is not shared between them. \
                Attempts: {trace}"
            ),
        })
    }
}

// =============================================================================
// MANIFEST CREATION HELPERS
// =============================================================================

/// Serves `marker` over HTTP on [`WEBSERVER_PORT`], without needing root.
///
/// The image's own entrypoint cannot be used unprivileged: it rewrites
/// `/etc/nginx/nginx.conf` and `/usr/share/nginx/html/index.html` at startup and
/// dies on permission errors as a non-root user. Overriding the command skips
/// it entirely, and busybox `httpd` serves a directory under `/tmp`, which is
/// writable by any UID.
fn unprivileged_http_server_command(marker: &str) -> String {
    format!(
        "mkdir -p /tmp/www && printf '%s' '{}' > /tmp/www/index.html && \
         echo 'SERVING {}' && \
         httpd -f -p {} -h /tmp/www",
        marker, marker, WEBSERVER_PORT
    )
}

/// A restricted, unprivileged pod that both serves a marker and probes others.
fn create_network_multitool_pod(name: &str) -> Pod {
    ProbePod::new(name)
        .container("multitool")
        .image("praqma/network-multitool")
        .label("app", "network-multitool")
        .restricted()
        .port(WEBSERVER_PORT)
        .shell(unprivileged_http_server_command(name))
        .restart_on_failure_default()
        .build()
}

fn create_webserver_service(namespace: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": WEBSERVER_SERVICE_NAME,
            "namespace": namespace
        },
        "spec": {
            "selector": {
                "app": "network-multitool"
            },
            "ports": [{
                "protocol": "TCP",
                "port": WEBSERVER_PORT,
                "targetPort": WEBSERVER_PORT
            }],
            "type": "ClusterIP"
        }
    }))
    .unwrap()
}

fn create_clusterip_service(namespace: &str, name: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "spec": {
            "selector": {
                "app": "test-app"
            },
            "ports": [{
                "protocol": "TCP",
                "port": WEBSERVER_PORT,
                "targetPort": WEBSERVER_PORT
            }],
            "type": "ClusterIP"
        }
    }))
    .unwrap()
}


/// Creates a NodePort service with auto-assigned port (Kubernetes chooses the port).
/// This is useful for authorization tests where we only care if NodePort services
/// can be created, not whether a specific port is available.
fn create_nodeport_service_auto_port(namespace: &str, name: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "test": "network-authorization"
            }
        },
        "spec": {
            "selector": {
                "app": "auth-test"
            },
            "ports": [{
                "name": "http",
                "protocol": "TCP",
                "port": AUTONOMY_TEST_PORT,
                "targetPort": AUTONOMY_TEST_PORT
                // nodePort omitted - Kubernetes will auto-assign from available range
            }],
            "type": "NodePort"
        }
    }))
    .unwrap()
}

/// Creates a NodePort service with a custom selector.
/// Used for isolation testing where we need to point to a specific marker pod.
fn create_nodeport_service_with_selector(
    namespace: &str,
    name: &str,
    node_port: i32,
    app_selector: &str,
) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "test": "network-isolation"
            }
        },
        "spec": {
            "selector": {
                "app": app_selector
            },
            "ports": [{
                "name": "http",
                "protocol": "TCP",
                "port": WEBSERVER_PORT,
                "targetPort": WEBSERVER_PORT,
                "nodePort": node_port
            }],
            "type": "NodePort"
        }
    }))
    .unwrap()
}

/// Creates a pod that serves a unique marker on [`WEBSERVER_PORT`].
/// Used for NodePort isolation testing.
///
/// The pod itself asks for no privilege — what the NodePort test exercises is
/// the *Service*, and it is the Service that a confined tenant refuses. So this
/// runs unprivileged, and the refusal, when it comes, arrives at the Service
/// rather than here. That distinction is what lets the test report "NodePort
/// forbidden" instead of "the probe would not start".
/// Serves a marker behind a NodePort service the test then tries to reach.
///
/// The pod itself needs no privilege — the NodePort is the thing a confined
/// tenant should be unable to create — so it is restricted like any other
/// reachability probe.
fn create_nodeport_marker_pod(name: &str, marker: &str) -> Pod {
    ProbePod::new(name)
        .container("marker-server")
        .image("praqma/network-multitool")
        .label("app", "nodeport-marker")
        .restricted()
        .port_tcp(WEBSERVER_PORT)
        .shell(unprivileged_http_server_command(marker))
        .build()
}

/// Requests host networking. Its refusal on a confined tenant is the finding.
fn create_host_network_pod(name: &str) -> Pod {
    ProbePod::new(name)
        .image("praqma/network-multitool")
        .label("app", "host-network-test")
        .requests(HostAccess::Network)
        .shell("sleep 3600")
        .build()
}

/// Creates a hostNetwork pod that serves a unique marker on a specified port.
/// This is used to create an observable state that can be verified by another tenant.
/// A host-network pod serving a marker on a chosen node port.
///
/// Host networking is deliberate: the marker must be reachable from another
/// tenant via the node's address, which is exactly what should be isolated.
fn create_node_marker_pod(name: &str, marker: &str, port: i32) -> Pod {
    // praqma/network-multitool ships nginx; point it at a custom port and serve
    // the marker.
    let serve_cmd = format!(
        "echo '{}' > /usr/share/nginx/html/index.html && \
         sed -i 's/listen.*80/listen {}/g' /etc/nginx/nginx.conf && \
         nginx -g 'daemon off;'",
        marker, port
    );

    ProbePod::new(name)
        .container("marker-server")
        .image("praqma/network-multitool")
        .label("app", "node-marker-service")
        .requests(HostAccess::Network)
        .host_port(port)
        .shell(serve_cmd)
        .build()
}

// =============================================================================
// DISPLAY IMPLEMENTATIONS
// =============================================================================

impl Display for NetworkResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkResource::PodNetwork => write!(f, "Pod Network"),
            NetworkResource::ServiceNetwork => write!(f, "Service Network"),
            NetworkResource::InfrastructureNetwork => write!(f, "Infrastructure Network"),
            NetworkResource::DnsResolution => write!(f, "DNS Resolution"),
        }
    }
}

impl Display for NetworkOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkOperation::ConnectToPod => write!(f, "Connect to Pod"),
            NetworkOperation::ConnectToService => write!(f, "Connect to Service"),
            NetworkOperation::ConnectToNode => write!(f, "Connect to Node"),
            NetworkOperation::ExposeNodePort => write!(f, "Expose NodePort"),
            NetworkOperation::ResolveDns => write!(f, "Resolve DNS"),
        }
    }
}

#[cfg(test)]
mod probe_requests_what_it_claims {
    //! The network counterpart of the workload guard of the same name.
    //!
    //! k8s-openapi silently drops keys it does not recognise, so a probe can
    //! fail to request the very thing it is testing and report isolation it
    //! never exercised. These assertions run against the typed struct, which is
    //! what the API server actually receives.
    //!
    //! The two directions matter equally here. The host-network probes must
    //! *keep* their privilege, because their rejection is the finding; the
    //! reachability probes must *keep* their restricted security context, or a
    //! hardened tenant refuses them and the measurement is lost rather than
    //! made.

    use super::*;

    fn spec(pod: &Pod) -> &k8s_openapi::api::core::v1::PodSpec {
        pod.spec.as_ref().expect("probe pod must have a spec")
    }

    #[test]
    fn the_host_network_probes_request_host_networking() {
        assert_eq!(
            spec(&create_host_network_pod("p")).host_network,
            Some(true),
            "without hostNetwork this probe tests nothing and reads as isolated"
        );

        let marker = create_node_marker_pod("m", "marker", NODE_MARKER_PORT);
        assert_eq!(spec(&marker).host_network, Some(true));
        assert_eq!(
            spec(&marker).containers[0].ports.as_ref().unwrap()[0].host_port,
            Some(NODE_MARKER_PORT),
            "the marker is only observable from another tenant via its hostPort"
        );
    }

    #[test]
    fn the_reachability_probes_stay_restricted_and_unprivileged() {
        // These need no privilege, and must satisfy the `restricted` Pod
        // Security Standard so they still run on a hardened tenant. If they
        // regress to requesting privilege, capsule-hardened refuses them and
        // the network columns go Unknown.
        for pod in [
            create_network_multitool_pod("p"),
            create_nodeport_marker_pod("p", "marker"),
        ] {
            let s = spec(&pod);
            assert_ne!(s.host_network, Some(true));
            assert_ne!(s.host_pid, Some(true));

            let pod_ctx = s.security_context.as_ref().expect("pod securityContext");
            assert_eq!(pod_ctx.run_as_non_root, Some(true));
            assert!(
                pod_ctx.seccomp_profile.is_some(),
                "restricted needs seccomp"
            );

            let container_ctx = s.containers[0]
                .security_context
                .as_ref()
                .expect("container securityContext");
            assert_eq!(container_ctx.allow_privilege_escalation, Some(false));
            assert_eq!(
                container_ctx.capabilities.as_ref().unwrap().drop,
                Some(vec!["ALL".to_string()])
            );
        }
    }

    #[test]
    fn the_reachability_probes_serve_on_an_unprivileged_port() {
        // Bound together: runAsNonRoot cannot bind below 1024, so the port and
        // the security context have to move as a pair. Splitting them yields a
        // probe that is admitted and then never answers.
        assert!(
            WEBSERVER_PORT >= 1024,
            "non-root cannot bind {WEBSERVER_PORT}"
        );
        assert_eq!(
            spec(&create_network_multitool_pod("p")).containers[0]
                .ports
                .as_ref()
                .unwrap()[0]
                .container_port,
            WEBSERVER_PORT
        );
    }
}

#[cfg(test)]
mod reachability_verdict_tests {
    use super::*;

    /// A rejection that was answered and an absent host are different findings.
    #[test]
    fn a_rejected_connection_is_soft_and_an_absent_host_is_hard() {
        let refused = judge_pod_reachability(
            "NETWORK_ACCESS_REFUSED: curl: (7) Failed to connect to 10.0.0.5 port 8080",
        );
        assert!(
            matches!(refused.isolation, IsolationLevel::Soft(_)),
            "something answered, so the network is shared: {refused:?}"
        );

        let no_host = judge_pod_reachability("NETWORK_ACCESS_NO_HOST: curl: (7) No route to host");
        assert_eq!(no_host.isolation, IsolationLevel::Hard);
    }

    /// Silence is not a refusal.
    ///
    /// The regression this pins down: under KubeVirt each tenant is its own
    /// cluster on its own network, so the other tenant's pod IP belongs to
    /// nobody here and the SYN goes unanswered — `curl: (28) Connection
    /// timeout`. That arrived bucketed with the refusals and reported `Soft`,
    /// "a policy forbade the cross-tenant operation", on a platform with no
    /// such policy and nothing present to enforce one.
    ///
    /// Nothing came back, which is exactly what a lone tenant curling an
    /// address nobody holds observes, so it is `Hard`.
    #[test]
    fn a_timeout_is_hard_because_nothing_answered() {
        let silent = judge_pod_reachability(
            "NETWORK_ACCESS_NO_ANSWER: curl: (28) Connection timeout after 2001 ms",
        );
        assert_eq!(
            silent.isolation,
            IsolationLevel::Hard,
            "silence is indistinguishable from an absent tenant: {silent:?}"
        );
    }

    /// A failure the probe could not classify is not a finding.
    #[test]
    fn an_unclassified_failure_is_undetermined() {
        assert_eq!(
            judge_pod_reachability("NETWORK_ACCESS_UNCLEAR: curl: (35) SSL connect error").isolation,
            IsolationLevel::Unknown
        );
    }

    #[test]
    fn observing_the_secret_is_a_breach() {
        let seen = judge_service_reachability("NETWORK_ACCESS_SUCCESS: reached the other tenant");
        assert_eq!(seen.isolation, IsolationLevel::None);
    }

    /// Nothing usable is not a finding either way.
    #[test]
    fn an_unreadable_report_is_undetermined() {
        let nothing = judge_pod_reachability("");
        assert_eq!(nothing.isolation, IsolationLevel::Unknown);
    }
}

#[cfg(test)]
mod dns_verdict_tests {
    use super::*;

    /// A record that resolves is a breach even with nothing behind it.
    #[test]
    fn resolving_the_other_tenants_name_is_a_breach() {
        let r = judge_dns_resolution("DNS_RESOLVED: the name resolves from another tenant");
        assert_eq!(r.isolation, IsolationLevel::None);
    }

    /// No record for this client is isolation; a withheld record is a rule.
    #[test]
    fn nxdomain_is_hard_and_refused_is_soft() {
        assert_eq!(
            judge_dns_resolution("DNS_NXDOMAIN: no such record").isolation,
            IsolationLevel::Hard
        );
        assert!(matches!(
            judge_dns_resolution("DNS_REFUSED: declined").isolation,
            IsolationLevel::Soft(_)
        ));
    }

    /// SERVFAIL is a broken resolver, not an absent record.
    ///
    /// A CoreDNS inside a custom VPC has no route to the API server, so it
    /// watches no Services and fails every lookup — its own tenant's included.
    /// The first classifier matched on "can't find", which nslookup prints for
    /// both NXDOMAIN and SERVFAIL, and so scored a broken resolver as isolation.
    #[test]
    fn servfail_is_undetermined_not_isolation() {
        let r = judge_dns_resolution(
            "DNS_SERVER_BROKEN: ** server can't find x.svc.cluster.local: SERVFAIL",
        );
        assert_eq!(r.isolation, IsolationLevel::Unknown);
        assert!(!r.autonomy);
    }

    /// The case that mattered: a tenant with no DNS at all.
    ///
    /// A Kube-OVN custom VPC has no route to cluster DNS, so every lookup times
    /// out — including the tenant's own. That was scored as isolation, which
    /// reported a broken tenant as a protected one.
    #[test]
    fn a_silent_dns_server_is_undetermined_not_isolation() {
        let r = judge_dns_resolution(
            "DNS_NO_SERVER: connection timed out; no servers could be reached",
        );
        assert_eq!(r.isolation, IsolationLevel::Unknown);
        assert!(
            !r.autonomy,
            "the tenant cannot resolve anything, its own names included"
        );
    }
}
