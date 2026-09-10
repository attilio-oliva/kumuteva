//! Network Fairness Assessor
//!
//! Measures network latency using TCP ping with per-packet RTT measurements.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use tracing::info;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, RateLimitStrategy, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

use futures::{StreamExt, TryStreamExt};
use kube::api::WatchParams;
use kube::Api;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Network assessor configuration
#[derive(Debug, Clone)]
pub struct FairnessNetworkConfig {
    /// Number of TCP ping client-server pod pairs per tenant
    pub pod_pairs: u32,
    /// Number of parallel streams per client (like iperf3 -P flag)
    pub streams: u32,
    /// Packet payload size in bytes (excluding protocol overhead)
    pub packet_size: u32,
}

impl Default for FairnessNetworkConfig {
    fn default() -> Self {
        Self {
            pod_pairs: 1,
            streams: 4,      // Default to 4 parallel streams like iperf3
            packet_size: 64, // Default 64 bytes payload
        }
    }
}

// =============================================================================
// ASSESSOR
// =============================================================================

/// Network fairness assessor using TCP ping for per-packet RTT measurements
pub struct FairnessNetworkAssessor {
    config: FairnessNetworkConfig,
}

impl FairnessNetworkAssessor {
    pub fn new(config: FairnessNetworkConfig) -> Self {
        Self { config }
    }

    /// Run a test phase
    async fn run_phase(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        duration: Duration,
        t1_pairs: u32,
        t2_pairs: u32,
        t1_rate: Option<f64>,
        t2_rate: Option<f64>,
    ) -> Result<PhaseResult> {
        let duration_secs = duration.as_secs();

        // Create TCP echo servers first (in parallel across tenants)
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        let (t1_servers, t2_servers) = tokio::try_join!(
            create_tcp_servers(&t1_clone, t1_pairs),
            create_tcp_servers(&t2_clone, t2_pairs)
        )?;

        // Small delay for servers to start listening
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Create all clients in parallel (they will start the actual test)
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        let streams = self.config.streams;
        let packet_size = self.config.packet_size;
        tokio::try_join!(
            create_tcp_ping_clients(
                &t1_clone,
                &t1_servers,
                duration_secs,
                t1_rate,
                streams,
                packet_size
            ),
            create_tcp_ping_clients(
                &t2_clone,
                &t2_servers,
                duration_secs,
                t2_rate,
                streams,
                packet_size
            )
        )?;

        // Wait for completion (in parallel across tenants)
        info!("Waiting for test completion ({} seconds)...", duration_secs);
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            wait_for_completion(&t1_clone, t1_pairs),
            wait_for_completion(&t2_clone, t2_pairs)
        )?;

        // Collect results
        info!("Collecting results from pods...");
        let t1_points = collect_results(&tenant1, t1_pairs).await?;
        let t2_points = collect_results(&tenant2, t2_pairs).await?;
        info!(
            "Collected {} points for Tenant 1 and {} points for Tenant 2",
            t1_points.len(),
            t2_points.len()
        );

        // Cleanup
        info!("Cleaning up pods...");
        tokio::try_join!(
            cleanup_pods(&tenant1, t1_pairs),
            cleanup_pods(&tenant2, t2_pairs)
        )?;

        info!("Cleanup completed.");

        // One logical operation is a TCP echo: the payload crosses the wire twice.
        // Reporting this makes the paper's bandwidth figures measured rather than
        // restated from the configured packet rate. Note that a "125 Mbps" style
        // figure quoting one-way payload is half the traffic actually carried.
        let bytes_per_operation = self.config.packet_size as f64 * 2.0;

        Ok(PhaseResult {
            tenant1: TenantMetrics::from_raw(t1_points)
                .with_bytes_per_operation(bytes_per_operation),
            tenant2: TenantMetrics::from_raw(t2_points)
                .with_bytes_per_operation(bytes_per_operation),
        })
    }
}

#[async_trait]
impl FairnessAssessor for FairnessNetworkAssessor {
    fn name(&self) -> &'static str {
        "Network"
    }

    fn metric(&self) -> &'static str {
        "TCP round-trip latency"
    }

    fn configuration(&self) -> Option<serde_json::Value> {
        // Bandwidth is derived from these, so a Mbps figure is uninterpretable
        // without them.
        Some(serde_json::json!({
            "pod_pairs": self.config.pod_pairs,
            "streams": self.config.streams,
            "packet_size_bytes": self.config.packet_size,
        }))
    }

    async fn run_baseline(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let rate = if matches!(config.strategy, RateLimitStrategy::Unlimited) {
            None
        } else {
            Some(config.tenant1_rate)
        };

        self.run_phase(
            tenant1,
            tenant2,
            config.baseline_duration,
            self.config.pod_pairs,
            self.config.pod_pairs,
            rate,
            rate,
        )
        .await
    }

    async fn run_unbalanced(
        &self,
        tenant1: Arc<TenantClusterConfig>,
        tenant2: Arc<TenantClusterConfig>,
        config: &FairnessConfig,
    ) -> Result<PhaseResult> {
        let t1_rate = if matches!(config.strategy, RateLimitStrategy::Unlimited) {
            None
        } else {
            Some(config.tenant1_rate)
        };
        let t2_rate = if matches!(config.strategy, RateLimitStrategy::Unlimited) {
            None
        } else {
            Some(config.malicious_rate())
        };
        let malicious_pairs =
            (self.config.pod_pairs as f64 * config.malicious_pod_multiplier) as u32;

        self.run_phase(
            tenant1,
            tenant2,
            config.test_duration,
            self.config.pod_pairs,
            malicious_pairs.max(1),
            t1_rate,
            t2_rate,
        )
        .await
    }
}

// =============================================================================
// HELPERS
// =============================================================================

const TCP_ECHO_PORT: u16 = 9999;

/// Server info: (index, server_ip)
type ServerInfo = (u32, String);

/// Create a high-performance TCP echo server pod using Python asyncio
fn tcp_server_pod(index: u32) -> Pod {
    // Python asyncio echo server - much faster than socat for handling multiple connections
    let python_script = format!(
        r#"
import asyncio

async def handle_client(reader, writer):
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except:
        pass
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', {port})
    print(f'TCP Echo Server listening on port {port}', flush=True)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"#,
        port = TCP_ECHO_PORT
    );

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("net-fairness-srv-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "tcp-server",
                "image": "python:3.11-alpine",
                "command": ["python3", "-c", python_script],
                "ports": [{"containerPort": TCP_ECHO_PORT}],
                "resources": {
                    "requests": { "memory": "128Mi", "cpu": "200m" },
                    "limits": { "memory": "256Mi", "cpu": "1000m" }
                }
            }]
        }
    }))
    .unwrap()
}

/// Create a high-performance TCP ping client pod using Python asyncio with pipelining
fn tcp_ping_client_pod(
    index: u32,
    server_ip: &str,
    duration: u64,
    rate: Option<f64>,
    streams: u32,
    packet_size: u32,
) -> Pod {
    // Calculate target packets per second per stream
    let rate_per_stream = rate.map(|r| r / streams as f64);
    let rate_str = rate_per_stream
        .map(|r| format!("{:.1}", r))
        .unwrap_or_else(|| "None".to_string());
    let total_rate_str = rate
        .map(|r| format!("{} pkt/s total", r))
        .unwrap_or_else(|| "unlimited".to_string());

    // Python asyncio TCP ping client, pipelined across `streams` connections.
    //
    // Written for cost per packet, because that cost is a hard constraint on
    // what can be measured. At 18,750 pkt/s the previous version burned 1.25
    // CPU per client pod — 67us per round trip — so ten intruder pods needed
    // ~14 CPUs of real work. On a 16-core budget that fits only if the tenants
    // are containers; inside KubeVirt VMs it did not, the generators were
    // starved, and the intruder delivered 24k of its 187.5k pkt/s target while
    // its own latency blew out to 1.9s. The degradation factor then described a
    // load generator that could not run.
    //
    // Four things were paid per packet and none of them had to be:
    //
    //   * a fresh `b'X' * 985` payload built for every send;
    //   * `asyncio.wait_for` around every `readline`, which allocates a Task
    //     and arms a timer each time;
    //   * a full decode of the 1000-byte response to recover a sequence number;
    //   * an f-string per sample.
    //
    // The sequence number is what forced the last two, and it is unnecessary: a
    // TCP connection to an echo server returns responses in the order they were
    // sent, so the Nth reply belongs to the Nth send. Matching by order means
    // one constant packet buffer, no parsing, and a deque instead of a dict.
    // Samples are kept as raw floats and formatted once at the end.
    //
    // Everything the previous version reported is still reported: a latency for
    // every individual packet rather than an average over a window, independent
    // streams, and the same `RESULTS:` line.
    let python_script = format!(
        r#"
import asyncio
import time
import sys
import gc
from array import array
from collections import deque

# The cyclic collector is off for the whole run.
#
# This client keeps a sample per packet, and CPython's generational GC scans
# *all* tracked objects on a gen-2 pass — inside the event loop, so the loop
# stops and every request in flight completes late together. It showed up as
# bursts of thousands of consecutive samples over 10ms while p50 stayed at
# 0.7ms, and those bursts decided p95. Refcounting frees everything here; the
# collector only exists for reference cycles, which floats in an array do not
# make.
gc.disable()
gc.freeze()

SERVER = "{server_ip}"
PORT = {port}
DURATION = {duration}
STREAMS = {streams}
RATE_PER_STREAM = {rate_str}  # packets per second per stream, None = unlimited
PACKET_SIZE = {packet_size}   # payload size in bytes
MAX_IN_FLIGHT = 1000          # per stream

# One packet, built once. Its contents carry no meaning: replies are matched to
# sends by order, not by anything written in them.
PKT = b'X' * max(1, PACKET_SIZE - 1) + b'\n'

print("=== TCP Ping Client Configuration ===", flush=True)
print(f"Server: {{SERVER}}:{{PORT}}", flush=True)
print(f"Duration: {{DURATION}} seconds", flush=True)
print(f"Streams: {{STREAMS}} (async connections)", flush=True)
print(f"Rate per stream: {{RATE_PER_STREAM}} pkt/s", flush=True)
print(f"Packet size: {{PACKET_SIZE}} bytes", flush=True)
print(f"Rate limit: {total_rate}", flush=True)
print(f"Pipelining: enabled (max {{MAX_IN_FLIGHT}} in-flight)", flush=True)
print("======================================", flush=True)

async def sender(writer, sent_at, start, end):
    """Pace packets to the target rate, sending whatever is due in one batch."""
    clock = time.perf_counter
    write = writer.write
    drain = writer.drain
    seq = 0
    while True:
        now = clock()
        if now >= end:
            break
        if len(sent_at) >= MAX_IN_FLIGHT:
            await asyncio.sleep(0.0005)
            continue
        if RATE_PER_STREAM:
            due = int((now - start) * RATE_PER_STREAM) - seq
            if due <= 0:
                # Ahead of schedule: wait for the next packet to fall due.
                ahead = (seq + 1) / RATE_PER_STREAM - (now - start)
                await asyncio.sleep(min(max(ahead, 0.0002), 0.005))
                continue
        else:
            due = 256
        for _ in range(due):
            sent_at.append(clock())
            write(PKT)
            seq += 1
        await drain()
    return seq

async def receiver(reader, sent_at, ts, rtt, start, stop):
    """One reply per send, in order, so matching is a popleft."""
    clock = time.perf_counter
    readline = reader.readline
    while True:
        # One await per packet, deliberately.
        #
        # Reading larger chunks and counting newlines is cheaper — but only by
        # about 3%, and it changes what is measured: every packet in a chunk
        # then shares the instant the application saw them, which drops the
        # reported latency roughly tenfold because the client's own
        # serialisation backlog stops being counted. Cheaper numbers that mean
        # something else are not a saving.
        line = await readline()
        if not line:
            break
        now = clock()
        if not sent_at:
            continue
        sent = sent_at.popleft()
        ts.append(sent - start)
        rtt.append((now - sent) * 1000.0)
        if stop.is_set() and not sent_at:
            break
    return len(rtt)

async def run_stream(stream_id, all_results):
    try:
        reader, writer = await asyncio.open_connection(SERVER, PORT)
    except Exception as e:
        print(f"[Stream {{stream_id}}] Connection failed: {{e}}", file=sys.stderr, flush=True)
        return

    start = time.perf_counter()
    end = start + DURATION
    sent_at = deque()
    ts = array('d')
    rtt = array('d')
    stop = asyncio.Event()
    sent = 0
    received = 0

    try:
        send_task = asyncio.create_task(sender(writer, sent_at, start, end))
        recv_task = asyncio.create_task(receiver(reader, sent_at, ts, rtt, start, stop))
        sent = await send_task
        stop.set()
        try:
            # One timer for the whole stream rather than one per packet.
            received = await asyncio.wait_for(recv_task, timeout=5.0)
        except asyncio.TimeoutError:
            recv_task.cancel()
    except Exception as e:
        print(f"[Stream {{stream_id}}] Error: {{e}}", file=sys.stderr, flush=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    # Formatted once, at the end, rather than per packet.
    append = all_results.append
    for i in range(len(rtt)):
        append("%.3f:%.3f:0" % (ts[i], rtt[i]))
    # Anything still outstanding never came back.
    for sent_time in sent_at:
        append("%.3f:2000.0:1" % (sent_time - start))
    print(
        f"[Stream {{stream_id}}] Sent {{sent}}, received {{received}}, lost {{len(sent_at)}}",
        file=sys.stderr,
        flush=True,
    )

async def main():
    print(f"Launching {{STREAMS}} pipelined streams...", flush=True)
    all_results = []
    await asyncio.gather(*[run_stream(i, all_results) for i in range(STREAMS)])
    print("All streams completed.", flush=True)

    total_errors = sum(1 for r in all_results if r.endswith(":1"))
    print(f"=== Summary ===", file=sys.stderr, flush=True)
    print(f"Total packets: {{len(all_results)}}", file=sys.stderr, flush=True)
    print(f"Total errors: {{total_errors}}", file=sys.stderr, flush=True)
    print(f"===============", file=sys.stderr, flush=True)

    print("RESULTS:" + ",".join(all_results) + ",", flush=True)

asyncio.run(main())
"#,
        server_ip = server_ip,
        port = TCP_ECHO_PORT,
        duration = duration,
        streams = streams,
        rate_str = rate_str,
        packet_size = packet_size,
        total_rate = total_rate_str,
    );

    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": format!("net-fairness-cli-{}", index) },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "tcp-ping",
                "image": "python:3.11-alpine",
                "command": ["python3", "-c", python_script],
                "resources": {
                    "requests": { "memory": "256Mi", "cpu": "500m" },
                    "limits": { "memory": "512Mi", "cpu": "2000m" }
                }
            }]
        }
    }))
    .unwrap()
}

/// Create all TCP echo servers and return their IPs
async fn create_tcp_servers(tenant: &TenantClusterConfig, pairs: u32) -> Result<Vec<ServerInfo>> {
    let mut servers = Vec::new();

    // Create all server pods
    for i in 0..pairs {
        let server = tcp_server_pod(i);
        let server_name = server.metadata.name.clone().unwrap();
        tenant
            .cluster
            .create_pod_in_namespace(&server, &tenant.namespace)
            .await?;
        servers.push((i, server_name));
    }

    // Wait for all servers to be ready and get their IPs
    let mut server_infos = Vec::new();
    for (index, server_name) in servers {
        tenant
            .cluster
            .wait_for_pod_to_be_ready(&server_name, &tenant.namespace)
            .await?;

        // Get server IP
        let mut server_ip = String::new();
        for _ in 0..10 {
            if let Ok(ip) = tenant
                .cluster
                .get_pod_ip(&server_name, &tenant.namespace)
                .await
            {
                if !ip.is_empty() {
                    server_ip = ip;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        if server_ip.is_empty() {
            return Err(anyhow::anyhow!(
                "Failed to get server IP for {}",
                server_name
            ));
        }

        server_infos.push((index, server_ip));
    }

    Ok(server_infos)
}

/// Create all TCP ping clients pointing to their respective servers
async fn create_tcp_ping_clients(
    tenant: &TenantClusterConfig,
    servers: &[ServerInfo],
    duration: u64,
    rate: Option<f64>,
    streams: u32,
    packet_size: u32,
) -> Result<()> {
    // Create all client pods
    let mut client_names = Vec::new();
    for (index, server_ip) in servers {
        let client = tcp_ping_client_pod(*index, server_ip, duration, rate, streams, packet_size);
        let client_name = client.metadata.name.clone().unwrap();
        tenant
            .cluster
            .create_pod_in_namespace(&client, &tenant.namespace)
            .await?;
        client_names.push(client_name);
    }

    // Wait for all clients to be ready (they start the test immediately)
    for client_name in client_names {
        tenant
            .cluster
            .wait_for_pod_to_be_ready(&client_name, &tenant.namespace)
            .await?;
    }

    Ok(())
}

async fn wait_for_completion(tenant: &TenantClusterConfig, pairs: u32) -> Result<()> {
    let api: Api<Pod> = Api::namespaced(tenant.cluster.client().clone(), &tenant.namespace);

    for i in 0..pairs {
        let name = format!("net-fairness-cli-{}", i);

        let is_pod_completed = async |pod_name: &str| -> bool {
            if let Ok(pod) = api.get(pod_name).await {
                return pod
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.as_ref())
                    .map(|p| p == "Succeeded" || p == "Failed")
                    .unwrap_or(false);
            }
            false
        };

        // First check if pod already completed
        if is_pod_completed(&name).await {
            continue;
        }

        // Watch for completion
        let wp = WatchParams::default()
            .fields(&format!("metadata.name={}", name))
            .timeout(290);

        let mut stream = api.watch(&wp, "0").await?.boxed();

        while let Some(_event) = stream.try_next().await? {
            if is_pod_completed(&name).await {
                break;
            }
        }
    }
    info!("All pods have completed their tests and terminated.");

    Ok(())
}

async fn collect_results(tenant: &TenantClusterConfig, pairs: u32) -> Result<Vec<MetricPoint>> {
    let mut points = Vec::new();

    for i in 0..pairs {
        let name = format!("net-fairness-cli-{}", i);
        let logs = tenant
            .cluster
            .get_pod_logs(&name, &tenant.namespace)
            .await?;

        // Parse "RESULTS:ts1:rtt1:err1,ts2:rtt2:err2,..." format
        if let Some(results_start) = logs.find("RESULTS:") {
            let results_str = &logs[results_start + 8..];
            for entry in results_str.split(',') {
                let parts: Vec<&str> = entry.trim().split(':').collect();
                if parts.len() >= 2 {
                    if let (Ok(ts), Ok(rtt)) = (parts[0].parse::<f64>(), parts[1].parse::<f64>()) {
                        let is_error = parts.get(2).map(|e| *e == "1").unwrap_or(false);
                        points.push(MetricPoint {
                            // Pacing happens inside the pod, so there is no dispatch schedule to
                            // measure against: the recorded latency is already the service time,
                            // and `ts` is already the pod's own dispatch clock.
                            scheduled_latency_ms: None,
                            slot_timestamp_secs: None,
                            timestamp_secs: ts,
                            latency_ms: rtt,
                            is_error,
                            label: Some(format!("tcp-ping-{}", i)),
                        });
                    }
                }
            }
        }
    }

    Ok(points)
}

async fn cleanup_pods(tenant: &TenantClusterConfig, pairs: u32) -> Result<()> {
    // First, initiate deletion for all pods in parallel (without waiting for the one before with another id to finish)

    tokio::try_join!(
        async {
            for i in 0..pairs {
                let server_name = format!("net-fairness-srv-{}", i);
                tenant
                    .cluster
                    .delete_pod_in_namespace(&server_name, &tenant.namespace)
                    .await?;
            }
            anyhow::Ok(())
        },
        async {
            for i in 0..pairs {
                let client_name = format!("net-fairness-cli-{}", i);
                tenant
                    .cluster
                    .delete_pod_in_namespace(&client_name, &tenant.namespace)
                    .await?;
            }
            anyhow::Ok(())
        }
    )?;

    // Wait for pods to be fully deleted to avoid "AlreadyExists" errors
    // Use timeout to prevent hanging if pods are stuck in Terminating state
    for i in 0..pairs {
        let server_name = format!("net-fairness-srv-{}", i);
        let client_name = format!("net-fairness-cli-{}", i);

        tenant
            .cluster
            .wait_for_pod_deletion(&server_name, &tenant.namespace)
            .await?;

        tenant
            .cluster
            .wait_for_pod_deletion(&client_name, &tenant.namespace)
            .await?;
    }

    Ok(())
}
