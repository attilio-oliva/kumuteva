//! Network Fairness Assessor
//!
//! Measures network latency using TCP ping with per-packet RTT measurements.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use crate::assessment::fairness_assessor::{
    FairnessAssessor, FairnessConfig, MetricPoint, PhaseResult, RateLimitStrategy, TenantMetrics,
};
use crate::assessment::TenantClusterConfig;

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
            streams: 4, // Default to 4 parallel streams like iperf3
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
            create_tcp_ping_clients(&t1_clone, &t1_servers, duration_secs, t1_rate, streams, packet_size),
            create_tcp_ping_clients(&t2_clone, &t2_servers, duration_secs, t2_rate, streams, packet_size)
        )?;

        // Wait for completion (in parallel across tenants)
        let t1_clone = tenant1.clone();
        let t2_clone = tenant2.clone();
        tokio::try_join!(
            wait_for_completion(&t1_clone, t1_pairs),
            wait_for_completion(&t2_clone, t2_pairs)
        )?;

        // Collect results
        let t1_points = collect_results(&tenant1, t1_pairs).await?;
        let t2_points = collect_results(&tenant2, t2_pairs).await?;

        // Cleanup
        cleanup_pods(&tenant1, t1_pairs).await?;
        cleanup_pods(&tenant2, t2_pairs).await?;

        Ok(PhaseResult {
            tenant1: TenantMetrics::from_raw(t1_points),
            tenant2: TenantMetrics::from_raw(t2_points),
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
            (self.config.pod_pairs as f64 * config.malicious_load_multiplier) as u32;

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

/// Create a high-performance TCP ping client pod using Python asyncio
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

    // Python asyncio TCP ping client - can achieve very high packet rates
    let python_script = format!(
        r#"
import asyncio
import time
import sys

SERVER = "{server_ip}"
PORT = {port}
DURATION = {duration}
STREAMS = {streams}
RATE_PER_STREAM = {rate_str}  # packets per second per stream, None = unlimited
PACKET_SIZE = {packet_size}  # payload size in bytes

# Pre-generate padding for packet payload (message format: "P<seq><padding>\n")
# We need room for: "P" (1) + seq number (~10 max) + "\n" (1) = ~12 bytes overhead
# The rest is padding. Final message is exactly PACKET_SIZE bytes.
def make_packet(seq):
    prefix = f"P{{seq}}".encode()
    # Total size = PACKET_SIZE, last byte is newline
    padding_len = max(0, PACKET_SIZE - len(prefix) - 1)
    return prefix + (b'X' * padding_len) + b'\n'

print("=== TCP Ping Client Configuration ===", flush=True)
print(f"Server: {{SERVER}}:{{PORT}}", flush=True)
print(f"Duration: {{DURATION}} seconds", flush=True)
print(f"Streams: {{STREAMS}} (async connections)", flush=True)
print(f"Rate per stream: {{RATE_PER_STREAM}} pkt/s", flush=True)
print(f"Packet size: {{PACKET_SIZE}} bytes", flush=True)
print(f"Rate limit: {total_rate}", flush=True)
print("======================================", flush=True)

async def run_stream(stream_id: int, results: list):
    interval = 1.0 / RATE_PER_STREAM if RATE_PER_STREAM else 0
    
    try:
        reader, writer = await asyncio.open_connection(SERVER, PORT)
        print(f"[Stream {{stream_id}}] Connected", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"[Stream {{stream_id}}] Connection failed: {{e}}", file=sys.stderr, flush=True)
        return
    
    start_time = time.perf_counter()
    end_time = start_time + DURATION
    packet_count = 0
    error_count = 0
    stream_results = []
    
    try:
        while time.perf_counter() < end_time:
            loop_start = time.perf_counter()
            
            # Send packet with configured size (ends with \n for readline)
            msg = make_packet(packet_count)
            before = time.perf_counter()
            writer.write(msg)
            await writer.drain()
            
            # Receive response (server echoes back, ends with \n)
            try:
                response = await asyncio.wait_for(reader.readline(), timeout=1.0)
                after = time.perf_counter()
                rtt_ms = (after - before) * 1000
                rel_ts = before - start_time
                stream_results.append(f"{{rel_ts:.3f}}:{{rtt_ms:.3f}}:0")
            except asyncio.TimeoutError:
                after = time.perf_counter()
                rtt_ms = (after - before) * 1000
                rel_ts = before - start_time
                stream_results.append(f"{{rel_ts:.3f}}:{{rtt_ms:.3f}}:1")
                error_count += 1
            
            packet_count += 1
            
            # Rate limiting
            if interval > 0:
                elapsed = time.perf_counter() - loop_start
                sleep_time = interval - elapsed
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
    except Exception as e:
        print(f"[Stream {{stream_id}}] Error: {{e}}", file=sys.stderr, flush=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
    
    results.extend(stream_results)
    print(f"[Stream {{stream_id}}] Completed {{packet_count}} packets ({{error_count}} errors)", file=sys.stderr, flush=True)

async def main():
    print(f"Launching {{STREAMS}} async streams...", flush=True)
    
    all_results = []
    tasks = [run_stream(i, all_results) for i in range(STREAMS)]
    
    print("Waiting for streams to complete...", flush=True)
    await asyncio.gather(*tasks)
    print("All streams completed.", flush=True)
    
    # Output results
    total_packets = len(all_results)
    total_errors = sum(1 for r in all_results if r.endswith(":1"))
    
    print(f"=== Summary ===", file=sys.stderr, flush=True)
    print(f"Total packets: {{total_packets}}", file=sys.stderr, flush=True)
    print(f"Total errors: {{total_errors}}", file=sys.stderr, flush=True)
    print(f"===============", file=sys.stderr, flush=True)
    
    # Print results in expected format
    results_str = ",".join(all_results)
    print(f"RESULTS:{{results_str}},", flush=True)

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
                    "requests": { "memory": "128Mi", "cpu": "200m" },
                    "limits": { "memory": "256Mi", "cpu": "1000m" }
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
    use futures::{StreamExt, TryStreamExt};
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::WatchParams;
    use kube::Api;

    let api: Api<Pod> = Api::namespaced(tenant.cluster.client().clone(), &tenant.namespace);

    for i in 0..pairs {
        let name = format!("net-fairness-cli-{}", i);

        let is_completed = |pod: &Pod| -> bool {
            pod.status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| p == "Succeeded" || p == "Failed")
                .unwrap_or(false)
        };

        // First check if pod already completed
        if let Ok(pod) = api.get(&name).await {
            if is_completed(&pod) {
                continue;
            }
        }

        // Watch for completion
        let wp = WatchParams::default()
            .fields(&format!("metadata.name={}", name))
            .timeout(290);

        let mut stream = api.watch(&wp, "0").await?.boxed();

        while let Some(event) = stream.try_next().await? {
            if let kube::api::WatchEvent::Modified(pod) = event {
                if is_completed(&pod) {
                    break;
                }
            }
        }
    }

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
    // First, initiate deletion for all pods
    for i in 0..pairs {
        let server_name = format!("net-fairness-srv-{}", i);
        let client_name = format!("net-fairness-cli-{}", i);

        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&server_name, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .delete_pod_in_namespace(&client_name, &tenant.namespace)
            .await;
    }

    // Wait for pods to be fully deleted to avoid "AlreadyExists" errors
    for i in 0..pairs {
        let server_name = format!("net-fairness-srv-{}", i);
        let client_name = format!("net-fairness-cli-{}", i);

        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&server_name, &tenant.namespace)
            .await;
        let _ = tenant
            .cluster
            .wait_for_pod_deletion(&client_name, &tenant.namespace)
            .await;
    }

    Ok(())
}
