//! The `fairness` subcommand.
//!
//! Assembling this configuration is genuinely long — CLI over YAML over
//! defaults, across four subsystems, each with its own knobs — but it is
//! assembly, not orchestration. It lived inside a `match` arm in `main`, which
//! is how `async fn main` reached 438 lines and became the place to look for
//! everything.

use anyhow::Result;

use super::prelude::*;

use crate::assessment::fairness_assessor::FairnessRunnerBuilder;
use crate::assessment::{
    FairnessControlPlaneAssessor, FairnessControlPlaneConfig, FairnessNetworkAssessor,
    FairnessNetworkConfig, FairnessStorageAssessor, FairnessStorageConfig,
    FairnessWorkloadAssessor, FairnessWorkloadConfig,
};

/// Run a fairness assessment from parsed CLI arguments.
/// Print a subsystem's escalation when it differs from the global one.
///
/// Escalation is per subsystem, so the header's "Pod multiplier: 10x" is only
/// the default. A run that escalated the control plane 20x and the network 30x
/// printed 10x for both and said nothing about the override — so a campaign
/// file whose keys were silently dropped looked identical to one that applied,
/// and the only way to tell was to read the manifest afterwards.
fn print_pod_multiplier(subsystem: f64, global: f64) {
    if subsystem != global {
        println!("  Pod multiplier: {subsystem}x (custom, global is {global}x)");
    }
}

/// The rate half of the escalation, on the same terms.
fn print_load_multiplier(subsystem: f64, global: f64) {
    if subsystem != global {
        println!("  Rate multiplier: {subsystem}x (custom, global is {global}x)");
    }
}

/// What the intruder was actually asked for, once both halves are applied.
///
/// Neither multiplier means anything on its own — 3x pods at 10x rate and 30x
/// pods at 1x rate are the same offered load by very different routes — and
/// the total is the number that has to clear the subsystem's contention
/// threshold. Printing it removes the mental arithmetic at the point where a
/// misconfigured campaign is still cheap to catch.
fn print_escalation(rate: f64, load_multiplier: f64, pod_multiplier: f64, unit: &str) {
    let factor = load_multiplier * pod_multiplier;
    println!(
        "  Intruder target: {:.0} {unit} ({factor}x the owner\'s {:.0})",
        rate * factor,
        rate
    );
}

pub async fn run(cli_args: FairnessCliLayer) -> Result<()> {
    setup_logging(cli_args.verbose)?;
    println!("Running fairness assessment...\n");

    // Build Configuration (CLI > YAML > Defaults)
    let config_path = cli_args.config_file.clone();

    if let Some(ref path) = config_path {
        println!("Loading configuration from: {}\n", path.display());
    }

    let t1_path = cli_args.tenant1_kubeconfig_path.clone();
    let t2_path = cli_args.tenant2_kubeconfig_path.clone();
    let t1_ns = cli_args.tenant1_namespace.clone();
    let t2_ns = cli_args.tenant2_namespace.clone();

    let config = FairnessConfigBuilder::new()
        .with_yaml(config_path.as_ref())?
        .with_cli(cli_args)
        .build(); // No args passed here, logic is internal to build()

    // Load tenant configurations
    let tenant1_config = Arc::new(TenantClusterConfig {
        cluster: KubernetesClient::load_with_retry(&t1_path, 5).await?,
        namespace: t1_ns,
    });
    let tenant2_config = Arc::new(TenantClusterConfig {
        cluster: KubernetesClient::load_with_retry(&t2_path, 5).await?,
        namespace: t2_ns,
    });

    println!("Fairness Test Configuration:");
    println!(
        "  Baseline duration: {} seconds",
        config.baseline_duration.as_secs()
    );
    println!(
        "  Test duration: {} seconds",
        config.test_duration.as_secs()
    );
    println!("  Rate strategy: {:?}", config.rate_strategy);
    if !matches!(config.rate_strategy, RateLimitStrategy::Unlimited) {
        println!("  Rate limit: {} req/s", config.rate_limit);
    }
    println!("  Rate multiplier: {}x", config.load_multiplier);
    println!("  Pod multiplier: {}x", config.pod_multiplier);
    println!();

    let mut results = Vec::new();
    let mut failed_subsystems: Vec<&str> = Vec::new();

    // Helper to build a runner for a specific subsystem
    // Escalation is per subsystem, not global: each saturates at its own load.
    // On a 16-core node the network path needs ~30x before the victim degrades
    // at all — below that the kernel serves more traffic *faster*, and the
    // measurement reports the tenant improving under attack — while 10x is
    // already past what the control plane absorbs.
    let create_runner = |rate: f64, load_multiplier: f64, pod_multiplier: f64| {
        let mut builder = FairnessRunnerBuilder::new()
            .baseline_duration(config.baseline_duration)
            .test_duration(config.test_duration)
            .rate(rate)
            .strategy(config.rate_strategy.into())
            .malicious_multiplier(load_multiplier)
            .pod_multiplier(pod_multiplier);

        if config.export_csv {
            builder = builder.export_csv(&config.output_dir);
        }
        builder
            .build()
            .with_solution_label(config.solution_label.clone())
    };

    // Control Plane
    if config.run_cp {
        println!("═══════════════════════════════════════════════════════════");
        println!("Control Plane Fairness Assessment");
        println!("  Workers: {}", config.cp_requesters);
        if config.cp_rate != config.rate_limit {
            println!("  Rate limit: {} req/s (custom)", config.cp_rate);
        }
        print_load_multiplier(config.cp_load_multiplier, config.load_multiplier);
        print_pod_multiplier(config.cp_pod_multiplier, config.pod_multiplier);
        print_escalation(
            config.cp_rate,
            config.cp_load_multiplier,
            config.cp_pod_multiplier,
            "req/s",
        );
        println!("═══════════════════════════════════════════════════════════");

        let cp_assessor = FairnessControlPlaneAssessor::new(FairnessControlPlaneConfig {
            max_workers: config.cp_requesters,
        });
        let runner = create_runner(
            config.cp_rate,
            config.cp_load_multiplier,
            config.cp_pod_multiplier,
        );
        match runner
            .run(&cp_assessor, tenant1_config.clone(), tenant2_config.clone())
            .await
        {
            Ok(result) => results.push(("Control Plane", result)),
            Err(error) => {
                // One subsystem failing must not cancel the others. A
                // leftover PVC in storage previously aborted the whole
                // invocation, so the workload assessment never ran and
                // four repetitions produced no data for either.
                eprintln!("\n  ✗ Control Plane assessment failed: {error:#}");
                eprintln!("    continuing with the remaining subsystems");
                failed_subsystems.push("Control Plane");
            }
        }
    }

    // Network
    if config.run_network {
        println!("\n═══════════════════════════════════════════════════════════");
        println!("Network Fairness Assessment (TCP Ping)");
        println!(
            "  Pod pairs: {}, Streams: {}, Pkt byte size: {}",
            config.net_pod_pairs, config.net_streams, config.net_packet_size
        );
        if config.net_rate != config.rate_limit {
            println!("  Rate limit: {} req/s (custom)", config.net_rate);
        }
        print_load_multiplier(config.net_load_multiplier, config.load_multiplier);
        print_pod_multiplier(config.net_pod_multiplier, config.pod_multiplier);
        print_escalation(
            config.net_rate,
            config.net_load_multiplier,
            config.net_pod_multiplier,
            "pkt/s",
        );
        println!("═══════════════════════════════════════════════════════════");

        let net_assessor = FairnessNetworkAssessor::new(FairnessNetworkConfig {
            pod_pairs: config.net_pod_pairs,
            streams: config.net_streams,
            packet_size: config.net_packet_size,
        });
        let runner = create_runner(
            config.net_rate,
            config.net_load_multiplier,
            config.net_pod_multiplier,
        );
        match runner
            .run(
                &net_assessor,
                tenant1_config.clone(),
                tenant2_config.clone(),
            )
            .await
        {
            Ok(result) => results.push(("Network", result)),
            Err(error) => {
                // One subsystem failing must not cancel the others. A
                // leftover PVC in storage previously aborted the whole
                // invocation, so the workload assessment never ran and
                // four repetitions produced no data for either.
                eprintln!("\n  ✗ Network assessment failed: {error:#}");
                eprintln!("    continuing with the remaining subsystems");
                failed_subsystems.push("Network");
            }
        }
    }

    // Storage
    if config.run_storage {
        println!("\n═══════════════════════════════════════════════════════════");
        println!("Storage Fairness Assessment");
        println!(
            "  Pods: {}, Block: {}KB, File: {}MB, Scenario: {:?}, iodepth: {}",
            config.st_pods,
            config.st_block_size,
            config.st_file_size,
            config.st_scenario,
            config.st_iodepth
        );
        // Which path is under test decides what the number means, so it
        // belongs in the log as well as the manifest.
        println!(
            "  Volume: {:?}{}",
            config.st_volume,
            config
                .st_storage_class
                .as_deref()
                .map(|c| format!(" (storageClass {c})"))
                .unwrap_or_default()
        );
        if config.st_rate != config.rate_limit {
            println!("  Rate limit: {} req/s (custom)", config.st_rate);
        }
        print_load_multiplier(config.st_load_multiplier, config.load_multiplier);
        print_pod_multiplier(config.st_pod_multiplier, config.pod_multiplier);
        print_escalation(
            config.st_rate,
            config.st_load_multiplier,
            config.st_pod_multiplier,
            "IOPS",
        );
        println!("═══════════════════════════════════════════════════════════");

        let st_assessor = FairnessStorageAssessor::new(FairnessStorageConfig {
            pods: config.st_pods,
            block_size_kb: config.st_block_size,
            file_size_mb: config.st_file_size,
            scenario: config.st_scenario.into(),
            iodepth: config.st_iodepth,
            volume: config.st_volume.into(),
            storage_class_name: config.st_storage_class.clone(),
            qos_class: config.probe_qos.into(),
            runtime_class_name: config.runtime_class.clone(),
        });
        let runner = create_runner(
            config.st_rate,
            config.st_load_multiplier,
            config.st_pod_multiplier,
        );
        match runner
            .run(&st_assessor, tenant1_config.clone(), tenant2_config.clone())
            .await
        {
            Ok(result) => results.push(("Storage", result)),
            Err(error) => {
                // One subsystem failing must not cancel the others. A
                // leftover PVC in storage previously aborted the whole
                // invocation, so the workload assessment never ran and
                // four repetitions produced no data for either.
                eprintln!("\n  ✗ Storage assessment failed: {error:#}");
                eprintln!("    continuing with the remaining subsystems");
                failed_subsystems.push("Storage");
            }
        }
    }

    // Workload
    if config.run_workload {
        println!("\n═══════════════════════════════════════════════════════════");
        println!("Workload (CPU) Fairness Assessment");
        println!(
            "  Pods: {}, Threads: {}, Prime: {}",
            config.wl_pods, config.wl_threads, config.wl_max_prime
        );
        if config.wl_rate != config.rate_limit {
            println!("  Rate limit: {} req/s (custom)", config.wl_rate);
        }
        print_load_multiplier(config.wl_load_multiplier, config.load_multiplier);
        print_pod_multiplier(config.wl_pod_multiplier, config.pod_multiplier);
        print_escalation(
            config.wl_rate,
            config.wl_load_multiplier,
            config.wl_pod_multiplier,
            "req/s",
        );
        println!("═══════════════════════════════════════════════════════════");

        let wl_assessor = FairnessWorkloadAssessor::new(FairnessWorkloadConfig {
            pods: config.wl_pods,
            threads: config.wl_threads,
            max_prime: config.wl_max_prime,
            intruder_noise: config.wl_noise.into(),
            probe_qos: config.probe_qos.into(),
            intruder_qos: config.intruder_qos.into(),
            runtime_class_name: config.runtime_class.clone(),
        });
        let runner = create_runner(
            config.wl_rate,
            config.wl_load_multiplier,
            config.wl_pod_multiplier,
        );
        match runner
            .run(&wl_assessor, tenant1_config.clone(), tenant2_config.clone())
            .await
        {
            Ok(result) => results.push(("Workload", result)),
            Err(error) => {
                // One subsystem failing must not cancel the others. A
                // leftover PVC in storage previously aborted the whole
                // invocation, so the workload assessment never ran and
                // four repetitions produced no data for either.
                eprintln!("\n  ✗ Workload assessment failed: {error:#}");
                eprintln!("    continuing with the remaining subsystems");
                failed_subsystems.push("Workload");
            }
        }
    }

    // Summary
    println!("\n═══════════════════════════════════════════════════════════");
    println!("FAIRNESS ASSESSMENT SUMMARY");
    println!("═══════════════════════════════════════════════════════════\n");

    for (_, result) in &results {
        println!("{}", result);
    }

    // State plainly which subsystems produced no data. Without this a
    // partially failed run looks like a complete one in the summary, and
    // the gap is only noticed later when the analysis finds no files.
    if !failed_subsystems.is_empty() {
        println!(
            "\n  ✗ no data from: {} — these subsystems failed and were skipped",
            failed_subsystems.join(", ")
        );
    }

    if !results.is_empty() {
        let avg_deg: f64 = results
            .iter()
            .map(|(_, r)| r.latency_degradation)
            .sum::<f64>()
            / results.len() as f64;
        println!("\n───────────────────────────────────────────────────────────");
        println!("Overall Average Latency Degradation: {:.2}x", avg_deg);

        if let Some((worst_name, worst_res)) = results.iter().max_by(|a, b| {
            a.1.latency_degradation
                .partial_cmp(&b.1.latency_degradation)
                .unwrap()
        }) {
            println!(
                "Worst Subsystem: {} ({:.2}x degradation, {})",
                worst_name,
                worst_res.latency_degradation,
                worst_res.fairness_level()
            );
        }

        // Throughput retention is reported separately from latency because a
        // saturated system harms the victim on both axes at once, and a
        // latency-only figure understates the harm.
        let min_retention = results
            .iter()
            .map(|(_, r)| r.throughput_retention)
            .fold(f64::INFINITY, f64::min);
        if min_retention.is_finite() {
            println!(
                "Lowest Regular-Tenant Throughput Retention: {:.1}%",
                min_retention * 100.0
            );
            if min_retention < 0.95 {
                println!("  ⚠ at least one subsystem throttled the regular tenant below its");
                println!("    configured rate — degradation factors are lower bounds there");
            }
        }
    }

    if config.export_csv {
        println!("\n📁 Results exported to: {}/", config.output_dir);
    }

    Ok(())
}
