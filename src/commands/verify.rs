//! The `verify` subcommand: assess isolation between two tenants.

use anyhow::{Context, Result};

use super::prelude::*;

use crate::assessment;
use crate::assessment::AssessmentConfig;

pub async fn run(args: VerifyArgs) -> Result<()> {
    let verbose = args.verbose;
    let tenant1_kubeconfig_path = args.tenant1_kubeconfig_path;
    let tenant2_kubeconfig_path = args.tenant2_kubeconfig_path;
    let tenant1_namespace = args.tenant1_namespace;
    let tenant2_namespace = args.tenant2_namespace;
    let output_json = args.output_json;
    let list_properties = args.list_properties;
    let solution_label = args.solution_label;
    let runtime_class = args.runtime_class;
    let dns_nameserver = args.dns_nameserver;
    let control_plane = args.control_plane;
    let storage = args.storage;
    let network = args.network;
    let workload = args.workload;

    setup_logging(verbose)?;

    // Before anything touches a cluster: this is an inventory of what
    // the tool can assess, not a measurement of anything.
    if let Some(path) = list_properties {
        let inventory = assessment::report_json::PropertyInventoryJson::build();
        let count = inventory.property_count;
        std::fs::write(&path, serde_json::to_vec_pretty(&inventory)?)
            .with_context(|| format!("Failed to write property list to {:?}", path))?;
        println!(
            "{} assessable properties written to {}",
            count,
            path.display()
        );
        return Ok(());
    }

    // Set before any probe is constructed. Every probe reads it at build time,
    // so a later call would produce a run where some pods were sandboxed and
    // some were not.
    if let Some(name) = &runtime_class {
        println!("Probes will run under RuntimeClass '{name}'");
    }
    assessment::probe::set_runtime_class(runtime_class);
    if let Some(server) = &dns_nameserver {
        println!("Probes will resolve names through {server}");
    }
    assessment::probe::set_dns_nameserver(dns_nameserver);

    println!("Verifying cluster isolation...");
    // Taken before the assessment so the timestamp reflects when the run
    // started, not when it happened to finish.
    let started_at_utc = assessment::fairness_assessor::format_unix_utc(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    );
    let assessment_config = AssessmentConfig::from_flags(control_plane, storage, network, workload);
    println!("Assessment config: {}", assessment_config);

    let tenant1_config = Arc::new(TenantClusterConfig {
        cluster: KubernetesClient::load_with_retry(&tenant1_kubeconfig_path, 5).await?,
        namespace: tenant1_namespace,
    });
    let tenant2_config = Arc::new(TenantClusterConfig {
        cluster: KubernetesClient::load_with_retry(&tenant2_kubeconfig_path, 5).await?,
        namespace: tenant2_namespace,
    });

    let report =
        assessment::assess_multitenancy(tenant1_config, tenant2_config, &assessment_config)
            .await
            .context("Failed to run multitenancy assessment")?;

    println!("\nCluster isolation assessment report:");
    if let Some(cp) = &report.control_plane {
        println!("{}", cp);
    }
    if let Some(storage) = &report.storage {
        println!("{}", storage);
    }
    if let Some(network) = &report.network {
        println!("{}", network);
    }
    if let Some(workload) = &report.workload {
        println!("{}", workload);
    }
    println!("{}", report);

    if let Some(path) = output_json {
        let document = assessment::report_json::VerifyReportJson::new(
            &report,
            solution_label,
            started_at_utc,
            assessment::fairness_assessor::git_commit_hash(),
        );
        std::fs::write(&path, serde_json::to_vec_pretty(&document)?)
            .with_context(|| format!("Failed to write JSON report to {:?}", path))?;
        println!("\nJSON report written to {}", path.display());
    }

    Ok(())
}
