//! The `setup` subcommand: provision a two-tenant test cluster.

use anyhow::Result;

use super::prelude::*;

pub async fn run(args: SetupArgs) -> Result<()> {
    let existing_cluster_kubeconfig = args.existing_cluster_kubeconfig;
    let output_dir = args.output_dir;
    let cluster_name = args.cluster_name;
    let kind = args.kind;
    let provider = args.provider;
    let tenant1 = args.tenant1;
    let tenant2 = args.tenant2;
    let verbose = args.verbose;

    setup_logging(verbose)?;
    println!("Setting up test environment...");
    // `--cluster-name` is used exactly as given. It previously had the
    // solution appended, so `--cluster-name bench` silently became
    // `bench-capsule`, and every later command that needs the real name
    // — `kind delete cluster`, `docker update --cpuset-cpus`, reading
    // back the kubeconfig — had to know about the rewrite to find it.
    let solution = kind.as_str().to_string();
    setup_test_environment(
        existing_cluster_kubeconfig,
        output_dir,
        &cluster_name,
        kind,
        provider,
        tenant1,
        tenant2,
    )
    .await?;
    println!("Test environment setup complete");
    println!("  cluster:  {cluster_name}");
    println!("  solution: {solution}");
    println!("  pass `--solution-label {solution}` to `fairness` so the run manifest records it");

    Ok(())
}
