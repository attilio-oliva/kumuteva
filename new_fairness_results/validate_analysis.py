"""Validate the refactored analysis pipeline against the campaign data.

Run from `new_fairness_results/`:

    ../.venv/bin/python validate_analysis.py

Checks that every figure function renders for every subsystem, and that the
refactor still reproduces the published Table I degradation factors.

Loads one subsystem at a time and frees it before the next. The network and
storage runs are ~10^6 rows each, and `preprocessing` retains the full frame
plus per-tenant copies, so holding all four subsystems for all five solutions
at once costs several GB.
"""

import gc
import os
import resource

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

import utils.dataloader as dataloader
import utils.plots as plots
import utils.stats as stats
import utils.style as style

RAW_DATA_DIR = "./raw"
OUT_DIR = "./_validation_figures"
SYSTEMS = ["control_plane", "network", "storage", "workload"]

# Published Table I degradation factors.
PUBLISHED = {
    ("capsule", "control_plane"): 9.91,
    ("capsule-proxy", "control_plane"): 42.97,
    ("kubezoo", "control_plane"): 39.30,
    ("vcluster", "control_plane"): 1.54,
    ("kubevirt", "control_plane"): 0.68,
    ("capsule", "network"): 1.62,
    ("capsule-proxy", "network"): 1.37,
    ("kubezoo", "network"): 0.47,
    ("vcluster", "network"): 1.38,
    ("kubevirt", "network"): 0.71,
    ("capsule", "storage"): 3.02,
    ("capsule-proxy", "storage"): 3.25,
    ("kubezoo", "storage"): 2.37,
    ("vcluster", "storage"): 2.90,
    ("kubevirt", "storage"): 1.70,
    ("capsule", "workload"): 3.02,
    ("capsule-proxy", "workload"): 3.25,
    ("kubezoo", "workload"): 2.92,
    ("vcluster", "workload"): 2.96,
    ("kubevirt", "workload"): 0.96,
}

TOLERANCE = 0.05


def peak_memory_gb():
    # ru_maxrss is in kilobytes on Linux.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024


def main():
    style.apply_paper_style()
    os.makedirs(OUT_DIR, exist_ok=True)

    all_measurements = []

    for system in SYSTEMS:
        experiments = dataloader.load_experiment_data(RAW_DATA_DIR, [system])
        if not experiments:
            print(f"  {system}: no data")
            continue

        measurements = stats.measure_all(experiments)
        all_measurements.extend(measurements)

        plots.plot_latency_over_time(experiments, system, out_dir=OUT_DIR, save=False)
        plots.plot_latency_distribution(experiments, system, out_dir=OUT_DIR, save=False)
        plots.plot_p95_comparison(experiments, system, out_dir=OUT_DIR, save=False)
        plots.plot_latency_violin(experiments, system, out_dir=OUT_DIR, save=False)
        plots.plot_degradation(measurements, system, out_dir=OUT_DIR, save=False)
        plots.plot_throughput_retention(measurements, system, out_dir=OUT_DIR, save=False)
        plots.plot_latency_transition(experiments, system, out_dir=OUT_DIR, save=False)
        first_solution = plots.ordered_solutions(experiments)[0]
        plt.close("all")

        rows = sum(
            len(e["baseline"].raw_df) + len(e["stress_test"].raw_df)
            for e in experiments[first_solution].values()
        )
        print(
            f"  {system}: 7 figures rendered, "
            f"{rows:,} rows for {first_solution}, peak RSS {peak_memory_gb():.2f} GB"
        )

        del experiments
        gc.collect()

    summary = stats.to_frame(all_measurements)
    pd.set_option("display.width", 250)
    print()
    print(
        summary.sort_values(["system", "solution"])[
            [
                "solution",
                "system",
                "delta_latency",
                "delta_ci_low",
                "delta_ci_high",
                "throughput_retention",
                "owner_throttled",
                "stress_err_pct",
            ]
        ].to_string(index=False)
    )

    print()
    print("published vs recomputed (error rows excluded):")
    mismatches = 0
    for (solution, system), expected in sorted(PUBLISHED.items()):
        row = summary[(summary.solution == solution) & (summary.system == system)]
        if row.empty:
            print(f"  {solution:15s} {system:14s} MISSING")
            mismatches += 1
            continue
        actual = float(row.delta_latency.iloc[0])
        difference = abs(actual - expected)
        if difference >= TOLERANCE:
            mismatches += 1
            verdict = f"DIFFERS by {difference:.2f}"
        else:
            verdict = "ok"
        print(
            f"  {solution:15s} {system:14s} "
            f"published={expected:6.2f} recomputed={actual:6.2f}  {verdict}"
        )

    # PNG only: PGF export needs a working LaTeX toolchain.
    figure, _ = plots.plot_degradation(
        all_measurements, "control_plane", out_dir=OUT_DIR, save=False
    )
    style.save_plot(figure, f"{OUT_DIR}/control_plane_degradation", formats=("png",))
    plt.close("all")

    print(f"\npeak RSS {peak_memory_gb():.2f} GB")
    print(f"{mismatches} mismatch(es) against published values")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
