"""Load a result directory once, for either the latest run or every run.

The notebook selects between the two with a single flag and otherwise calls the
same plotting functions, so there is one narrative rather than two parallel sets
of cells.

Three constraints shape this module.

**Memory.** `dataloader.load_all_experiment_runs` builds an `ExperimentData` per
run and keeps them all; a storage run is around 10^6 rows and `ExperimentData`
holds the frame plus a copy per tenant, so five solutions x five repeats exhausts
a 32 GB machine. Here each run is loaded, reduced, and dropped before the next is
touched. Peak memory is one run plus the accumulated subsamples, a few hundred MB
rather than tens of GB. Reading only the columns that are used, with narrow
dtypes, takes another factor of three off.

**Statistical validity.** Per-run scalars are computed from that run's *full*
data, never from the subsample, and repeats are combined by
`stats.aggregate_runs` as the mean of per-run ratios. Averaging pooled means, or
averaging the per-run means and dividing, would both be wrong: the paper defines
the degradation factor per run, and for skewed data the ratio of means is not the
mean of ratios.

**Faithful figures.** Distribution plots need samples, not scalars, so each run
contributes an equal-sized uniform subsample to a pooled frame. Equal-sized
matters — a run that lasted longer would otherwise dominate the pooled shape and
the figure would describe that run rather than the set.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
import pyarrow as pa
from pyarrow import csv as pacsv

import utils.dataloader as dataloader
import utils.preprocessing as preprocessing
import utils.stats as stats

# Per-run contribution to a pooled figure. 20k rows is far more than any plot can
# resolve — a violin or a sliding mean is indistinguishable well below this — and
# it bounds the pooled frame to a few tens of MB across every solution.
SAMPLES_PER_RUN = 20_000

# Only these are read. The CSV also carries `scheduled_latency_ms` and
# `slot_timestamp_secs`, both diagnostics of whether the generator kept up
# rather than anything plotted, and there is no reason to pay for them in every
# frame.
CSV_COLUMNS = ["tenant", "timestamp_secs", "latency_ms", "is_error", "label"]

# The shape `summarise` returns when there is nothing to summarise, so the
# notebook's column selection still finds what it asks for.
SUMMARY_COLUMNS = [
    "solution",
    "system",
    "runs",
    "failed_runs",
    "delta_latency",
    "delta_ci_low",
    "delta_ci_high",
    "throughput_retention",
    "owner_throttled",
    "delta_spread",
    "baseline_err_pct",
    "stress_err_pct",
    "baseline_ops",
    "stress_ops",
]

# How those columns are narrowed on the way in. Declaring the types up front is
# what keeps the conversion cheap: an Arrow dictionary column becomes a pandas
# category without a second pass, and the numerics never materialise as float64.
# A campaign's largest frame is 109 MB this way against ~495 MB left to
# inference.
ARROW_TYPES = {
    "tenant": pa.dictionary(pa.int32(), pa.string()),
    "timestamp_secs": pa.float32(),
    "latency_ms": pa.float32(),
    "is_error": pa.bool_(),
    "label": pa.dictionary(pa.int32(), pa.string()),
}


@dataclass
class LoadReport:
    """What was loaded, so a notebook can state it rather than imply it."""

    selection: str
    runs_per_pair: dict
    total_runs: int

    def describe(self):
        if self.selection == "latest":
            return f"latest run only ({self.total_runs} loaded)"
        counts = sorted({n for n in self.runs_per_pair.values()})
        spread = counts[0] if len(counts) == 1 else f"{counts[0]}-{counts[-1]}"
        return f"all runs ({self.total_runs} loaded, {spread} per solution/subsystem)"


def _read_csv(path):
    """Read one result CSV with narrow dtypes and only the needed columns.

    Arrow's reader rather than `pd.read_csv`, which is the single biggest cost in
    a load: 0.23 s against 1.21 s on the campaign's largest file (374 MB, 9.9M
    rows). It reads the columns in parallel, and `include_columns` means the
    three we do not plot are never converted.

    Not `pd.read_csv(engine="pyarrow")`, which is nearly as fast and peaks at
    1.76 GB on that file against 0.59 GB here. The difference is
    `self_destruct`: it releases each Arrow buffer as it is converted, instead of
    holding the whole table alongside the finished frame. The table is unusable
    afterwards, hence the `del`.
    """
    table = pacsv.read_csv(
        path,
        convert_options=pacsv.ConvertOptions(
            include_columns=CSV_COLUMNS,
            # Older runs predate some columns. A missing one comes back as a
            # typed all-null column, which is what the rest of the pipeline
            # expects; without this the read would raise instead.
            include_missing_columns=True,
            column_types=ARROW_TYPES,
        ),
    )
    frame = table.to_pandas(self_destruct=True, split_blocks=True)
    del table
    return frame


def _to_experiment(frame, metadata=None):
    """Wrap a raw frame in the `ExperimentData` the plot functions expect."""
    renames = preprocessing.TestResultDeserializer().column_mapping
    frame = frame.rename(columns={k: v for k, v in renames.items() if k in frame.columns})
    return preprocessing.ExperimentData(frame, metadata or {})


def _subsample(frame, budget):
    """Take up to `budget` rows spread evenly across the frame.

    Evenly rather than randomly: these rows are also used for the latency-over-
    time figures, and a uniform stride keeps the series covering the whole phase
    instead of clumping. For distribution plots a stride is equivalent to a
    random draw, since row order carries no relation to latency beyond the time
    trend the figures are meant to show.
    """
    if len(frame) <= budget:
        return frame
    stride = len(frame) / budget
    positions = (np.arange(budget) * stride).astype(np.int64)
    return frame.iloc[positions]


def load(src_dir, systems, selection="latest", samples_per_run=SAMPLES_PER_RUN, confidence=0.95):
    """Load `src_dir` and return `(measurements, experiments, report)`.

    `selection` is `"latest"` for the most recent run of each
    (solution, subsystem), or `"all"` for every run.

    `measurements` holds one `stats.FairnessMeasurement` per *run*, each computed
    from that run's complete data. Pass it to `stats.aggregate_runs` to combine
    repeats; `stats.to_frame` tabulates it as-is.

    `experiments` is the `[solution][system]` tree the plot functions take. Under
    `"all"` each entry pools an equal-sized subsample from every run of that
    pair, so the figures describe the set rather than whichever run happened to
    be last.
    """
    if selection not in ("latest", "all"):
        raise ValueError(f"selection must be 'latest' or 'all', got {selection!r}")

    pairs = _index_runs(src_dir, systems)
    if selection == "latest":
        pairs = {key: [max(timestamps)] for key, timestamps in pairs.items()}

    measurements = []
    experiments = {}
    # Subsamples accumulate here as small frames and are concatenated once at the
    # end; concatenating per run would copy the whole thing on every iteration.
    pooled = {}

    for (solution, system), timestamps in sorted(pairs.items()):
        # Split the budget so every run contributes equally to the pooled figure,
        # whatever its length.
        budget = max(1, samples_per_run // max(1, len(timestamps)))

        for timestamp in sorted(timestamps):
            paths = _paths_for(src_dir, solution, system, timestamp)
            if paths is None:
                continue

            baseline_raw, stress_raw = (_read_csv(p) for p in paths)

            baseline = _to_experiment(baseline_raw)
            metadata = baseline.as_baseline_metadata()
            stress = _to_experiment(stress_raw, metadata)

            # Measured on the full run, before anything is thrown away.
            measurements.append(
                stats.measure(
                    {
                        "baseline": baseline,
                        "stress_test": stress,
                        "manifest": dataloader.load_manifest(paths[1]),
                    },
                    solution,
                    system,
                    confidence=confidence,
                )
            )

            key = (solution, system)
            pooled.setdefault(key, {"baseline": [], "stress": [], "metadata": metadata})
            pooled[key]["baseline"].append(_subsample(baseline_raw, budget))
            pooled[key]["stress"].append(_subsample(stress_raw, budget))

            # The full frames are the expensive part; release them before the
            # next run is read rather than at the end of the loop's scope.
            del baseline_raw, stress_raw, baseline, stress

    for (solution, system), parts in pooled.items():
        baseline = _to_experiment(pd.concat(parts["baseline"], ignore_index=True))
        stress = _to_experiment(
            pd.concat(parts["stress"], ignore_index=True), parts["metadata"]
        )
        experiments.setdefault(solution, {})[system] = {
            "baseline": baseline,
            "stress_test": stress,
            "baseline_metadata": parts["metadata"],
        }

    report = LoadReport(
        selection=selection,
        runs_per_pair={f"{s}/{y}": len(t) for (s, y), t in pairs.items()},
        total_runs=sum(len(t) for t in pairs.values()),
    )
    return measurements, experiments, report


def summarise(measurements, selection, confidence=0.95):
    """Tabulate measurements, aggregating repeats when there are any.

    Under `"all"` the degradation column is the mean of per-run ratios with a
    bootstrap interval over runs — not a statistic recomputed from pooled rows,
    which would silently weight the longer runs more heavily.

    Loading nothing gives an empty table rather than an error: the notebook
    already reports "no data" per subsystem, and a traceback from the summary
    cell buries that message under a stack trace about a missing column.
    """
    if not measurements:
        return pd.DataFrame(columns=SUMMARY_COLUMNS)

    if selection == "latest":
        return stats.to_frame(measurements)

    aggregated = stats.aggregate_runs(measurements, confidence=confidence)
    per_run = stats.to_frame(measurements)
    # Error rates and achieved operations are counts, so a plain mean across runs
    # is the right combination for them; only the ratios need the careful path.
    extras = (
        per_run.groupby(["solution", "system"], as_index=False)[
            ["baseline_err_pct", "stress_err_pct", "baseline_ops", "stress_ops"]
        ].mean()
    )

    frame = pd.DataFrame(
        [
            {
                "solution": a.solution,
                "system": a.system,
                "runs": a.runs,
                "failed_runs": a.excluded_runs,
                "delta_latency": a.mean_degradation,
                "delta_ci_low": a.degradation_ci[0],
                "delta_ci_high": a.degradation_ci[1],
                "throughput_retention": a.mean_throughput_retention,
                "owner_throttled": a.mean_throughput_retention
                < stats.THROUGHPUT_RETENTION_THRESHOLD,
                "delta_spread": (
                    max(a.per_run_degradations) - min(a.per_run_degradations)
                    if a.per_run_degradations
                    else float("nan")
                ),
            }
            for a in aggregated
        ]
    )
    return frame.merge(extras, on=["solution", "system"], how="left")


def measurements_for_plots(measurements, selection):
    """Reduce per-run measurements to the one-per-pair the bar charts expect.

    `plot_degradation` and `plot_throughput_retention` draw one bar per solution.
    Handed five runs of the same solution they would draw five. Collapse to the
    aggregate, keeping the mean of per-run ratios rather than re-deriving
    anything from pooled samples.
    """
    if selection == "latest":
        return measurements

    collapsed = []
    for aggregate in stats.aggregate_runs(measurements):
        matching = [
            m
            for m in measurements
            if m.solution == aggregate.solution and m.system == aggregate.system
        ]
        template = matching[0]
        collapsed.append(
            stats.FairnessMeasurement(
                solution=aggregate.solution,
                system=aggregate.system,
                latency_degradation=aggregate.mean_degradation,
                latency_ci=aggregate.degradation_ci,
                throughput_retention=aggregate.mean_throughput_retention,
                baseline_mean_ms=float(np.mean([m.baseline_mean_ms for m in matching])),
                stress_mean_ms=float(np.mean([m.stress_mean_ms for m in matching])),
                baseline_p95_ms=float(np.mean([m.baseline_p95_ms for m in matching])),
                stress_p95_ms=float(np.mean([m.stress_p95_ms for m in matching])),
                baseline_error_rate=float(np.mean([m.baseline_error_rate for m in matching])),
                stress_error_rate=float(np.mean([m.stress_error_rate for m in matching])),
                baseline_operations=template.baseline_operations,
                stress_operations=template.stress_operations,
            )
        )
    return collapsed


def _index_runs(src_dir, systems):
    """Map (solution, system) to the timestamps that have both phases present.

    Globs only — no CSV is opened here, so the run inventory costs nothing and
    the per-run subsample budget can be decided before any data is read.
    """
    stress = dataloader._get_all_file_paths_generic(
        src_dir, dataloader.DATA_CONFIGS["stresstest"]
    )
    baseline = dataloader._get_all_file_paths_generic(
        src_dir, dataloader.DATA_CONFIGS["baseline"]
    )

    pairs = {}
    for solution, system, timestamp in stress:
        if systems and system not in systems:
            continue
        if (solution, system, timestamp) not in baseline:
            continue
        pairs.setdefault((solution, system), []).append(timestamp)
    return pairs


def _paths_for(src_dir, solution, system, timestamp):
    """Locate the baseline/unbalanced pair for one run."""
    import os

    directory = os.path.join(src_dir, solution)
    baseline = os.path.join(directory, f"{system}_baseline_{timestamp}.csv")
    stress = os.path.join(directory, f"{system}_unbalanced_{timestamp}.csv")
    if not (os.path.exists(baseline) and os.path.exists(stress)):
        return None
    return baseline, stress
