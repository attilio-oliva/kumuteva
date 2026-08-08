"""Fairness statistics: degradation, throughput retention, and uncertainty.

Three corrections to the original notebook analysis live here.

1. Error rows are excluded from latency statistics. The network probe emits a
   2000 ms sentinel with `is_error=true` when a request times out; averaging
   that in makes a lost packet look like a very slow one. Error *rate* is
   reported separately instead, as its own fairness dimension.

2. Uncertainty on the degradation ratio is estimated by bootstrap rather than
   Gaussian error propagation. The original propagated the standard deviation
   of individual request latencies, which describes how spread out requests are,
   not how uncertain the mean is — for n in the thousands that overstates the
   error bar by roughly sqrt(n). Latency is also heavy-tailed (every published
   plot is log-scale), so the normal approximation behind the propagation
   formula does not hold in the first place.

3. Aggregating repeated runs uses the mean of per-run ratios, not the ratio of
   pooled means. Delta is defined per run; by Jensen's inequality the two differ
   for skewed data, and only the former answers "what degradation does a tenant
   typically see".
"""

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

# A regular tenant retaining less than this fraction of its baseline request
# rate was throttled rather than merely slowed, which makes the latency
# degradation a lower bound on the true impact.
THROUGHPUT_RETENTION_THRESHOLD = 0.95

LATENCY_COLUMN = "duration_ms"
ERROR_COLUMN = "is_error"


def successful(frame):
    """Rows usable for latency statistics: no errors, positive duration."""
    if frame is None or len(frame) == 0:
        return frame
    usable = frame[LATENCY_COLUMN] > 0
    if ERROR_COLUMN in frame.columns:
        usable &= ~frame[ERROR_COLUMN].astype(bool)
    return frame[usable]


def error_rate(frame):
    """Fraction of operations that failed, in percent."""
    if frame is None or len(frame) == 0 or ERROR_COLUMN not in frame.columns:
        return 0.0
    return 100.0 * float(frame[ERROR_COLUMN].astype(bool).mean())


def achieved_rate(frame, duration_seconds=None):
    """Operations per second over the window the data actually covers.

    Derived from the timestamps rather than the configured phase duration: the
    pod-based subsystems measure inside the pod, so wall-clock would charge them
    for pod startup.
    """
    if frame is None or len(frame) == 0:
        return 0.0
    if duration_seconds is None:
        if "elapsed_seconds" not in frame.columns:
            return 0.0
        duration_seconds = frame["elapsed_seconds"].max() - frame["elapsed_seconds"].min()
    if not duration_seconds or duration_seconds <= 0:
        return 0.0
    return len(frame) / duration_seconds


# Above this sample size the bootstrap is switched off in favour of the delta
# method. Two reasons, and both matter:
#
#   * Memory. A percentile bootstrap materialises a (resamples x n) matrix. At
#     n = 1.2e6 (a storage run) and 2000 resamples that is 2.4e9 float64s, about
#     19 GB — enough to take the machine into swap.
#   * Statistics. By the central limit theorem the sampling distribution of the
#     mean is essentially normal once n is in the thousands, however heavy the
#     tail of the underlying latency distribution. Resampling then buys nothing
#     the closed form does not already give.
BOOTSTRAP_MAX_SAMPLE_SIZE = 20_000

# Two-sided normal quantiles for the confidence levels worth supporting.
_NORMAL_QUANTILES = {0.90: 1.6449, 0.95: 1.9600, 0.99: 2.5758}


def _standard_error_of_mean(values):
    """SE of the mean: the sample standard deviation divided by sqrt(n).

    The distinction this encodes is the one the original analysis missed. The
    sample standard deviation describes how spread out individual requests are
    and barely shrinks as more data arrives; the standard error describes how
    precisely the *mean* is known and falls as 1/sqrt(n). Propagating the former
    into a ratio inflates the error bar by roughly sqrt(n).
    """
    if len(values) < 2:
        return float("nan")
    return float(values.std(ddof=1) / np.sqrt(len(values)))


def delta_method_ratio_ci(baseline, stress, confidence=0.95):
    """Closed-form CI for mean(stress) / mean(baseline).

    Works on the log ratio, where the two means enter additively and the
    interval is guaranteed positive, then exponentiates back.
    """
    baseline = np.asarray(baseline, dtype=float)
    stress = np.asarray(stress, dtype=float)
    if len(baseline) < 2 or len(stress) < 2:
        return (float("nan"), float("nan"))

    baseline_mean = baseline.mean()
    stress_mean = stress.mean()
    if baseline_mean <= 0 or stress_mean <= 0:
        return (float("nan"), float("nan"))

    relative_error = np.sqrt(
        (_standard_error_of_mean(stress) / stress_mean) ** 2
        + (_standard_error_of_mean(baseline) / baseline_mean) ** 2
    )
    if not np.isfinite(relative_error):
        return (float("nan"), float("nan"))

    z = _NORMAL_QUANTILES.get(confidence, 1.9600)
    log_ratio = np.log(stress_mean) - np.log(baseline_mean)
    return (
        float(np.exp(log_ratio - z * relative_error)),
        float(np.exp(log_ratio + z * relative_error)),
    )


def bootstrap_ratio_ci(baseline, stress, confidence=0.95, resamples=2000, seed=0):
    """CI for mean(stress) / mean(baseline).

    Percentile bootstrap for samples small enough to resample cheaply, delta
    method beyond `BOOTSTRAP_MAX_SAMPLE_SIZE`. The two agree closely wherever
    both are applicable; the cutoff exists so a million-row run cannot allocate
    tens of gigabytes.
    """
    baseline = np.asarray(baseline, dtype=float)
    stress = np.asarray(stress, dtype=float)
    if len(baseline) < 2 or len(stress) < 2:
        return (float("nan"), float("nan"))

    if max(len(baseline), len(stress)) > BOOTSTRAP_MAX_SAMPLE_SIZE:
        return delta_method_ratio_ci(baseline, stress, confidence)

    rng = np.random.default_rng(seed)
    baseline_means = rng.choice(baseline, (resamples, len(baseline)), replace=True).mean(axis=1)
    stress_means = rng.choice(stress, (resamples, len(stress)), replace=True).mean(axis=1)

    with np.errstate(divide="ignore", invalid="ignore"):
        ratios = stress_means / baseline_means
    ratios = ratios[np.isfinite(ratios)]
    if ratios.size == 0:
        return (float("nan"), float("nan"))

    tail = (1.0 - confidence) / 2.0
    return (
        float(np.quantile(ratios, tail)),
        float(np.quantile(ratios, 1.0 - tail)),
    )


@dataclass
class FairnessMeasurement:
    """One (solution, subsystem) run reduced to the reportable numbers."""

    solution: str
    system: str
    latency_degradation: float
    latency_ci: tuple = (float("nan"), float("nan"))
    throughput_retention: float = float("nan")
    baseline_mean_ms: float = float("nan")
    stress_mean_ms: float = float("nan")
    baseline_p95_ms: float = float("nan")
    stress_p95_ms: float = float("nan")
    baseline_error_rate: float = 0.0
    stress_error_rate: float = 0.0
    baseline_operations: int = 0
    stress_operations: int = 0

    @property
    def owner_throttled(self):
        """True when the victim could not sustain its configured request rate.

        Where this holds, `latency_degradation` understates the real impact: the
        tenant was cut off rather than merely slowed, and the requests it never
        managed to issue carry no latency at all.
        """
        retention = self.throughput_retention
        return retention == retention and retention < THROUGHPUT_RETENTION_THRESHOLD


def measure(experiment, solution, system, confidence=0.95, seed=0):
    """Reduce one loaded experiment to a `FairnessMeasurement`.

    `experiment` is the per-system dict produced by `dataloader`, with
    `baseline` and `stress_test` entries.
    """
    baseline_all = experiment["baseline"].t1_df
    stress_all = experiment["stress_test"].t1_df

    baseline = successful(baseline_all)
    stress = successful(stress_all)

    baseline_latencies = baseline[LATENCY_COLUMN].to_numpy()
    stress_latencies = stress[LATENCY_COLUMN].to_numpy()

    baseline_mean = float(baseline_latencies.mean()) if len(baseline_latencies) else float("nan")
    stress_mean = float(stress_latencies.mean()) if len(stress_latencies) else float("nan")
    degradation = stress_mean / baseline_mean if baseline_mean else float("nan")

    baseline_rate = achieved_rate(baseline)
    stress_rate = achieved_rate(stress)
    retention = stress_rate / baseline_rate if baseline_rate else float("nan")

    return FairnessMeasurement(
        solution=solution,
        system=system,
        latency_degradation=degradation,
        latency_ci=bootstrap_ratio_ci(
            baseline_latencies, stress_latencies, confidence=confidence, seed=seed
        ),
        throughput_retention=retention,
        baseline_mean_ms=baseline_mean,
        stress_mean_ms=stress_mean,
        baseline_p95_ms=float(np.percentile(baseline_latencies, 95))
        if len(baseline_latencies)
        else float("nan"),
        stress_p95_ms=float(np.percentile(stress_latencies, 95))
        if len(stress_latencies)
        else float("nan"),
        baseline_error_rate=error_rate(baseline_all),
        stress_error_rate=error_rate(stress_all),
        baseline_operations=len(baseline_all) if baseline_all is not None else 0,
        stress_operations=len(stress_all) if stress_all is not None else 0,
    )


def measure_all(experiments, confidence=0.95, seed=0):
    """Measure every (solution, system) pair in a loaded experiment tree."""
    measurements = []
    for solution, systems in experiments.items():
        for system, experiment in systems.items():
            if not experiment.get("baseline") or not experiment.get("stress_test"):
                continue
            measurements.append(measure(experiment, solution, system, confidence, seed))
    return measurements


def to_frame(measurements):
    """Tabulate measurements, one row per (solution, system)."""
    return pd.DataFrame(
        [
            {
                "solution": m.solution,
                "system": m.system,
                "delta_latency": m.latency_degradation,
                "delta_ci_low": m.latency_ci[0],
                "delta_ci_high": m.latency_ci[1],
                "throughput_retention": m.throughput_retention,
                "owner_throttled": m.owner_throttled,
                "baseline_ms": m.baseline_mean_ms,
                "stress_ms": m.stress_mean_ms,
                "baseline_p95_ms": m.baseline_p95_ms,
                "stress_p95_ms": m.stress_p95_ms,
                "baseline_err_pct": m.baseline_error_rate,
                "stress_err_pct": m.stress_error_rate,
                "baseline_ops": m.baseline_operations,
                "stress_ops": m.stress_operations,
            }
            for m in measurements
        ]
    )


@dataclass
class AggregatedMeasurement:
    """Repeated runs of one (solution, subsystem) combined."""

    solution: str
    system: str
    runs: int
    mean_degradation: float
    degradation_ci: tuple
    per_run_degradations: list = field(default_factory=list)
    mean_throughput_retention: float = float("nan")
    #: Runs discarded because they produced no usable measurement at all.
    excluded_runs: int = 0


def aggregate_runs(measurements, confidence=0.95, seed=0):
    """Combine repeated runs of the same (solution, system).

    Delta is the **mean of per-run ratios**, not the ratio of pooled means. The
    two are not interchangeable for skewed data, and the paper defines delta per
    run. The CI is a bootstrap over the per-run ratios, which is the right level
    once several runs exist — the within-run bootstrap in `measure` only covers
    sampling noise inside a single run, not run-to-run variation.
    """
    grouped = {}
    for measurement in measurements:
        grouped.setdefault((measurement.solution, measurement.system), []).append(measurement)

    rng = np.random.default_rng(seed)
    aggregated = []
    for (solution, system), runs in grouped.items():
        # Drop the whole run when its ratio is not a number, and drop the same
        # runs from every other statistic. A run where the owner produced no
        # operations at all — a failed benchmark pod, a truncated log — yields a
        # non-finite ratio but a perfectly finite retention of 0.0, so filtering
        # the two independently silently averages a failure into the retention
        # while excluding it from the degradation factor.
        usable = [r for r in runs if np.isfinite(r.latency_degradation)]
        excluded = len(runs) - len(usable)
        if not usable:
            continue

        ratios = np.array([r.latency_degradation for r in usable], dtype=float)
        retentions = np.array([r.throughput_retention for r in usable], dtype=float)
        retentions = retentions[np.isfinite(retentions)]

        if ratios.size >= 2:
            resampled = rng.choice(ratios, (2000, ratios.size), replace=True).mean(axis=1)
            tail = (1.0 - confidence) / 2.0
            interval = (
                float(np.quantile(resampled, tail)),
                float(np.quantile(resampled, 1.0 - tail)),
            )
        else:
            # A single run has no run-to-run variation to estimate; fall back to
            # that run's own within-run interval rather than inventing one.
            interval = runs[0].latency_ci

        aggregated.append(
            AggregatedMeasurement(
                solution=solution,
                system=system,
                runs=int(ratios.size),
                mean_degradation=float(ratios.mean()),
                degradation_ci=interval,
                per_run_degradations=[float(r) for r in ratios],
                mean_throughput_retention=float(retentions.mean())
                if retentions.size
                else float("nan"),
                excluded_runs=excluded,
            )
        )

    return aggregated
