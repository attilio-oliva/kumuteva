"""Figure functions for the paper.

One function per figure, each writing exactly one output name. The original
notebook had the p95 plot and the violin plot both writing
`comparative_latency_distribution`, so whichever ran last silently replaced the
other; that class of bug is why the mapping below is explicit.

    paper figure                     function                          output
    -------------------------------  --------------------------------  ------------------------------------
    Baseline-to-stress transition    plot_latency_transition           {system}_latency_transition
    API latency over time            plot_latency_over_time            {system}_latency_over_time
    Latency distribution by role     plot_latency_distribution         {system}_latency_distribution
    95th percentile comparison       plot_p95_comparison               {system}_p95_comparison
    Latency distribution (violin)    plot_latency_violin               {system}_latency_violin
    Degradation with CIs             plot_degradation                  {system}_degradation
    Throughput retention             plot_throughput_retention         {system}_throughput_retention

"""

import numpy as np
from matplotlib.patches import Patch

from . import stats
from matplotlib.ticker import FuncFormatter

from .style import (
    PLOT_DURATION_LIMIT,
    TICK_FONT_SIZE,
    categorical_xaxis,
    marker_size,
    legend_above,
    palette,
    paper_figure,
    save_plot,
)

# Shared outline for every filled mark — boxes, bars, violins — so the figures
# read as one family. Previously the boxes carried a thin black outline and the
# bars had none, which made them look like they came from different papers.
FILL_ALPHA = 0.8
OUTLINE = {"edgecolor": "black", "linewidth": 0.4}

# A second, redundant channel alongside colour, so the figures survive greyscale
# printing and the common forms of colour blindness.
#
# Fine and dense rather than bold and sparse: a few thick strokes across a small
# box read as competing content, while a close-set fine texture reads as a fill.
# Stroke weight is set once via `style.HATCH_LINEWIDTH`; the repeat count here
# controls only how close the strokes sit.
#
# Index matches the series order: baseline, owner, intruder.
SERIES_HATCHES = ("", "/////", ".....")

# Line figures get markers instead, thinned out so the line shape stays visible.
LINE_MARKERS = ("o", "s", "^", "D", "v")

# Markers are placed on a fixed *time* grid, in seconds, not every N-th point.
# `markevery=N` counts data points, and the series do not share a point count:
# `_sliding_mean` drops windows in which no request landed, so a quiet solution
# produces fewer points than a busy one and its markers drift to different x
# positions. Anchoring to time keeps every line's markers vertically aligned.
MARKER_TIME_INTERVAL = 2

# How far each series is shifted off that shared grid, as a fraction of the
# interval. This is the knob deciding whether markers line up vertically:
#
#   0.0  every series marks the same instants — 0, 2, 4 s and so on. Tidiest
#        where lines are well separated, as they are on a log axis, and it lets
#        the series be compared at a glance.
#   1.0  series are spread evenly across one interval so their markers
#        interleave. Worth it where lines overlap and markers would otherwise
#        sit on top of each other.
#
# Anything in between is a partial shift.
MARKER_STAGGER = 1.0

# Order solutions consistently across every figure, weakest isolation first, so
# the reader can compare panels without re-reading legends.
DEFAULT_SOLUTION_ORDER = ["capsule", "capsule-proxy", "kubezoo", "vcluster", "kubevirt"]

DISPLAY_NAMES = {
    "capsule": "Capsule",
    "capsule-proxy": "Capsule\nProxy",
    "kubezoo": "KubeZoo",
    "vcluster": "vCluster",
    "kubevirt": "KubeVirt",
}

SYSTEM_LABELS = {
    "control_plane": "API request latency",
    "network": "TCP round-trip latency",
    "storage": "I/O latency",
    "workload": "CPU task latency",
}

SYSTEM_NAMES = {
    "control_plane": "Control plane",
    "network": "Network",
    "storage": "Storage",
    "workload": "Workload",
}

# Phase labels, kept short so they fit at footnotesize. The important nuance —
# that the owner holds its nominal rate throughout and only the intruder
# escalates, so "owner under stress" means subjected to load, not generating it
# — belongs in the figure caption, which has room for a sentence. The original
# "Regular user (high load)" invited exactly the opposite reading.
BASELINE_LABEL = "Baseline"
OWNER_STRESS_LABEL = "Owner"
INTRUDER_STRESS_LABEL = "Intruder"


def figure_label(system, description):
    """Human-readable label for a figure.

    Used for widget tab labels and captions in the notebook. Deliberately not
    applied to the figure itself: these are rendered at publication size and the
    paper supplies the caption.
    """
    return f"{SYSTEM_NAMES.get(system, system)} — {description}"


def ordered_solutions(experiments, order=None):
    """Solutions present in `experiments`, in the canonical order."""
    order = order or DEFAULT_SOLUTION_ORDER
    present = list(experiments.keys())
    known = [s for s in order if s in present]
    return known + [s for s in present if s not in known]


def display_name(solution):
    return DISPLAY_NAMES.get(solution, solution)


def _successful_latencies(frame):
    usable = stats.successful(frame)
    if usable is None or len(usable) == 0:
        return np.array([])
    return usable[stats.LATENCY_COLUMN].to_numpy()


def _marker_indices(
    times,
    series_index=0,
    series_count=1,
    interval=None,
    stagger=None,
):
    """Indices of the samples nearest a regular time grid.

    Returned as an explicit index list for `markevery`, which accepts one.

    The grid is anchored at zero rather than at each series' first sample, so a
    series that happens to start slightly later still marks the same instants as
    the rest instead of drifting out of step. `stagger` then shifts each series
    off that shared grid by a fraction of the interval — see `MARKER_STAGGER`.
    """
    # Resolved here, not as default arguments: a default is bound once when the
    # function is defined, so reassigning the module constant from a notebook
    # would silently have no effect on a knob whose whole purpose is tuning.
    interval = MARKER_TIME_INTERVAL if interval is None else interval
    stagger = MARKER_STAGGER if stagger is None else stagger

    times = np.asarray(times, dtype=float)
    if times.size == 0 or interval <= 0:
        return []

    offset = stagger * series_index * interval / max(1, series_count)
    grid = np.arange(offset, times[-1] + interval * 1e-9, interval)
    grid = grid[grid >= times[0] - interval * 1e-9]
    if grid.size == 0:
        return []

    nearest = np.abs(times[None, :] - grid[:, None]).argmin(axis=1)
    return sorted({int(index) for index in nearest})


def _sliding_mean(series, window_size, window_step, max_duration):
    """Sliding-window mean latency, computed in one pass.

    The obvious implementation — loop the window start and boolean-mask the
    frame each time — costs `windows x rows` comparisons. At 121 windows over a
    4.5 M-row network run that is half a billion comparisons per solution, which
    is what made this figure take minutes.

    Instead bin once at the step resolution, then take a rolling sum over
    `window_size / window_step` bins. Bin `i` of the rolling result covers
    `[(i - k + 1) * step, (i + 1) * step)`, i.e. exactly the window starting at
    `(i - k + 1) * step`, so the output matches the loop's semantics.
    """
    bins_per_window = max(1, int(round(window_size / window_step)))
    bin_index = (series["elapsed_seconds"] // window_step).astype("int64")

    grouped = series.groupby(bin_index)[stats.LATENCY_COLUMN].agg(["sum", "count"])
    if grouped.empty:
        return np.array([]), np.array([])

    # Reindex onto the full bin range so gaps do not shift the rolling window.
    full_range = np.arange(0, int(max_duration // window_step) + 1)
    grouped = grouped.reindex(full_range, fill_value=0)

    rolling_sum = grouped["sum"].rolling(bins_per_window, min_periods=1).sum()
    rolling_count = grouped["count"].rolling(bins_per_window, min_periods=1).sum()

    # Drop the leading partial windows and any window that saw no requests.
    usable = (rolling_count.index >= bins_per_window - 1) & (rolling_count > 0)
    if not usable.any():
        return np.array([]), np.array([])

    indices = rolling_count.index[usable].to_numpy()
    window_start = (indices - bins_per_window + 1) * window_step
    centres = window_start + window_size / 2
    means = (rolling_sum[usable] / rolling_count[usable]).to_numpy()
    return centres, means


def plot_latency_over_time(
    experiments,
    system,
    out_dir="./",
    save=True,
    window_size=2.0,
    window_step=0.5,
    max_duration=PLOT_DURATION_LIMIT,
):
    """Rolling-mean latency of the regular tenant, one line per solution."""
    fig, ax = paper_figure()
    colors = palette()

    for index, solution in enumerate(ordered_solutions(experiments)):
        experiment = experiments[solution].get(system)
        if not experiment:
            continue

        stress = stats.successful(experiment["stress_test"].t1_df)
        if stress is None or len(stress) == 0:
            continue

        series = stress[stress["elapsed_seconds"] <= max_duration]
        if len(series) == 0:
            continue

        centres, means = _sliding_mean(series, window_size, window_step, max_duration)
        if len(centres) == 0:
            continue

        marker = LINE_MARKERS[index % len(LINE_MARKERS)]

        ax.plot(
            centres,
            means,
            label=display_name(solution).replace("\n", " "),
            color=colors[index % len(colors)],
            linewidth=0.9,
            marker=marker,
            markersize=marker_size(marker),
            markeredgewidth=0.0,
            markevery=_marker_indices(centres, index, len(LINE_MARKERS)),
        )

    ax.set_yscale("log")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Latency (ms)")
    legend_above(ax, ncol=3)

    if save:
        save_plot(fig, f"{out_dir}/{system}_latency_over_time")
    return fig, ax


# Transition figure: how much of the baseline phase to show before the stress
# phase begins, and how much of its start to skip. The offset drops the warm-up
# at the very beginning of a run, where the first requests pay for connection
# setup and cold caches and are not representative of steady state.
TRANSITION_BASELINE_SECONDS = 20
TRANSITION_BASELINE_OFFSET = 2


def plot_latency_transition(
    experiments,
    system,
    out_dir="./",
    save=True,
    window_size=2.0,
    window_step=0.5,
    baseline_seconds=TRANSITION_BASELINE_SECONDS,
    baseline_offset=TRANSITION_BASELINE_OFFSET,
    max_duration=PLOT_DURATION_LIMIT,
):
    """Owner latency across the baseline-to-stress transition, per solution.

    The two phases are separate runs, so this splices them onto one axis: the
    baseline segment first, then the stress phase starting at the marked
    boundary. It is an illustrative figure rather than a measurement — the
    degradation factor is what quantifies the effect — but it shows the moment
    the intruder starts and how each architecture responds, which no summary
    statistic conveys.
    """
    fig, ax = paper_figure()
    colors = palette()
    smallest_value = np.inf

    for index, solution in enumerate(ordered_solutions(experiments)):
        experiment = experiments[solution].get(system)
        if not experiment:
            continue

        times, values = [], []
        # Baseline segment, shifted so the plotted window starts at zero.
        baseline = stats.successful(experiment["baseline"].t1_df)
        if baseline is not None and len(baseline):
            window = baseline[
                (baseline["elapsed_seconds"] >= baseline_offset)
                & (baseline["elapsed_seconds"] <= baseline_offset + baseline_seconds)
            ].copy()
            if len(window):
                window["elapsed_seconds"] = window["elapsed_seconds"] - baseline_offset
                centres, means = _sliding_mean(
                    window, window_size, window_step, baseline_seconds
                )
                times.extend(centres)
                values.extend(means)

        # Stress segment, appended after the boundary.
        stress = stats.successful(experiment["stress_test"].t1_df)
        if stress is not None and len(stress):
            window = stress[stress["elapsed_seconds"] <= max_duration]
            if len(window):
                centres, means = _sliding_mean(
                    window, window_size, window_step, max_duration
                )
                times.extend(np.asarray(centres) + baseline_seconds)
                values.extend(means)

        if not times:
            continue
        smallest_value = min(smallest_value, float(np.min(values)))

        marker = LINE_MARKERS[index % len(LINE_MARKERS)]
        ax.plot(
            times,
            values,
            label=display_name(solution).replace("\n", " "),
            color=colors[index % len(colors)],
            linewidth=0.9,
            marker=marker,
            markersize=marker_size(marker),
            markeredgewidth=0.0,
            markevery=_marker_indices(times, index, len(LINE_MARKERS)),
        )

    ax.axvline(baseline_seconds, color="black", linestyle="--", linewidth=0.5)

    ax.set_yscale("log")
    # Floor at 1 ms where the data allows, matching the original control-plane
    # figure, but drop below it when a subsystem is faster than that. Storage
    # latencies are sub-millisecond, and a hardcoded floor of 1 put every point
    # underneath the axis and left the panel blank.
    if np.isfinite(smallest_value) and smallest_value > 0:
        # Headroom is relative, not absolute: it leaves a band beneath the data
        # for the phase labels while staying proportional to whatever range the
        # subsystem occupies. The original hardcoded a floor of 1 ms, which
        # suited the control plane alone — it hid sub-millisecond storage and
        # network entirely, and left three empty decades under the workload
        # figure, whose latencies start near two seconds.
        ax.set_ylim(bottom=smallest_value * 0.45)
    ax.set_xlim(0, baseline_seconds + max_duration)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Latency (ms)")
    ax.tick_params(axis="y", which="minor", left=True)

    # Integer tick labels above 1 ms, one decimal below, as in the original.
    ax.yaxis.set_major_formatter(
        FuncFormatter(lambda value, _: f"{value:.1f}" if value < 1 else f"{int(value)}")
    )

    # Name the two regimes: the vertical rule alone does not say which side is
    # which. Positioned in axes fraction on the y axis so the labels stay pinned
    # just above the frame whatever range the data happens to occupy — a fixed
    # data-space height lands on top of the lines on the faster subsystems.
    phase_transform = ax.get_xaxis_transform()
    for x_position, text in (
        (baseline_seconds / 2, "Low load"),
        (baseline_seconds + max_duration / 2, "High load (noisy tenant)"),
    ):
        ax.text(
            x_position, 0.03, text,
            transform=phase_transform,
            ha="center", va="bottom", fontsize=TICK_FONT_SIZE,
        )

    legend_above(ax, ncol=3)

    if save:
        save_plot(fig, f"{out_dir}/{system}_latency_transition")
    return fig, ax


def _role_series(experiments, system, solutions):
    """Baseline / regular-under-stress / intruder-under-stress, per solution."""
    baseline, regular, malicious = [], [], []
    for solution in solutions:
        experiment = experiments[solution].get(system)
        if not experiment:
            baseline.append(np.array([]))
            regular.append(np.array([]))
            malicious.append(np.array([]))
            continue
        baseline.append(_successful_latencies(experiment["baseline"].t1_df))
        regular.append(_successful_latencies(experiment["stress_test"].t1_df))
        malicious.append(_successful_latencies(experiment["stress_test"].t2_df))
    return baseline, regular, malicious


# --- Grouped-mark spacing -------------------------------------------------
#
# Both knobs are *relative*, so they mean the same thing regardless of how many
# series a figure has and never need re-tuning per figure:
#
#   GROUP_PADDING  fraction of each category's slot left blank between one group
#                  and the next. 0.25 means a quarter of the pitch is gap.
#                  Raise it to push groups apart.
#
#   BAR_SPACING    gap between bars inside a group, as a multiple of one bar's
#                  width. 0.15 means the gap is about a sixth of a bar.
#                  Raise it to push bars within a group apart.
#
# The bar width is *derived* from these rather than set alongside them. That is
# the point: width and offset used to be two unrelated magic numbers picked per
# figure, which silently left the box plot with a 0.04 gap and the bar plot with
# 0.02 — different spacing in two figures meant to be read side by side.
GROUP_PADDING = 0.25
BAR_SPACING = 0.15


def _grouped_positions(count, series=3, group_padding=GROUP_PADDING, bar_spacing=BAR_SPACING):
    """Centre positions for `series` side-by-side marks in each of `count` groups.

    Returns `(positions, mark_width)`, where `positions[i]` holds the centres of
    the i-th series. Categories sit 1.0 apart, so

        group_width = 1 - group_padding
                    = series * width + (series - 1) * bar_spacing * width

    and solving for `width` keeps intra-group gaps equal by construction.
    """
    group_width = 1.0 - group_padding
    mark_width = group_width / (series + (series - 1) * bar_spacing)
    gap = bar_spacing * mark_width

    first_offset = -group_width / 2 + mark_width / 2
    categories = np.arange(count)
    positions = [
        categories + first_offset + index * (mark_width + gap) for index in range(series)
    ]
    return positions, mark_width


def plot_latency_distribution(experiments, system, out_dir="./", save=True):
    """Grouped box plot: baseline, regular under stress, intruder under stress.

    The three series answer distinct questions, so they are labelled by *phase*
    rather than by load. "Regular (stress phase)" is the owner still running at
    its nominal rate while the intruder escalates — not the owner generating
    high load, which the original legend could be read as implying.
    """
    fig, ax = paper_figure()
    colors = palette()
    solutions = ordered_solutions(experiments)
    baseline, regular, malicious = _role_series(experiments, system, solutions)
    (left, centre, right), width = _grouped_positions(len(solutions), series=3)

    handles = []
    for index, (positions, series, color, label) in enumerate((
        (left, baseline, colors[0], BASELINE_LABEL),
        (centre, regular, colors[1], OWNER_STRESS_LABEL),
        (right, malicious, colors[2], INTRUDER_STRESS_LABEL),
    )):
        hatch = SERIES_HATCHES[index % len(SERIES_HATCHES)]
        data = [s if len(s) else np.array([np.nan]) for s in series]
        box = ax.boxplot(
            data,
            positions=positions,
            widths=width,
            patch_artist=True,
            showfliers=False,
            medianprops={"color": "black", "linewidth": 0.6},
            boxprops=OUTLINE,
            whiskerprops={"linewidth": OUTLINE["linewidth"]},
            capprops={"linewidth": OUTLINE["linewidth"]},
        )
        for patch in box["boxes"]:
            patch.set_facecolor(color)
            patch.set_alpha(FILL_ALPHA)
            patch.set_hatch(hatch)
        handles.append(
            Patch(facecolor=color, alpha=FILL_ALPHA, hatch=hatch, label=label, **OUTLINE)
        )

    categorical_xaxis(ax, np.arange(len(solutions)), [display_name(s) for s in solutions])
    ax.set_yscale("log")
    ax.set_ylabel("Latency (ms)")
    legend_above(ax, ncol=3, handles=handles)

    if save:
        save_plot(fig, f"{out_dir}/{system}_latency_distribution")
    return fig, ax


def plot_p95_comparison(experiments, system, out_dir="./", save=True):
    """95th-percentile latency per solution and phase."""
    fig, ax = paper_figure()
    colors = palette()
    solutions = ordered_solutions(experiments)
    baseline, regular, malicious = _role_series(experiments, system, solutions)
    (left, centre, right), width = _grouped_positions(len(solutions), series=3)

    percentile = lambda series: [
        np.percentile(s, 95) if len(s) else np.nan for s in series
    ]

    for index, (positions, series, color, label) in enumerate((
        (left, baseline, colors[0], BASELINE_LABEL),
        (centre, regular, colors[1], OWNER_STRESS_LABEL),
        (right, malicious, colors[2], INTRUDER_STRESS_LABEL),
    )):
        ax.bar(
            positions, percentile(series), width=width,
            color=color, alpha=FILL_ALPHA, label=label,
            hatch=SERIES_HATCHES[index % len(SERIES_HATCHES)], **OUTLINE,
        )

    categorical_xaxis(ax, np.arange(len(solutions)), [display_name(s) for s in solutions])
    ax.set_yscale("log")
    ax.set_ylabel("p95 latency (ms)")
    legend_above(ax, ncol=3)

    if save:
        save_plot(fig, f"{out_dir}/{system}_p95_comparison")
    return fig, ax


def plot_latency_violin(experiments, system, out_dir="./", save=True):
    """Violin view of the same distributions as `plot_latency_distribution`.

    Kept as a separate figure with its own filename. In the original notebook
    this overwrote the box plot's output.
    """
    fig, ax = paper_figure()
    colors = palette()
    solutions = ordered_solutions(experiments)
    _, regular, malicious = _role_series(experiments, system, solutions)
    positions = np.arange(len(solutions))
    (left, right), width = _grouped_positions(len(solutions), series=2)

    handles = []
    for series_positions, series, color, label, hatch in (
        (left, regular, colors[1], OWNER_STRESS_LABEL, SERIES_HATCHES[1]),
        (right, malicious, colors[2], INTRUDER_STRESS_LABEL, SERIES_HATCHES[2]),
    ):
        data = [np.log10(s[s > 0]) if len(s[s > 0]) else np.array([0.0]) for s in series]
        parts = ax.violinplot(data, positions=series_positions, widths=width, showextrema=False)
        for body in parts["bodies"]:
            body.set_facecolor(color)
            body.set_alpha(FILL_ALPHA)
            body.set_edgecolor(OUTLINE["edgecolor"])
            body.set_linewidth(OUTLINE["linewidth"])
            body.set_hatch(hatch)
        handles.append(
            Patch(facecolor=color, alpha=FILL_ALPHA, hatch=hatch, label=label, **OUTLINE)
        )

    categorical_xaxis(ax, positions, [display_name(s) for s in solutions])
    ax.set_ylabel(r"$\log_{10}$ latency (ms)")
    legend_above(ax, ncol=2, handles=handles)

    if save:
        save_plot(fig, f"{out_dir}/{system}_latency_violin")
    return fig, ax


def plot_degradation(measurements, system, out_dir="./", save=True):
    """Degradation factor per solution, with bootstrap confidence intervals.

    Takes `FairnessMeasurement`s rather than raw frames, so the figure and the
    reported table can never disagree about how delta was computed.
    """
    fig, ax = paper_figure()
    rows = [m for m in measurements if m.system == system]
    order = {name: i for i, name in enumerate(DEFAULT_SOLUTION_ORDER)}
    rows.sort(key=lambda m: order.get(m.solution, len(order)))

    positions = np.arange(len(rows))
    values = [m.latency_degradation for m in rows]
    lower = [max(0.0, v - m.latency_ci[0]) for v, m in zip(values, rows)]
    upper = [max(0.0, m.latency_ci[1] - v) for v, m in zip(values, rows)]

    # Hatch the bars whose owner was throttled: their delta is a lower bound,
    # because the requests the owner never issued contribute no latency.
    #
    # Both colours come from the same first two slots every other figure uses.
    # This previously reached for colors[3] — a darker red outside the working
    # set — which read as a fourth category rather than as one of the two.
    colors = palette()
    sustained_color, throttled_color = colors[0], colors[1]
    throttled_hatch = SERIES_HATCHES[1]

    bar_colors = [throttled_color if m.owner_throttled else sustained_color for m in rows]
    bars = ax.bar(
        positions, values, yerr=[lower, upper], capsize=1.5,
        color=bar_colors, alpha=FILL_ALPHA, **OUTLINE,
    )
    for bar, measurement in zip(bars, rows):
        if measurement.owner_throttled:
            bar.set_hatch(throttled_hatch)

    ax.axhline(1.0, color="grey", linewidth=0.5, linestyle="--")
    categorical_xaxis(ax, positions, [display_name(m.solution) for m in rows])
    ax.set_yscale("log")
    ax.set_ylabel(r"Degradation factor $\delta$")

    # Without this the hatching is unexplained, and the hatched bars are exactly
    # the ones whose value must not be read at face value.
    legend_above(
        ax,
        ncol=1,
        handles=[
            Patch(facecolor=sustained_color, alpha=FILL_ALPHA,
                  label="Rate sustained", **OUTLINE),
            Patch(facecolor=throttled_color, alpha=FILL_ALPHA, hatch=throttled_hatch,
                  label=r"Owner throttled", **OUTLINE),
        ],
    )

    if save:
        save_plot(fig, f"{out_dir}/{system}_degradation")
    return fig, ax


def plot_throughput_retention(measurements, system, out_dir="./", save=True):
    """Fraction of its baseline request rate the owner sustained under stress.

    The companion to the degradation figure: a saturated system harms the victim
    on both axes at once, and latency alone hides half of it.
    """
    fig, ax = paper_figure()
    rows = [m for m in measurements if m.system == system]
    order = {name: i for i, name in enumerate(DEFAULT_SOLUTION_ORDER)}
    rows.sort(key=lambda m: order.get(m.solution, len(order)))

    positions = np.arange(len(rows))
    values = [100.0 * m.throughput_retention for m in rows]

    ax.bar(positions, values, color=palette()[0], alpha=FILL_ALPHA, **OUTLINE)
    threshold = 100.0 * stats.THROUGHPUT_RETENTION_THRESHOLD
    ax.axhline(
        threshold, color="grey", linewidth=0.5, linestyle="--",
        label=f"{threshold:.0f} percent threshold",
    )
    categorical_xaxis(ax, positions, [display_name(m.solution) for m in rows])
    ax.set_ylabel("Owner throughput retained (percent)")
    ax.set_ylim(0, 105)
    legend_above(ax, ncol=1)

    if save:
        save_plot(fig, f"{out_dir}/{system}_throughput_retention")
    return fig, ax
