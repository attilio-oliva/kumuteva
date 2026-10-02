"""Figure styling for the paper.

Everything here is lifted verbatim from the original notebook cells so that
regenerated figures are byte-identical to the published ones. Do not "tidy" the
values: they are calibrated against the IEEE two-column template.

The one behavioural change is that the PGF export no longer leaves global
matplotlib state modified. The original `save_plot` switched the backend to
"pgf", set `text.usetex = True`, wrote the file, then switched back — which made
figure output order-dependent, because anything rendered between those points
picked up a different backend. `pgf_export()` restores the full set of touched
rcParams on the way out, including on exception.
"""

from contextlib import contextmanager

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import markers
from matplotlib.ticker import LogFormatter, NullLocator
import scienceplots  # noqa: F401  (registers the 'science' styles on import)
from cycler import cycler

# Single-column width of the IEEE template, in inches.
SINGLE_COLUMN_WIDTH_IN = 3.31314
DEFAULT_ASPECT_RATIO = 6 / 8
DEFAULT_DPI = 300

# Seconds of each phase to plot, matching `testDurationSeconds` in
# experiments/campaign.yaml. This is a crop, not a window into a longer run: set
# above the phase length the x-axis simply ends early with dead space, and set
# below it the figure silently hides the tail. It was 60 while the campaign ran
# 60 s phases; the campaign now runs 30.
PLOT_DURATION_LIMIT = 30

# Font sizes are given as matplotlib's relative keywords rather than points.
# They scale off `font.size`, which the IEEE style sets to 8 pt, so the figures
# follow the document's base size instead of being pinned to magic numbers. At
# 8 pt these resolve to:
#
#     xx-small  4.63    x-small  5.55    small  6.66    medium  8.00
#
# `medium` is the default because these figures are placed at their natural
# 3.31 in width, so 8 pt in the figure is 8 pt on the page — IEEE's
# \footnotesize, and the smallest size the templates recommend for figures and
# tables. The first submission used 4.5 and 5 pt, roughly half that, which is
# below anything the guidelines allow; the legend labels were shortened to make
# the larger text fit rather than shrinking the text to fit the labels.
LEGEND_FONT_SIZE = "medium"
TICK_FONT_SIZE = "medium"

_SCIENCEPLOTS_STYLES = ["science", "ieee", "vibrant"]

# Index of the colour dropped from the 'vibrant' cycle: it is close enough to
# the third to be indistinguishable in print.
_DROPPED_COLOR_INDEX = 3


# Hatch stroke width. Matplotlib defaults to 1.0 pt, which drew hatching as a set
# of heavy bars competing with the data. Matched to the 0.8 pt outline: finer
# strokes, especially light ones on a dark fill, disappeared once the figure was
# printed at column width. Note this is independent of density: how *close* the
# strokes sit is the repeat count in the hatch string ("//" vs "////"), not this.
HATCH_LINEWIDTH = 0.8

# Marker sizing. `MARKER_REFERENCE_SIZE` is the markersize of a square; every
# other shape is scaled to look like it. `MARKER_AREA_WEIGHT` picks how that
# match is defined: 0 gives every shape the same width, 1 the same amount of
# ink.
#
# Neither extreme reads as even, and they fail in opposite directions, because a
# square packs the most ink into a given width and a triangle the least:
#
#     weight   width spread   ink spread
#       0.40        115%         152%     circle and square look too heavy
#       0.65        125%         127%     the two cues cross here
#       1.00        141%         100%     circle and square look too small
#
# 0.65 is the minimax point: whichever cue the eye happens to weight, no shape
# is more than about a quarter off the others. This is a perceptual balance, not
# a derivable constant, so it stays a knob.
MARKER_REFERENCE_SIZE = 3
MARKER_AREA_WEIGHT = 0.65


def apply_paper_style():
    """Install the paper's matplotlib style. Call once, before plotting."""
    plt.style.use(_SCIENCEPLOTS_STYLES)
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    colors.pop(_DROPPED_COLOR_INDEX)
    plt.rcParams["axes.prop_cycle"] = cycler(color=colors)
    plt.rcParams["hatch.linewidth"] = HATCH_LINEWIDTH


def palette():
    """Colours of the active cycle, in order."""
    return plt.rcParams["axes.prop_cycle"].by_key()["color"]


@contextmanager
def pgf_export():
    """Temporarily switch matplotlib to the PGF/LaTeX backend.

    Restores the backend and every rcParam touched, so callers cannot leak PGF
    settings into subsequent figures.
    """
    previous_backend = matplotlib.get_backend()
    touched = ("text.usetex", "pgf.texsystem", "pgf.rcfonts")
    previous_params = {key: matplotlib.rcParams[key] for key in touched}
    try:
        matplotlib.use("pgf")
        matplotlib.rcParams.update(
            {
                "pgf.texsystem": "pdflatex",
                "text.usetex": True,
                "pgf.rcfonts": False,
            }
        )
        yield
    finally:
        matplotlib.use(previous_backend)
        matplotlib.rcParams.update(previous_params)


def save_plot(fig, filename, formats=("png", "pgf")):
    """Write `fig` to `{filename}.{ext}` for each requested format.

    Axis titles are stripped for the duration of the write and restored after.
    The figure functions do not set titles — the paper supplies captions, and
    the notebook labels figures externally through `utils.display` — so this is
    purely defensive against a caller adding one interactively.
    """
    axes = fig.get_axes()
    titles = [axis.get_title() for axis in axes]
    for axis in axes:
        axis.set_title("")

    try:
        if "png" in formats:
            fig.savefig(f"{filename}.png", bbox_inches="tight", dpi=DEFAULT_DPI)

        if "pgf" in formats:
            with pgf_export():
                fig.savefig(f"{filename}.pgf", bbox_inches="tight")
    finally:
        for axis, title in zip(axes, titles):
            axis.set_title(title)

    return filename


def unit_marker_area(marker):
    """Area a marker covers at `markersize=1`, in the same units squared.

    Measured from the marker's own path rather than tabulated, so it stays
    correct for any marker matplotlib supports. Curved outlines (a circle) are
    flattened to polygons first, then the shoelace formula gives the area.
    """
    style = markers.MarkerStyle(marker)
    path = style.get_path().transformed(style.get_transform())
    area = 0.0
    for polygon in path.to_polygons():
        if len(polygon) < 3:
            continue
        x, y = polygon[:, 0], polygon[:, 1]
        area += 0.5 * abs(
            np.dot(x, np.roll(y, -1)) - np.dot(y, np.roll(x, -1))
        )
    return area


def unit_marker_extent(marker):
    """Largest span of a marker at `markersize=1`, across its bounding box."""
    style = markers.MarkerStyle(marker)
    bounds = style.get_path().transformed(style.get_transform()).get_extents()
    return max(bounds.width, bounds.height)


def marker_size(marker, reference=None, area_weight=None):
    """`markersize` making `marker` look the same size as a square at `reference`.

    Neither obvious rule works on its own:

    * Matching **area** leaves triangles and diamonds looking too big, because
      at equal ink they span 25-40% wider than a circle or square. Extent is
      what the eye compares first.
    * Matching **extent** leaves triangles looking too faint, since a triangle
      covers only half the ink of a square across the same width.

    So interpolate between the two, geometrically, with `area_weight` choosing
    the balance: 0 matches width exactly, 1 matches ink exactly. Both targets
    are taken from a square at `reference`, whose unit area and unit extent are
    both 1, so `reference` reads directly as "the markersize of a square".
    """
    # Resolved here rather than as default arguments, which bind once at
    # definition time and would ignore a constant reassigned from a notebook.
    reference = MARKER_REFERENCE_SIZE if reference is None else reference
    area_weight = MARKER_AREA_WEIGHT if area_weight is None else area_weight

    unit_area = unit_marker_area(marker)
    unit_extent = unit_marker_extent(marker)
    if unit_area <= 0 or unit_extent <= 0:
        return float(reference)

    size_matching_area = np.sqrt(reference**2 / unit_area)
    size_matching_extent = reference / unit_extent
    return float(
        size_matching_area**area_weight * size_matching_extent ** (1.0 - area_weight)
    )


def plain_log_label(value, _=None):
    """Format a log-axis tick as a number: 10, 100, 1000 — not 10^1, 10^2.

    Powers-of-ten notation costs the reader a mental exponentiation on every
    glance, which is a poor trade when the values are latencies in milliseconds
    and the interesting comparisons are ratios between neighbouring ticks.

    Below 1 the value is printed at its natural precision (`0.5`, `0.1`,
    `0.05`) rather than rounded to zero, since the network subsystem's
    sub-millisecond ticks are exactly where rounding would erase the axis.
    """
    if value <= 0:
        return ""
    return f"{value:.0f}" if value >= 1 else f"{value:g}"


class PlainLogFormatter(LogFormatter):
    """`LogFormatter` that writes 10, 100, 1000 instead of 10^1, 10^2, 10^3.

    Subclassed rather than replaced with a plain `FuncFormatter`, because the
    exponent is not the only thing `LogFormatter` decides. It also chooses
    *which* minor ticks deserve a label: none across a wide range, a few (2, 5)
    when the axis spans about a decade, more when it spans less. A
    `FuncFormatter` has no such logic and labels every tick it is handed —
    which on a four-decade latency axis stacks 2,3,4...9 in every decade into an
    unreadable smear.

    Overriding `_num_to_string` keeps that selection intact and changes only the
    notation, so both major and minor ticks can use one formatter.
    """

    def _num_to_string(self, x, vmin, vmax):
        return plain_log_label(x)


def log_scale(ax, axis="y"):
    """Put `axis` on a log scale with plain-number ticks.

    One call rather than `set_yscale` plus a formatter, because the two were
    only ever correct together: a bare `set_yscale("log")` reverts the axis to
    `10^n` labels, and that is how one figure ends up in a different notation
    from the rest of the paper.
    """
    for name in axis:
        target = ax.yaxis if name == "y" else ax.xaxis
        (ax.set_yscale if name == "y" else ax.set_xscale)("log")
        target.set_major_formatter(PlainLogFormatter())
        target.set_minor_formatter(PlainLogFormatter(labelOnlyBase=False))
    return ax


def categorical_xaxis(ax, positions, labels, fontsize=TICK_FONT_SIZE):
    """Label a categorical x-axis: one major tick per category, no minor ticks.

    The paper style adds minor ticks by default, which is right for a continuous
    axis and wrong here — there is nothing between "Capsule" and "KubeZoo" to
    subdivide, so the extra ticks imply a scale that does not exist.
    """
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, fontsize=fontsize)
    ax.xaxis.set_minor_locator(NullLocator())
    ax.tick_params(axis="x", which="minor", bottom=False, top=False)
    return ax


def legend_above(ax, ncol=3, handles=None, fontsize=LEGEND_FONT_SIZE):
    """Place the legend outside the axes, above the plot.

    Inside the axes it collides with the data on several of these figures —
    log-scale latency fills the upper left, which is exactly where matplotlib's
    "best" placement tends to land.

    Pass `handles` for figures whose marks are not legend-able on their own
    (box plots and violins), so every figure routes through one implementation
    rather than repeating this keyword list inline. A handle may be a tuple of
    artists drawn on top of each other, labelled by its first artist.
    """
    entries = {}
    if handles is not None:
        entries["handles"] = handles
        entries["labels"] = [
            (handle[0] if isinstance(handle, tuple) else handle).get_label()
            for handle in handles
        ]
    return ax.legend(
        **entries,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.02),
        ncol=ncol,
        fontsize=fontsize,
        frameon=False,
        handlelength=1.4,
        columnspacing=1.0,
        borderaxespad=0.0,
    )


def paper_figure(aspect_ratio=DEFAULT_ASPECT_RATIO, scale=1.0, dpi=DEFAULT_DPI):
    """Create a figure sized for one column of the paper.

    Replaces the original `plot_for_paper`, whose `scale` argument was dead —
    the body reassigned `scale = 1.0` on its first line, so callers passing a
    scale silently got the default. Here it is honoured.
    """
    width = SINGLE_COLUMN_WIDTH_IN * scale
    height = width * aspect_ratio
    return plt.subplots(figsize=(width, height), dpi=dpi)
