"""Notebook layout helpers.

The figures are rendered at publication size and carry no titles — a title
inside the image would duplicate the paper's caption and would have to be
stripped on export. That leaves the notebook needing to label them some other
way, and a cell that emits four unlabelled plots in a vertical stack is both
unreadable and enormous.

These helpers put related figures behind ipywidgets tabs (or in a grid), so the
label lives in the tab, outside the image, and only one figure occupies vertical
space at a time. Each figure is an ordinary inline render inside an `Output`
widget, so right-click-to-save and the usual Jupyter behaviour still work.

For interactive pan and zoom, install `ipympl` and switch the backend with
`%matplotlib widget` before rendering; these helpers work either way.
"""

import io

import ipywidgets as widgets
import matplotlib.pyplot as plt

# Rasterise at a higher DPI than the figure's own so the embedded image stays
# legible when the browser scales it. The figures are ~3.3 inches wide.
PREVIEW_DPI = 200


def _render_to_image(render, key):
    """Run `render(key)` and return its figure as an Image widget.

    Deliberately **not** an `Output` widget. `Output` delivers its content over
    the widget comm protocol, and that path is unreliable in practice: the
    `with output:` capture context records nothing at all under nbclient, and
    even `append_display_data` frequently renders as an empty box in VS Code's
    notebook client. `Image` carries the PNG bytes as a plain trait value, so it
    renders anywhere the widget itself renders.

    The figure is closed afterwards so the inline backend does not also emit it
    at the end of the cell, which would defeat the point of grouping.
    """
    result = render(key)
    figure = result[0] if isinstance(result, tuple) else result
    if figure is None:
        return widgets.Image()

    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", dpi=PREVIEW_DPI, bbox_inches="tight")
    plt.close(figure)
    return widgets.Image(value=buffer.getvalue(), format="png")


def figure_tabs(render, keys, labels=None):
    """Tabbed view of one figure per key.

    `render(key)` should build and return the figure; anything it draws is
    captured. `labels` maps a key to its tab label, defaulting to `str`.

        display.figure_tabs(
            lambda s: plots.plot_degradation(measurements, s),
            SYSTEMS,
            labels=plots.SYSTEM_NAMES,
        )
    """
    labels = labels or {}
    tabs = widgets.Tab(children=[_render_to_image(render, key) for key in keys])
    for index, key in enumerate(keys):
        tabs.set_title(index, labels.get(key, str(key)))
    # Returned rather than displayed: the notebook cell renders the return value
    # itself, and calling display() here as well would show every tab strip twice.
    return tabs


def figure_grid(render, keys, labels=None, columns=2):
    """Grid of figures, each with a caption above it.

    Use when figures are meant to be compared side by side rather than flipped
    between; tabs are the better default when vertical space matters.
    """
    labels = labels or {}
    cells = [
        widgets.VBox(
            [
                widgets.HTML(f"<b>{labels.get(key, str(key))}</b>"),
                _render_to_image(render, key),
            ]
        )
        for key in keys
    ]
    return widgets.GridBox(
        cells,
        layout=widgets.Layout(grid_template_columns=f"repeat({columns}, max-content)"),
    )
