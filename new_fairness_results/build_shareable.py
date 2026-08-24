"""Execute `fairness-analyzer.ipynb` into a copy that can be sent to someone.

    ../.venv/bin/python build_shareable.py

`display.figure_tabs` returns an `ipywidgets.Tab`. A widget is drawn by
JavaScript talking to a live kernel, so the notebook on its own shows empty
cells to anyone who has not run it: the figures exist only in the kernel's
memory, never in the file.

The fix is not to change how the figures are drawn. `nbclient` records the state
of every widget the kernel created into `metadata.widgets`, and does so by
default (`store_widget_state = True`), which `nbconvert --execute` inherits.
Executing the notebook headlessly therefore produces a file that carries its own
tabs, PNGs and all. VS Code, which does not reliably write that state when you
save, never enters the picture.

Two artefacts, because they are shareable in different ways:

* `fairness-analyzer-shared.ipynb` — renders in nbviewer and JupyterLab with no
  network access needed.
* `fairness-analyzer-shared.html` — one file, opens in a browser, but fetches
  `@jupyter-widgets/html-manager` from a CDN the first time it is viewed.

Both are written beside the source notebook and both are gitignored. The source
notebook stays output-free so that `build_notebook.py` remains the thing that
defines it and its diffs stay readable.

Expect the executed notebook to be a few MB larger than the source: every tab's
PNG is base64 inside the widget state. Expect it to take as long as running the
notebook by hand, which is dominated by loading the run data.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent.resolve()
SOURCE = "fairness-analyzer.ipynb"
SHARED = "fairness-analyzer-shared.ipynb"

# Through the venv's jupyter, so the kernel is the venv interpreter: the
# notebook declares kernelspec "python3", and that name resolves to
# `.venv/share/jupyter/kernels/python3` only for this jupyter.
JUPYTER = HERE.parent / ".venv" / "bin" / "jupyter"

STEPS = [
    # No --inplace: the executed copy is a separate file. No --ExecutePreprocessor
    # .timeout either, since its default is already "no limit" and a campaign of
    # ten repetitions takes minutes to load.
    ([str(JUPYTER), "nbconvert", "--to", "notebook", "--execute",
      "--output", SHARED, SOURCE], f"executing {SOURCE} -> {SHARED}"),
    ([str(JUPYTER), "nbconvert", "--to", "html", SHARED],
     f"exporting {SHARED} -> html"),
]


def _from_cwd(path):
    """`path` as the caller would type it, absolute if that is shorter."""
    relative = os.path.relpath(path, Path.cwd())
    return relative if len(relative) < len(str(path)) else str(path)


def main():
    if not (HERE / SOURCE).exists():
        sys.exit(f"{SOURCE} not found; run build_notebook.py first")
    if not JUPYTER.exists():
        sys.exit(f"{JUPYTER} not found; see requirements.txt")

    for command, description in STEPS:
        print(f"-> {description}")
        result = subprocess.run(command, cwd=HERE)
        if result.returncode != 0:
            sys.exit(f"failed: {' '.join(command)}")

    # Say it rather than assume it: an execution that produced no widgets is a
    # notebook that will look empty to whoever it is sent to, and the failure is
    # otherwise silent until they say so.
    with open(HERE / SHARED) as handle:
        state = json.load(handle)["metadata"].get("widgets")
    if not state:
        sys.exit(f"{SHARED} carries no widget state; its tabs will render empty")

    for name in (SHARED, SHARED.replace(".ipynb", ".html")):
        written = HERE / name
        # nbconvert runs with cwd=HERE, so it writes beside the notebook however
        # this script was invoked. Report the path from where the caller is
        # standing: bare filenames read as if the files landed in *their* cwd.
        print(f"wrote {_from_cwd(written)} ({written.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
