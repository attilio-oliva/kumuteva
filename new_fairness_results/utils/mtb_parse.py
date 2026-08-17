"""Parse kubectl-mtb console output into per-benchmark verdicts.

kubectl-mtb's default reporter ends with a scorecard table whose columns are
`No. | ID | Test | Result`, where Result is one of `Passed`, `Failed`,
`Skipped` or `Error`. The table is drawn with box characters and the result
cells are ANSI-colourised, so both have to be stripped before matching.

Three things make this less mechanical than it looks.

**Benchmark IDs are not unique.** `MTB-PL1-BC-HI-1` is used by both
`block_use_of_host_path` and `block_use_of_nodeport_services`. A verdict keyed
on the ID alone silently overwrites one with the other, so rows are resolved to
a catalogue *directory* using the ID and title together.

**Long titles wrap** across several physical lines in the rendered table, with
the ID and Result cells left blank on the continuation rows. Those have to be
folded back into the preceding row rather than parsed as separate benchmarks.

**`Skipped` and `Error` are not failures.** A benchmark that could not run tells
us nothing about the cluster, and scoring it as a failure would manufacture
disagreement with KUMUTEVA out of a missing measurement. They are returned
separately and excluded from the comparison.

This parser was written against the reporter's source rather than a live run.
`parse_results` raises when it recognises nothing, because a parser that
silently matches nothing produces an empty comparison that looks exactly like a
clean one — and "not comparable" is also the expected result for the
cluster-per-tenant solutions, so a silent failure would hide inside the finding.
"""

import re

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
BENCHMARK_ID = re.compile(r"MTB-PL\d+-[A-Z]{2}-[A-Z]+-\d+")
RESULTS = ("Passed", "Failed", "Skipped", "Error")

#: Verdicts that say something about the cluster. Anything else means the
#: benchmark did not produce a measurement.
CONCLUSIVE = {"Passed": True, "Failed": False}


def _clean(line):
    """Strip ANSI colour and the table's box drawing, keeping the cell text."""
    line = ANSI.sub("", line)
    return [cell.strip() for cell in line.split("|")]


def parse_scorecard(text):
    """Extract `(benchmark_id, title, result)` triples from the scorecard table.

    Continuation lines — where a wrapped title leaves the ID and Result cells
    empty — are folded into the row above.
    """
    rows = []
    for line in text.splitlines():
        cells = _clean(line)
        # No. | ID | Test | Result, plus the empty strings either side of the
        # outer pipes.
        if len(cells) < 5:
            continue

        identifier = next((c for c in cells if BENCHMARK_ID.fullmatch(c)), None)
        result = next((c for c in cells if c in RESULTS), None)

        if identifier and result:
            index = cells.index(identifier)
            title = cells[index + 1] if index + 1 < len(cells) else ""
            rows.append([identifier, title, result])
        elif rows and not identifier and not result:
            # A wrapped title. The only non-empty cell is the rest of the name.
            remainder = [c for c in cells[1:-1] if c]
            if len(remainder) == 1 and not remainder[0].isdigit():
                rows[-1][1] = f"{rows[-1][1]} {remainder[0]}".strip()

    return [tuple(row) for row in rows]


def _normalise(title):
    return re.sub(r"\s+", " ", title).strip().lower()


def resolve(rows, catalogue):
    """Map scorecard rows onto catalogue directories.

    Matching is on ID *and* title because the ID alone is ambiguous. Where the
    title does not match any benchmark carrying that ID, the row is returned as
    unresolved rather than guessed at.
    """
    by_id = {}
    for benchmark in catalogue["benchmarks"]:
        by_id.setdefault(benchmark["id"], []).append(benchmark)

    resolved, unresolved = {}, []
    for identifier, title, result in rows:
        candidates = by_id.get(identifier, [])
        if not candidates:
            unresolved.append((identifier, title, result, "unknown benchmark ID"))
            continue

        if len(candidates) == 1:
            match = candidates[0]
        else:
            # Duplicate ID: the title is what tells them apart.
            wanted = _normalise(title)
            named = [c for c in candidates if _normalise(c["title"]) == wanted]
            if len(named) != 1:
                unresolved.append(
                    (
                        identifier,
                        title,
                        result,
                        f"ID shared by {len(candidates)} benchmarks and the title "
                        "matched none of them uniquely",
                    )
                )
                continue
            match = named[0]

        resolved[match["directory"]] = result

    return resolved, unresolved


def parse_results(text, catalogue):
    """Return `(verdicts, inconclusive, unresolved)` for one kubectl-mtb run.

    `verdicts` maps directory -> bool, suitable for `mtb.compare`.
    `inconclusive` maps directory -> "Skipped" | "Error"; those are excluded
    from the comparison because they measured nothing.
    """
    rows = parse_scorecard(text)
    if not rows:
        raise ValueError(
            "no benchmark rows found in kubectl-mtb output. The reporter format "
            "may have changed, or the run failed before the scorecard was "
            "printed. Refusing to return an empty result, which would be "
            "indistinguishable from a clean comparison."
        )

    resolved, unresolved = resolve(rows, catalogue)
    verdicts = {d: CONCLUSIVE[r] for d, r in resolved.items() if r in CONCLUSIVE}
    inconclusive = {d: r for d, r in resolved.items() if r not in CONCLUSIVE}
    return verdicts, inconclusive, unresolved


def parse_file(path, catalogue):
    from pathlib import Path

    return parse_results(Path(path).read_text(errors="replace"), catalogue)
