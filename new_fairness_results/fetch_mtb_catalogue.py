"""Fetch the kubectl-mtb benchmark catalogue from upstream and write it as JSON.

    ../.venv/bin/python fetch_mtb_catalogue.py

The catalogue is *generated, never transcribed*. Four cells of Table I in the
first submission were wrong because a table was assembled by hand, and a list of
nineteen opaque identifiers like `MTB-PL1-CC-CPI-1` is exactly the kind of thing
that goes wrong the same way.

Three upstream data-quality problems, all of which would corrupt an analysis
that keys or groups on the obvious field. Each is checked at the bottom so that
an upstream fix triggers a review rather than silent drift:

- **IDs are not unique.** `MTB-PL1-BC-HI-1` belongs to *two* benchmarks,
  `block_use_of_host_path` (Host Protection) and `block_use_of_nodeport_services`
  (Host Isolation). Keying on `id` merges them and loses one. The catalogue is
  therefore keyed on `directory`, which is unique by construction.

- **The ID and the `profileLevel` field disagree.** `block_other_tenant_resources`
  is `MTB-PL1-CC-TI-2` but declares `profileLevel: 2`. Anything that needs the
  profile level must read the field; parsing it out of the ID gives the wrong
  answer.

- **`benchmarkType` has two spellings for each value** — "Behavioral" and
  "Behavioral Check", "Configuration" and "Configuration Check". Grouping on the
  raw string yields four categories where there are two, so a normalised field
  is emitted alongside the original.

- **The source is archived.** `kubernetes-sigs/multi-tenancy` moved to
  `kubernetes-retired/`, and the last commit to master is from December 2021.
  The commit below is pinned for that reason: the comparison must stay
  reproducible even though nobody is maintaining the thing being compared
  against. That the baseline is unmaintained is a fact for the paper, not a
  reason to skip the comparison — a reviewer asked for it.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

# Last commit on master of the archived repository, 2021-12-20.
MTB_COMMIT = "44dad58150a1ccd3d8f22b05b4b7489984700d4d"
MTB_REPO = "kubernetes-retired/multi-tenancy"

BENCHMARK_ROOT = "benchmarks/kubectl-mtb/test/benchmarks"
RAW_BASE = f"https://raw.githubusercontent.com/{MTB_REPO}/{MTB_COMMIT}/{BENCHMARK_ROOT}"
API_TREE = f"https://api.github.com/repos/{MTB_REPO}/contents/{BENCHMARK_ROOT}?ref={MTB_COMMIT}"

OUTPUT = Path(__file__).parent / "mtb_catalogue.json"

# What upstream had when this was written. A different count means the catalogue
# changed and the mapping in mtb_mapping.yaml needs review, so it is checked
# rather than assumed.
EXPECTED_BENCHMARKS = 19

# "Behavioral" and "Behavioral Check" are the same thing upstream; so are
# "Configuration" and "Configuration Check". Normalised for grouping, with the
# original preserved so the catalogue stays a faithful record of the source.
BENCHMARK_TYPES = {
    "behavioral": "Behavioral Check",
    "behavioral check": "Behavioral Check",
    "configuration": "Configuration Check",
    "configuration check": "Configuration Check",
}


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "kumuteva-catalogue"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def benchmark_directories():
    """Directory names under the benchmark root, one per benchmark."""
    entries = json.loads(get(API_TREE))
    return sorted(e["name"] for e in entries if e["type"] == "dir")


def fetch_benchmark(directory):
    """Read one benchmark's config.yaml into a catalogue entry."""
    config = yaml.safe_load(get(f"{RAW_BASE}/{directory}/config.yaml"))
    raw_type = config.get("benchmarkType")
    return {
        # The stable key. `id` is not unique upstream.
        "directory": directory,
        "id": config["id"],
        "title": config["title"],
        "benchmark_type": BENCHMARK_TYPES.get(
            (raw_type or "").strip().lower(), raw_type
        ),
        "benchmark_type_raw": raw_type,
        "category": config.get("category"),
        "profile_level": config.get("profileLevel"),
        "namespace_required": config.get("namespaceRequired"),
        "description": (config.get("description") or "").strip(),
        "rationale": (config.get("rationale") or "").strip(),
    }


def main():
    try:
        directories = benchmark_directories()
    except urllib.error.URLError as error:
        print(f"could not reach GitHub: {error}", file=sys.stderr)
        return 1

    benchmarks = []
    for directory in directories:
        try:
            benchmarks.append(fetch_benchmark(directory))
            print(f"  {benchmarks[-1]['id']:22s} {directory}")
        except (urllib.error.URLError, KeyError, yaml.YAMLError) as error:
            print(f"  SKIPPED {directory}: {error}", file=sys.stderr)

    catalogue = {
        "source_repo": MTB_REPO,
        "source_commit": MTB_COMMIT,
        "source_path": BENCHMARK_ROOT,
        "benchmark_count": len(benchmarks),
        "benchmarks": benchmarks,
    }
    OUTPUT.write_text(json.dumps(catalogue, indent=2) + "\n")

    print(f"\nwrote {OUTPUT} ({len(benchmarks)} benchmarks)")

    problems = []

    # Keying on a non-unique field is the failure mode that loses a benchmark
    # without anyone noticing, so it is checked explicitly rather than trusted.
    by_id = {}
    for benchmark in benchmarks:
        by_id.setdefault(benchmark["id"], []).append(benchmark["directory"])
    duplicates = {i: dirs for i, dirs in by_id.items() if len(dirs) > 1}
    if duplicates:
        print("\nduplicate IDs upstream (the catalogue is keyed on `directory`):")
        for benchmark_id, dirs in sorted(duplicates.items()):
            print(f"  {benchmark_id:22s} {', '.join(dirs)}")
    else:
        problems.append(
            "no duplicate IDs found — upstream may have fixed them; `id` could "
            "now be a safe key, but check before relying on it"
        )

    directories_seen = {b["directory"] for b in benchmarks}
    if len(directories_seen) != len(benchmarks):
        problems.append("directory names are not unique — the catalogue has no safe key")

    if len(benchmarks) != EXPECTED_BENCHMARKS:
        problems.append(
            f"expected {EXPECTED_BENCHMARKS} benchmarks, found {len(benchmarks)} — "
            "upstream changed and mtb_mapping.yaml needs review"
        )

    # The ID/field mismatch is load-bearing: code that parses the level out of
    # the ID would be wrong today. If upstream ever fixes it, this fires and the
    # assumption gets rechecked instead of quietly becoming stale.
    mismatched = [
        b for b in benchmarks if f"-PL{b['profile_level']}-" not in b["id"]
    ]
    if mismatched:
        print("\nID/profileLevel mismatches (read the field, not the ID):")
        for b in mismatched:
            print(f"  {b['id']:22s} declares profileLevel {b['profile_level']}")
    else:
        problems.append(
            "no ID/profileLevel mismatch found — upstream may have corrected the "
            "IDs; re-check anything that relies on the field"
        )

    for problem in problems:
        print(f"\nWARNING: {problem}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
