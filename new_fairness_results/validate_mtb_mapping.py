"""Check the kubectl-mtb mapping against the catalogue and the property inventory.

    kumuteva verify /dev/null /dev/null --list-properties /tmp/props.json
    ../.venv/bin/python validate_mtb_mapping.py /tmp/props.json

Exits non-zero on any problem, so it can gate the comparison.

The failure this guards against is silent. A mistyped resource string does not
raise anything — it simply matches no property, the benchmark drops out of the
comparison as "not comparable", and the result looks like a clean run with a
slightly smaller sample. Since "not comparable" is also the *expected* outcome
for the cluster-per-tenant solutions, a typo would hide inside the finding the
comparison exists to report.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import utils.mtb as mtb  # noqa: E402


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    inventory = json.loads(Path(sys.argv[1]).read_text())
    known = {
        (p["subsystem"], p["resource"], p["operation"]) for p in inventory["properties"]
    }
    print(f"property inventory: {len(known)} properties")

    catalogue = mtb.load_catalogue()
    mapping = mtb.load_mapping()
    vocabulary = mtb.load_vocabulary()
    problems = []

    # --- the shared capability vocabulary ---
    #
    # Both tools are described against one list so that an "absent" cell in the
    # feature table is computed rather than decided. That only holds if every
    # name resolves: a benchmark declaring a capability nobody defined would
    # vanish from the table exactly like one that declares none, and the
    # data-plane rows would read as findings when they are typos.
    capability_names = set(vocabulary["capabilities"])
    probe_kinds = {"rbac", "admission", "runtime"}

    for directory, entry in sorted(mapping["benchmarks"].items()):
        capability = entry.get("capability")
        if not capability:
            problems.append(
                f"{directory}: no capability declared — it would silently "
                "contribute to no row of the feature table"
            )
        elif capability not in capability_names:
            problems.append(
                f"{directory}: capability {capability!r} is not in "
                f"capability_vocabulary.yaml"
            )
        probe_kind = entry.get("probe_kind")
        if probe_kind not in probe_kinds:
            problems.append(
                f"{directory}: probe_kind {probe_kind!r} is not one of "
                f"{sorted(probe_kinds)}"
            )

    # KUMUTEVA's side of the vocabulary, checked the same way and for the same
    # reason as the mapping's property strings below.
    for capability, spec in sorted(vocabulary["kumuteva"].items()):
        if capability not in capability_names:
            problems.append(
                f"capability_vocabulary.yaml: kumuteva declares {capability!r}, "
                "which is not among the defined capabilities"
            )
        for triple in spec.get("properties", []):
            if tuple(triple) not in known:
                problems.append(
                    f"capability_vocabulary.yaml: {capability} lists "
                    f"{'/'.join(triple)}, which is not a KUMUTEVA property — "
                    "it would match nothing and the capability would read as absent"
                )

    # Every non-control-plane property must belong to exactly one capability.
    # An unassigned one is a probe the feature table cannot see; a
    # double-assigned one is counted twice in two different rows.
    assigned = {}
    for capability, spec in vocabulary["kumuteva"].items():
        for triple in spec.get("properties", []):
            assigned.setdefault(tuple(triple), []).append(capability)
    for key, owners in sorted(assigned.items()):
        if len(owners) > 1:
            problems.append(
                f"capability_vocabulary.yaml: {'/'.join(key)} is claimed by "
                f"{', '.join(owners)} — a property belongs to one capability"
            )
    unassigned = sorted(
        key for key in known if key[0] != "control_plane" and key not in assigned
    )
    for key in unassigned:
        problems.append(
            f"capability_vocabulary.yaml: {'/'.join(key)} belongs to no "
            "capability, so nothing in the feature table reflects it"
        )

    # --- the tenancy taxonomy ---
    taxonomy = mtb.load_taxonomy()
    declared_classes = set(taxonomy["classes"])
    for solution, entry in sorted(taxonomy["solutions"].items()):
        for plane in ("control_plane", "data_plane"):
            value = entry.get(plane)
            if value not in declared_classes:
                problems.append(
                    f"solution_taxonomy.yaml: {solution}.{plane} is {value!r}, "
                    f"not one of {sorted(declared_classes)}"
                )

    # The mapping is authored against a specific upstream snapshot. If that
    # moved, the entries below may no longer describe what they claim to.
    if mapping.get("catalogue_commit") != catalogue.get("source_commit"):
        problems.append(
            f"mapping was authored against {mapping.get('catalogue_commit')} but the "
            f"catalogue is {catalogue.get('source_commit')} — re-review the entries"
        )
    if mapping.get("catalogue_benchmark_count") != catalogue.get("benchmark_count"):
        problems.append(
            f"benchmark count changed: mapping expects "
            f"{mapping.get('catalogue_benchmark_count')}, catalogue has "
            f"{catalogue.get('benchmark_count')}"
        )

    # Every benchmark mapped or explicitly declined. Silence is not a decision:
    # an unmapped benchmark and a deliberately-not-covered one look identical in
    # the results table unless the difference is written down.
    catalogue_dirs = {b["directory"] for b in catalogue["benchmarks"]}
    mapped_dirs = set(mapping["benchmarks"])
    for missing in sorted(catalogue_dirs - mapped_dirs):
        problems.append(f"{missing}: in the catalogue, absent from the mapping")
    for extra in sorted(mapped_dirs - catalogue_dirs):
        problems.append(f"{extra}: in the mapping, absent from the catalogue")

    # Every property string must resolve. This is the silent-failure guard.
    covered = set()
    for benchmark in mtb.benchmarks(catalogue, mapping):
        if not benchmark.covered:
            if benchmark.properties:
                problems.append(
                    f"{benchmark.directory}: marked not_covered but lists properties"
                )
            if not benchmark.rationale:
                problems.append(
                    f"{benchmark.directory}: not_covered without a rationale — "
                    "a gap must be explained, not just recorded"
                )
            continue

        if not benchmark.properties:
            problems.append(f"{benchmark.directory}: covered but maps to no property")
        if benchmark.dimension not in ("isolation", "autonomy"):
            problems.append(
                f"{benchmark.directory}: unknown dimension {benchmark.dimension!r}"
            )
        if benchmark.confidence not in ("exact", "partial"):
            problems.append(
                f"{benchmark.directory}: unknown confidence {benchmark.confidence!r}"
            )

        for prop in benchmark.properties:
            key = (prop["subsystem"], prop["resource"], prop["operation"])
            if key not in known:
                problems.append(
                    f"{benchmark.directory}: no such property "
                    f"{prop['subsystem']}/{prop['resource']}/{prop['operation']} — "
                    "it would match nothing and drop out silently"
                )
            else:
                covered.add(key)

    # Reported, not enforced. Stated as resolution rather than as a coverage
    # fraction: "146 of 152 reached" invites the reading that MTB covers almost
    # everything, when one benchmark accounts for 105 of those by asking a single
    # binary question about all namespaced resources at once.
    resolution = mtb.resolution(inventory, catalogue, mapping)
    print(
        f"\nresolution: {resolution['mtb_verdicts']} MTB verdicts vs "
        f"{resolution['kumuteva_properties']} KUMUTEVA properties over the same ground"
    )
    widest = resolution["widest_benchmark"]
    if widest:
        print(f"  widest single benchmark: {widest[1]} ({widest[2]}) -> {widest[0]} properties")
    unreached = resolution["properties_unreached"]
    print(f"  properties no benchmark reaches: {len(unreached)}")
    for key in unreached:
        print(f"    {' / '.join(key)}")

    by_dimension = {}
    for benchmark in mtb.benchmarks(catalogue, mapping):
        by_dimension.setdefault(benchmark.dimension, []).append(benchmark.directory)
    for dimension, entries in sorted(by_dimension.items()):
        print(f"  {dimension}: {len(entries)}")

    # The two counts the feature table's claims rest on. Printed rather than
    # asserted here — test_mtb.py is where they are enforced — because seeing
    # them move is the earliest warning that the paper's wording needs revisiting.
    all_benchmarks = mtb.benchmarks(catalogue, mapping)
    runtime = [b.directory for b in all_benchmarks if b.probe_kind == "runtime"]
    print(f"\nkubectl-mtb benchmarks that observe runtime behaviour: {len(runtime)}")
    if runtime:
        print(f"  {', '.join(runtime)}")
        print("  (the Method row says 'static policy inspection' — revisit it)")

    data_plane = [
        name
        for name, spec in vocabulary["capabilities"].items()
        if spec["group"] == "data_plane"
    ]
    declared = {b.capability for b in all_benchmarks}
    print("kubectl-mtb coverage of the data-plane capabilities:")
    for capability in data_plane:
        state = "declared" if capability in declared else "absent"
        print(f"  {capability}: {state}")

    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("\nmapping is consistent with the catalogue and the property inventory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
