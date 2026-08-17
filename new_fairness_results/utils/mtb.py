"""Compare a kubectl-mtb run against a KUMUTEVA isolation assessment.

Three inputs, all machine-generated:

- `mtb_catalogue.json` — the 19 upstream benchmarks (`fetch_mtb_catalogue.py`)
- `mtb_mapping.yaml`   — benchmark to KUMUTEVA property, hand-authored, reviewable
- `verify --output-json` — one assessment per solution

## The reconciliation rule is fixed here, before any comparison is run

kubectl-mtb returns pass/fail. KUMUTEVA returns a graded isolation level. How
those correspond is a judgement call, and it is made in `AGREEMENT` below rather
than after seeing the numbers.

The case that forces the issue is KUMUTEVA `Soft` against an MTB `pass`: the
operation was blocked, but in a way that revealed the shared environment. Two
honest readings exist — "both tools agree it was blocked", or "MTB missed a leak
our graded scale caught". The first makes KUMUTEVA look consistent with the
established tool; the second makes it look better than it. Picking after seeing
the counts would be picking the conclusion, so it is `PARTIAL` and stays
`PARTIAL` whatever falls out.

## Two things the plan did not anticipate, both found in the upstream data

**Benchmarks are not all about prevention.** The two Self-Service Operations
benchmarks ask whether a tenant *can* create NetworkPolicies and RoleBindings.
Scored against an isolation level the verdict inverts — "well isolated" would
read as a failure. Each mapping entry therefore declares its `dimension`, and
autonomy comparisons use `AGREEMENT_AUTONOMY`.

**Some correspondences are approximate.** `block_privileged_containers` checks
the pod spec at admission; our probe attempts privileged syscalls at runtime. A
cluster that admits the pod but confines it would fail one and pass the other,
and that is a property of the mapping, not a disagreement between the tools.
Those entries are marked `confidence: partial` and are reported separately, so
they cannot inflate either the agreement or the disagreement count.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
import yaml

DATA_DIR = Path(__file__).resolve().parent.parent
CATALOGUE_PATH = DATA_DIR / "mtb_catalogue.json"
MAPPING_PATH = DATA_DIR / "mtb_mapping.yaml"
VOCABULARY_PATH = DATA_DIR / "capability_vocabulary.yaml"
TAXONOMY_PATH = DATA_DIR / "solution_taxonomy.yaml"

# Verdicts.
AGREE = "agree"
DISAGREE = "disagree"
PARTIAL = "partial"
NOT_COMPARABLE = "not comparable"

# Feature-table cell states. Deliberately only three: an earlier draft had a
# fourth "partial" symbol, and it turned out to be a symptom of naming the rows
# after topics ("network") rather than capabilities ("cross-tenant network
# reachability"). Once a row names what is actually established, no tool is
# ever partially there.
SUPPORTED = "supported"
ABSENT = "absent"
#: Produced a scorecard, but it does not describe the tenancy boundary. Worse
#: than ABSENT, and the distinction is the point of the comparison: a tool that
#: cannot be applied is a gap, while a tool that answers wrongly is a hazard.
WRONG = "wrong"

#: Run names. `admin` is kubectl-mtb used as designed — the cluster
#: administrator pointing it at a tenant namespace and impersonating with
#: `--as`. `tenant` uses the tenant's own kubeconfig, which only reaches a
#: different API server when the control plane is not shared.
ADMIN_RUN = "admin"
TENANT_RUN = "tenant"

# --- the reconciliation rule -------------------------------------------------
# Fixed before the first comparison run. Changing it after results exist means
# changing what "agreement" means to suit them; the git history is the record.

#: (KUMUTEVA isolation level, MTB passed) -> verdict
AGREEMENT_ISOLATION = {
    # Blocked as if single-tenant, and MTB saw it blocked.
    ("Hard", True): AGREE,
    # We found it fully blocked, MTB found a hole. Our probe may be too weak.
    ("Hard", False): DISAGREE,
    # Blocked, but it leaked that the environment is shared. MTB is binary and
    # records a pass; the graded scale carries information MTB cannot express.
    ("Soft", True): PARTIAL,
    # Both saw a problem, at different resolutions.
    ("Soft", False): AGREE,
    # Not isolated at all, yet MTB passed it. MTB missed something, or the
    # mapping is wrong.
    ("None", True): DISAGREE,
    ("None", False): AGREE,
    # We could not determine a level, so we have nothing to compare.
    ("Unknown", True): NOT_COMPARABLE,
    ("Unknown", False): NOT_COMPARABLE,
}

#: (KUMUTEVA autonomy granted, MTB passed) -> verdict
#: Self-Service benchmarks pass when the tenant *can* act, so the polarity is
#: the reverse of the isolation table above.
AGREEMENT_AUTONOMY = {
    (True, True): AGREE,
    (False, False): AGREE,
    (True, False): DISAGREE,
    (False, True): DISAGREE,
}


@dataclass
class Benchmark:
    """One upstream benchmark plus the mapping authored for it."""

    directory: str
    benchmark_id: str
    title: str
    category: str
    benchmark_type: str
    profile_level: int
    dimension: str
    confidence: str
    rationale: str
    capability: str = ""
    probe_kind: str = ""
    properties: list = field(default_factory=list)

    @property
    def covered(self):
        return self.dimension != "not_covered"


def load_catalogue(path=CATALOGUE_PATH):
    return json.loads(Path(path).read_text())


def load_mapping(path=MAPPING_PATH):
    return yaml.safe_load(Path(path).read_text())


def _expand(properties):
    """Turn a mapping's `properties` block into concrete property triples.

    Two forms, because a cross-product is right for some subsystems and wrong
    for others:

    - `resources` x `operations` — the control plane, where every resource takes
      the same five verbs.
    - `pairs` — an explicit list, needed wherever each resource has its own
      single operation. The workload subsystem is like that: a
      `resources x operations` block there generates twenty combinations of
      which only five exist, and the other fifteen match nothing.
    """
    if not properties:
        return []
    subsystem = properties["subsystem"]

    if "pairs" in properties:
        return [
            {
                "subsystem": subsystem,
                "resource": pair["resource"],
                "operation": pair["operation"],
            }
            for pair in properties["pairs"]
        ]

    return [
        {"subsystem": subsystem, "resource": resource, "operation": operation}
        for resource in properties["resources"]
        for operation in properties["operations"]
    ]


def benchmarks(catalogue=None, mapping=None):
    """Join the catalogue with the mapping, keyed on directory.

    Keyed on `directory` because upstream reuses `MTB-PL1-BC-HI-1` across two
    benchmarks; joining on the ID would drop one of them without complaint.
    """
    catalogue = catalogue or load_catalogue()
    mapping = mapping or load_mapping()
    entries = mapping["benchmarks"]

    result = []
    for item in catalogue["benchmarks"]:
        entry = entries.get(item["directory"])
        if entry is None:
            raise KeyError(
                f"{item['directory']} is in the catalogue but not in "
                f"{MAPPING_PATH.name}. Every benchmark must be mapped or "
                f"explicitly marked not_covered — silence is not a decision."
            )
        result.append(
            Benchmark(
                directory=item["directory"],
                benchmark_id=item["id"],
                title=item["title"],
                category=item["category"],
                benchmark_type=item["benchmark_type"],
                profile_level=item["profile_level"],
                dimension=entry["dimension"],
                confidence=entry.get("confidence", "exact"),
                rationale=(entry.get("rationale") or "").strip(),
                capability=entry.get("capability", ""),
                probe_kind=entry.get("probe_kind", ""),
                properties=_expand(entry.get("properties")),
            )
        )
    return result


def load_verify_report(path):
    """Flatten a `verify --output-json` document into one row per property."""
    document = json.loads(Path(path).read_text())
    rows = []
    for subsystem in document.get("subsystems", []):
        name = subsystem["name"].lower().replace(" ", "_")
        for resource in subsystem.get("resources", []):
            for operation in resource.get("operations", []):
                rows.append(
                    {
                        "solution": document.get("solution_label"),
                        "subsystem": name,
                        "resource": resource["resource"],
                        "operation": operation["operation"],
                        "isolation": operation["isolation"]["level"],
                        "isolation_reason": operation["isolation"].get("reason"),
                        "autonomy": operation["autonomy"],
                    }
                )
    return pd.DataFrame(rows)


@dataclass
class Run:
    """One kubectl-mtb invocation, with the evidence about what it aimed at.

    The targeting fields are the substance. A scorecard on its own cannot be
    read: the recorded vcluster run looks like a completed measurement, and is
    in fact kubectl-mtb benchmarking vcluster's own syncer namespace while
    impersonating an identity the host API server has never heard of. Only
    `identity_known_to_target` and `targets_tenant_workload_namespace`
    distinguish that from a real result.
    """

    name: str
    kubeconfig: str = ""
    server: str = ""
    namespace: str = ""
    identity: str = ""
    #: The -l selector given to kubectl-mtb, and how many objects it matched.
    #:
    #: MTB-PL1-BC-CPI-2 iterates the resources the label selects and tries to
    #: modify each one. An empty match means the loop never runs and the
    #: benchmark returns success, so a mistyped label is indistinguishable from
    #: a solution that protects its resources perfectly. The count is the only
    #: thing that separates them after the fact.
    multitenancy_label: str = ""
    multitenancy_label_matches: int = 0
    #: Groups on the tenant's real certificate.
    identity_groups: list = field(default_factory=list)
    #: The flags kubectl-mtb was actually given — `--as <name>` and nothing
    #: else, because the tool has no `--as-group`.
    impersonation: list = field(default_factory=list)
    #: Tri-state. None means the run predates the check, not that it passed.
    identity_known_to_target: bool | None = None
    #: Tri-state, same reason. True only when the API server benchmarked is the
    #: one the tenant's own kubeconfig reaches.
    targets_tenant_workload_namespace: bool | None = None
    namespace_contents: list = field(default_factory=list)
    exit_code: int | None = None
    verdicts: dict = field(default_factory=dict)
    inconclusive: dict = field(default_factory=dict)
    unresolved: list = field(default_factory=list)

    @property
    def produced_a_scorecard(self):
        return bool(self.verdicts) or bool(self.inconclusive)

    @property
    def label_tested_nothing(self):
        """A -l selector was given but matched no resources.

        The benchmark that uses it then passes without exercising anything. It
        is the same silent shape as a quota that turns away every pod: a result
        that looks like enforcement and is an absence of it.
        """
        return bool(self.multitenancy_label) and self.multitenancy_label_matches == 0

    @property
    def benchmarked_two_tenants(self):
        """Whether the run named a second tenant namespace.

        kubectl-mtb skips every benchmark declaring `namespaceRequired: 2`
        unless two are given, and does so before running them, so a one-tenant
        invocation quietly shrinks the suite rather than failing.
        """
        return "," in (self.namespace or "")

    @property
    def unexpressible_groups(self):
        """Authority the tenant has that kubectl-mtb could not be told about.

        Kubernetes impersonation carries a username; kubectl-mtb's only
        identity flag is `--as`, with no `--as-group`. So a tenant whose
        permissions come from a group — every kubeadm-style credential,
        `O=system:masters` — is benchmarked as a bare name with nothing bound
        to it. The run does not fail; it reports the resulting "cannot create
        pods" as benchmark errors, which reads like a measurement of the
        cluster rather than the tool's inability to describe the tenant.

        A non-empty value here means the scorecard beside it is about a
        different identity than the one the tenant actually uses.
        """
        return [g for g in self.identity_groups if g not in self.impersonation]

    @property
    def targeting_valid(self):
        """True / False / None, never a guess.

        None propagates: a run recorded before these fields existed cannot be
        judged, and the table generator reports it as needing a re-run rather
        than assuming the answer. Assuming would decide the paper's central
        claim by default.
        """
        checks = [self.identity_known_to_target, self.targets_tenant_workload_namespace]
        if any(check is False for check in checks):
            return False
        if any(check is None for check in checks):
            return None
        return True

    @property
    def counts(self):
        passed = sum(1 for value in self.verdicts.values() if value)
        failed = sum(1 for value in self.verdicts.values() if not value)
        errors = sum(1 for value in self.inconclusive.values() if value == "Error")
        skipped = sum(1 for value in self.inconclusive.values() if value == "Skipped")
        return {"passed": passed, "failed": failed, "errors": errors, "skipped": skipped}


def _parse_run(directory, raw_name, record, name, catalogue, solution):
    """Build a `Run` from one raw scorecard plus its manifest record."""
    from . import mtb_parse

    run = Run(
        name=name,
        kubeconfig=record.get("kubeconfig", record.get("kubeconfig_used", "")),
        server=record.get("server", ""),
        namespace=record.get("namespace", ""),
        identity=record.get("identity", ""),
        multitenancy_label=record.get("multitenancy_label", ""),
        multitenancy_label_matches=record.get("multitenancy_label_matches", 0),
        identity_groups=record.get("identity_groups", []),
        impersonation=record.get("impersonation", []),
        identity_known_to_target=record.get("identity_known_to_target"),
        targets_tenant_workload_namespace=record.get(
            "targets_tenant_workload_namespace"
        ),
        namespace_contents=record.get("namespace_contents", []),
        exit_code=record.get("exit_code", record.get("mtb_exit_code")),
    )

    raw = directory / raw_name
    if not raw.exists():
        return run
    try:
        run.verdicts, run.inconclusive, run.unresolved = mtb_parse.parse_file(
            raw, catalogue
        )
    except ValueError as error:
        # Loudly, not silently: an unparsed run and a run where nothing was
        # comparable produce the same empty table otherwise.
        print(f"{solution}/{name}: could not parse kubectl-mtb output — {error}")
    return run


def load_runs(directory, catalogue=None, solution=None):
    """Every kubectl-mtb run in one solution directory, keyed by run name.

    Two layouts are accepted, because two runs recorded before this change are
    on disk and re-reading them is how the change is checked:

    - current: `mtb-raw-admin.txt` / `mtb-raw-tenant.txt`, with the manifest
      carrying a `runs` object holding one record per run;
    - legacy: a single `mtb-raw.txt` and a flat manifest. It is read as the
      admin run, which is what it was — both recorded runs used the cluster
      admin kubeconfig with `--as`. Its targeting fields stay None, so it can
      never be mistaken for a run that passed the checks that did not yet exist.
    """
    directory = Path(directory)
    catalogue = catalogue or load_catalogue()
    solution = solution or directory.name

    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    records = manifest.get("runs")
    if records:
        return {
            name: _parse_run(
                directory, f"mtb-raw-{name}.txt", record, name, catalogue, solution
            )
            for name, record in sorted(records.items())
        }

    if not (directory / "mtb-raw.txt").exists():
        return {}
    return {
        ADMIN_RUN: _parse_run(
            directory, "mtb-raw.txt", manifest, ADMIN_RUN, catalogue, solution
        )
    }


def load_run_tree(root):
    """Read a `run-mtb.sh` output tree into the inputs `compare` expects.

    Layout is one directory per solution. Returns
    `(mtb_results, verify_frame, manifests)`, unchanged in shape so the existing
    comparison and notebook keep working. `mtb_results[solution]` holds the
    **admin run's** verdicts: that is kubectl-mtb used as intended, so it is the
    run its own agreement should be judged on.

    Each manifest additionally gains a `runs` key holding the parsed `Run`
    objects, which is what the feature table reads. Doing it here avoids
    walking the tree twice and keeps the two views from disagreeing.
    """
    root = Path(root)
    catalogue = load_catalogue()
    results, frames, manifests = {}, [], {}

    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        solution = directory.name
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

        runs = load_runs(directory, catalogue, solution)
        manifest["runs"] = runs
        manifests[solution] = manifest

        admin = runs.get(ADMIN_RUN)
        results[solution] = admin.verdicts if admin else {}
        if admin:
            manifest["inconclusive"] = admin.inconclusive
            manifest["unresolved"] = admin.unresolved

        verify = directory / "verify.json"
        if verify.exists():
            frame = load_verify_report(verify)
            # The label inside the report is authoritative, but fall back to the
            # directory name so a run without --solution-label still joins.
            frame["solution"] = frame["solution"].fillna(solution)
            frames.append(frame)

    verify_frame = (
        pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    )
    return results, verify_frame, manifests


def _aggregate_isolation(levels):
    """Worst level wins, matching how the tool summarises a subsystem.

    A benchmark usually maps to several properties. If any one of them is
    unisolated the benchmark's concern is not met, so the summary has to be the
    minimum rather than an average — averaging would let one bad property hide
    behind a dozen good ones.
    """
    order = ["None", "Soft", "Unknown", "Hard"]
    present = [lvl for lvl in order if lvl in set(levels)]
    return present[0] if present else None


def compare(mtb_results, verify_frame, catalogue=None, mapping=None):
    """One row per (benchmark, solution) where a comparison is possible.

    `mtb_results` maps solution -> {benchmark directory -> passed(bool)}.
    A benchmark absent from a solution's results is *not comparable* for that
    solution — which is the expected outcome for the cluster-per-tenant
    architectures, and the finding the comparison exists to record.
    """
    catalogue_benchmarks = benchmarks(catalogue, mapping)
    rows = []

    for solution, results in sorted(mtb_results.items()):
        properties = verify_frame[verify_frame.solution == solution]

        for benchmark in catalogue_benchmarks:
            passed = results.get(benchmark.directory)

            row = {
                "benchmark": benchmark.benchmark_id,
                "directory": benchmark.directory,
                "title": benchmark.title,
                "category": benchmark.category,
                "profile_level": benchmark.profile_level,
                "dimension": benchmark.dimension,
                "confidence": benchmark.confidence,
                "solution": solution,
                "mtb": None if passed is None else ("pass" if passed else "fail"),
                "kumuteva": None,
                "verdict": NOT_COMPARABLE,
            }

            if not benchmark.covered or passed is None:
                rows.append(row)
                continue

            matched = properties.merge(
                pd.DataFrame(benchmark.properties),
                on=["subsystem", "resource", "operation"],
                how="inner",
            )
            if matched.empty:
                rows.append(row)
                continue

            if benchmark.dimension == "autonomy":
                # Granted only if every mapped property is granted; a partially
                # available self-service operation is not self-service.
                granted = bool(matched.autonomy.all())
                row["kumuteva"] = "granted" if granted else "denied"
                row["verdict"] = AGREEMENT_AUTONOMY[(granted, passed)]
            else:
                level = _aggregate_isolation(matched.isolation.tolist())
                row["kumuteva"] = level
                row["verdict"] = AGREEMENT_ISOLATION[(level, passed)]

            rows.append(row)

    return pd.DataFrame(rows)


def contingency(comparison, include_partial_mappings=False):
    """Counts of KUMUTEVA verdict against MTB verdict — the table the paper prints.

    Rows whose mapping is `confidence: partial` are excluded by default. Those
    compare adjacent-but-different conditions, so a mismatch says more about the
    mapping than about either tool, and counting them would inflate whichever
    column happens to suit.
    """
    frame = comparison[comparison.verdict != NOT_COMPARABLE]
    if not include_partial_mappings:
        frame = frame[frame.confidence == "exact"]
    if frame.empty:
        return pd.DataFrame()
    return pd.crosstab(frame.kumuteva, frame.mtb)


def summarise(comparison):
    """Headline counts, including the ones that are findings in themselves."""
    total = len(comparison)
    not_comparable = int((comparison.verdict == NOT_COMPARABLE).sum())
    exact = comparison[
        (comparison.verdict != NOT_COMPARABLE) & (comparison.confidence == "exact")
    ]
    return {
        "cases": total,
        "not_comparable": not_comparable,
        "not_comparable_pct": 100.0 * not_comparable / total if total else 0.0,
        "compared_exact": len(exact),
        "agree": int((exact.verdict == AGREE).sum()),
        "partial": int((exact.verdict == PARTIAL).sum()),
        "disagree": int((exact.verdict == DISAGREE).sum()),
        "partial_mappings_excluded": int(
            (
                (comparison.verdict != NOT_COMPARABLE)
                & (comparison.confidence == "partial")
            ).sum()
        ),
    }


def resolution(property_inventory, catalogue=None, mapping=None):
    """How much detail each tool reports over the same ground.

    Counting properties reached by at least one benchmark makes MTB look almost
    complete — around 146 of our 152 — but that number is misleading on its own.
    A single benchmark, `block_other_tenant_resources`, accounts for 105 of them:
    it asks one binary question about all namespaced resources at once, where we
    return a graded verdict per resource and verb.

    The comparison is therefore not about ground covered but about resolution
    over that ground, plus the properties nothing reaches at all.
    """
    known = {
        (p["subsystem"], p["resource"], p["operation"])
        for p in property_inventory["properties"]
    }
    mapped = benchmarks(catalogue, mapping)

    reached = set()
    largest = []
    for benchmark in mapped:
        if not benchmark.covered:
            continue
        keys = {
            (p["subsystem"], p["resource"], p["operation"]) for p in benchmark.properties
        }
        reached |= keys
        largest.append((len(keys), benchmark.benchmark_id, benchmark.directory))
    largest.sort(reverse=True)

    return {
        "mtb_verdicts": len([b for b in mapped if b.covered]),
        "mtb_benchmarks_total": len(mapped),
        "kumuteva_properties": len(known),
        "properties_reached": len(reached),
        "properties_unreached": sorted(known - reached),
        "widest_benchmark": largest[0] if largest else None,
        "properties_per_benchmark": largest,
    }


def coverage(catalogue=None, mapping=None):
    """What each tool covers, per benchmark — the other half of the argument."""
    return pd.DataFrame(
        [
            {
                "benchmark": b.benchmark_id,
                "directory": b.directory,
                "title": b.title,
                "category": b.category,
                "type": b.benchmark_type,
                "profile_level": b.profile_level,
                "kumuteva_dimension": b.dimension,
                "confidence": b.confidence if b.covered else "",
                "kumuteva_properties": len(b.properties),
            }
            for b in benchmarks(catalogue, mapping)
        ]
    )


# =============================================================================
# The feature table
# =============================================================================
#
# Everything below answers one question per cell: does this tool establish this
# capability, and where it produces a control-plane verdict, is that verdict
# about the tenancy boundary at all.
#
# The rules are written here, once, rather than in the generator, for the same
# reason AGREEMENT_ISOLATION is: they decide what the paper claims, so they
# belong somewhere a reviewer can read them and git can date them.


def load_vocabulary(path=VOCABULARY_PATH):
    return yaml.safe_load(Path(path).read_text())


def load_taxonomy(path=TAXONOMY_PATH):
    return yaml.safe_load(Path(path).read_text())


def tabulated_capabilities(vocabulary=None):
    """The capability names that become table rows, in declaration order."""
    vocabulary = vocabulary or load_vocabulary()
    return [
        name
        for name, spec in vocabulary["capabilities"].items()
        if spec["group"] != "not_tabulated"
    ]


def mtb_capability_cell(capability, mapping=None):
    """SUPPORTED if any benchmark declares this capability, else ABSENT.

    That is the whole rule, and it is deliberately blunt. The five data-plane
    rows come out ABSENT not because we judged kubectl-mtb's benchmarks
    inadequate, but because none of the nineteen claims the capability at all —
    a fact anybody can recompute from mtb_mapping.yaml.
    """
    for benchmark in benchmarks(mapping=mapping):
        if benchmark.capability == capability:
            return SUPPORTED
    return ABSENT


def kumuteva_capability_cell(
    capability, verify_frame, fairness_manifests=None, vocabulary=None
):
    """SUPPORTED only where the run data actually carries the evidence.

    Not a description of what the tool can do in principle: a subsystem that
    was not run, or that returned Unknown everywhere, is ABSENT here. This is
    the half of the rule that can mark us down, and it has to be able to, or
    the KUMUTEVA column is decoration.
    """
    vocabulary = vocabulary or load_vocabulary()
    spec = vocabulary["kumuteva"].get(capability)
    if spec is None:
        return ABSENT

    metric = spec.get("fairness_metric")
    if metric:
        # Present means some run reported the number, not that the number was
        # good. A degradation of 3x is a successful measurement.
        for manifest in fairness_manifests or []:
            if manifest.get(metric) is not None:
                return SUPPORTED
        return ABSENT

    if verify_frame is None or len(verify_frame) == 0:
        return ABSENT

    subsystems = spec.get("subsystems")
    if subsystems:
        matched = verify_frame[verify_frame.subsystem.isin(subsystems)]
    else:
        wanted = {tuple(triple) for triple in spec.get("properties", [])}
        matched = verify_frame[
            verify_frame.apply(
                lambda row: (row.subsystem, row.resource, row.operation) in wanted,
                axis=1,
            )
        ]

    if matched.empty:
        return ABSENT
    # Unknown means the probe could not reach a conclusion. A capability
    # evidenced only by Unknowns has not been demonstrated.
    return SUPPORTED if (matched.isolation != "Unknown").any() else ABSENT


def tenancy_cell(solutions, manifests):
    """The control-plane verdict for one taxonomy class.

    Worst-of across the class, matching how a subsystem is summarised
    elsewhere: one solution the tool gets wrong is not redeemed by two it gets
    right, because a user cannot tell in advance which one they have.

    Returns WRONG, ABSENT, SUPPORTED, or None when the recorded runs predate
    the targeting checks and the question cannot be answered yet.
    """
    seen = []
    for solution in solutions:
        manifest = manifests.get(solution)
        if manifest is None:
            continue
        runs = manifest.get("runs") or {}
        if not runs:
            seen.append(ABSENT)
            continue

        scored = [run for run in runs.values() if run.produced_a_scorecard]
        if not scored:
            # It ran and said nothing. A gap, not a hazard.
            seen.append(ABSENT)
            continue

        validity = [run.targeting_valid for run in scored]
        if any(valid is False for valid in validity):
            # The hazard: a scorecard exists and does not describe the tenancy
            # boundary. This is the vcluster case.
            seen.append(WRONG)
        elif _runs_contradict(scored):
            # Two runs on the same cluster disagreeing about the same benchmark
            # means at least one is wrong and the tool cannot say which.
            seen.append(WRONG)
        elif any(valid is None for valid in validity):
            seen.append(None)
        else:
            seen.append(SUPPORTED)

    if not seen:
        return None
    for state in (WRONG, ABSENT, None):
        if state in seen:
            return state
    return SUPPORTED


def _runs_contradict(runs):
    """True when two runs return opposite verdicts for the same benchmark."""
    if len(runs) < 2:
        return False
    by_benchmark = {}
    for run in runs:
        for directory, passed in run.verdicts.items():
            by_benchmark.setdefault(directory, set()).add(passed)
    return any(len(values) > 1 for values in by_benchmark.values())
