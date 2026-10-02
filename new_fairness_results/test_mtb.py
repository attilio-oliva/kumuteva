"""Tests for the kubectl-mtb comparison.

    ../.venv/bin/python -m pytest test_mtb.py -q

Synthetic inputs throughout. The point is not to predict what a real run finds
but to prove the reconciliation logic does what `utils/mtb.py` says it does —
especially the two cases that are easy to get backwards: Self-Service benchmarks
whose polarity is inverted, and `Soft`, which must stay `partial` rather than
being folded into whichever column flatters the result.
"""

import json
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import utils.mtb as mtb  # noqa: E402


def verify_frame(rows):
    """A flattened verify report, as `load_verify_report` would produce."""
    return pd.DataFrame(
        [
            {
                "solution": solution,
                "subsystem": subsystem,
                "resource": resource,
                "operation": operation,
                "isolation": isolation,
                "isolation_reason": None,
                "autonomy": autonomy,
            }
            for solution, subsystem, resource, operation, isolation, autonomy in rows
        ]
    )


# --- the mapping itself ------------------------------------------------------


def test_every_catalogue_benchmark_is_mapped_or_explicitly_declined():
    # An unmapped benchmark and a deliberately-uncovered one look identical in a
    # results table. `benchmarks()` raises rather than letting one pass as the
    # other.
    entries = mtb.benchmarks()
    catalogue = mtb.load_catalogue()
    assert len(entries) == catalogue["benchmark_count"]
    assert all(b.dimension in ("isolation", "autonomy", "not_covered") for b in entries)


def test_duplicate_upstream_ids_do_not_collapse_two_benchmarks_into_one():
    # Upstream gives block_use_of_host_path and block_use_of_nodeport_services
    # the same ID. Keyed on `id` one of them disappears silently.
    entries = mtb.benchmarks()
    directories = [b.directory for b in entries]
    assert len(directories) == len(set(directories))

    duplicated = [b for b in entries if b.benchmark_id == "MTB-PL1-BC-HI-1"]
    assert len(duplicated) == 2, "both benchmarks sharing the ID must survive"
    assert {b.directory for b in duplicated} == {
        "block_use_of_host_path",
        "block_use_of_nodeport_services",
    }


def test_not_covered_entries_carry_a_rationale_and_no_properties():
    for benchmark in mtb.benchmarks():
        if benchmark.covered:
            continue
        assert benchmark.rationale, f"{benchmark.directory} must explain the gap"
        assert not benchmark.properties


# --- the reconciliation rule -------------------------------------------------


def test_soft_against_an_mtb_pass_is_partial_not_agreement():
    # The whole reason the rule is fixed in advance. Blocked, but leaking that
    # the environment is shared: MTB is binary and calls that a pass. Counting
    # it as agreement flatters MTB; counting it as disagreement flatters us.
    assert mtb.AGREEMENT_ISOLATION[("Soft", True)] == mtb.PARTIAL


def test_isolation_polarity_is_the_way_round_it_claims_to_be():
    assert mtb.AGREEMENT_ISOLATION[("Hard", True)] == mtb.AGREE
    assert mtb.AGREEMENT_ISOLATION[("None", False)] == mtb.AGREE
    assert mtb.AGREEMENT_ISOLATION[("Hard", False)] == mtb.DISAGREE
    assert mtb.AGREEMENT_ISOLATION[("None", True)] == mtb.DISAGREE


def test_autonomy_polarity_is_inverted_relative_to_isolation():
    # Self-Service benchmarks pass when the tenant CAN act. Scored on the
    # isolation table, a well-isolated tenant would read as a failure.
    assert mtb.AGREEMENT_AUTONOMY[(True, True)] == mtb.AGREE
    assert mtb.AGREEMENT_AUTONOMY[(False, False)] == mtb.AGREE
    assert mtb.AGREEMENT_AUTONOMY[(False, True)] == mtb.DISAGREE


def test_unknown_isolation_is_not_comparable_rather_than_a_disagreement():
    # We could not determine a level. That is an absence of evidence, and must
    # not be counted against either tool.
    assert mtb.AGREEMENT_ISOLATION[("Unknown", True)] == mtb.NOT_COMPARABLE
    assert mtb.AGREEMENT_ISOLATION[("Unknown", False)] == mtb.NOT_COMPARABLE


# --- aggregation -------------------------------------------------------------


def test_a_benchmark_takes_the_worst_of_the_properties_it_maps_to():
    # block_other_tenant_resources maps to 105 properties. One unisolated
    # property means the benchmark's concern is not met; averaging would let it
    # hide behind the other 104.
    assert mtb._aggregate_isolation(["Hard", "Hard", "None"]) == "None"
    assert mtb._aggregate_isolation(["Hard", "Soft"]) == "Soft"
    assert mtb._aggregate_isolation(["Hard", "Hard"]) == "Hard"
    assert mtb._aggregate_isolation([]) is None


# --- end to end --------------------------------------------------------------


def test_comparison_classifies_each_case_by_the_stated_rule():
    frame = verify_frame(
        [
            # host path: we found it wide open, MTB will also fail it -> agree
            ("capsule", "storage", "Volume", "Use HostPath in a Volume", "None", True),
            # nodeport: blocked but leaks -> partial against an MTB pass
            (
                "capsule",
                "network",
                "Service Network",
                "Expose NodePort",
                "Soft",
                False,
            ),
            # host PID: fully blocked, MTB fails it -> disagree, investigate
            (
                "capsule",
                "workload",
                "Process Namespace",
                "View Processes",
                "Hard",
                False,
            ),
            # self-service: tenant can create NetworkPolicies, MTB passes -> agree
            (
                "capsule",
                "control_plane",
                "networking.k8s.io/v1/NetworkPolicy",
                "CREATE",
                "Hard",
                True,
            ),
        ]
    )
    results = {
        "capsule": {
            "block_use_of_host_path": False,
            "block_use_of_nodeport_services": True,
            "block_use_of_host_pid": False,
            "create_network_policies": True,
        }
    }

    comparison = mtb.compare(results, frame)
    verdict = {
        row.directory: row.verdict
        for row in comparison.itertuples()
        if row.verdict != mtb.NOT_COMPARABLE
    }

    assert verdict["block_use_of_host_path"] == mtb.AGREE
    assert verdict["block_use_of_nodeport_services"] == mtb.PARTIAL
    assert verdict["block_use_of_host_pid"] == mtb.DISAGREE
    assert verdict["create_network_policies"] == mtb.AGREE


def test_a_solution_mtb_cannot_evaluate_is_not_comparable_everywhere():
    # The structural finding: for cluster-per-tenant architectures there is no
    # namespace to point MTB at, so it produces no verdicts. Every row must come
    # back "not comparable" rather than defaulting to agreement or being dropped.
    frame = verify_frame(
        [
            ("vcluster", "storage", "Volume", "Use HostPath in a Volume", "Hard", False),
        ]
    )
    comparison = mtb.compare({"vcluster": {}}, frame)

    assert len(comparison) == mtb.load_catalogue()["benchmark_count"]
    assert (comparison.verdict == mtb.NOT_COMPARABLE).all()

    summary = mtb.summarise(comparison)
    assert summary["not_comparable"] == summary["cases"]
    assert summary["not_comparable_pct"] == 100.0


def test_partial_mappings_are_excluded_from_the_headline_contingency():
    # block_privileged_containers compares admission policy against a runtime
    # probe. A mismatch there is a property of the mapping, so it must not land
    # in the table the paper prints.
    frame = verify_frame(
        [
            (
                "capsule",
                "workload",
                "Privileged Syscalls",
                "Use Privileged Syscalls",
                "Hard",
                False,
            ),
            (
                "capsule",
                "workload",
                "Process Namespace",
                "View Processes",
                "Hard",
                False,
            ),
        ]
    )
    results = {
        "capsule": {
            # partial: admission-time policy vs our runtime probe
            "block_privileged_containers": False,
            # exact: both share the host PID namespace and look
            "block_use_of_host_pid": False,
        }
    }
    comparison = mtb.compare(results, frame)

    default = mtb.contingency(comparison)
    assert default.to_numpy().sum() == 1, "only the exact mapping should be counted"

    including = mtb.contingency(comparison, include_partial_mappings=True)
    assert including.to_numpy().sum() == 2

    summary = mtb.summarise(comparison)
    assert summary["partial_mappings_excluded"] == 1


def test_a_mistyped_property_matches_nothing_and_is_reported_not_hidden():
    # The silent-failure mode validate_mtb_mapping.py exists to catch: a typo
    # yields "not comparable", which is indistinguishable from the real finding.
    frame = verify_frame(
        [("capsule", "storage", "Volume", "Use HostPath in a Volume", "None", True)]
    )
    mapping = mtb.load_mapping()
    mapping["benchmarks"]["block_use_of_host_path"]["properties"]["resources"] = [
        "Volumes"  # note the typo
    ]

    comparison = mtb.compare({"capsule": {"block_use_of_host_path": False}}, frame, mapping=mapping)
    row = comparison[comparison.directory == "block_use_of_host_path"].iloc[0]
    assert row.verdict == mtb.NOT_COMPARABLE


def test_verify_report_flattening_reads_the_shape_the_tool_writes():
    document = {
        "solution_label": "capsule",
        "subsystems": [
            {
                "name": "Storage",
                "resources": [
                    {
                        "resource": "Volume",
                        "operations": [
                            {
                                "operation": "Use HostPath in a Volume",
                                "isolation": {"level": "Soft", "reason": "Forbidden"},
                                "autonomy": False,
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = Path("/tmp/kumuteva-verify-test.json")
    path.write_text(json.dumps(document))
    frame = mtb.load_verify_report(path)
    path.unlink()

    assert len(frame) == 1
    row = frame.iloc[0]
    assert row.solution == "capsule"
    # "Storage" must become "storage" to join against the mapping's subsystem key.
    assert row.subsystem == "storage"
    assert row.isolation == "Soft"
    assert row.isolation_reason == "Forbidden"


# --- kubectl-mtb output parsing ----------------------------------------------

import utils.mtb_parse as mtb_parse  # noqa: E402

# The scorecard as the default reporter draws it: box-drawn table, ANSI colour on
# the result cells, and a long title wrapped across two physical lines.
SCORECARD = (
    "Running Benchmarks...\n"
    "+-----+------------------+----------------------------------+--------+\n"
    "| NO. |        ID        |               TEST               | RESULT |\n"
    "+-----+------------------+----------------------------------+--------+\n"
    "|   1 | MTB-PL1-CC-CPI-1 | Block access to cluster          | \x1b[32mPassed\x1b[0m |\n"
    "|     |                  | resources                        |        |\n"
    "|   2 | MTB-PL1-BC-HI-1  | Block use of host path volumes   | \x1b[31mFailed\x1b[0m |\n"
    "|   3 | MTB-PL1-BC-HI-1  | Block use of NodePort services   | \x1b[32mPassed\x1b[0m |\n"
    "|   4 | MTB-PL1-BC-HI-4  | Block use of host PID namespace  | \x1b[33mSkipped\x1b[0m |\n"
    "+-----+------------------+----------------------------------+--------+\n"
    "1 Passed | 1 Failed | 1 Skipped | 0 Errors | \n"
)


def test_scorecard_rows_survive_ansi_colour_and_wrapped_titles():
    rows = mtb_parse.parse_scorecard(SCORECARD)
    assert len(rows) == 4
    # The wrapped title must be rejoined, not split into a phantom benchmark.
    assert rows[0] == (
        "MTB-PL1-CC-CPI-1",
        "Block access to cluster resources",
        "Passed",
    )


def test_duplicate_ids_are_separated_by_title_not_collapsed():
    # Upstream gives host-path and NodePort the same ID. Keyed on the ID alone
    # one verdict overwrites the other and a real result is lost.
    catalogue = mtb.load_catalogue()
    verdicts, inconclusive, unresolved = mtb_parse.parse_results(SCORECARD, catalogue)

    assert not unresolved, unresolved
    assert verdicts["block_use_of_host_path"] is False
    assert verdicts["block_use_of_nodeport_services"] is True


def test_skipped_is_inconclusive_rather_than_a_failure():
    # A benchmark that did not run says nothing about the cluster. Scoring it as
    # a failure would invent disagreement out of a missing measurement.
    catalogue = mtb.load_catalogue()
    verdicts, inconclusive, _ = mtb_parse.parse_results(SCORECARD, catalogue)

    assert "block_use_of_host_pid" not in verdicts
    assert inconclusive["block_use_of_host_pid"] == "Skipped"


def test_unparseable_output_raises_instead_of_returning_nothing():
    # An empty result is indistinguishable from a clean comparison, and "not
    # comparable" is the expected outcome for cluster-per-tenant solutions, so a
    # silent parse failure would hide inside the finding.
    with pytest.raises(ValueError, match="no benchmark rows"):
        mtb_parse.parse_results("kubectl-mtb: connection refused\n", mtb.load_catalogue())


def test_a_title_that_matches_no_benchmark_with_that_id_is_unresolved():
    ambiguous = (
        "+-----+------------------+------------------+--------+\n"
        "|   1 | MTB-PL1-BC-HI-1  | Something else   | Passed |\n"
        "+-----+------------------+------------------+--------+\n"
    )
    _, _, unresolved = mtb_parse.parse_results(ambiguous, mtb.load_catalogue())
    assert len(unresolved) == 1
    assert "matched none of them uniquely" in unresolved[0][3]


def test_privilege_benchmarks_read_the_whole_privileged_pod_spec_probe_set():
    # From the first real Capsule run. The workload subsystem found every host
    # namespace shareable (None) while the privileged-syscall probe alone
    # reported Hard. Mapped to that one probe, all four PodSecurity benchmarks
    # inherited the single optimistic verdict and disagreed with kubectl-mtb.
    #
    # They now map to all five privileged pod-spec probes, so worst-of
    # aggregation reflects what the subsystem actually found.
    frame = verify_frame(
        [
            ("capsule", "workload", "Privileged Syscalls", "Use Privileged Syscalls", "Hard", True),
            ("capsule", "workload", "Process Namespace", "View Processes", "None", True),
            ("capsule", "workload", "IPC Namespace", "Access IPC Resources", "None", True),
            ("capsule", "workload", "Network Namespace", "Create Network Connections", "None", True),
            ("capsule", "workload", "User Namespace", "Access Host User Namespace", "None", True),
        ]
    )
    results = {
        "capsule": {
            name: False
            for name in (
                "block_privileged_containers",
                "block_privilege_escalation",
                "block_add_capabilities",
                "require_run_as_non_root_user",
            )
        }
    }
    comparison = mtb.compare(results, frame)
    scored = comparison[comparison.verdict != mtb.NOT_COMPARABLE]

    assert len(scored) == 4
    assert (scored.kumuteva == "None").all(), "the optimistic probe must not dominate"
    assert (scored.verdict == mtb.AGREE).all()


# --- the feature table -------------------------------------------------------
#
# These guard the three sentences the results chapter makes. Each claim is only
# as good as the data behind it, so each has a test that fails when the data
# stops supporting it rather than when someone edits the prose.


def test_every_benchmark_declares_a_capability_and_probe_kind():
    """A benchmark with neither contributes to no row, silently."""
    vocabulary = mtb.load_vocabulary()
    names = set(vocabulary["capabilities"])
    for benchmark in mtb.benchmarks():
        assert benchmark.capability in names, benchmark.directory
        assert benchmark.probe_kind in {"rbac", "admission", "runtime"}, (
            benchmark.directory
        )


def test_no_benchmark_observes_runtime_behaviour():
    """The claim behind the Method row "static policy inspection".

    Upstream labels twelve of the nineteen "Behavioral Check", but behavioural
    there means "create an object and see whether the API server rejects it" —
    an admission decision, taken before anything runs. If this count ever moves
    off zero, the Method row is wrong and so is the sentence in the paper that
    says kubectl-mtb never observes behaviour.
    """
    runtime = [b.directory for b in mtb.benchmarks() if b.probe_kind == "runtime"]
    assert runtime == []


def test_kubectl_mtb_declares_no_data_plane_capability():
    """The claim behind the five absent cells in the Data plane block.

    Not "we judged its data-plane benchmarks inadequate" — none of the nineteen
    claims the capability at all. `host_resource_policy` is deliberately
    excluded: kubectl-mtb does cover it, and the table says so.
    """
    vocabulary = mtb.load_vocabulary()
    declared = {b.capability for b in mtb.benchmarks()}
    data_plane = {
        name
        for name, spec in vocabulary["capabilities"].items()
        if spec["group"] == "data_plane"
    }
    assert declared & data_plane == {"host_resource_policy"}


def test_mtb_capability_cell_reflects_the_mapping():
    assert mtb.mtb_capability_cell("control_plane") == mtb.SUPPORTED
    assert mtb.mtb_capability_cell("host_resource_policy") == mtb.SUPPORTED
    assert mtb.mtb_capability_cell("cross_tenant_network") == mtb.ABSENT
    assert mtb.mtb_capability_cell("performance_isolation") == mtb.ABSENT


def test_kumuteva_capability_cell_can_report_absent():
    """The half of the rule that is able to mark us down.

    A rule that only ever returns SUPPORTED for our own tool would make the
    KUMUTEVA column decoration. A subsystem that was not run is absent, and a
    subsystem that returned Unknown everywhere has demonstrated nothing.
    """
    empty = pd.DataFrame(columns=["subsystem", "resource", "operation", "isolation"])
    assert mtb.kumuteva_capability_cell("cross_tenant_network", empty) == mtb.ABSENT

    unknown = pd.DataFrame(
        [
            {
                "subsystem": "network",
                "resource": "Pod Network",
                "operation": "Connect to Pod",
                "isolation": "Unknown",
            }
        ]
    )
    assert mtb.kumuteva_capability_cell("cross_tenant_network", unknown) == mtb.ABSENT

    determinate = unknown.assign(isolation="Hard")
    assert (
        mtb.kumuteva_capability_cell("cross_tenant_network", determinate)
        == mtb.SUPPORTED
    )


def test_image_provenance_is_a_gap_on_our_side():
    """The standing proof that the vocabulary is not written to flatter us."""
    vocabulary = mtb.load_vocabulary()
    assert "image_provenance" in vocabulary["capabilities"]
    assert "image_provenance" not in vocabulary["kumuteva"]
    assert mtb.mtb_capability_cell("image_provenance") == mtb.SUPPORTED


def _run(name, **kwargs):
    defaults = {
        "verdicts": {"block_access_to_cluster_resources": True},
        "identity_known_to_target": True,
        "targets_tenant_workload_namespace": True,
    }
    defaults.update(kwargs)
    return mtb.Run(name=name, **defaults)


def _manifests(**solutions):
    return {name: {"runs": runs} for name, runs in solutions.items()}


def test_tenancy_cell_wrong_when_the_identity_is_unknown_to_the_target():
    """The vcluster case, and the reason the comparison exists.

    A scorecard was produced. It does not describe the tenancy boundary,
    because the API server benchmarked has never heard of the identity being
    impersonated. That is worse than being inapplicable, and it has to grade
    differently from it.
    """
    manifests = _manifests(
        vcluster={mtb.ADMIN_RUN: _run(mtb.ADMIN_RUN, identity_known_to_target=False)}
    )
    assert mtb.tenancy_cell(["vcluster"], manifests) == mtb.WRONG


def test_tenancy_cell_wrong_when_the_namespace_is_not_the_tenants():
    manifests = _manifests(
        vcluster={
            mtb.ADMIN_RUN: _run(
                mtb.ADMIN_RUN, targets_tenant_workload_namespace=False
            )
        }
    )
    assert mtb.tenancy_cell(["vcluster"], manifests) == mtb.WRONG


def test_tenancy_cell_wrong_when_the_two_runs_contradict():
    """Same cluster, same benchmark, opposite verdicts.

    The tool cannot say which of its own answers to believe, and neither can a
    reader. That is a wrong result, not two partial ones.
    """
    manifests = _manifests(
        vcluster={
            mtb.ADMIN_RUN: _run(mtb.ADMIN_RUN, verdicts={"block_ns_quota": True}),
            mtb.TENANT_RUN: _run(mtb.TENANT_RUN, verdicts={"block_ns_quota": False}),
        }
    )
    assert mtb.tenancy_cell(["vcluster"], manifests) == mtb.WRONG


def test_tenancy_cell_absent_when_nothing_was_produced():
    """Ran and said nothing: a gap, not a hazard. Must not read as WRONG."""
    manifests = _manifests(
        kubezoo={mtb.ADMIN_RUN: _run(mtb.ADMIN_RUN, verdicts={}, inconclusive={})}
    )
    assert mtb.tenancy_cell(["kubezoo"], manifests) == mtb.ABSENT


def test_tenancy_cell_ungraded_when_the_checks_were_never_recorded():
    """A run predating the targeting checks cannot be graded.

    None, never True. Defaulting to supported would decide the paper's central
    claim by omission, in kubectl-mtb's favour, on no evidence.
    """
    manifests = _manifests(
        capsule={
            mtb.ADMIN_RUN: _run(
                mtb.ADMIN_RUN,
                identity_known_to_target=None,
                targets_tenant_workload_namespace=None,
            )
        }
    )
    assert mtb.tenancy_cell(["capsule"], manifests) is None


def test_tenancy_cell_supported_when_targeting_checks_out():
    manifests = _manifests(capsule={mtb.ADMIN_RUN: _run(mtb.ADMIN_RUN)})
    assert mtb.tenancy_cell(["capsule"], manifests) == mtb.SUPPORTED


def test_tenancy_cell_takes_the_worst_solution_in_the_class():
    """One solution the tool gets wrong is not redeemed by one it gets right.

    A user cannot tell in advance which of the two they have, so the class
    verdict is the worse of them.
    """
    manifests = _manifests(
        vcluster={mtb.ADMIN_RUN: _run(mtb.ADMIN_RUN, identity_known_to_target=False)},
        kamaji={mtb.ADMIN_RUN: _run(mtb.ADMIN_RUN)},
    )
    assert mtb.tenancy_cell(["kamaji", "vcluster"], manifests) == mtb.WRONG


def test_every_solution_that_can_be_run_is_classified():
    """A blank tenancy row is indistinguishable from a measured one."""
    import subprocess

    taxonomy = mtb.load_taxonomy()["solutions"]
    listed = subprocess.run(
        ["../target/release/kumuteva", "setup", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent,
    ).stdout
    for solution in taxonomy:
        assert solution in listed, (
            f"{solution} is classified but `setup --type` does not offer it"
        )


def test_run_counts_add_up():
    run = mtb.Run(
        name=mtb.ADMIN_RUN,
        verdicts={"a": True, "b": False, "c": False},
        inconclusive={"d": "Error", "e": "Skipped"},
    )
    assert run.counts == {"passed": 1, "failed": 2, "errors": 1, "skipped": 1}
    assert run.produced_a_scorecard


def test_load_runs_reads_the_legacy_flat_manifest(tmp_path):
    """The two runs already on disk must keep parsing.

    They are the evidence the change is checked against, and they predate the
    nested layout. Read as the admin run — which is what they were — with the
    targeting fields left unrecorded rather than assumed.
    """
    directory = tmp_path / "capsule"
    directory.mkdir()
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "solution": "capsule",
                "namespace": "tenant1",
                "identity": "tenant1-admin",
                "kubeconfig_used": "bench-capsule.kubeconfig",
                "mtb_exit_code": 0,
            }
        )
    )
    (directory / "mtb-raw.txt").write_text(SCORECARD)

    runs = mtb.load_runs(directory)
    assert set(runs) == {mtb.ADMIN_RUN}
    admin = runs[mtb.ADMIN_RUN]
    assert admin.identity == "tenant1-admin"
    assert admin.kubeconfig == "bench-capsule.kubeconfig"
    assert admin.identity_known_to_target is None
    assert admin.targeting_valid is None
    assert admin.produced_a_scorecard


def test_load_runs_reads_the_nested_manifest(tmp_path):
    directory = tmp_path / "vcluster"
    directory.mkdir()
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "solution": "vcluster",
                "runs": {
                    "admin": {
                        "kubeconfig": "bench-vcluster.kubeconfig",
                        "server": "https://127.0.0.1:6443",
                        "namespace": "tenant1",
                        "identity": "kubernetes-super-admin",
                        "identity_known_to_target": False,
                        "targets_tenant_workload_namespace": False,
                        "namespace_contents": ["statefulset/vcluster-tenant1"],
                    },
                    "tenant": {
                        "kubeconfig": "tenant1-bench-vcluster.kubeconfig",
                        "server": "https://127.0.0.1:8443",
                        "namespace": "tenant1",
                        "identity": "kubernetes-super-admin",
                        "identity_known_to_target": True,
                        "targets_tenant_workload_namespace": True,
                        "namespace_contents": [],
                    },
                },
            }
        )
    )
    (directory / "mtb-raw-admin.txt").write_text(SCORECARD)
    (directory / "mtb-raw-tenant.txt").write_text(SCORECARD)

    runs = mtb.load_runs(directory)
    assert set(runs) == {mtb.ADMIN_RUN, mtb.TENANT_RUN}
    assert runs[mtb.ADMIN_RUN].targeting_valid is False
    assert runs[mtb.ADMIN_RUN].namespace_contents == ["statefulset/vcluster-tenant1"]
    assert runs[mtb.TENANT_RUN].targeting_valid is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


def test_a_run_reports_groups_kubectl_mtb_cannot_express():
    """kubectl-mtb has only `--as`. There is no `--as-group`.

    Kubernetes impersonation carries a username, so a tenant whose permissions
    come from a group cannot be represented at all. Every kubeadm-style
    credential is like this — vcluster, Kamaji and KubeVirt all issue
    `O=system:masters, CN=kubernetes-super-admin`, where the O is the entire
    authority. kubectl-mtb can only say `--as kubernetes-super-admin`, a name
    with nothing bound to it, and reports the resulting "cannot create pods" as
    thirteen benchmark errors rather than as an inability to model the tenant.

    Recording both lists is what makes that visible. Without it the scorecard
    reads as a measurement of the cluster.
    """
    run = mtb.Run(
        name=mtb.ADMIN_RUN,
        identity="kubernetes-super-admin",
        identity_groups=["system:masters"],
        impersonation=["--as", "kubernetes-super-admin"],
    )
    assert run.unexpressible_groups == ["system:masters"]

    # A tenant whose authority is bound to the username loses nothing, which is
    # why capsule benchmarks cleanly and the limitation went unnoticed.
    capsule = mtb.Run(
        name=mtb.ADMIN_RUN,
        identity="tenant1-admin",
        identity_groups=[],
        impersonation=["--as", "tenant1-admin"],
    )
    assert capsule.unexpressible_groups == []


def test_a_label_matching_nothing_is_recorded_as_untested():
    """MTB-PL1-BC-CPI-2 iterates the resources its -l selector matches.

    An empty match means the loop body never runs and the benchmark returns
    success. A mistyped label therefore looks exactly like a solution that
    protects its admin-managed resources perfectly, and only the match count
    separates them once the cluster is gone.
    """
    tested = mtb.Run(
        name=mtb.ADMIN_RUN,
        multitenancy_label="capsule.clastix.io/tenant=tenant1",
        multitenancy_label_matches=3,
    )
    assert not tested.label_tested_nothing

    vacuous = mtb.Run(
        name=mtb.ADMIN_RUN,
        multitenancy_label="wrong.example.com/tenant=tenant1",
        multitenancy_label_matches=0,
    )
    assert vacuous.label_tested_nothing

    # No label at all is not a vacuous pass: the benchmark errors instead, which
    # is visible in the scorecard.
    assert not mtb.Run(name=mtb.ADMIN_RUN).label_tested_nothing


def test_a_one_tenant_run_silently_drops_the_cross_tenant_benchmarks():
    """kubectl-mtb's `shouldSkipTest` drops `namespaceRequired: 2` benchmarks.

    It does so before running them and without failing, so a one-tenant
    invocation shrinks the suite rather than reporting that it could not ask the
    question. Recording the namespaces makes the difference legible.
    """
    both = mtb.Run(name=mtb.ADMIN_RUN, namespace="tenant1,tenant2")
    assert both.benchmarked_two_tenants

    one = mtb.Run(name=mtb.ADMIN_RUN, namespace="tenant1")
    assert not one.benchmarked_two_tenants
