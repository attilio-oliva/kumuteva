#!/usr/bin/env bash
#
# Run the fairness campaign over a set of solutions, N repetitions each.
#
#   experiments/run-campaign.sh --reps 5 capsule capsule-proxy vcluster kubevirt
#   experiments/run-campaign.sh --reps 5 --volume emptydir capsule
#   experiments/run-campaign.sh --dry-run --reps 5 capsule
#
# This automates sections 4 and 5 of RUNBOOK.md: provision a cluster, pin it to
# the benchmark cores, run the fairness assessment N times, check each result,
# tear the cluster down, move to the next solution.
#
# Solutions run strictly one at a time. Two on one host would contend, and
# contention is the thing being measured.
#
# After every run the manifests are inspected and anything that would invalidate
# the result is reported immediately — a subsystem that produced no data, an
# intruder that never reached its configured load, a tenant that could not hold
# its rate. Finding those at the end of a six-hour campaign is too late.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KUMUTEVA_BIN=${KUMUTEVA_BIN:-"$REPO_ROOT/target/release/kumuteva"}
CONFIG=${CONFIG:-"$REPO_ROOT/experiments/campaign.yaml"}
KUBECONFIG_DIR=${KUBECONFIG_DIR:-"$HOME/kumuteva-kubeconfigs"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$HOME/kumuteva-runs"}
HOST_PREP_STATE=/var/lib/kumuteva-host-prep.state

REPS=5
VOLUME=pvc
CLUSTER_PREFIX=bench
BENCH_CPUS=${BENCH_CPUS:-}
EXTRA_ARGS=()
SOLUTIONS=()
DRY_RUN=false
KEEP_CLUSTER=false
SKIP_SETUP=false

# Solutions `kumuteva setup` can provision. KubeZoo is deliberately absent: the
# CLI rejects it, so it has to be brought up by hand.
SUPPORTED="capsule capsule-proxy vcluster kubevirt native kamaji"

usage() {
    cat <<'EOF'
Usage: run-campaign.sh [options] <solution> [solution...]

Options:
  -r, --reps N          Repetitions per solution (default 5; 5 is the minimum
                        for the confidence intervals the analysis computes)
  -o, --output DIR      Result root; one subdirectory per solution
                        (default ~/kumuteva-runs)
  -c, --config FILE     Campaign config (default experiments/campaign.yaml)
      --volume MODE     pvc | emptydir (default pvc). pvc measures the CSI
                        path, emptydir node-local disk. Report both.
      --cpus LIST       Cores to pin the cluster to. Derived from NUMA node 0,
                        one CPU per physical core, when not given.
      --prefix NAME     Cluster name prefix (default bench)
      --keep-cluster    Leave the cluster running after the last repetition
      --skip-setup      Use an existing cluster; do not create or pin one
      --dry-run         Print what would run, touch nothing
      --                Everything after this is passed to `kumuteva fairness`
  -h, --help

Examples:
  run-campaign.sh --reps 5 capsule capsule-proxy vcluster kubevirt
  run-campaign.sh --reps 3 --volume emptydir capsule
  run-campaign.sh --reps 5 capsule -- --wl-noise mixed
EOF
}

# --- logging ---------------------------------------------------------------

BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)

banner() { printf '\n%s=== %s ===%s\n' "$BOLD" "$1" "$RESET"; }
info()   { printf '  %s\n' "$1"; }
ok()     { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()   { printf '  %s⚠%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail()   { printf '  %s✗%s %s\n' "$RED" "$RESET" "$1"; }

run() {
    if [[ $DRY_RUN == true ]]; then
        printf '  [dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

# --- arguments -------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--reps)      REPS="$2"; shift 2 ;;
        -o|--output)    OUTPUT_ROOT="$2"; shift 2 ;;
        -c|--config)    CONFIG="$2"; shift 2 ;;
        --volume)       VOLUME="$2"; shift 2 ;;
        --cpus)         BENCH_CPUS="$2"; shift 2 ;;
        --prefix)       CLUSTER_PREFIX="$2"; shift 2 ;;
        --keep-cluster) KEEP_CLUSTER=true; shift ;;
        --skip-setup)   SKIP_SETUP=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)      usage; exit 0 ;;
        --)             shift; EXTRA_ARGS=("$@"); break ;;
        -*)             echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)              SOLUTIONS+=("$1"); shift ;;
    esac
done

if [[ ${#SOLUTIONS[@]} -eq 0 ]]; then
    echo "No solutions given." >&2
    usage >&2
    exit 2
fi

if [[ ! ${REPS} =~ ^[0-9]+$ ]] || [[ ${REPS} -lt 1 ]]; then
    echo "--reps must be a positive integer, got '${REPS}'" >&2
    exit 2
fi

case "$VOLUME" in
    pvc|emptydir) ;;
    *) echo "--volume must be pvc or emptydir, got '${VOLUME}'" >&2; exit 2 ;;
esac

# --- preflight -------------------------------------------------------------
# Everything checked here is something that silently ruins a campaign rather
# than stopping it: an unpinned cluster measures the whole machine, a drifting
# governor produces a degradation factor below 1.0, an uncommitted tree makes
# the recorded commit meaningless.

banner "Preflight"

preflight_failed=0

if [[ ! -x $KUMUTEVA_BIN ]]; then
    fail "kumuteva binary not found or not executable: $KUMUTEVA_BIN"
    info "build it with: cargo build --release"
    preflight_failed=1
else
    ok "binary: $KUMUTEVA_BIN"
fi

if [[ ! -f $CONFIG ]]; then
    fail "campaign config not found: $CONFIG"
    preflight_failed=1
else
    ok "config: $CONFIG"
fi

for tool in docker kind kubectl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool not on PATH"
        preflight_failed=1
    fi
done

# python3 is used only to read the manifests after each run. Without it the
# campaign still runs; it just cannot check itself.
CHECK_RESULTS=true
if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found — per-run result checking disabled"
    CHECK_RESULTS=false
fi

# The governor lock does not survive a reboot, so its absence is worth saying
# out loud every time rather than assuming a previous session applied it.
if [[ -f $HOST_PREP_STATE ]]; then
    ok "host prepared (state at $HOST_PREP_STATE)"
else
    warn "host-prep.sh has not been applied — CPU frequency may scale between"
    info "  the baseline and stress phases, which is what produced a degradation"
    info "  factor below 1.0 in the first submission. Run:"
    info "    sudo experiments/host-prep.sh | tee experiments/host-state-\$(date +%F).txt"
fi

if [[ -z $BENCH_CPUS ]]; then
    # One CPU per physical core on NUMA node 0: SMT siblings share execution
    # resources, so counting them as separate cores overstates the machine.
    BENCH_CPUS=$(lscpu --parse=CPU,NODE,CORE 2>/dev/null | grep -v '^#' \
        | awk -F, '$2 == 0 && !seen[$3]++ { print $1 }' | head -16 | paste -sd,)
fi

if [[ -z $BENCH_CPUS ]]; then
    warn "could not derive a core list; the cluster will not be pinned"
else
    ok "cores: $BENCH_CPUS ($(tr ',' '\n' <<<"$BENCH_CPUS" | grep -c .) CPUs)"
fi

if git -C "$REPO_ROOT" rev-parse --short HEAD >/dev/null 2>&1; then
    commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
    if [[ -n $(git -C "$REPO_ROOT" status --porcelain --untracked-files=no) ]]; then
        warn "working tree is dirty — manifests will record ${commit}-dirty,"
        info "  which does not identify the binary that produced the numbers."
        info "  Commit before the campaign if these results are for publication."
    else
        ok "commit: $commit (clean)"
    fi
fi

for solution in "${SOLUTIONS[@]}"; do
    if [[ " $SUPPORTED " != *" $solution "* ]]; then
        warn "'$solution' is not provisioned by \`kumuteva setup\`"
        info "  (KubeZoo in particular must be brought up by hand; use --skip-setup)"
    fi
done

[[ $preflight_failed -eq 1 ]] && { echo; echo "Preflight failed."; exit 1; }

# --- per-run result check --------------------------------------------------

# Read the manifests a run just wrote and report anything that invalidates it.
# The checks mirror the ones the tool prints, but across all four subsystems at
# once and after the fact, so a campaign left running unattended still surfaces
# its own failures.
check_run() {
    local out_dir="$1" since="$2"

    [[ $CHECK_RESULTS == true ]] || return 0
    [[ $DRY_RUN == true ]] && return 0

    python3 - "$out_dir" "$since" <<'PYTHON'
import glob, json, os, sys

out_dir, since = sys.argv[1], float(sys.argv[2])
problems, seen = [], []

for path in sorted(glob.glob(os.path.join(out_dir, "*_manifest_*.json"))):
    if os.path.getmtime(path) < since:
        continue
    try:
        m = json.load(open(path))
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(f"unreadable manifest {os.path.basename(path)}: {exc}")
        continue

    name = m.get("subsystem", "?")
    seen.append(name)

    delta = m.get("latency_degradation")
    if delta is None or delta != delta:
        problems.append(f"{name}: degradation is not a number — the run produced no usable data")

    # An intruder that never delivered its load did not apply the experiment's
    # stress, so the factor is not comparable with a run where it did.
    ratio = m.get("intruder_load_ratio")
    if ratio is not None and ratio == ratio and ratio < 0.90:
        problems.append(
            f"{name}: intruder delivered {ratio * 100:.0f}% of its configured load — "
            "the specified stress was never applied"
        )

    if m.get("owner_throttled"):
        retention = m.get("throughput_retention", float("nan"))
        problems.append(
            f"{name}: regular tenant held only {retention * 100:.0f}% of its rate — "
            "degradation is a lower bound"
        )

    # Near 1.0 the probe kept up. Far above, it spent the phase working through
    # its own backlog and its latency describes the probe, not the platform.
    for phase in ("baseline", "unbalanced"):
        co = m.get(phase, {}).get("tenant1", {}).get("coordinated_omission_factor")
        if co is not None and co > 2.0:
            problems.append(
                f"{name}: probe fell {co:.0f}x behind its schedule in the {phase} phase — "
                "it was saturated, so its latency is unreliable"
            )

expected = {"Control Plane", "Network", "Storage", "Workload"}
missing = sorted(expected - set(seen))
if missing:
    problems.append("no manifest written by: " + ", ".join(missing))

if problems:
    for p in problems:
        print(f"      ! {p}")
    sys.exit(1)
print(f"      all {len(seen)} subsystems reported, no warnings")
PYTHON
}

# --- campaign --------------------------------------------------------------

mkdir -p "$OUTPUT_ROOT"
campaign_started=$(date +%s)
declare -a SUMMARY=()

for solution in "${SOLUTIONS[@]}"; do
    cluster="${CLUSTER_PREFIX}-${solution}"
    out_dir="$OUTPUT_ROOT/$solution"
    t1="$KUBECONFIG_DIR/tenant1-${cluster}.kubeconfig"
    t2="$KUBECONFIG_DIR/tenant2-${cluster}.kubeconfig"

    banner "$solution"
    run mkdir -p "$out_dir" "$KUBECONFIG_DIR"

    # --- provision ---
    if [[ $SKIP_SETUP == true ]]; then
        info "reusing existing cluster $cluster"
    else
        info "creating cluster $cluster"
        if ! run "$KUMUTEVA_BIN" setup \
            --cluster-name "$cluster" \
            --type "$solution" \
            --provider kind \
            --output "$KUBECONFIG_DIR"; then
            fail "setup failed for $solution — skipping"
            SUMMARY+=("$solution: SETUP FAILED")
            continue
        fi

        # Only possible now: the containers did not exist before setup ran, and
        # each solution gets fresh ones, so this repeats every time.
        if [[ -n $BENCH_CPUS ]]; then
            for node in $(docker ps --format '{{.Names}}' | grep "^${cluster}" || true); do
                run docker update --cpuset-cpus "$BENCH_CPUS" "$node" >/dev/null
            done
            if [[ $DRY_RUN == false ]]; then
                unpinned=0
                for node in $(docker ps --format '{{.Names}}' | grep "^${cluster}" || true); do
                    actual=$(docker inspect --format '{{.HostConfig.CpusetCpus}}' "$node")
                    [[ -z $actual ]] && { fail "$node is UNPINNED"; unpinned=1; }
                done
                if [[ $unpinned -eq 1 ]]; then
                    fail "cluster not pinned — it would use the whole machine; skipping $solution"
                    SUMMARY+=("$solution: PIN FAILED")
                    continue
                fi
                ok "pinned to $BENCH_CPUS"
            fi
        fi
    fi

    # --- reachability ---
    if [[ $DRY_RUN == false ]]; then
        unreachable=0
        for kc in "$t1" "$t2"; do
            [[ -f $kc ]] || { fail "missing kubeconfig $kc"; unreachable=1; continue; }
            kubectl --kubeconfig "$kc" get --raw /readyz >/dev/null 2>&1 \
                || { fail "tenant API not reachable via $(basename "$kc")"; unreachable=1; }
        done
        if [[ $unreachable -eq 1 ]]; then
            SUMMARY+=("$solution: TENANTS UNREACHABLE")
            continue
        fi
        ok "both tenants reachable"
    fi

    # --- repetitions ---
    clean_runs=0
    flagged_runs=0
    for rep in $(seq 1 "$REPS"); do
        info "run $rep/$REPS"
        started=$(date +%s)
        log="$out_dir/run-$rep.log"

        if [[ $DRY_RUN == true ]]; then
            run "$KUMUTEVA_BIN" fairness "$t1" "$t2" \
                --config "$CONFIG" --solution-label "$solution" \
                --export-csv --output-dir "$out_dir" \
                --st-volume "$VOLUME" --verbose "${EXTRA_ARGS[@]}"
            continue
        fi

        if ! "$KUMUTEVA_BIN" fairness "$t1" "$t2" \
            --config "$CONFIG" \
            --solution-label "$solution" \
            --export-csv --output-dir "$out_dir" \
            --st-volume "$VOLUME" \
            --verbose "${EXTRA_ARGS[@]}" 2>&1 | tee "$log"; then
            fail "run $rep exited non-zero (log: $log)"
            flagged_runs=$((flagged_runs + 1))
            continue
        fi

        if check_run "$out_dir" "$started"; then
            clean_runs=$((clean_runs + 1))
        else
            flagged_runs=$((flagged_runs + 1))
        fi
    done

    if [[ $DRY_RUN == false ]]; then
        if [[ $flagged_runs -eq 0 ]]; then
            ok "$clean_runs/$REPS runs clean"
        else
            warn "$clean_runs/$REPS clean, $flagged_runs flagged — see above"
        fi
        SUMMARY+=("$solution: $clean_runs clean, $flagged_runs flagged -> $out_dir")
    fi

    # --- teardown ---
    if [[ $KEEP_CLUSTER == true ]]; then
        info "leaving $cluster running (--keep-cluster)"
    elif [[ $SKIP_SETUP == true ]]; then
        info "leaving $cluster running (created outside this script)"
    else
        info "deleting cluster $cluster"
        run kind delete cluster --name "$cluster" >/dev/null 2>&1
    fi
done

# --- summary ---------------------------------------------------------------

banner "Campaign summary"
elapsed=$(( $(date +%s) - campaign_started ))
printf '  %dh%02dm elapsed, volume=%s, reps=%s\n' \
    $((elapsed / 3600)) $(((elapsed % 3600) / 60)) "$VOLUME" "$REPS"
for line in "${SUMMARY[@]:-}"; do
    [[ -n $line ]] && info "$line"
done

cat <<EOF

  Next:
    rsync -av $OUTPUT_ROOT/ <analysis-host>:<repo>/new_fairness_results/raw/
    cd new_fairness_results && ../.venv/bin/python validate_analysis.py

  A flagged run is not automatically discarded — read the warning first. A
  throttled tenant is a real result; an intruder that never reached its load
  is not, and that run should be repeated after the cause is fixed.
EOF
