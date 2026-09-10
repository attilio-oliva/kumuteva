#!/usr/bin/env bash
#
# Assess isolation and autonomy across every solution, and build the results
# table from what comes back.
#
#   experiments/run-isolation-matrix.sh capsule capsule-hardened vcluster
#   experiments/run-isolation-matrix.sh --all
#   experiments/run-isolation-matrix.sh --dry-run capsule
#
# The isolation counterpart to run-fairness-campaign.sh, which measures fairness. Both
# provision a kind cluster per solution and tear it down afterwards; this one
# runs `kumuteva verify` rather than `kumuteva fairness`, and ends by rendering
# the table instead of leaving CSVs to be analysed later.
#
# Nothing here decides a verdict. Every number in the table comes from the
# `verify --output-json` reports, so the table cannot disagree with the runs it
# was built from — the failure mode where a figure is transcribed by hand and
# then diverges from the data.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KUMUTEVA_BIN=${KUMUTEVA_BIN:-"$REPO_ROOT/target/release/kumuteva"}
KUBECONFIG_DIR=${KUBECONFIG_DIR:-"$HOME/kumuteva-kubeconfigs"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$HOME/kumuteva-isolation"}
VENV_PY=${VENV_PY:-"$REPO_ROOT/.venv/bin/python"}

CLUSTER_PREFIX=bench
TENANT1_NS=tenant1
TENANT2_NS=tenant2

# Published on the host, so an unrelated cluster already holding these makes
# every solution fail at "Preparing nodes" with `port is already allocated`.
# Overridable for the same reason as in run-mtb.sh.
TENANT1_MAPPING=${TENANT1_MAPPING:-30010:30001}
TENANT2_MAPPING=${TENANT2_MAPPING:-30020:30002}

# Every solution the `setup` subcommand can provision. `native` is the control:
# two namespaces and no multi-tenancy layer at all, which is what the other
# rows are worth comparing against.
ALL_SOLUTIONS="native capsule capsule-hardened capsule-proxy vcluster kubevirt kamaji kubezoo"

# The data-plane rows, each on the `native` baseline so the effect measured is
# the technology's own. `native` leads, as the control: a technology that
# closes a property `native` also closes has not been shown to do anything.
ALL_DATA_PLANE="native native+network-policy native+kubeovn native+kubeovn-subnet native+kubeovn-vpc native+scoped-dns native+gvisor native+kata native+storage-classes"

SOLUTIONS=()
DRY_RUN=false
SKIP_SETUP=false
KEEP_CLUSTER=false

usage() {
    cat <<EOF
Usage: run-isolation-matrix.sh [options] <solution> [solution...]
       run-isolation-matrix.sh --all

A solution is a control-plane name, optionally with data-plane technologies
appended after '+':

  capsule                 the control-plane solution alone
  native+network-policy   the deny-all NetworkPolicy, on no control-plane
                          isolation at all
  capsule+network-policy  both, to see whether they compose

Data-plane technologies (compose with '+', and with each other):
  network-policy          the cross-tenant deny-all NetworkPolicy. Calico is
                          the host cluster's CNI in every run, so the policy is
                          enforced rather than merely written
  kubeovn                 Kube-OVN as the CNI, enforcing the same policy
  kubeovn-subnet          a private Subnet per tenant on the shared router
  kubeovn-vpc             a VPC per tenant: separate routers, no route between
  scoped-dns              a resolver per tenant, answering only for its own
                          namespace — CNI-agnostic, composes with anything
  gvisor                  gVisor sandbox, every probe running under it
  kata                    Kata Containers, each pod in its own VM
  storage-classes         a StorageClass per tenant with reclaimPolicy Retain

A row whose control plane is 'native' is assessed on the data plane only: the
control-plane pass would DELETE the node and destroy the cluster mid-run.

Options:
  -o, --output DIR    Result root, one subdirectory per solution
                      (default ~/kumuteva-isolation)
      --all           Every control-plane solution: $ALL_SOLUTIONS
      --all-data-plane
                      Every data-plane row on the 'native' baseline:
                      $ALL_DATA_PLANE
      --skip-setup    Use existing clusters; do not create or delete any
      --keep-cluster  Leave each cluster running after its assessment
      --dry-run       Print what would run, touch nothing
  -h, --help

Environment:
  TENANT1_MAPPING   NodePort mapping, container:host (default 30010:30001)
  TENANT2_MAPPING   NodePort mapping, container:host (default 30020:30002)

Produces, per solution:
  <solution>/verify.json      the machine-readable report
  <solution>/verify-raw.txt   the printed assessment, verbatim
And once, at the end:
  isolation_matrix.md         the table, for reading
  isolation_matrix.csv        the same table as data, for the paper's template
EOF
}

BOLD=$(tput bold 2>/dev/null || true); RESET=$(tput sgr0 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true); YELLOW=$(tput setaf 3 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)

banner() { printf '\n%s=== %s ===%s\n' "$BOLD" "$1" "$RESET"; }
info()   { printf '  %s\n' "$1"; }
ok()     { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()   { printf '  %s⚠%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail()   { printf '  %s✗%s %s\n' "$RED" "$RESET" "$1"; }

run() {
    if [[ $DRY_RUN == true ]]; then printf '  [dry-run] %s\n' "$*"; return 0; fi
    "$@"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)    OUTPUT_ROOT="$2"; shift 2 ;;
        --all)          read -r -a SOLUTIONS <<< "$ALL_SOLUTIONS"; shift ;;
        --all-data-plane) read -r -a SOLUTIONS <<< "$ALL_DATA_PLANE"; shift ;;
        --skip-setup)   SKIP_SETUP=true; shift ;;
        --keep-cluster) KEEP_CLUSTER=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)      usage; exit 0 ;;
        -*)             echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)              SOLUTIONS+=("$1"); shift ;;
    esac
done

[[ ${#SOLUTIONS[@]} -eq 0 ]] && { echo "No solutions given." >&2; usage >&2; exit 2; }

# --- preflight --------------------------------------------------------------

banner "Preflight"
preflight_failed=0

if [[ -x $KUMUTEVA_BIN ]]; then
    ok "binary: $KUMUTEVA_BIN"
else
    fail "kumuteva binary not found: $KUMUTEVA_BIN (cargo build --release)"
    preflight_failed=1
fi

# The binary is what runs, not the source. `cargo test` does not rebuild it, so
# it is easy to measure a fix that was never compiled — which happened, and cost
# a full campaign before the timestamps gave it away.
newest_source=$(find "$REPO_ROOT/src" -name '*.rs' -newer "$KUMUTEVA_BIN" -print -quit 2>/dev/null)
if [[ -n $newest_source ]]; then
    fail "$KUMUTEVA_BIN is older than $newest_source"
    fail "  run: cargo build --release"
    preflight_failed=1
fi

# Kube-OVN's datapath is the openvswitch kernel module, and a container cannot
# load one under a rootless runtime — even `--privileged`, because the container
# sits in a user namespace:
#
#     modprobe: ERROR: could not insert 'openvswitch': Operation not permitted
#
# The helm install then sits for its full timeout while ovs-ovn, kube-ovn-cni
# and kube-ovn-pinger never become available, which costs ten minutes to learn
# something checkable in one second.
# Note on the idiom below: these capture into a variable rather than using
# `grep -q` in a pipeline. Under `set -o pipefail`, `grep -q` exits on its first
# match, the producer takes SIGPIPE, and the pipeline reports failure — so a
# successful match reads as "not found". It silently inverted the openvswitch
# check.
if [[ -n $(printf '%s\n' "${SOLUTIONS[@]}" | grep kubeovn) ]]; then
    if [[ -n $(lsmod 2>/dev/null | grep '^openvswitch') ]]; then
        ok "openvswitch module loaded"
    elif [[ -n $(docker info 2>/dev/null | grep -i rootless) ]]; then
        # Only fatal on a rootless runtime. Given a rootful daemon, ovs-ovn is
        # privileged in the initial user namespace and loads the module itself.
        fail "Kube-OVN needs the openvswitch kernel module, which is not loaded"
        fail "  and a container cannot load it under a rootless runtime. Either"
        fail "  use the rootful daemon:"
        fail "      DOCKER_HOST=unix:///var/run/docker.sock $0 ..."
        fail "  or load it on the host once:  sudo modprobe openvswitch geneve"
        preflight_failed=1
    else
        warn "openvswitch not loaded; ovs-ovn should load it itself on a rootful runtime"
    fi
fi

for tool in kubectl kind; do
    command -v "$tool" >/dev/null 2>&1 || { fail "$tool not on PATH"; preflight_failed=1; }
done

if [[ -x $VENV_PY ]]; then
    ok "python: $VENV_PY"
else
    warn "no venv at $VENV_PY — the runs will happen but the table will not render"
fi

# The workload subsystem loads a kernel module to prove a shared kernel. Under a
# rootless container runtime the pod's CAP_SYS_MODULE is scoped to a user
# namespace, `insmod` returns EPERM, and every solution reports the same Soft
# verdict for privileged syscalls — measuring the runtime rather than the
# solution. Worth knowing before reading that column, not after.
if [[ -n $(docker info 2>/dev/null | grep -i rootless) ]]; then
    warn "rootless container runtime detected"
    warn "  the privileged-syscall probe cannot load a kernel module here, so"
    warn "  that column will read Soft for every solution regardless of merit."
    warn "  This host also runs a rootful daemon, and you are in the docker"
    warn "  group — so no sudo and no code change is needed, just:"
    warn "      DOCKER_HOST=unix:///var/run/docker.sock $0 ..."
fi

[[ $preflight_failed -eq 1 ]] && exit 1

run mkdir -p "$OUTPUT_ROOT"

# --- per solution -----------------------------------------------------------

declare -a SUMMARY=()

for solution in "${SOLUTIONS[@]}"; do
    # A solution name is `<control-plane>[+<data-plane>[+...]]`, matching the
    # label `kumuteva setup` records — so `native+network-policy` is one row, its
    # directory, and its `--data-plane` arguments, all named the same thing.
    control_plane="${solution%%+*}"
    data_plane_args=()
    if [[ $solution == *+* ]]; then
        # Commas rather than repeated flags: `--data-plane` takes a list.
        data_plane_args=(--data-plane "$(printf '%s' "${solution#*+}" | tr '+' ',')")
    fi

    cluster="${CLUSTER_PREFIX}-${solution//+/-}"
    out_dir="$OUTPUT_ROOT/$solution"
    t1="$KUBECONFIG_DIR/tenant1-${cluster}.kubeconfig"
    t2="$KUBECONFIG_DIR/tenant2-${cluster}.kubeconfig"

    banner "$solution"
    run mkdir -p "$out_dir"

    # `native` gives the tenant the host admin kubeconfig, which is the point of
    # it as a control — and it means the control-plane autonomy pass, which
    # attempts DELETE on every resource including Node, succeeds. Deleting the
    # only node is silent: the API server stays up and every later probe sits
    # Pending forever with `no nodes available to schedule pods`, so the run
    # spends its time measuring a cluster it has already destroyed.
    # `native` gives the tenant the host admin kubeconfig — the point of it as a
    # control — so the control-plane autonomy pass, which attempts DELETE on
    # every resource including Node, succeeds. Deleting the only node is
    # silent: the API server stays up and every later probe sits Pending with
    # `no nodes available to schedule pods`, so the run spends its time
    # measuring a cluster it has already destroyed.
    #
    # Data-plane rows are built on `native` precisely so the effect measured is
    # the technology's own, so this is the common case rather than an edge one.
    subsystem_args=()
    if [[ $control_plane == native ]]; then
        warn "'native' grants the tenant cluster-admin: assessing the data plane only,"
        warn "  because the control-plane pass would DELETE the node mid-run."
        subsystem_args=(--storage --network --workload)
    fi

    if [[ $SKIP_SETUP == false ]]; then
        info "creating cluster $cluster (nodeports $TENANT1_MAPPING, $TENANT2_MAPPING)"
        [[ ${#data_plane_args[@]} -gt 0 ]] && info "  data plane: ${data_plane_args[1]}"
        if ! run "$KUMUTEVA_BIN" setup --cluster-name "$cluster" --type "$control_plane" \
            "${data_plane_args[@]}" \
            --provider kind --output "$KUBECONFIG_DIR" \
            --tenant1-mapping "$TENANT1_MAPPING" \
            --tenant2-mapping "$TENANT2_MAPPING"; then
            fail "setup failed"
            info "  if this says 'port is already allocated', another cluster holds"
            info "  the NodePorts. Move this campaign rather than tearing that down:"
            info "      TENANT1_MAPPING=30010:30003 TENANT2_MAPPING=30020:30004 $0 ..."
            # A failed setup can still leave a cluster behind, and it would hold
            # the ports for every solution after this one.
            if [[ -n $(kind get clusters 2>/dev/null | grep -x "$cluster") ]]; then
                info "  removing the partially created cluster"
                kind delete cluster --name "$cluster" >/dev/null 2>&1
            fi
            SUMMARY+=("$solution: SETUP FAILED")
            continue
        fi
    fi

    # A tenant with its own resolver only benefits if its pods actually ask it,
    # and nothing injects the address automatically. The intruder is the one
    # doing the resolving, so it is tenant2's resolver that matters.
    verify_dns_args=()
    if [[ $solution == *scoped-dns* ]]; then
        dns_ip=$(kubectl --kubeconfig "$KUBECONFIG_DIR/${cluster}.kubeconfig" \
            -n "$TENANT2_NS" get svc tenant-dns -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
        if [[ -n $dns_ip ]]; then
            verify_dns_args=(--dns-nameserver "$dns_ip")
            info "  probes resolve via the tenant's own DNS at $dns_ip"
        else
            warn "  scoped-dns selected but tenant2 has no tenant-dns Service"
        fi
    fi

    # A RuntimeClass is opt-in per pod, so the probes have to name it. Nothing
    # injects it for them.
    verify_runtime_args=()
    sandbox=""
    [[ $solution == *gvisor* ]] && sandbox=gvisor
    [[ $solution == *kata* ]] && sandbox=kata

    if [[ -n $sandbox ]]; then
        verify_runtime_args=(--runtime-class "$sandbox")
    fi

    if [[ -n $sandbox && $DRY_RUN == false ]]; then
        # Prove the sandbox is real before measuring anything under it. A
        # RuntimeClass naming a handler containerd cannot run leaves pods in
        # ContainerCreating; one that silently fell back to runc reports exactly
        # the isolation the sandbox was supposed to provide, with no sandbox.
        #
        # The test is the pod's kernel against the node's, rather than a string
        # only one vendor prints: gVisor answers with its user-space kernel and
        # Kata with its guest kernel, while runc answers with the node's own —
        # which is the fallback this exists to catch. It must also *look* like a
        # kernel release: kubectl prints its own diagnostics to the same stream,
        # so a pod that never started yields something like `error: timed out`,
        # which an inequality test alone would accept as proof of a sandbox.
        info "  verifying the sandbox is real"
        node_kernel=$(kubectl --kubeconfig "$t2" get node \
            -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}' 2>/dev/null)
        pod_kernel=$(kubectl --kubeconfig "$t2" -n "$TENANT2_NS" run sandbox-check \
            --image=alpine --restart=Never \
            --overrides="{\"spec\":{\"runtimeClassName\":\"$sandbox\"}}" \
            --attach --rm --quiet --command -- uname -r 2>&1 | head -1 | tr -d '\r')
        kubectl --kubeconfig "$t2" -n "$TENANT2_NS" delete pod sandbox-check --ignore-not-found >/dev/null 2>&1

        if [[ -n $node_kernel && $pod_kernel =~ ^[0-9]+\.[0-9]+ && $pod_kernel != "$node_kernel" ]]; then
            ok "  sandbox confirmed: pod kernel $pod_kernel, node kernel $node_kernel"
        else
            fail "  RuntimeClass $sandbox did not produce a kernel of its own"
            fail "  pod kernel: ${pod_kernel:-<none>} / node kernel: ${node_kernel:-<none>}"
            fail "  refusing to measure — a fallback to runc would read as sandbox isolation"
            SUMMARY+=("$solution: SANDBOX NOT ACTIVE")
            [[ $SKIP_SETUP == false && $KEEP_CLUSTER == false ]] && \
                kind delete cluster --name "$cluster" >/dev/null 2>&1
            continue
        fi
    fi

    info "assessing isolation and autonomy"
    # The redirect is inside the dry-run guard rather than on the `run` call:
    # the shell applies a redirect before the command runs, so on a dry run it
    # would try to write into a directory that was never created.
    if [[ $DRY_RUN == true ]]; then
        info "[dry-run] $KUMUTEVA_BIN verify $t1 $t2 --solution-label $solution" \
             "--output-json $out_dir/verify.json > $out_dir/verify-raw.txt"
        SUMMARY+=("$solution: dry-run")
    elif "$KUMUTEVA_BIN" verify "$t1" "$t2" \
        --tenant1-ns "$TENANT1_NS" --tenant2-ns "$TENANT2_NS" \
        --solution-label "$solution" \
        "${subsystem_args[@]}" "${verify_runtime_args[@]}" "${verify_dns_args[@]}" \
        --output-json "$out_dir/verify.json" > "$out_dir/verify-raw.txt" 2>&1; then
        ok "verify.json written"
        SUMMARY+=("$solution: ok")
    else
        # Recorded rather than fatal: one solution failing should not cost the
        # rest of the matrix, and the raw output says why.
        fail "verify exited non-zero — see $out_dir/verify-raw.txt"
        SUMMARY+=("$solution: VERIFY FAILED")
    fi

    if [[ $SKIP_SETUP == false && $KEEP_CLUSTER == false ]]; then
        info "deleting cluster $cluster"
        run kind delete cluster --name "$cluster" >/dev/null 2>&1
    fi
done

# --- the table --------------------------------------------------------------

banner "Results"

if [[ $DRY_RUN == true ]]; then
    info "[dry-run] would render $OUTPUT_ROOT/isolation_matrix.{md,tex} and dataplane_matrix.{md,tex}"
elif [[ -x $VENV_PY ]]; then
    "$VENV_PY" "$REPO_ROOT/new_fairness_results/build_isolation_table.py" "$OUTPUT_ROOT"
    # The property-level table as well. The subsystem summary answers "is this
    # solution isolated"; this one answers "which properties does it close",
    # which is the question a data-plane technology has to answer and a
    # subsystem verdict hides.
    "$VENV_PY" "$REPO_ROOT/new_fairness_results/build_dataplane_table.py" "$OUTPUT_ROOT" || true
else
    warn "no venv; render later with:"
    warn "  .venv/bin/python new_fairness_results/build_isolation_table.py $OUTPUT_ROOT"
    warn "  .venv/bin/python new_fairness_results/build_dataplane_table.py $OUTPUT_ROOT"
fi

banner "Summary"
for line in "${SUMMARY[@]}"; do info "$line"; done
info ""
info "reports:  $OUTPUT_ROOT/<solution>/verify.json"
info "table:    $OUTPUT_ROOT/isolation_matrix.md"
info "csv:      $OUTPUT_ROOT/isolation_matrix.csv"
