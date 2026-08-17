#!/usr/bin/env bash
#
# Run kubectl-mtb against a set of solutions and record the results beside a
# KUMUTEVA assessment of the same clusters.
#
#   experiments/run-mtb.sh capsule capsule-proxy vcluster kubevirt
#   experiments/run-mtb.sh --dry-run capsule
#   experiments/run-mtb.sh --skip-setup kubezoo        # provisioned by hand
#
# Standalone by design. It neither requires nor triggers a fairness run: which
# of the two to run, and in what order, is the operator's decision.
#
# What this is for: a reviewer asked for a comparison against kubectl-mtb. The
# interesting question is not which tool scores better but what each can
# express. kubectl-mtb's unit of tenancy is a namespace plus an RBAC identity
# inside one cluster. Three of the solutions under study — vcluster, KubeVirt,
# Kamaji — give each tenant its own API server, so there is no such namespace to
# point it at. That is a structural coverage gap rather than a score, and this
# script is built to record it as evidence rather than assert it: for those
# solutions it looks for the namespace, fails to find it, and says so in the
# manifest.
#
# The comparison baseline is unmaintained. kubectl-mtb lives in an archived
# repository whose master branch last moved in December 2021, so the commit is
# pinned below. That is a fact for the paper, not a reason to skip the work.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Pinned: kubernetes-retired/multi-tenancy@master, 2021-12-20. Must match
# `catalogue_commit` in new_fairness_results/mtb_mapping.yaml, or the mapping
# describes benchmarks other than the ones being run.
MTB_COMMIT=${MTB_COMMIT:-44dad58150a1ccd3d8f22b05b4b7489984700d4d}
MTB_REPO=${MTB_REPO:-https://github.com/kubernetes-retired/multi-tenancy.git}

KUMUTEVA_BIN=${KUMUTEVA_BIN:-"$REPO_ROOT/target/release/kumuteva"}
KUBECONFIG_DIR=${KUBECONFIG_DIR:-"$HOME/kumuteva-kubeconfigs"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$HOME/kumuteva-mtb"}
BUILD_DIR=${BUILD_DIR:-"$HOME/.cache/kumuteva/kubectl-mtb"}

CLUSTER_PREFIX=bench
TENANT_NS=tenant1
TENANT2_NS=${TENANT2_NS:-tenant2}

# Label identifying resources the *administrator* placed in a tenant namespace
# for multi-tenancy — role bindings, network policies, quotas — which the tenant
# must not be able to modify. MTB-PL1-BC-CPI-2 refuses to run without it and
# errors out in PreRun.
#
# Necessarily per-solution, because each operator marks its own objects. There
# is no portable answer, so an unknown solution gets no label and the benchmark
# reports an honest error rather than a fabricated pass.
#
# Capsule's value is `projectcapsule.dev/managed-by=controller`, taken from a
# live tenant namespace rather than from the documentation. The documented
# `capsule.clastix.io/tenant=<name>` is a *namespace* label; the RoleBindings,
# ResourceQuotas and LimitRanges the controller creates inside the namespace do
# not carry it, so it selects nothing. That is worth stating because it selected
# nothing *quietly*: the benchmark iterates whatever the label matches, so an
# empty match tested no resources and still reported a pass.
#
# `managed-by=controller` says what the benchmark actually means — created by
# the operator, not by the tenant — and unlike the equivalent
# `capsule.clastix.io/managed-by=<tenant>` it does not embed the tenant's name.
multitenancy_label() {
    case "$1" in
        capsule|capsule-hardened|capsule-proxy)
            echo "projectcapsule.dev/managed-by=controller"
            ;;
        *) echo "" ;;
    esac
}

# How many objects the label actually selects.
#
# Worth counting rather than assuming. The benchmark lists the labelled
# resources and tries to modify each one; if the selector matches nothing the
# loop body never executes and the benchmark returns success. A wrong label is
# therefore indistinguishable from a solution that protects its resources
# perfectly, and it is the same silent-pass shape as a quota that turns away
# every pod.
count_labelled_resources() {
    local kubeconfig="$1" namespace="$2" label="$3"
    [[ -n $label ]] || { echo 0; return; }
    KUBECONFIG="$kubeconfig" kubectl get rolebindings,networkpolicies,resourcequotas,limitranges \
        -n "$namespace" -l "$label" --no-headers 2>/dev/null | grep -c . || true
}

# NodePort mappings passed through to `setup`, in its container:host form.
#
# Overridable because they are the campaign's most common hard failure and the
# least interesting one: kind publishes these on the host, so any other cluster
# already holding 30001 or 30002 makes every solution fail at "Preparing nodes"
# with `port is already allocated`. That reads like a broken testbed rather than
# a port clash. Moving the campaign out of the way beats tearing down whatever
# else the machine is running.
TENANT1_MAPPING=${TENANT1_MAPPING:-30010:30001}
TENANT2_MAPPING=${TENANT2_MAPPING:-30020:30002}

EXTRA_ARGS=()
SOLUTIONS=()
DRY_RUN=false
SKIP_SETUP=false
SKIP_VERIFY=false

usage() {
    cat <<'EOF'
Usage: run-mtb.sh [options] <solution> [solution...]

Options:
  -o, --output DIR    Result root, one subdirectory per solution
                      (default ~/kumuteva-mtb)
      --namespace NS  Tenant namespace to target (default tenant1)
      --prefix NAME   Cluster name prefix (default bench)
      --skip-setup    Use an existing cluster; do not create one
      --skip-verify   Do not run `kumuteva verify` alongside kubectl-mtb
      --dry-run       Print what would run, touch nothing
      --              Everything after this is passed to kubectl-mtb
  -h, --help

Environment:
  TENANT1_MAPPING   NodePort mapping, container:host (default 30010:30001)
  TENANT2_MAPPING   NodePort mapping, container:host (default 30020:30002)
                    Change these when another cluster on the host already holds
                    the default host ports; kind fails cluster creation
                    outright with "port is already allocated".

Produces, per solution:
  mtb-raw.txt        kubectl-mtb output verbatim (the scorecard is parsed from this)
  verify.json        the matching KUMUTEVA assessment
  manifest.json      provenance: pinned commit, namespace, identity, applicability
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
        -o|--output)   OUTPUT_ROOT="$2"; shift 2 ;;
        --namespace)   TENANT_NS="$2"; shift 2 ;;
        --prefix)      CLUSTER_PREFIX="$2"; shift 2 ;;
        --skip-setup)  SKIP_SETUP=true; shift ;;
        --skip-verify) SKIP_VERIFY=true; shift ;;
        --dry-run)     DRY_RUN=true; shift ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; EXTRA_ARGS=("$@"); break ;;
        -*)            echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)             SOLUTIONS+=("$1"); shift ;;
    esac
done

[[ ${#SOLUTIONS[@]} -eq 0 ]] && { echo "No solutions given." >&2; usage >&2; exit 2; }

# --- preflight -------------------------------------------------------------

banner "Preflight"
preflight_failed=0

if [[ ! -x $KUMUTEVA_BIN ]]; then
    if [[ $SKIP_VERIFY == true ]]; then
        warn "kumuteva binary missing, but --skip-verify was given"
    else
        fail "kumuteva binary not found: $KUMUTEVA_BIN (cargo build --release)"
        preflight_failed=1
    fi
else
    ok "binary: $KUMUTEVA_BIN"
fi

for tool in kubectl git openssl; do
    command -v "$tool" >/dev/null 2>&1 || { fail "$tool not on PATH"; preflight_failed=1; }
done

# kubectl-mtb has no release binary; it has to be built. Failing loudly beats
# skipping silently and producing an empty comparison.
MTB_BIN="$BUILD_DIR/kubectl-mtb"
if [[ -x $MTB_BIN ]]; then
    ok "kubectl-mtb: $MTB_BIN"
elif [[ $DRY_RUN == true ]]; then
    info "[dry-run] would build kubectl-mtb at $MTB_COMMIT into $BUILD_DIR"
else
    if ! command -v go >/dev/null 2>&1; then
        fail "go is required to build kubectl-mtb — upstream ships no release binary"
        info "  install Go, then re-run; or set MTB_BIN to a prebuilt binary"
        preflight_failed=1
    else
        info "building kubectl-mtb at ${MTB_COMMIT:0:12} (one time)"
        mkdir -p "$(dirname "$BUILD_DIR")"
        if [[ ! -d $BUILD_DIR/src ]]; then
            git clone --quiet "$MTB_REPO" "$BUILD_DIR/src" || preflight_failed=1
        fi
        # `go generate` is not optional. Two generators run: bundle/box embeds
        # the benchmarks' config.yaml as static assets, and bundle/importer
        # writes the file that imports every benchmark package so their init()
        # functions register them. Neither generated file is committed. Skip the
        # step and the binary still compiles and still runs — it just has an
        # empty registry and reports "Running 0 of 0", which looks like a
        # completed run with nothing to report rather than a broken build.
        (
            cd "$BUILD_DIR/src" &&
            git checkout --quiet "$MTB_COMMIT" &&
            cd benchmarks/kubectl-mtb &&
            GOPROXY=https://proxy.golang.org,direct go generate ./... &&
            GOPROXY=https://proxy.golang.org,direct \
                go build -o "$MTB_BIN" ./cmd/kubectl-mtb/main.go
        ) || { fail "kubectl-mtb build failed"; preflight_failed=1; }
        [[ -x $MTB_BIN ]] && ok "built $MTB_BIN"
    fi
fi

# A binary with an empty benchmark registry produces empty results, and empty
# results are indistinguishable from "no benchmark applied to this solution" —
# which is the genuine finding for the cluster-per-tenant architectures. Confirm
# the tool knows its benchmarks before letting it near a campaign.
if [[ -x $MTB_BIN && $DRY_RUN == false ]]; then
    registered=$("$MTB_BIN" get benchmarks 2>/dev/null | grep -cE 'MTB-PL[0-9]+-')
    if [[ ${registered:-0} -lt 1 ]]; then
        fail "the kubectl-mtb binary registers no benchmarks"
        info "  its registry is empty, so every run would report 'Running 0 of 0'."
        info "  This means \`go generate\` did not run before the build. Remove"
        info "  $BUILD_DIR and re-run to rebuild from scratch."
        preflight_failed=1
    else
        ok "kubectl-mtb registers $registered benchmarks"
    fi
fi

[[ $preflight_failed -eq 1 ]] && { echo; echo "Preflight failed."; exit 1; }

# --- identity resolution ---------------------------------------------------

# kubectl-mtb impersonates a user with `--as`. KUMUTEVA hands out kubeconfigs.
# The identity is read out of the kubeconfig rather than assumed from a naming
# convention, so this keeps working if a provisioner changes what it issues.
# The client certificate's subject line, however the kubeconfig carries it.
#
# Two forms are in play here and both are used by solutions under test:
# vcluster embeds the certificate as base64 `client-certificate-data`, while the
# capsule provisioner writes `client-certificate: tenant1-admin-tenant1.crt`, a
# path resolved relative to the kubeconfig's own directory. Handling only the
# embedded form silently yields an empty subject for capsule, and every field
# derived from it — username, groups — quietly falls back or comes out blank.
cert_subject() {
    local kubeconfig="$1"
    [[ -f $kubeconfig ]] || return 1

    local data
    data=$(kubectl --kubeconfig "$kubeconfig" config view --raw \
        -o jsonpath='{.users[0].user.client-certificate-data}' 2>/dev/null)
    if [[ -n $data ]]; then
        echo "$data" | base64 -d 2>/dev/null | openssl x509 -noout -subject 2>/dev/null
        return 0
    fi

    local path
    path=$(kubectl --kubeconfig "$kubeconfig" config view --raw \
        -o jsonpath='{.users[0].user.client-certificate}' 2>/dev/null)
    [[ -n $path ]] || return 0
    # Relative paths are relative to the kubeconfig, not to $PWD.
    [[ $path == /* ]] || path="$(dirname "$kubeconfig")/$path"
    [[ -f $path ]] || return 0
    openssl x509 -in "$path" -noout -subject 2>/dev/null
}

resolve_identity() {
    local kubeconfig="$1"
    [[ -f $kubeconfig ]] || return 1

    # The certificate's CN is the username the API server sees. That is the
    # authoritative answer, not the kubeconfig's own user label, which is
    # arbitrary.
    local cn
    cn=$(cert_subject "$kubeconfig" \
        | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p' | head -1 | xargs)
    [[ -n $cn ]] && { echo "$cn"; return 0; }

    # No client certificate (token auth, or an exec plugin). Fall back to the
    # kubeconfig's declared user name.
    kubectl --kubeconfig "$kubeconfig" config view --raw \
        -o jsonpath='{.users[0].name}' 2>/dev/null
}

# The groups the tenant's certificate carries, one per line.
#
# This is not a refinement, it is a correctness requirement. Kubernetes
# impersonation carries the *username* only: `--as X` grants X's name and no
# groups whatsoever, even when X's real credential derives all of its authority
# from a group membership. A vcluster admin certificate is
# `CN=kubernetes-super-admin, O=system:masters` — every permission it has comes
# from the O, so impersonating the CN alone produces an identity that can do
# nothing at all.
#
# The first run of this script did exactly that, and the symptom is diagnostic:
# the admin run and the tenant run returned byte-identical scorecards
# (3 Passed | 2 Failed | 13 Errors) from two different API servers. Two clusters
# cannot agree that precisely unless neither was really being measured. What was
# measured was a nameless identity with no group.
#
# Capsule hid the bug: it binds its Tenant CR to the *user* tenant1-admin, so
# the CN alone was enough there and the run looked healthy.
resolve_groups() {
    local kubeconfig="$1"
    [[ -f $kubeconfig ]] || return 0

    # A subject may carry several O= fields; all of them are groups.
    # `openssl x509 -subject` prints `subject=O=system:masters, CN=admin`.
    # Stripping the `subject=` prefix is not cosmetic: without it the first
    # field reads `subject=O=system:masters`, the `^ *O *=` anchor misses, and
    # the function reports no groups on exactly the certificate whose only
    # authority is a group. It did, and the run looked fine.
    cert_subject "$kubeconfig" \
        | sed 's/^subject=//' \
        | sed 's![,/]!\n!g' \
        | sed -n 's/^ *O *= *\(.*\)$/\1/p' \
        | sed 's/ *$//' \
        | grep -v '^$' || true
}

# The UID a given kubeconfig sees for a namespace.
#
# Used to decide whether two kubeconfigs reach the same control plane, which the
# server URL cannot answer. capsule-proxy publishes its own NodePort and its own
# serving certificate, so the tenant's URL differs from the administrator's
# while both are ultimately served by one API server holding one etcd. Comparing
# URLs there reports a separate control plane and marks the admin run as not
# targeting the tenant's real namespace — the same verdict vcluster earns for
# genuinely having its own API server, which is precisely the distinction this
# comparison exists to draw.
#
# A namespace UID settles it. It is assigned once by the API server that owns
# the object, so the same value from both vantage points means one control
# plane, and different values mean two. Reading one's own namespace is
# something every tenant can do, unlike listing cluster-scoped objects.
namespace_uid() {
    local kubeconfig="$1" namespace="$2"
    [[ -f $kubeconfig ]] || return 0
    KUBECONFIG="$kubeconfig" kubectl get namespace "$namespace" \
        -o jsonpath='{.metadata.uid}' 2>/dev/null
}

# Which API server a kubeconfig actually talks to. Comparing this between the
# admin and tenant kubeconfigs is what tells the two tenancy models apart, and
# it is evidence rather than a hardcoded list of solution names: if the tenant's
# credential reaches a different server, the tenant is not a namespace in the
# admin's cluster, whatever the solution is called.
resolve_server() {
    local kubeconfig="$1"
    [[ -f $kubeconfig ]] || return 1
    kubectl --kubeconfig "$kubeconfig" config view --raw \
        -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null
}

# Does this API server know this identity at all?
#
# kubectl-mtb's own PreRun validation asks almost exactly this, which is why the
# recorded vcluster run produced thirteen "User cannot create pods" errors: the
# identity came from the tenant's virtual cluster and was impersonated against
# the host, which has never heard of it. Recording the answer separates "the
# tenant is genuinely restricted" from "we aimed the tool at the wrong cluster",
# two situations that produce an identical-looking scorecard.
# Takes the same impersonation flags the kubectl-mtb run will use, so the answer
# describes the run that actually happens rather than a different one.
identity_known() {
    local kubeconfig="$1" namespace="$2"
    shift 2
    local answer
    answer=$(KUBECONFIG="$kubeconfig" kubectl auth can-i create pods \
        -n "$namespace" "$@" 2>/dev/null)
    [[ $answer == yes ]]
}

# What is actually in the namespace about to be benchmarked.
#
# This is the evidence for the central finding. `setup` creates a namespace
# named tenant1 in the host cluster for vcluster too — but it holds vcluster's
# own syncer StatefulSet, not the tenant's workloads. A name match is not a
# tenancy match, and the only way to show that is to list what is inside.
namespace_contents() {
    local kubeconfig="$1" namespace="$2"
    KUBECONFIG="$kubeconfig" kubectl get pods,statefulsets -n "$namespace" \
        -o name 2>/dev/null | paste -sd',' || true
}

json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))'; }

# --- campaign --------------------------------------------------------------

mkdir -p "$OUTPUT_ROOT"
declare -a SUMMARY=()

for solution in "${SOLUTIONS[@]}"; do
    cluster="${CLUSTER_PREFIX}-${solution}"
    out_dir="$OUTPUT_ROOT/$solution"
    host_kubeconfig="$KUBECONFIG_DIR/${cluster}.kubeconfig"
    t1="$KUBECONFIG_DIR/tenant1-${cluster}.kubeconfig"
    t2="$KUBECONFIG_DIR/tenant2-${cluster}.kubeconfig"

    banner "$solution"
    run mkdir -p "$out_dir"

    if [[ $SKIP_SETUP == false ]]; then
        info "creating cluster $cluster (nodeports $TENANT1_MAPPING, $TENANT2_MAPPING)"
        if ! run "$KUMUTEVA_BIN" setup --cluster-name "$cluster" --type "$solution" \
            --provider kind --output "$KUBECONFIG_DIR" \
            --tenant1-mapping "$TENANT1_MAPPING" \
            --tenant2-mapping "$TENANT2_MAPPING"; then
            fail "setup failed"
            info "  if this says 'port is already allocated', another cluster on"
            info "  this host holds the NodePorts. Move the campaign rather than"
            info "  tearing that down:"
            info "      TENANT1_MAPPING=30010:30003 TENANT2_MAPPING=30020:30004 $0 ..."
            # Tear down whatever was created before the failure. `setup` can
            # fail well after kind has brought the cluster up — a missing helm
            # chart, for instance — and the half-built cluster keeps holding the
            # published NodePorts. Left behind, it makes every *later* solution
            # in the campaign fail with "port is already allocated", so one
            # broken solution silently invalidates the rest of the run.
            if kind get clusters 2>/dev/null | grep -qx "$cluster"; then
                info "removing the partially created cluster $cluster"
                kind delete cluster --name "$cluster" >/dev/null 2>&1
            fi
            SUMMARY+=("$solution: SETUP FAILED")
            continue
        fi
    else
        info "reusing existing cluster $cluster"
    fi

    if [[ $DRY_RUN == true ]]; then
        info "[dry-run] would resolve the tenant identity from $t1"
        info "[dry-run] would compare the admin and tenant API server URLs"
        info "[dry-run] admin run:  KUBECONFIG=$(basename "$host_kubeconfig") $(basename "$MTB_BIN") run benchmarks -n $TENANT_NS --as <identity> -p 3"
        info "[dry-run] tenant run: KUBECONFIG=$(basename "$t1") $(basename "$MTB_BIN") run benchmarks -n $TENANT_NS --as <identity> -p 3"
        info "[dry-run]             (tenant run is skipped when both kubeconfigs reach the same server)"
        info "[dry-run] $KUMUTEVA_BIN verify $t1 $t2 --output-json $out_dir/verify.json --solution-label $solution"
        continue
    fi

    identity=$(resolve_identity "$t1")
    if [[ -z $identity ]]; then
        fail "could not resolve a tenant identity from $t1"
        SUMMARY+=("$solution: NO IDENTITY")
        continue
    fi
    mapfile -t identity_groups < <(resolve_groups "$t1")
    ok "tenant identity: $identity"
    if [[ ${#identity_groups[@]} -gt 0 ]]; then
        info "tenant groups: ${identity_groups[*]}"
    else
        info "tenant groups: none in the certificate subject"
    fi

    # The second tenant, for the benchmarks that need one.
    #
    # kubectl-mtb takes `--as` and `-n` as lists of up to two, and skips every
    # benchmark declaring `namespaceRequired: 2` unless both are given —
    # silently, before the benchmark runs. Passing one tenant does not fail; it
    # quietly shrinks the suite, which reads afterwards as a solution that was
    # never asked the question.
    # What the tenant's own credential sees for its namespace. The yardstick for
    # deciding, per run, whether the API server being addressed is the one that
    # owns the tenant's workloads.
    tenant_ns_uid=$(namespace_uid "$t1" "$TENANT_NS")

    identity2=$(resolve_identity "$t2" 2>/dev/null)
    if [[ -z $identity2 ]]; then
        info "no second tenant kubeconfig; cross-tenant benchmarks will be skipped"
    elif [[ $identity2 == "$identity" ]]; then
        # Both credentials carry the same username, which happens whenever each
        # tenant gets its own API server: vcluster issues every tenant an admin
        # certificate with CN=kubernetes-super-admin, so "the other tenant" is
        # the same principal by name. Handing kubectl-mtb that name twice would
        # have it impersonate one identity and call it two, and the cross-tenant
        # benchmark would compare a tenant against itself and pass.
        info "second tenant resolves to the same identity ('$identity2')"
        info "  they are separate tenants only because they are separate"
        info "  clusters, so there is no second principal here to impersonate."
        identity2=""
    else
        info "second tenant identity: $identity2 (namespace $TENANT2_NS)"
    fi

    label=$(multitenancy_label "$solution")
    if [[ -n $label ]]; then
        info "admin-managed resource label: $label"
    else
        warn "no admin-managed resource label known for '$solution'"
        warn "  MTB-PL1-BC-CPI-2 will error rather than run. That is the honest"
        warn "  outcome: a label matching nothing makes it pass without testing."
    fi

    # --- which runs apply, decided by looking rather than by solution name ---
    #
    # kubectl-mtb is designed to be used by the cluster administrator: point it
    # at a tenant's namespace and impersonate the tenant with --as. That is the
    # "admin run", and for a shared control plane it is the whole story.
    #
    # When the tenant's own kubeconfig reaches a *different* API server, the
    # tenant does not live in the admin's cluster at all, and the admin run is
    # benchmarking something other than the tenancy boundary. The "tenant run"
    # then asks the complementary question: what does kubectl-mtb say when
    # aimed at the API server the tenant actually uses?
    #
    # Both answers are recorded. Neither is discarded for being inconvenient.
    admin_server=$(resolve_server "$host_kubeconfig")
    tenant_server=$(resolve_server "$t1")

    declare -a RUN_NAMES=()
    if [[ -f $host_kubeconfig && -n $admin_server ]]; then
        RUN_NAMES+=(admin)
    else
        warn "no admin kubeconfig at $host_kubeconfig; the admin run cannot be made"
    fi
    if [[ -n $tenant_server && $tenant_server != "$admin_server" ]]; then
        RUN_NAMES+=(tenant)
        info "tenant kubeconfig reaches a different API server:"
        info "  admin:  ${admin_server:-<none>}"
        info "  tenant: $tenant_server"
        info "  the control plane is not shared, so both runs are made."
    else
        info "admin and tenant kubeconfigs reach the same API server; admin run only"
    fi

    if [[ ${#RUN_NAMES[@]} -eq 0 ]]; then
        fail "no usable kubeconfig for either run"
        SUMMARY+=("$solution: NO KUBECONFIG")
        continue
    fi

    run_records=()
    solution_note=""

    for run_name in "${RUN_NAMES[@]}"; do
        # Username only, because that is the entirety of what kubectl-mtb can
        # express. Its flag set is `--as`, `--namespace`, `--labels`, `--out`,
        # `--skip`, `--profile-level`: there is no `--as-group`, and passing one
        # makes it print usage and exit.
        #
        # That limitation is a finding, not an inconvenience. Kubernetes
        # impersonation carries the username alone, so a tenant whose authority
        # comes from a group cannot be represented at all. A kubeadm-style
        # tenant credential — `O=system:masters, CN=kubernetes-super-admin`, as
        # vcluster, Kamaji and KubeVirt all issue — derives every permission
        # from the O. kubectl-mtb can only say `--as kubernetes-super-admin`,
        # a name with no bindings behind it, and then reports the resulting
        # "User cannot create pods" as thirteen benchmark *errors* rather than
        # as an inability to model the tenant.
        #
        # The groups are recorded in the manifest regardless. They are the
        # evidence for what was lost between the real credential and what the
        # tool could be told about it.
        impersonation=(--as "$identity")

        case "$run_name" in
            admin)  mtb_kubeconfig="$host_kubeconfig"; mtb_server="$admin_server" ;;
            tenant) mtb_kubeconfig="$t1";              mtb_server="$tenant_server" ;;
        esac

        # Add the second tenant when, and only when, this API server actually
        # serves it. Decided by asking the server for the namespace rather than
        # by the solution's name: for a cluster-per-tenant design the two
        # tenants live behind different API servers, and naming a namespace this
        # server has never heard of would make the cross-tenant benchmarks fail
        # on a missing namespace instead of skipping honestly. A skip there is a
        # true statement about the architecture; a failure would be an artefact.
        benchmarked_namespaces="$TENANT_NS"
        if [[ -n $identity2 ]] &&
           KUBECONFIG="$mtb_kubeconfig" kubectl get namespace "$TENANT2_NS" >/dev/null 2>&1; then
            impersonation=(--as "$identity,$identity2")
            benchmarked_namespaces="$TENANT_NS,$TENANT2_NS"
            info "both tenants live on this API server; cross-tenant benchmarks will run"
        else
            info "only $TENANT_NS on this API server; cross-tenant benchmarks stay skipped"
        fi

        # How many objects the label selects here, recorded so a vacuous pass
        # can be told apart from a real one after the fact.
        label_matches=$(count_labelled_resources "$mtb_kubeconfig" "$TENANT_NS" "$label")
        if [[ -n $label ]]; then
            if [[ ${label_matches:-0} -gt 0 ]]; then
                ok "label selects $label_matches admin-managed resource(s) in $TENANT_NS"
            else
                warn "label '$label' selects nothing in $TENANT_NS"
                warn "  MTB-PL1-BC-CPI-2 iterates the matched resources, so an empty"
                warn "  match returns success without testing anything. Treat a pass"
                warn "  from this run as unproven."
            fi
        fi

        banner "$solution / $run_name run"
        info "impersonating: ${impersonation[*]}"

        # The namespace benchmarked is the tenant's own only when this API
        # server owns the object the tenant works in. A namespace of the right
        # *name* in the admin cluster is not the same thing — for vcluster it
        # holds the syncer, not the tenant's workloads.
        #
        # Decided on the namespace UID rather than the server URL. The URL says
        # capsule-proxy is a separate control plane, because the proxy has its
        # own endpoint, when in fact it forwards to the very API server the
        # administrator is using; the UID is identical from both sides and says
        # so. For vcluster the two namespaces are genuinely different objects
        # with different UIDs.
        this_uid=$(namespace_uid "$mtb_kubeconfig" "$TENANT_NS")
        if [[ -n $this_uid && -n $tenant_ns_uid && $this_uid == "$tenant_ns_uid" ]]; then
            targets_workload_ns=true
        elif [[ -z $this_uid || -z $tenant_ns_uid ]]; then
            # UID unavailable from one side; fall back to the URL comparison
            # rather than inventing an answer.
            [[ $mtb_server == "$tenant_server" ]] &&
                targets_workload_ns=true || targets_workload_ns=false
        else
            targets_workload_ns=false
        fi

        if ! KUBECONFIG="$mtb_kubeconfig" kubectl get namespace "$TENANT_NS" >/dev/null 2>&1; then
            warn "namespace '$TENANT_NS' does not exist here; skipping this run"
            run_records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
                "$run_name" "$(basename "$mtb_kubeconfig")" "$mtb_server" \
                "${benchmarked_namespaces:-$TENANT_NS}" "${label:-}" "${label_matches:-0}" \
                "$identity" \
                "$(IFS=,; echo "${identity_groups[*]:-}")" \
                "$(IFS=,; echo "${impersonation[*]}")" \
                "null" "$targets_workload_ns" "")")
            continue
        fi

        contents=$(namespace_contents "$mtb_kubeconfig" "$TENANT_NS")
        info "namespace $TENANT_NS contains: ${contents:-<empty>}"

        # Only the first tenant, and only ever one: kubectl's `--as` takes a
        # single username, where kubectl-mtb's takes a list. Passing the list
        # through would impersonate a user literally named
        # "tenant1-admin,tenant2-admin", which no cluster knows, and the check
        # would report that the API server does not recognise the tenant.
        if identity_known "$mtb_kubeconfig" "$TENANT_NS" --as "$identity"; then
            known=true
            ok "this API server grants the tenant pod creation in $TENANT_NS"
        else
            known=false
            warn "this API server does not grant the tenant pod creation in $TENANT_NS"
            info "  kubectl-mtb's own PreRun validation makes the same check, so"
            info "  expect its benchmarks to report errors rather than verdicts."
            info "  Recorded: a scorecard produced here does not describe the"
            info "  tenancy boundary."
        fi

        # --- kubectl-mtb ---
        #
        # It takes no --kubeconfig flag. The client is built with
        # genericclioptions.NewConfigFlags, i.e. the standard clientcmd loading
        # rules, so the cluster is selected through the environment.
        #
        # `-o policyreport` is deliberately not used. That reporter does not
        # write to stdout: it POSTs a PolicyReport resource into the namespace
        # being benchmarked, and needs the PolicyReport CRD installed first.
        # Both are unacceptable here — it would mean modifying the cluster under
        # test and writing objects into the very tenant namespace whose
        # isolation is being measured. The scorecard table in the default output
        # carries the same verdicts; utils/mtb_parse.py reads it.
        #
        # -p 3 is the default, stated explicitly so the record shows every
        # profile level was run rather than relying on an upstream default.
        raw="$out_dir/mtb-raw-${run_name}.txt"
        label_args=()
        [[ -n $label ]] && label_args=(-l "$label")
        info "running kubectl-mtb against namespace(s) $benchmarked_namespaces"
        KUBECONFIG="$mtb_kubeconfig" "$MTB_BIN" run benchmarks \
            -n "$benchmarked_namespaces" "${impersonation[@]}" \
            "${label_args[@]}" -p 3 "${EXTRA_ARGS[@]}" >"$raw" 2>&1
        mtb_exit=$?

        # A CLI rejection prints usage and exits, which is not a measurement.
        # Left undetected it becomes a manifest that looks valid, a parse that
        # finds no rows, and a table cell that reads as a genuine finding.
        if grep -qE '^(Error: )?unknown (flag|command)|^Usage:' "$raw" 2>/dev/null; then
            fail "kubectl-mtb rejected the invocation — this is not a result"
            sed -n '1,3p' "$raw" | sed 's/^/      /'
            solution_note="$run_name run: INVOCATION REJECTED"
            rm -f "$raw"
            continue
        fi

        if [[ ! -s $raw ]]; then
            fail "kubectl-mtb produced no output (exit $mtb_exit)"
            solution_note="$run_name run: NO OUTPUT"
            rm -f "$raw"
            continue
        fi

        # No `|| echo 0` here: `grep -c` already prints 0 when it matches
        # nothing, and also exits non-zero, so the fallback appended a second
        # line and the arithmetic test below then failed on "0\n0" — swallowing
        # this very guard.
        benchmark_rows=$(grep -cE 'MTB-PL[0-9]+-' "$raw" 2>/dev/null)
        if [[ ${benchmark_rows:-0} -eq 0 ]]; then
            fail "no benchmark rows in the output — nothing was measured"
            if grep -q "Running 0 of 0" "$raw" 2>/dev/null; then
                info "  the tool reports 'Running 0 of 0': its benchmark registry"
                info "  is empty, which means it was built without \`go generate\`."
                info "  Remove $BUILD_DIR and re-run."
            fi
            solution_note="$run_name run: NO BENCHMARK ROWS"
            continue
        fi
        ok "kubectl-mtb finished (exit $mtb_exit, $benchmark_rows benchmark lines)"

        run_records+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
            "$run_name" "$(basename "$mtb_kubeconfig")" "$mtb_server" \
            "${benchmarked_namespaces:-$TENANT_NS}" "${label:-}" "${label_matches:-0}" \
            "$identity" \
            "$(IFS=,; echo "${identity_groups[*]:-}")" \
            "$(IFS=,; echo "${impersonation[*]}")" \
            "$known" "$targets_workload_ns" "$contents")")
    done

    # --- KUMUTEVA, on the same cluster ---
    if [[ $SKIP_VERIFY == false ]]; then
        info "running kumuteva verify"
        if "$KUMUTEVA_BIN" verify "$t1" "$t2" \
            --output-json "$out_dir/verify.json" \
            --solution-label "$solution" >"$out_dir/verify-raw.txt" 2>&1; then
            ok "verify.json written"
        else
            warn "kumuteva verify exited non-zero; see verify-raw.txt"
        fi
    fi

    # --- manifest ---
    #
    # Assembled by python3 rather than a heredoc: the per-run records are nested
    # and one unescaped character in a namespace listing would produce a file
    # that parses as valid JSON with the wrong shape.
    kumuteva_commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    if [[ -n $(git -C "$REPO_ROOT" status --porcelain --untracked-files=no 2>/dev/null) ]]; then
        kumuteva_commit="${kumuteva_commit}-dirty"
    fi

    # `${run_records[@]:-}` rather than `${run_records[@]}`: on a solution where
    # every run bailed out the array is empty, and under `set -u` an older bash
    # treats that as an unbound variable and aborts the whole campaign. A
    # solution with no usable run still needs its manifest written — "nothing
    # could be run here" is a result the table reads as absent.
    #
    # The assignments go *before* `python3`, as a command prefix. Written after
    # it they are argv, not environment, and `os.environ[...]` raises KeyError
    # after the benchmarks have already run — losing a completed measurement to
    # a shell quoting mistake.
    printf '%s\n' "${run_records[@]:-}" \
        | SOLUTION="$solution" \
          MTB_COMMIT="$MTB_COMMIT" \
          MTB_REPO="$MTB_REPO" \
          KUMUTEVA_COMMIT="$kumuteva_commit" \
          TENANT_NS="$TENANT_NS" \
          STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          MANIFEST="$out_dir/manifest.json" \
          python3 -c '
import json, os, sys

runs = {}
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line.strip():
        continue
    name, kubeconfig, server, namespace, label, label_matches, identity, \
        groups, impersonation, known, targets, contents = line.split("\t")
    runs[name] = {
        "kubeconfig": kubeconfig,
        "server": server,
        # Every namespace the suite was pointed at. One name means the
        # benchmarks needing two tenants were skipped before running.
        "namespace": namespace,
        # The -l selector and how many objects it actually matched. A label
        # matching nothing turns MTB-PL1-BC-CPI-2 into a pass that tested
        # nothing, and only the count can tell the two apart afterwards.
        "multitenancy_label": label,
        "multitenancy_label_matches": int(label_matches or 0),
        "identity": identity,
        # The groups the tenant certificate really carries, and the flags
        # kubectl-mtb was actually given. They differ whenever the tenant has
        # any group at all, because the tool has no --as-group: everything in
        # `identity_groups` and absent from `impersonation` is authority the
        # benchmark run could not be told about.
        "identity_groups": [g for g in groups.split(",") if g],
        "impersonation": [f for f in impersonation.split(",") if f],
        # Tri-state on purpose. "null" means the check could not be made, and
        # must never be read as "it passed".
        "identity_known_to_target": None if known == "null" else known == "true",
        "targets_tenant_workload_namespace": targets == "true",
        "namespace_contents": [c for c in contents.split(",") if c],
    }

json.dump({
    "solution": os.environ["SOLUTION"],
    "mtb_commit": os.environ["MTB_COMMIT"],
    "mtb_repo": os.environ["MTB_REPO"],
    "kumuteva_commit": os.environ["KUMUTEVA_COMMIT"],
    "namespace": os.environ["TENANT_NS"],
    "started_at_utc": os.environ["STARTED_AT"],
    "runs": runs,
}, open(os.environ["MANIFEST"], "w"), indent=2)
'
    manifest_status=$?

    recorded=${#run_records[@]}
    if [[ $manifest_status -ne 0 ]]; then
        # Raw scorecards without a manifest cannot be graded: the targeting
        # fields are the manifest's whole job. Louder than a warning, because a
        # silently missing manifest reads downstream as an ungraded run.
        fail "manifest could not be written — the runs cannot be graded"
        SUMMARY+=("$solution: $recorded run(s) but MANIFEST FAILED -> $out_dir")
    else
        ok "manifest written ($recorded run(s))"
        if [[ -n $solution_note ]]; then
            SUMMARY+=("$solution: $recorded run(s) recorded; $solution_note -> $out_dir")
        else
            SUMMARY+=("$solution: $recorded run(s) recorded -> $out_dir")
        fi
    fi

    if [[ $SKIP_SETUP == false ]]; then
        info "deleting cluster $cluster"
        run kind delete cluster --name "$cluster" >/dev/null 2>&1
    fi
done

banner "Summary"
for line in "${SUMMARY[@]:-}"; do [[ -n $line ]] && info "$line"; done

cat <<EOF

  Next:
    rsync -av $OUTPUT_ROOT/ <analysis-host>:<repo>/new_fairness_results/mtb/
    cd new_fairness_results
    ../target/release/kumuteva verify /dev/null /dev/null --list-properties /tmp/props.json
    ../.venv/bin/python validate_mtb_mapping.py /tmp/props.json
    ../.venv/bin/python build_comparison_table.py

  Each solution directory holds one mtb-raw-<run>.txt per run made, plus a
  manifest recording, for each, which API server was addressed, whether that
  server knows the impersonated identity, and what the benchmarked namespace
  actually contained. Those three fields are what separate a measurement of the
  tenancy boundary from a scorecard about something else entirely; a run
  missing them cannot be graded and the table will say so rather than guess.

  Check mtb-raw-admin.txt against utils/mtb_parse.py if the format ever moves:
  a parser that silently matches nothing looks exactly like a clean comparison.
EOF
