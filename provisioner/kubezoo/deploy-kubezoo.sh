#!/bin/bash
#
# Install the KubeZoo gateway on the host cluster and leave it answering on a
# published NodePort.
#
# This replaces upstream's hack/make-rules/local_up.sh, which cannot be used as
# a provisioning step: it builds the images locally, `kind load`s them, and then
# ends in a foreground `kubectl port-forward svc/kubezoo 6443:6443` that never
# returns. Published images are used instead, and the Service is a NodePort that
# kind's extraPortMapping already carries to 127.0.0.1 on the host.
#
# Idempotent: a second tenant's provisioning pass reuses the gateway installed
# by the first. Install steps are skipped when the object is already there;
# readiness checks always run, because "installed once" is not "ready now" —
# the same distinction that bit the CAPI provisioner.
#
# Usage: deploy-kubezoo.sh <host_kubeconfig> <nodeport> <host_port> <work_dir>

set -uo pipefail

KUBECONFIG_PATH="$1"
NODEPORT="$2"
HOST_PORT="$3"
WORK_DIR="$4"

if [ -z "$KUBECONFIG_PATH" ] || [ -z "$NODEPORT" ] || [ -z "$HOST_PORT" ] || [ -z "$WORK_DIR" ]; then
    echo "Usage: $0 <host_kubeconfig> <nodeport> <host_port> <work_dir>"
    exit 1
fi

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# v0.2.0 is what the project publishes to Docker Hub; the repository's only git
# tag is v0.1.0. Overridable, but nothing else in the harness moves it.
export KUBEZOO_IMAGE_TAG=${KUBEZOO_IMAGE_TAG:-v0.2.0}
export KUBEZOO_NODEPORT="$NODEPORT"

QUOTA_READY_TIMEOUT=${QUOTA_READY_TIMEOUT:-300}
GATEWAY_READY_TIMEOUT=${GATEWAY_READY_TIMEOUT:-600}
GATEWAY_ANSWER_TIMEOUT=${GATEWAY_ANSWER_TIMEOUT:-300}

kc() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }

dump_state() {
    echo ""
    echo "--- KubeZoo state at failure ---"
    kc get sts,deploy,pod,svc,endpoints -o wide 2>&1 | sed 's/^/  /'
    echo "--- recent events (default namespace) ---"
    kc get events --sort-by=.lastTimestamp 2>&1 | tail -30 | sed 's/^/  /'
    echo "--- kubezoo-0 logs (tail) ---"
    kc logs kubezoo-0 --tail=50 2>&1 | sed 's/^/  /'
    echo "--------------------------------"
}

wait_for() {
    local description="$1" timeout="$2" command="$3"
    local waited=0 interval=5

    echo "Waiting for ${description} (up to $((timeout / 60))m)..."
    while [ "$waited" -lt "$timeout" ]; do
        if eval "$command" >/dev/null 2>&1; then
            echo "  ${description}: ready after ${waited}s"
            return 0
        fi
        sleep "$interval"
        waited=$((waited + interval))
        if [ $((waited % 60)) -eq 0 ]; then
            echo "  still waiting for ${description} (${waited}s elapsed)"
        fi
    done

    echo "ERROR: timed out after ${timeout}s waiting for ${description}"
    dump_state
    return 1
}

# --- 1. PKI -----------------------------------------------------------------
# Also writes the gateway's admin kubeconfig, which step 3 and the tenant script
# both address the gateway with.

if ! "$THIS_DIR"/gen-pki.sh "$KUBECONFIG_PATH" "$WORK_DIR" "$HOST_PORT"; then
    echo "ERROR: KubeZoo PKI generation failed"
    exit 1
fi

# --- 2. Cluster resource quota webhook --------------------------------------
# Applied *before* the gateway, and waited on, because its
# ValidatingWebhookConfiguration intercepts pod CREATE with failurePolicy: Fail.
# It is scoped to tenant namespaces (see quota.tmpl.yaml for why), so the
# gateway itself no longer depends on this order; tenant pods still do, and a
# webhook that exists while nothing serves it refuses every one of them.
#
# Applied only when missing, so a cluster installed before the scoping keeps
# the old every-namespace webhook until it is recreated.

if kc get deployment kubezoo-cluster-resource-quota >/dev/null 2>&1; then
    echo "Cluster resource quota webhook already installed; verifying it is ready."
else
    echo "Installing the cluster resource quota webhook..."
    if ! kc apply -f "$WORK_DIR"/quota.yaml; then
        echo "ERROR: failed to apply the quota manifest"
        exit 1
    fi
fi

wait_for "quota webhook deployment to roll out" "$QUOTA_READY_TIMEOUT" \
    "kc rollout status deployment/kubezoo-cluster-resource-quota --timeout=20s" || exit 1

wait_for "quota webhook service to have endpoints" "$QUOTA_READY_TIMEOUT" \
    "[ -n \"\$(kc get endpoints kubezoo-cluster-resource-quota -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null)\" ]" || exit 1

# --- 3. The gateway ---------------------------------------------------------

if kc get statefulset kubezoo >/dev/null 2>&1; then
    echo "KubeZoo gateway already installed; verifying it is ready."
else
    echo "Installing the KubeZoo gateway (nodePort ${NODEPORT})..."
    applied=false
    for attempt in 1 2 3 4 5; do
        if envsubst < "$THIS_DIR"/all_in_one.tmpl.yaml | kc apply -f -; then
            applied=true
            break
        fi
        echo "  apply attempt ${attempt}/5 failed; retrying in 15s (the quota webhook may still be settling)"
        sleep 15
    done
    if [ "$applied" != true ]; then
        echo "ERROR: failed to apply the KubeZoo manifests after 5 attempts"
        dump_state
        exit 1
    fi
fi

wait_for "pod kubezoo-etcd-0 to be Ready" "$GATEWAY_READY_TIMEOUT" \
    "[ \"\$(kc get pod kubezoo-etcd-0 -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null)\" = True ]" || exit 1

wait_for "pod kubezoo-0 to be Ready" "$GATEWAY_READY_TIMEOUT" \
    "[ \"\$(kc get pod kubezoo-0 -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null)\" = True ]" || exit 1

wait_for "service kubezoo to have endpoints" "$GATEWAY_READY_TIMEOUT" \
    "[ -n \"\$(kc get endpoints kubezoo -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null)\" ]" || exit 1

# --- 4. The gateway actually answering on the host --------------------------
# A Service with endpoints is not yet a TLS listener, and this is the address
# every tenant kubeconfig will use. Checked with the admin credentials rather
# than `curl -k`, so a certificate the tenants could not verify fails here
# instead of much later.

ADMIN_KUBECONFIG="$WORK_DIR/zoo-admin.kubeconfig"

wait_for "the gateway to answer /healthz on 127.0.0.1:${HOST_PORT}" "$GATEWAY_ANSWER_TIMEOUT" \
    "kubectl --kubeconfig '$ADMIN_KUBECONFIG' get --raw /healthz" || exit 1

echo "KubeZoo gateway is serving on https://127.0.0.1:${HOST_PORT}"
