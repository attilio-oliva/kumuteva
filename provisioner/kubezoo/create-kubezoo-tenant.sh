#!/bin/bash
#
# Create one KubeZoo tenant and write its kubeconfig to $OUTPUT_PATH.
#
# The Tenant CR is served by KubeZoo itself, not by the host cluster, so this
# runs against the gateway's published address with the admin credentials
# gen-pki.sh minted — the host kubeconfig cannot see this resource at all.
#
# Usage: create-kubezoo-tenant.sh <out_kubeconfig> <tenant_id> <host_port> <work_dir>
#
# <tenant_id> must be exactly six digits. KubeZoo prefixes every namespaced
# object's namespace and every cluster-scoped object's name with it, so it has
# to fit inside a DNS label — and its CRD types spec.id as an integer, so a
# word-shaped id such as `tnt001` is rejected at validation.

set -uo pipefail

OUTPUT_PATH="$1"
TENANT_ID="$2"
HOST_PORT="$3"
WORK_DIR="$4"

if [ -z "$OUTPUT_PATH" ] || [ -z "$TENANT_ID" ] || [ -z "$HOST_PORT" ] || [ -z "$WORK_DIR" ]; then
    echo "Usage: $0 <out_kubeconfig> <tenant_id> <host_port> <work_dir>"
    exit 1
fi

if ! [[ "$TENANT_ID" =~ ^[0-9]{6}$ ]]; then
    echo "ERROR: tenant id '$TENANT_ID' must be exactly six digits"
    exit 1
fi

# The tenant's hard limits: counts only, set high enough not to bind.
#
# No cpu or memory limit, deliberately. A quota that constrains a compute
# resource makes that resource mandatory on every pod — the webhook answers
# "must specify cpu for: <pod>" — so every probe that does not set requests
# would be refused and the refusal scored as KubeZoo's isolation rather than as
# our own quota choice.
export TENANT_POD_QUOTA=${TENANT_POD_QUOTA:-200}
export TENANT_PVC_QUOTA=${TENANT_PVC_QUOTA:-50}
export TENANT_SERVICE_QUOTA=${TENANT_SERVICE_QUOTA:-50}

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_KUBECONFIG="$WORK_DIR/zoo-admin.kubeconfig"

TENANT_READY_TIMEOUT=${TENANT_READY_TIMEOUT:-300}

export TENANT_ID

if [ ! -s "$ADMIN_KUBECONFIG" ]; then
    echo "ERROR: no gateway admin kubeconfig at $ADMIN_KUBECONFIG — run deploy-kubezoo.sh first"
    exit 1
fi

zoo() { kubectl --kubeconfig "$ADMIN_KUBECONFIG" "$@"; }
tenant_kc() { kubectl --kubeconfig "$OUTPUT_PATH" "$@"; }

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
    echo "--- tenants known to the gateway ---"
    zoo get tenants 2>&1 | sed 's/^/  /'
    return 1
}

# --- 1. The Tenant ----------------------------------------------------------

echo "Creating tenant ${TENANT_ID} through the gateway..."
if ! envsubst < "$THIS_DIR"/tenant.tmpl.yaml | zoo apply -f -; then
    echo "ERROR: failed to create tenant ${TENANT_ID}"
    exit 1
fi

# --- 2. Its kubeconfig ------------------------------------------------------
# KubeZoo mints a client certificate for the tenant and hands it back as a
# base64 annotation on the Tenant object. It appears a moment after the object
# does, so it is waited for rather than read straight away.

KUBECONFIG_ANNOTATION='{.metadata.annotations.kubezoo\.io/tenant\.kubeconfig\.base64}'

wait_for "tenant ${TENANT_ID} to publish its kubeconfig" "$TENANT_READY_TIMEOUT" \
    "[ -n \"\$(zoo get tenant '$TENANT_ID' -o jsonpath='$KUBECONFIG_ANNOTATION' 2>/dev/null)\" ]" || exit 1

zoo get tenant "$TENANT_ID" -o jsonpath="$KUBECONFIG_ANNOTATION" | base64 -d > "$OUTPUT_PATH"

if [ ! -s "$OUTPUT_PATH" ]; then
    echo "ERROR: the extracted kubeconfig at $OUTPUT_PATH is empty"
    exit 1
fi

# --- 3. Point it at the published NodePort ----------------------------------
# KubeZoo writes https://127.0.0.1:6443, the address upstream's foreground
# port-forward would have provided. Only the port changes: the host stays
# 127.0.0.1, which is exactly the SAN the serving certificate carries, so —
# unlike every other solution here — no --insecure-skip-tls-verify is needed and
# none is set. If TLS verification fails after this, the certificate is wrong
# and that is worth failing on.

CLUSTER_NAME="$(tenant_kc config view -o jsonpath='{.clusters[0].name}')"
if [ -z "$CLUSTER_NAME" ]; then
    echo "ERROR: the tenant kubeconfig names no cluster"
    exit 1
fi

tenant_kc config set-cluster "$CLUSTER_NAME" --server="https://127.0.0.1:${HOST_PORT}" >/dev/null || exit 1

wait_for "tenant ${TENANT_ID} to be served on 127.0.0.1:${HOST_PORT}" "$TENANT_READY_TIMEOUT" \
    "tenant_kc get namespaces" || exit 1

echo "Tenant ${TENANT_ID} is ready; kubeconfig at $OUTPUT_PATH"
