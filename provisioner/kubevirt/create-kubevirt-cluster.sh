#!/bin/bash
#
# Create a CAPI/KubeVirt tenant cluster on the host cluster and write its
# kubeconfig to $OUTPUT_PATH.
#
# The stages here are strictly sequential and each one takes minutes: CAPI
# reconciles the Cluster, KubeadmControlPlane mints certificates, CAPK creates a
# VirtualMachineInstance, the ~1GB node container disk pulls, the VM boots, and
# only then does kubeadm run inside it. Every wait below is therefore a real
# wait with a timeout, not a poll-three-times-and-hope: the previous version
# checked for the VMI with no retries at all, immediately after the kubeconfig
# secret appeared, and so could never succeed.

set -uo pipefail

KUBECONFIG_PATH="$1"
OUTPUT_PATH="$2"
TENANT_NAME="$3"
EXPOSE_NODEPORT_API_SERVER="$4"
NODEPORT_API_SERVER_PORT="$5"
KUBECONFIG_API_SERVER_PORT="$6"

KUBECONFIG_API_SERVER_PORT=${KUBECONFIG_API_SERVER_PORT:-6443}
NODEPORT_API_SERVER_PORT=${NODEPORT_API_SERVER_PORT:-30064}

CNI_PLUGIN_YAML_PATH=${CNI_PLUGIN_YAML_PATH:-"https://raw.githubusercontent.com/projectcalico/calico/v3.30.1/manifests/calico-typha.yaml"}
LOCAL_PATH_PROVISIONER_YAML=${LOCAL_PATH_PROVISIONER_YAML:-"https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.34/deploy/local-path-storage.yaml"}

# Budgets, in seconds. The VMI one dominates: it covers the container-disk pull,
# which on a cold node is the single longest step in the whole provision.
KUBECONFIG_SECRET_TIMEOUT=${KUBECONFIG_SECRET_TIMEOUT:-300}
VMI_APPEAR_TIMEOUT=${VMI_APPEAR_TIMEOUT:-600}
VMI_RUNNING_TIMEOUT=${VMI_RUNNING_TIMEOUT:-900}
API_REACHABLE_TIMEOUT=${API_REACHABLE_TIMEOUT:-900}

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$KUBECONFIG_PATH" ] || [ -z "$OUTPUT_PATH" ] || [ -z "$TENANT_NAME" ]; then
    echo "Usage: $0 <kubeconfig_path> <output_path> <tenant_name> <expose_nodeport> <nodeport> <local_port>"
    exit 1
fi

export CLUSTER_NAME=${TENANT_NAME}-kv
export NAMESPACE=${TENANT_NAME}
export NODE_VM_IMAGE_TEMPLATE="quay.io/capk/ubuntu-2404-container-disk:v1.32.1"
export CONTROL_PLANE_MACHINE_COUNT=1
export WORKER_MACHINE_COUNT=1

# Size of the tenant node VMs, control plane and worker set separately.
#
# The figure that matters is the *total per tenant*, because that is what the
# namespace-based solutions give their tenants: both of those share one 16-core
# node and either can demand all of it. The defaults below give each tenant
# 8 + 8 = 16 vCPU, matching the pinned host, so a KubeVirt tenant can offer the
# same load as a Capsule tenant and the comparison is between isolation
# mechanisms rather than between allocations.
#
# Both VMs are sized because the untaint step lets benchmark pods run on the
# control plane as well as the worker, and because the control-plane subsystem
# measures the tenant's own API server, which lives there.
#
# vCPUs overcommit cleanly: a vCPU is a host thread that consumes a core only
# while the guest is running, and an idle one costs nothing. KubeVirt's
# cpuAllocationRatio (10 by default) means the virt-launcher pod requests a
# tenth of the core count, so these VMs schedule comfortably on the host node.
#
# Memory is the opposite and must NOT be scaled the same way: guest memory is
# reserved for the VM's lifetime, so four VMs take four times what is set here.
# 8Gi each needs roughly 36Gi free on the host once overhead is counted. Lower
# it if the machine cannot spare that; the run stays valid, it is just measured
# on a tenant with less memory, which belongs in the write-up.
export CONTROL_PLANE_VM_CORES=${CONTROL_PLANE_VM_CORES:-8}
export CONTROL_PLANE_VM_MEMORY=${CONTROL_PLANE_VM_MEMORY:-8Gi}
export WORKER_VM_CORES=${WORKER_VM_CORES:-8}
export WORKER_VM_MEMORY=${WORKER_VM_MEMORY:-8Gi}

# Kubelet container-log limits for the tenant nodes. These must match what the
# host kind cluster sets, because the storage benchmark retrieves fio's per-I/O
# latency log through pod stdout and the default 10Mi rotates most of a run away
# before it can be read. The host patch does not reach here: these nodes are VMs
# with their own kubelet, provisioned by CAPI rather than kind.
export CONTAINER_LOG_MAX_SIZE=${CONTAINER_LOG_MAX_SIZE:-512Mi}
export CONTAINER_LOG_MAX_FILES=${CONTAINER_LOG_MAX_FILES:-5}
export KUBERNETES_VERSION="v1.32.1"
export CRI_PATH="/run/containerd/containerd.sock"

# The name of every tenant's control-plane Machine, and so of its node.
#
# Host-namespace probes are per-node, so the intruder must run on the node named
# by the victim. Where each tenant is its own cluster the victim's node name
# means nothing on the intruder's side: the pod pins to a node that does not
# exist, is never scheduled, never runs, and writes no logs — and "no marker in
# empty output" reads as isolation. The property is reported without being
# tested.
#
# Giving both tenants' nodes the same name makes that pin resolve to the
# intruder's *own* node, so the probe actually executes: it joins its own host
# namespace, looks for the other tenant's secret, and does not find it. Same
# verdict, reached by a measurement.
#
# Applied through `machineNamingStrategy` rather than kubelet's
# `nodeRegistration.name`: the node inherits the Machine's name either way, but
# only the former keeps the Machine -> Node link intact. See the comment on the
# KubeadmControlPlane in tenant-cluster.yaml.
export TENANT_NODE_NAME=${TENANT_NODE_NAME:-kumuteva-tenant-node}

# The worker's name, likewise identical across tenants but distinct from the
# control plane's. Both nodes sharing one name collides within a cluster: the
# worker's registration is refused and its machine sits Pending forever, which
# is what happened when a single name was used for both roles.
#
# One name per role, so WORKER_MACHINE_COUNT must stay 1 — a second worker would
# collide with the first.
export TENANT_WORKER_NODE_NAME=${TENANT_WORKER_NODE_NAME:-kumuteva-tenant-worker}

kc() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }
tenant_kc() { kubectl --kubeconfig "$OUTPUT_PATH" "$@"; }

# CAPI failures are almost never legible from the resource that failed — the
# cause sits in a sibling object's status or in an event. Dump the lot rather
# than leaving the next person to reconstruct it.
dump_state() {
    echo ""
    echo "--- state of ${NAMESPACE}/${CLUSTER_NAME} at failure ---"
    kc get cluster,kubeadmcontrolplane,machine,kubevirtmachine,vmi,pod -n "$NAMESPACE" 2>&1 | sed 's/^/  /'
    echo "--- recent events ---"
    kc get events -n "$NAMESPACE" --sort-by=.lastTimestamp 2>&1 | tail -30 | sed 's/^/  /'
    echo "--- KubeVirt readiness on the host ---"
    kc get kubevirt -n kubevirt 2>&1 | sed 's/^/  /'
    echo "-------------------------------------------------------"
}

# Poll `command` until it succeeds or the budget runs out. Progress is printed
# at a decreasing rate so a 15-minute wait does not bury the log.
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

# --- 1. Apply the cluster manifests ----------------------------------------
# The KubevirtMachineTemplate manifests go through a validating webhook served
# by capk-controller-manager. If that pod is not yet answering, the apply fails
# with "connection refused" from the API server, no machines are ever created,
# and the VMI wait below then times out against a cause that is nowhere near it.
# Check here as well as in deploy-capi-provider.sh, so running this script on
# its own cannot reproduce that.

wait_for "CAPK validating webhook to have endpoints" 300 \
    "[ -n \"\$(kc get endpoints capk-webhook-service -n kubevirt-infrastructure-system -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null)\" ]" || exit 1

kc create namespace "$NAMESPACE" 2>/dev/null || true

envsubst < "$THIS_DIR"/tenant-cluster.yaml > "$CLUSTER_NAME"-applied.yaml

# Retried, because waiting cannot make this reliable.
#
# Every webhook Service is checked for endpoints before we get here, and that
# check passes — yet the apply still loses to the *conversion* webhook for
# KubeadmControlPlane:
#
#   conversion webhook for controlplane.cluster.x-k8s.io/v1beta1,
#   Kind=KubeadmControlPlane failed: dial tcp ...:443: connect: connection refused
#
# An Endpoints entry means the pod passed its readiness probe, which is not the
# same instant as its TLS listener accepting connections; kube-proxy rejects in
# the gap. The window is short and it closes on its own, so the fix is to try
# again rather than to wait for yet another precondition.
#
# `apply` is idempotent, so the objects created by a partial first pass are
# simply re-applied — which matters, because the failing apply does create some
# of them before it dies.
apply_manifests() {
    envsubst < "$THIS_DIR"/tenant-cluster.yaml | kc apply -f -
}

applied=false
for attempt in 1 2 3 4 5; do
    if apply_manifests; then
        applied=true
        break
    fi
    echo "  apply attempt ${attempt}/5 failed; retrying in 15s (webhooks may still be starting)"
    sleep 15
done

if [ "$applied" != true ]; then
    echo "ERROR: failed to apply the tenant cluster manifests after 5 attempts"
    exit 1
fi

# --- 2. Kubeconfig secret ---------------------------------------------------
# Minted by the KubeadmControlPlane provider from the cluster CA, so it lands
# well before any VM exists. Its presence says the control plane object is being
# reconciled — nothing more.

wait_for "kubeconfig secret ${CLUSTER_NAME}-kubeconfig" "$KUBECONFIG_SECRET_TIMEOUT" \
    "kc get secret '${CLUSTER_NAME}-kubeconfig' -n '$NAMESPACE'" || exit 1

echo "Extracting kubeconfig for cluster $CLUSTER_NAME in namespace $NAMESPACE..."
kc get secret "${CLUSTER_NAME}-kubeconfig" -n "$NAMESPACE" -o jsonpath='{.data.value}' \
    | base64 -d > "$OUTPUT_PATH"

# An empty or truncated kubeconfig fails much later and much more confusingly,
# usually as an unrelated connection error against the wrong cluster.
if [ ! -s "$OUTPUT_PATH" ]; then
    echo "ERROR: extracted kubeconfig at $OUTPUT_PATH is empty"
    dump_state
    exit 1
fi

# --- 3. Point the kubeconfig at the NodePort --------------------------------
# CAPK gives the control plane a ClusterIP, which is unreachable from the host.
# On kind we publish it as a NodePort and rewrite the server address to match.

if [ "$EXPOSE_NODEPORT_API_SERVER" = "y" ]; then
    API_SERVER_ADDRESS="https://127.0.0.1:${KUBECONFIG_API_SERVER_PORT}"
    echo "Setting API server address to $API_SERVER_ADDRESS in the extracted kubeconfig..."
    tenant_kc config set-cluster "$CLUSTER_NAME" --server="$API_SERVER_ADDRESS"
    # The serving certificate is issued for the in-cluster address, not for
    # 127.0.0.1, so verification cannot succeed over the forwarded port.
    tenant_kc config set-cluster "$CLUSTER_NAME" --insecure-skip-tls-verify=true
fi

# --- 4. The control plane VM ------------------------------------------------
# Existence first, then Running. They fail for different reasons and are worth
# distinguishing: no VMI at all means CAPK never got as far as creating one,
# while a VMI stuck Pending is almost always the node lacking /dev/kvm or the
# container disk still pulling.

wait_for "control plane VMI to be created" "$VMI_APPEAR_TIMEOUT" \
    "[ -n \"\$(kc get vmi -n '$NAMESPACE' -l 'cluster.x-k8s.io/cluster-name=$CLUSTER_NAME,cluster.x-k8s.io/role=control-plane' -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)\" ]" || exit 1

CONTROL_PLANE_VMI=$(kc get vmi -n "$NAMESPACE" \
    -l "cluster.x-k8s.io/cluster-name=$CLUSTER_NAME,cluster.x-k8s.io/role=control-plane" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
echo "Control plane VMI: $CONTROL_PLANE_VMI"

wait_for "VMI $CONTROL_PLANE_VMI to reach phase Running" "$VMI_RUNNING_TIMEOUT" \
    "[ \"\$(kc get vmi '$CONTROL_PLANE_VMI' -n '$NAMESPACE' -o jsonpath='{.status.phase}' 2>/dev/null)\" = Running ]" || exit 1

# --- 5. Publish the API server ----------------------------------------------

echo "Exposing API server of cluster $CLUSTER_NAME as NodePort service..."
cat <<EOF | kc apply -f -
apiVersion: v1
kind: Service
metadata:
  name: ${CLUSTER_NAME}-api-server
  namespace: ${NAMESPACE}
spec:
  type: NodePort
  selector:
    cluster.x-k8s.io/cluster-name: ${CLUSTER_NAME}
    cluster.x-k8s.io/role: control-plane
  ports:
    - name: api-server
      port: 6443
      targetPort: 6443
      nodePort: ${NODEPORT_API_SERVER_PORT}
EOF

# kubeadm runs inside the VM only after it boots, so the API answers well after
# the VMI reports Running. Everything below talks to the tenant cluster and
# would otherwise fail on the first call.
wait_for "tenant API server to answer on ${KUBECONFIG_API_SERVER_PORT}" "$API_REACHABLE_TIMEOUT" \
    "tenant_kc get --raw /readyz" || exit 1

# --- 6. CNI -----------------------------------------------------------------
# Nodes stay NotReady until a CNI is installed, so this precedes the untaint.

echo "Deploying Calico CNI plugin inside cluster $CLUSTER_NAME..."
if ! wait_for "Calico manifests to apply" 300 "tenant_kc apply -f '$CNI_PLUGIN_YAML_PATH'"; then
    exit 1
fi

wait_for "at least one node to become Ready" 600 \
    "tenant_kc get nodes -o jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}' | grep -q True" || exit 1

# Single-node tenant clusters have nowhere else to put benchmark pods. Absent
# taints make this a no-op, hence the tolerated failure.
tenant_kc taint node --all node-role.kubernetes.io/control-plane:NoSchedule- 2>/dev/null || true

# --- 7. Storage -------------------------------------------------------------
# The storage fairness assessor provisions a PVC per fio pod, so the tenant
# cluster needs a default StorageClass or that subsystem cannot run at all.

echo "Installing local-path-storage inside cluster $CLUSTER_NAME..."
if ! tenant_kc apply -f "$LOCAL_PATH_PROVISIONER_YAML"; then
    echo "ERROR: failed to install the local-path provisioner"
    exit 1
fi

tenant_kc patch storageclass local-path \
    -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

echo "Cluster $CLUSTER_NAME is ready."
