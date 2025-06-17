# Extract the kubeconfig file from the kubevirt cluster
# and save it to the specified path

#!/bin/bash
KUBECONFIG_PATH="$1"
OUTPUT_PATH="$2"
TENANT_NAME="$3"
API_SERVER_PORT=6443

if [ -z "$KUBECONFIG_PATH" ] || [ -z "$OUTPUT_PATH" ] || [ -z "$TENANT_NAME" ]; then
    echo "Usage: $0 <kubeconfig_path> <output_path> <tenant_name>"
    exit 1
fi

# Create a Kubevirt Cluster from the provided YAML file

export CLUSTER_NAME="tenant1-cluster"
export NAMESPACE="tenant1"
export NODE_VM_IMAGE_TEMPLATE="quay.io/capk/ubuntu-2404-container-disk:v1.32.1"
export CONTROL_PLANE_MACHINE_COUNT=1
export WORKER_MACHINE_COUNT=1
export KUBERNETES_VERSION="v1.32.1"
export CRI_PATH="/var/run/containerd/containerd.sock"

kubectl create namespace "$NAMESPACE" --kubeconfig "$KUBECONFIG_PATH"

# Replace variables and apply
envsubst < tenant-cluster.yaml | kubectl apply -f - --kubeconfig "$KUBECONFIG_PATH"

# Wait for the cluster to be ready
kubectl wait --for=condition=Ready --timeout=10m -n "$NAMESPACE" cluster "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_PATH"

# Extract the kubeconfig file from the Kubevirt cluster
kubectl get secret ${CLUSTER_NAME}-kubeconfig -o jsonpath='{.data.value}' | base64 -D > "$OUTPUT_PATH"

# Check the control plane VMI name
CONTROL_PLANE_VMI=$(kubectl get virtualmachineinstance -n "$NAMESPACE" -l "kubevirt.io/tenant-cluster=$CLUSTER_NAME,control-plane=true" -o jsonpath='{.items[0].metadata.name}' --kubeconfig "$KUBECONFIG_PATH")
if [ -z "$CONTROL_PLANE_VMI" ]; then
    echo "Control plane VMI not found for cluster $CLUSTER_NAME in namespace $NAMESPACE."
    exit 1
fi
# Expose the api server of the Kubevirt cluster as a NodePort service
kubectl expose virtualmachineinstance "$CONTROL_PLANE_VMI" --type=NodePort --name="${CLUSTER_NAME}-api-server" --port="$API_SERVER_PORT" --target-port=6443 -n "$NAMESPACE" --kubeconfig "$KUBECONFIG_PATH"
