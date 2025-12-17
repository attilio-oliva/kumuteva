#!/bin/bash
KUBECONFIG_PATH="$1"
OUTPUT_PATH="$2"
TENANT_NAME="$3"
API_SERVER_PORT=6443
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 <kubeconfig_path> <output_path> <tenant_name> <action>"
    echo "  kubeconfig_path: Path to kubeconfig file"
    echo "  output_path: Path to save the tenant cluster kubeconfig"
    echo "  tenant_name: Name of the tenant (namespace) to create the cluster in"
    echo "  action: [install,uninstall]"
    exit 1
}

create_cluster() {
    # Create a Kubevirt Cluster from the provided YAML file
    export CLUSTER_NAME=${TENANT_NAME}-kv
    export NAMESPACE=${TENANT_NAME}
    export NODE_VM_IMAGE_TEMPLATE="quay.io/capk/ubuntu-2404-container-disk:v1.32.1"
    export CONTROL_PLANE_MACHINE_COUNT=1
    export WORKER_MACHINE_COUNT=1
    export KUBERNETES_VERSION="v1.32.1"
    export CRI_PATH="/run/containerd/containerd.sock"

    kubectl create namespace "$NAMESPACE" --kubeconfig "$KUBECONFIG_PATH"

    # save the applied YAML file to this directory
    envsubst < "$THIS_DIR"/tenant-cluster.yaml > "$CLUSTER_NAME"-applied.yaml

    # Replace variables and apply
    envsubst < "$THIS_DIR"/tenant-cluster.yaml | kubectl apply -f - --kubeconfig "$KUBECONFIG_PATH"

    # wait for secret to be created
    echo "Waiting for kubeconfig secret for cluster $CLUSTER_NAME in namespace $NAMESPACE..."
    MAX_ATTEMPTS=20
    ATTEMPT=0
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if kubectl get secret "${CLUSTER_NAME}-kubeconfig" -n $TENANT_NAME --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
            echo "Kubeconfig secret for cluster $CLUSTER_NAME found!"
            break
        fi

        echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Kubeconfig secret not found yet, waiting..."
        sleep 5
        ATTEMPT=$((ATTEMPT + 1))
    done

    # Extract the kubeconfig file from the Kubevirt cluster
    kubectl get secret "${CLUSTER_NAME}-kubeconfig" -n $TENANT_NAME -o jsonpath='{.data.value}' | base64 -d > "$OUTPUT_PATH"

    # try to apply the CNI until it works
    echo "Applying CNI plugin to the Kubevirt cluster..."
    MAX_ATTEMPTS=20
    ATTEMPT=0
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.30.1/manifests/calico-typha.yaml --kubeconfig "$OUTPUT_PATH"; then
            echo "CNI plugin applied successfully!"
            break
        fi
        echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Failed to apply CNI plugin, retrying..."
        sleep 15
        ATTEMPT=$((ATTEMPT + 1))
    done
}

delete_cluster() {
    kubectl delete cluster -n $TENANT_NAME --kubeconfig "$KUBECONFIG_PATH"
    kubectl delete namespace "$TENANT_NAME" --kubeconfig "$KUBECONFIG_PATH"
}

# check the number of arguments
if [ "$#" -ne 4 ]; then
    usage
fi

if [ $4 == "uninstall" ]; then
    echo "Uninstalling KubeVirt..."
    delete_cluster
elif [ $4 == "install" ]; then
    echo "Installing KubeVirt..."
    create_cluster
else
    echo "Invalid action. Use 'install' or 'uninstall'."
    exit 1
fi