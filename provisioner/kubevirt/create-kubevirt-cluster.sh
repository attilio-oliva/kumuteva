#!/bin/bash
KUBECONFIG_PATH="$1"
OUTPUT_PATH="$2"
TENANT_NAME="$3"
EXPOSE_NODEPORT_API_SERVER="$4"
NODEPORT_API_SERVER_PORT="$5"
KUBECONFIG_API_SERVER_PORT="$6"

KUBECONFIG_API_SERVER_PORT=${KUBECONFIG_API_SERVER_PORT:-6443}
NODEPORT_API_SERVER_PORT=${NODEPORT_API_SERVER_PORT:-30064}

CNI_PLUGIN_YAML_PATH=${CNI_PLUGIN_YAML_PATH:-"https://raw.githubusercontent.com/projectcalico/calico/v3.30.1/manifests/calico-typha.yaml"}

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$KUBECONFIG_PATH" ] || [ -z "$OUTPUT_PATH" ] || [ -z "$TENANT_NAME" ]; then
    echo "Usage: $0 <kubeconfig_path> <output_path> <tenant_name>"
    exit 1
fi

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

# Extract the kubeconfig file from the Kubevirt cluster
echo "Waiting for Kubeconfig secret to be generated..."
max_attempts=3
attempt=0
while [ $attempt -lt $max_attempts ]; do
    # This secret is created by the Kubeadm Control Plane provider
    if ! kubectl get secret "${CLUSTER_NAME}-kubeconfig" -n "$NAMESPACE" --kubeconfig "$KUBECONFIG_PATH" >/dev/null 2>&1; then
        echo "Kubeconfig secret not found yet, waiting..."
        sleep 5
        attempt=$((attempt + 1))
    else
        echo "Kubeconfig secret found!"
        break
    fi
done

echo "Extracting kubeconfig for cluster $CLUSTER_NAME in namespace $NAMESPACE..."
kubectl get secret "${CLUSTER_NAME}-kubeconfig"  -n "$NAMESPACE" --kubeconfig "$KUBECONFIG_PATH" -o jsonpath='{.data.value}' | base64 -d > "$OUTPUT_PATH"

# Remap the server address in the extracted kubeconfig to use localhost and the NodePort
echo "Setting API server address to $API_SERVER_ADDRESS in the extracted kubeconfig..."
if [ "$EXPOSE_NODEPORT_API_SERVER" = "y" ]; then
  API_SERVER_ADDRESS="https://127.0.0.1:${KUBECONFIG_API_SERVER_PORT}"
  kubectl config --kubeconfig="$OUTPUT_PATH" set-cluster "$CLUSTER_NAME" --server="$API_SERVER_ADDRESS"
  # Set insecure-skip-tls-verify to true for simplicity
  kubectl config --kubeconfig="$OUTPUT_PATH" set-cluster "$CLUSTER_NAME" --insecure-skip-tls-verify=true
fi
# Check the control plane VMI name
CONTROL_PLANE_VMI=$(kubectl get vmi -n "$NAMESPACE" -l "cluster.x-k8s.io/cluster-name=$CLUSTER_NAME,cluster.x-k8s.io/role=control-plane" -o jsonpath='{.items[0].metadata.name}' --kubeconfig "$KUBECONFIG_PATH" 2>/dev/null)
 if [ -z "$CONTROL_PLANE_VMI" ]; then
    echo "Control plane VMI not found for cluster $CLUSTER_NAME in namespace $NAMESPACE."
    exit 1
fi 

# Expose the api server of the Kubevirt cluster as a NodePort service
echo "Exposing API server of cluster $CLUSTER_NAME as NodePort service..."

cat <<EOF | kubectl apply --kubeconfig "$KUBECONFIG_PATH" -f -
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

# Deploy CNI plugin
echo "Deploying Calico CNI plugin inside cluster $CLUSTER_NAME with the extracted kubeconfig..."
MAX_ATTEMPTS=20
    ATTEMPT=0
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if kubectl apply -f "$CNI_PLUGIN_YAML_PATH" --kubeconfig "$OUTPUT_PATH"; then
            echo "CNI operator applied successfully!"
            break
        fi
        echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Failed to apply CNI operator, retrying..."
        sleep 15
        ATTEMPT=$((ATTEMPT + 1))
    done

    kubectl taint node --kubeconfig "$OUTPUT_PATH" node-role.kubernetes.io/control-plane:NoSchedule- --all


# Install a basic storage class 
echo "Installing local-path-storage for storage inside cluster $CLUSTER_NAME with the extracted kubeconfig..."
kubectl apply -f kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.34/deploy/local-path-storage.yaml --kubeconfig "$OUTPUT_PATH"
# Set local-path as the default storage class
kubectl patch storageclass local-path --kubeconfig "$OUTPUT_PATH" -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

# Wait for the cluster to be ready

# Seems like Kubevirt clusters custom resource does not update to 'Ready' even after the cluster effectively becomes ready.
# echo "Waiting for cluster $CLUSTER_NAME to be ready..."
# kubectl wait --for=condition=Ready --timeout=10m -n "$NAMESPACE" cluster "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_PATH"



