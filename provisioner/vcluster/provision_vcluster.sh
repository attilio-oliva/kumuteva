#!/bin/bash
# filepath: deploy_vcluster.sh

set -euo pipefail

# Function to display usage
usage() {
    echo "Usage: $0 <namespace> <kubeconfig_path> <kind_kubeconfig_path> <host_port> <container_port>"
    echo "  namespace: Target namespace for vCluster (e.g., tenant1, tenant2)"
    echo "  kubeconfig_path: Path where tenant kubeconfig will be saved"
    echo "  kind_kubeconfig_path: Path to kind cluster kubeconfig"
    echo "  host_port: Host port for NodePort service"
    echo "  container_port: Container port for NodePort service"
    exit 1
}

# Check arguments
if [ $# -ne 5 ]; then
    usage
fi

NAMESPACE="$1"
KUBECONFIG_PATH="$2"
KIND_KUBECONFIG_PATH="$3"
HOST_PORT="$4"
CONTAINER_PORT="$5"

RELEASE_NAME="vcluster-${NAMESPACE}"
VCLUSTER_VALUES_PATH="vcluster.yaml"

echo "Deploying vCluster in namespace: $NAMESPACE"

# Create vCluster Helm values file
create_vcluster_values() {
    cat > "$VCLUSTER_VALUES_PATH" <<EOF
controlPlane:
  distro:
    k8s:
      enabled: true
  backingStore:
    etcd:
      deploy:
        enabled: true
exportKubeConfig:
  insecure: true
sync:
  fromHost:
    nodes:
      enabled: true
      syncBackChanges: true
    storageClasses:
      enabled: true
EOF
}

# Wait for pod to be ready
wait_for_pod_ready() {
    local pod_name="$1"
    local namespace="$2"
    local timeout=300
    local interval=5
    local elapsed=0

    echo "Waiting for pod $pod_name to be ready..."
    
    while [ $elapsed -lt $timeout ]; do
        if kubectl --kubeconfig="$KIND_KUBECONFIG_PATH" get pod "$pod_name" -n "$namespace" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q "Running"; then
            echo "Pod $pod_name is ready"
            return 0
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        echo "Waiting... ($elapsed/${timeout}s)"
    done
    
    echo "Timeout waiting for pod $pod_name to be ready"
    return 1
}

# Wait for resource to be created
wait_for_resource() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace="$3"
    local timeout=300
    local interval=5
    local elapsed=0

    echo "Waiting for $resource_type/$resource_name to be created..."
    
    while [ $elapsed -lt $timeout ]; do
        if kubectl --kubeconfig="$KIND_KUBECONFIG_PATH" get "$resource_type" "$resource_name" -n "$namespace" >/dev/null 2>&1; then
            echo "$resource_type/$resource_name is available"
            return 0
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        echo "Waiting... ($elapsed/${timeout}s)"
    done
    
    echo "Timeout waiting for $resource_type/$resource_name"
    return 1
}

# Extract vCluster kubeconfig from secret
get_vcluster_kubeconfig() {
    local namespace="$1"
    local release_name="$2"
    local secret_name="vc-${release_name}"
    
    echo "Extracting kubeconfig from secret: $secret_name"
    
    # Wait for secret to be created
    wait_for_resource "secret" "$secret_name" "$namespace"
    
    # Extract and decode the kubeconfig
    kubectl --kubeconfig="$KIND_KUBECONFIG_PATH" get secret "$secret_name" \
        -n "$namespace" \
        -o jsonpath='{.data.config}' | base64 -d
}

# Create NodePort service for vCluster
create_nodeport_service() {
    local namespace="$1"
    local container_port="$2"
    
    cat <<EOF | kubectl --kubeconfig="$KIND_KUBECONFIG_PATH" apply -f -
apiVersion: v1
kind: Service
metadata:
  name: vcluster-service
  namespace: $namespace
spec:
  type: NodePort
  selector:
    app: vcluster
    release: vcluster-$namespace
  ports:
  - name: https
    port: 443
    targetPort: 8443
    protocol: TCP
    nodePort: $container_port
EOF
}

# Main deployment process
main() {
    # Create vCluster values file
    echo "Creating vCluster Helm values..."
    create_vcluster_values
    
    # Deploy vCluster using Helm
    echo "Deploying vCluster with Helm..."
    helm upgrade --install "$RELEASE_NAME" vcluster \
        --values "$VCLUSTER_VALUES_PATH" \
        --repo https://charts.loft.sh \
        --namespace "$NAMESPACE" \
        --create-namespace \
        --kubeconfig "$KIND_KUBECONFIG_PATH"
    
    if [ $? -ne 0 ]; then
        echo "Failed to deploy vCluster"
        exit 1
    fi
    
    # Wait for vCluster pod to appear and be ready
    echo "Waiting for vCluster pod to appear..."
    sleep 10
    
    # Find the vCluster pod
    local pod_name
    local retries=5
    local retry_count=0
    
    while [ $retry_count -lt $retries ]; do
        pod_name=$(kubectl --kubeconfig="$KIND_KUBECONFIG_PATH" get pods \
            -n "$NAMESPACE" \
            -l app=vcluster \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        
        if [ -n "$pod_name" ] && [ "$pod_name" != "null" ]; then
            break
        fi
        
        echo "Pod not found, retrying... ($((retry_count + 1))/$retries)"
        sleep 5
        retry_count=$((retry_count + 1))
    done
    
    if [ -z "$pod_name" ] || [ "$pod_name" = "null" ]; then
        echo "Failed to find vCluster pod"
        exit 1
    fi
    
    echo "Found vCluster pod: $pod_name"
    
    # Wait for pod to be ready
    wait_for_pod_ready "$pod_name" "$NAMESPACE"
    
    # Extract vCluster kubeconfig
    echo "Extracting vCluster kubeconfig..."
    local vcluster_kubeconfig
    vcluster_kubeconfig=$(get_vcluster_kubeconfig "$NAMESPACE" "$RELEASE_NAME")
    
    if [ -z "$vcluster_kubeconfig" ]; then
        echo "Failed to extract vCluster kubeconfig"
        exit 1
    fi
    
    # Save kubeconfig to file
    echo "$vcluster_kubeconfig" > "$KUBECONFIG_PATH"
    echo "Saved vCluster kubeconfig to: $KUBECONFIG_PATH"
    
    # Create NodePort service
    echo "Creating NodePort service..."
    create_nodeport_service "$NAMESPACE" "$CONTAINER_PORT"
    
    # Update kubeconfig to use the correct port
    echo "Updating kubeconfig to use host port $HOST_PORT..."
    sed -i "s/8443/$HOST_PORT/g" "$KUBECONFIG_PATH"
    
    # Wait for vCluster to be ready and create namespace
    echo "Waiting for vCluster to be ready..."
    local ready_retries=10
    local ready_count=0
    
    while [ $ready_count -lt $ready_retries ]; do
        if kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
            echo "vCluster is ready"
            break
        fi
        
        echo "vCluster not ready yet, waiting... ($((ready_count + 1))/$ready_retries)"
        sleep 10
        ready_count=$((ready_count + 1))
    done
    
    if [ $ready_count -eq $ready_retries ]; then
        echo "Warning: vCluster may not be fully ready, but continuing..."
    fi
    
    # Create namespace in vCluster
    echo "Creating namespace $NAMESPACE in vCluster..."
    kubectl --kubeconfig="$KUBECONFIG_PATH" create namespace "$NAMESPACE" --dry-run=client -o yaml | \
        kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f -
    
    # Clean up values file
    rm -f "$VCLUSTER_VALUES_PATH"
    
    echo "vCluster deployment completed successfully!"
    echo "Tenant kubeconfig saved to: $KUBECONFIG_PATH"
    echo "vCluster accessible via NodePort on port: $HOST_PORT"
}

# Run main function
main "$@"