#!/bin/bash
set -e  # Exit on any error

KUBECONFIG_PATH="$1"
if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

# Function to wait for deployment to exist
wait_for_deployment_to_exist() {
    local deployment_name="$1"
    local namespace="$2"
    local max_attempts=60
    local attempt=0
    
    echo "Waiting for deployment $deployment_name in namespace $namespace to exist..."
    
    while [ $attempt -lt $max_attempts ]; do
        if kubectl get deployment "$deployment_name" -n "$namespace" --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
            echo "Deployment $deployment_name found!"
            return 0
        fi
        
        echo "Attempt $((attempt + 1))/$max_attempts: Deployment $deployment_name not found yet, waiting..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "Error: Deployment $deployment_name not found after $max_attempts attempts"
    return 1
}

# Function to wait for deployment to be ready
wait_for_deployment_ready() {
    local deployment_name="$1"
    local namespace="$2"
    
    echo "Waiting for deployment $deployment_name in namespace $namespace to be ready..."
    kubectl rollout status deployment/"$deployment_name" -n "$namespace" --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
    echo "Deployment $deployment_name is ready!"
}

# Check if CAPI is already installed
if kubectl get ns capi-system --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
    echo "CAPI is already installed. Exiting."
    exit 0
fi

echo "Setting up Helm repositories..."
helm repo add capi-operator https://kubernetes-sigs.github.io/cluster-api-operator
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update

echo "Installing cert-manager..."
helm install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --create-namespace \
    --set installCRDs=true \
    --wait \
    --timeout 90s \
    --kubeconfig "$KUBECONFIG_PATH"

echo "Installing CAPI operator..."
helm install capi-operator capi-operator/cluster-api-operator \
    --create-namespace \
    -n capi-operator-system \
    --set infrastructure.kubevirt.enabled=true \
    --set cert-manager.enabled=true \
    --wait \
    --timeout 300s \
    --kubeconfig "$KUBECONFIG_PATH"

echo "Waiting for all CAPI controllers to be deployed and ready..."

# Wait for deployments to exist first, then check if they're ready
wait_for_deployment_to_exist "capi-controller-manager" "capi-system"
wait_for_deployment_ready "capi-controller-manager" "capi-system"

wait_for_deployment_to_exist "capi-kubeadm-bootstrap-controller-manager" "capi-kubeadm-bootstrap-system"
wait_for_deployment_ready "capi-kubeadm-bootstrap-controller-manager" "capi-kubeadm-bootstrap-system"

wait_for_deployment_to_exist "capi-kubeadm-control-plane-controller-manager" "capi-kubeadm-control-plane-system"
wait_for_deployment_ready "capi-kubeadm-control-plane-controller-manager" "capi-kubeadm-control-plane-system"

wait_for_deployment_to_exist "capk-controller-manager" "kubevirt-infrastructure-system"
wait_for_deployment_ready "capk-controller-manager" "kubevirt-infrastructure-system"

echo "All CAPI controllers are ready!"
echo "CAPI installation completed successfully!"