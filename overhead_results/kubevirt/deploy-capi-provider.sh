#!/bin/bash
set -e  # Exit on any error

usage() {
    echo "Usage: $0 <action> <kubeconfig_path>"
    echo "  action: [install,uninstall]"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
}

# Check the number of arguments
if [ "$#" -ne 2 ]; then
    usage
fi

ACTION="$1"
KUBECONFIG_PATH="$2"

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

install_capi() {
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
}

uninstall_capi() {
    helm uninstall capi-operator -n capi-operator-system --kubeconfig "$KUBECONFIG_PATH"
    helm uninstall cert-manager -n cert-manager --kubeconfig "$KUBECONFIG_PATH"
    kubectl delete ns capi-operator-system cert-manager --kubeconfig "$KUBECONFIG_PATH"
    #kubectl delete ns capi-kubeadm-bootstrap-system --kubeconfig "$KUBECONFIG_PATH"
    #kubectl delete ns capi-kubeadm-control-plane-system --kubeconfig "$KUBECONFIG_PATH"
    echo "CAPI uninstalled successfully!"
}

if [ "$ACTION" == "uninstall" ]; then
    echo "Uninstalling CAPI..."
    uninstall_capi
elif [ "$ACTION" == "install" ]; then
    echo "Installing CAPI..."
    install_capi
else
    echo "Invalid action. Use 'install' or 'uninstall'."
    exit 1
fi