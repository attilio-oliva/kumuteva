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

# Wait for a Service to have at least one ready backing address.
#
# A Deployment reporting rolled-out is not the same as its webhook answering:
# the Service can exist with no endpoints while the pod finishes starting or
# while cert-manager injects the serving certificate. Applying cluster manifests
# in that window fails with "connection refused" from the API server's webhook
# call, and CAPI then never creates the machines.
wait_for_endpoints() {
    local service_name="$1" namespace="$2"
    local max_attempts=60 attempt=0

    echo "Waiting for service $service_name in namespace $namespace to have endpoints..."
    while [ $attempt -lt $max_attempts ]; do
        if [ -n "$(kubectl get endpoints "$service_name" -n "$namespace" \
                --kubeconfig "$KUBECONFIG_PATH" \
                -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null)" ]; then
            echo "Service $service_name has endpoints!"
            return 0
        fi
        sleep 5
        attempt=$((attempt + 1))
    done

    echo "Error: service $service_name has no endpoints after $max_attempts attempts"
    return 1
}

# An existing capi-system means the install ran before — but not that it
# finished, and not that anything is ready now. Skip the install, never the
# readiness checks: exiting here outright is what let the cluster manifests be
# applied against a CAPK webhook that was not yet serving.
CAPI_ALREADY_INSTALLED=false
if kubectl get ns capi-system --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
    echo "CAPI is already installed; verifying it is ready."
    CAPI_ALREADY_INSTALLED=true
fi

if [ "$CAPI_ALREADY_INSTALLED" = false ]; then
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

fi

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

# Every webhook that the cluster manifests will touch, not just the
# infrastructure one.
#
# A Deployment reporting Ready is not the same as its Service having endpoints:
# the rollout completes when the pod passes its readiness probe, and the
# endpoint slice is written moments later. Applying a Cluster or a
# KubeadmControlPlane in that window reaches the *conversion* webhook for
# cluster.x-k8s.io/v1beta1, and the apply dies with
#
#   conversion webhook for controlplane.cluster.x-k8s.io/v1beta1,
#   Kind=KubeadmControlPlane failed: dial tcp ...:443: connect: connection refused
#
# after some manifests have already been created — so the failure is both
# confusing and partial. Only capk-webhook-service was waited for, which is why
# the infrastructure objects applied and the control-plane ones did not.
wait_for_endpoints "capi-webhook-service" "capi-system"
wait_for_endpoints "capi-kubeadm-bootstrap-webhook-service" "capi-kubeadm-bootstrap-system"
wait_for_endpoints "capi-kubeadm-control-plane-webhook-service" "capi-kubeadm-control-plane-system"
wait_for_endpoints "capk-webhook-service" "kubevirt-infrastructure-system"

echo "All CAPI controllers are ready!"
echo "CAPI installation completed successfully!"