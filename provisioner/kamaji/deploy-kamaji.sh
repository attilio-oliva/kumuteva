#!/bin/bash
# Script to deploy Kamaji on a Kind cluster
# Based on: https://kamaji.clastix.io/getting-started/kamaji-kind/
#
# Usage: ./deploy-kamaji.sh [KUBECONFIG_PATH]

set -e

KUBECONFIG_PATH="${1:-$HOME/.kube/config}"
export KUBECONFIG="$KUBECONFIG_PATH"

echo "Installing Kamaji with kubeconfig: $KUBECONFIG_PATH"

# Add required helm repos
echo "Adding Helm repositories..."
helm repo add jetstack https://charts.jetstack.io || true
helm repo add clastix https://clastix.github.io/charts || true
helm repo update

# Install cert-manager (dependency)
echo "Installing cert-manager..."
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set "crds.enabled=true" \
  --wait \
  --timeout 5m

# Install MetalLB for LoadBalancer support
echo "Installing MetalLB..."
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml

# Wait for MetalLB to be ready
echo "Waiting for MetalLB pods to be ready..."
kubectl wait --namespace metallb-system \
  --for=condition=ready pod \
  --selector=app=metallb \
  --timeout=120s || true

sleep 10

# Configure MetalLB IP address pool
echo "Configuring MetalLB IP address pool..."
GW_IP=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' kind 2>/dev/null || echo "172.19.0.1")
NET_IP=$(echo ${GW_IP} | sed -E 's|^([0-9]+\.[0-9]+)\..*$|\1|g')

cat << EOF | kubectl apply -f -
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kind-ip-pool
  namespace: metallb-system
spec:
  addresses:
  - ${NET_IP}.255.200-${NET_IP}.255.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
EOF

# Install Kamaji
echo "Installing Kamaji..."
helm upgrade --install kamaji clastix/kamaji \
  --namespace kamaji-system \
  --create-namespace \
  --set 'resources=null' \
  --wait \
  --timeout 5m

echo "Verifying Kamaji installation..."
kubectl get crds | grep -i kamaji

echo "Kamaji installation complete!"
echo ""
echo "To create a tenant control plane, use:"
echo "  kubectl apply -f provisioner/kamaji/tenant-control-plane.yaml"
