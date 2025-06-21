#!/bin/bash
KV_VER="v1.5.0"
USE_NESTED_VIRTUALIZATION="n"
KUBECONFIG_PATH="$1"

if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

# Check if KubeVirt is already installed
if kubectl get ns kubevirt --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
    echo "KubeVirt is already installed. Exiting."
    exit 0
fi

# deploy required CRDs
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-operator.yaml" --kubeconfig "$KUBECONFIG_PATH"
# deploy the KubeVirt custom resource
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-cr.yaml" --kubeconfig "$KUBECONFIG_PATH"

kubectl wait -n kubevirt kv kubevirt --for=condition=Available --timeout=10m --kubeconfig "$KUBECONFIG_PATH"

if [ $USE_NESTED_VIRTUALIZATION == "y" ]; then
    kubectl -n kubevirt patch kubevirt kubevirt --type=merge --patch '{"spec":{"configuration":{"developerConfiguration":{"useEmulation":true}}}}' --kubeconfig "$KUBECONFIG_PATH"
fi