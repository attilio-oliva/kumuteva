#!/bin/bash

install_kubevirt() {
    # Check if KubeVirt is already installed
    if kubectl get ns kubevirt --kubeconfig "$KUBECONFIG_PATH" &> /dev/null ; then
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
}

uninstall_kubevirt() {
    # Check if KubeVirt is already installed
    if ! kubectl get ns kubevirt --kubeconfig "$KUBECONFIG_PATH"; then
        echo "KubeVirt is not installed. Exiting."
        exit 0
    fi

    # deploy the KubeVirt custom resource
    kubectl delete -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-cr.yaml" --kubeconfig "$KUBECONFIG_PATH" 
    # deploy required CRDs
    kubectl delete -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-operator.yaml" --kubeconfig "$KUBECONFIG_PATH" 
}

# check the number of arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <action> <kubeconfig_path>"
    echo "  action: [install,uninstall]"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
fi

KV_VER="v1.5.0"
USE_NESTED_VIRTUALIZATION="n"
KUBECONFIG_PATH="$2"

if [ $1 == "uninstall" ]; then
    echo "Uninstalling KubeVirt..."
    uninstall_kubevirt
elif [ $1 == "install" ]; then
    echo "Installing KubeVirt..."
    install_kubevirt
else
    echo "Invalid action. Use 'install' or 'uninstall'."
    exit 1
fi