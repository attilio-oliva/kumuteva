#!/bin/bash

usage() {
    echo "Usage: $0 <tools> <n_tenant> <kubeconfig_path> <duration>"
    echo "  tools: Comma separated list of tools to install [vcluster,capsule,kubevirt,reference]"
    echo "  n_tenant: Number of tenats to generate"
    echo "  kubeconfig_path: Path to kubeconfig file"
    echo "  duration: duration of the load for each tenant"
    exit 1
}

# Check arguments
if [ $# -ne 4 ]; then
    usage
    exit 1
fi

# Check if the Kubernetes cluster is reachable
KUBECONFIG_PATH="$3"
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes >/dev/null 2>&1; then
    echo "Error: Unable to reach the Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

TOOLS="$1"
N_TENANT="$2"
DURATION="$4"

IFS=',' read -ra TOOL_ARRAY <<< "$TOOLS"
for TOOL in "${TOOL_ARRAY[@]}"; do
    sleep 300
    case $TOOL in
        vcluster)
            echo "Provisioning vCluster tenants"
            cd vcluster
            ./run_test.sh create "$N_TENANT" "$KUBECONFIG_PATH" "$DURATION"
            cd ..
            ;;
        capsule)
            echo "Provisioning Capsule tenants"
            cd capsule
            ./run_test.sh "$N_TENANT" "$KUBECONFIG_PATH" "$DURATION"
            cd ..
            ;;
        kubevirt)
            echo "Provisioning KubeVirt tenants"
            cd kubevirt
            ./run_test.sh "$N_TENANT" "$KUBECONFIG_PATH" "$DURATION"
            cd ..
            ;;
        reference)
            echo "Provisioning reference tenants"
            cd reference
            ./run_test.sh "$N_TENANT" "$KUBECONFIG_PATH" "$DURATION"
            cd ..
            ;;
        *)
            echo "Unknown tool: $TOOL"
            usage
            ;;
    esac
done