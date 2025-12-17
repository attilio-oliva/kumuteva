#!/bin/bash

usage() {
    echo "Usage: $0 <action> <n_tenant> <kubeconfig_path>"
    echo "  n_tenant: Number of tenats to generate"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
}

# Check arguments
if [ $# -ne 2 ]; then
    usage
fi

# logic here
KUBECONFIG_PATH="$2"
N_TENANT="$1"

echo "Installing KubeVirt..."
./deploy-kubevirt.sh "install" $KUBECONFIG_PATH &> /dev/null
./deploy-capi-provider.sh "install" $KUBECONFIG_PATH &> /dev/null

for i in $(seq 1 "$N_TENANT"); do
    echo "Running test with $i tenants"
    for j in $(seq 1 "$i"); do
        ./create-kubevirt-cluster.sh $KUBECONFIG_PATH "/tmp/kubeconfig-tenant$i" "tenant$i" "install" &> /dev/null
    done

    ../load/generate_load.sh "$i" "tenant"

    for j in $(seq 1 "$i"); do
        ./create-kubevirt-cluster.sh $KUBECONFIG_PATH "/tmp/kubeconfig-tenant$i" "tenant$i" "uninstall" &> /dev/null
    done
done

echo "Uninstalling KubeVirt..."
./deploy-capi-provider.sh "uninstall" $KUBECONFIG_PATH &> /dev/null
./deploy-kubevirt.sh "uninstall" $KUBECONFIG_PATH &> /dev/null