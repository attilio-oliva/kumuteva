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

# Check if overhead file exists, if not create and add header
if [ ! -f ../results/overhead_kubevirt.csv ]; then
    touch ../results/overhead_kubevirt.csv
else
    rm ../results/overhead_kubevirt.csv
fi

echo "Start,End,Num_Tenants" > ../results/overhead_kubevirt.csv

echo "Installing KubeVirt..."
./deploy-kubevirt.sh "install" $KUBECONFIG_PATH &> /dev/null
./deploy-capi-provider.sh "install" $KUBECONFIG_PATH &> /dev/null

for i in $(seq 5 5 "$N_TENANT"); do
    echo "Running test with $i tenants"
    for j in $(seq 1 "$i"); do
        ./create-kubevirt-cluster.sh $KUBECONFIG_PATH "/tmp/kubeconfig-tenant$j" "tenant$j" "install" &> /dev/null
    done

    sleep 300

    ../load/generate_load.sh "$i" "tenant" "../results/overhead_kubevirt.csv"

    for j in $(seq 1 "$i"); do
        ./create-kubevirt-cluster.sh $KUBECONFIG_PATH "/tmp/kubeconfig-tenant$j" "tenant$j" "uninstall" &> /dev/null
    done
done

echo "Uninstalling KubeVirt..."
./deploy-capi-provider.sh "uninstall" $KUBECONFIG_PATH &> /dev/null
./deploy-kubevirt.sh "uninstall" $KUBECONFIG_PATH &> /dev/null