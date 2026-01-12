#!/bin/bash

usage() {
    echo "Usage: $0 <n_tenant> <kubeconfig_path>"
    echo "  n_tenant: Number of tenats to generate"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
}

# Check arguments
if [ $# -ne 2 ]; then
    usage
fi

N_TENANT="$1"

export KUBECONFIG="$2"

# Check if overhead file exists, if not create and add header
if [ ! -f ../results/overhead_reference.csv ]; then
    touch ../results/overhead_reference.csv
else
    rm ../results/overhead_reference.csv
fi

echo "Start,End,Num_Tenants" > ../results/overhead_reference.csv

for i in $(seq 5 5 "$N_TENANT"); do
    echo "Running tests with $i tenants"

    sleep 300

    for j in $(seq 1 1 "$i"); do
        kubectl create namespace "tenant$j" &> /dev/null
        cp $KUBECONFIG /tmp/kubeconfig-tenant$j
    done

    ../load/generate_load.sh "$i" "tenant" "../results/overhead_reference.csv"

    for j in $(seq 1 1 "$i"); do
        kubectl delete namespace "tenant$j" &> /dev/null
    done
done



