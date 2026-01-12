#!/bin/bash

usage() {
    echo "Usage: $0 <action> <n_tenant> <kubeconfig_path>"
    echo "  action: Action to perform [create, teardown]"
    echo "  n_tenant: Number of tenats to generate"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
}

# Check arguments
if [ $# -ne 3 ]; then
    usage
fi

create_tenants() {
    echo "Creating $1 tenants"

    for i in $(seq 1 "$1"); do
        NAMESPACE="tenant${i}"
        KUBECONFIG_PATH="/tmp/kubeconfig-${NAMESPACE}"

        echo " - Provisioning vCluster for $NAMESPACE"
        helm upgrade --install $NAMESPACE vcluster --repo https://charts.loft.sh --namespace $NAMESPACE --create-namespace --repository-config='' --values vcluster-config.yaml &> /dev/null

        resource_name="vc-$NAMESPACE"
        kubeconfig_path="/tmp/kubeconfig-$NAMESPACE"

        while [ true ]; do
            if kubectl get secret "$resource_name" -n "$NAMESPACE" >/dev/null 2>&1; then
                kubectl get secret "$resource_name" -n "$NAMESPACE" -o jsonpath='{.data.config}' | base64 -d > "$kubeconfig_path"
                break
            fi
        done

        kubectl patch service $NAMESPACE -n $NAMESPACE -p '{"spec": {"type": "NodePort"}}' &> /dev/null
        port=$(kubectl get svc $NAMESPACE -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')
        sed -i "s#server: https://[^:]\+:[0-9]\+#server: https://localhost:${port}#" $kubeconfig_path

    done
}

teardown_tenants() {
    echo "Tearing down $1 tenants"

    for j in $(seq 1 "$1"); do
        NAMESPACE="tenant${j}"

        echo " - Tearing down vCluster for $NAMESPACE" 
        helm uninstall $NAMESPACE -n $NAMESPACE &> /dev/null

        kubectl delete namespace $NAMESPACE &> /dev/null
    done
}

ACTION="$1"
N_TENANT="$2"

export KUBECONFIG="$3"

# Check if overhead file exists, if not create and add header
if [ ! -f ../results/overhead_vcluster.csv ]; then
    touch ../results/overhead_vcluster.csv
else
    rm ../results/overhead_vcluster.csv
fi

echo "Start,End,Num_Tenants" > ../results/overhead_vcluster.csv

if [ "$ACTION" == "create" ]; then
    for i in $(seq 5 5 "$N_TENANT"); do
        echo "Running tests with $i tenants"

        create_tenants "$i"

        sleep 300
        ../load/generate_load.sh "$i" "default" "../results/overhead_vcluster.csv"
        teardown_tenants "$i"
    done
    
elif [ "$ACTION" == "teardown" ]; then
    teardown_tenants "$N_TENANT"
else
    usage
fi




