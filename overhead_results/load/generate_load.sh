#!/bin/bash

worker() {
    id=$1
    duration=$2
    namespace=$3

    # check if the cluster is ready to accept commands
    while ! kubectl get po --kubeconfig="/tmp/kubeconfig-tenant$id" -n $namespace &> /dev/null; do
        sleep 1
    done

    echo " - Thread $id: starting, will run for $duration seconds"
    start=$(date +%s)

    # Simulate a sequence of operations
    while [ $(( $(date +%s) - start )) -lt $duration ]; do
        kubectl create deployment nginx --image=nginx --kubeconfig="/tmp/kubeconfig-tenant$id" -n $namespace &> /dev/null
        kubectl create configmap example-config --from-literal=key1=value1 --kubeconfig="/tmp/kubeconfig-tenant$id" -n $namespace &> /dev/null
        kubectl scale deployment nginx --replicas=3 --kubeconfig="/tmp/kubeconfig-tenant$id" -n $namespace &> /dev/null
        kubectl delete configmap example-config --kubeconfig="/tmp/kubeconfig-tenant$id" -n $namespace &> /dev/null
        kubectl delete deployment nginx --kubeconfig="/tmp/kubeconfig-tenant$id" -n $namespace &> /dev/null
    done

    echo " - Thread $id: finished"
}

echo "Running tests..."
n_tenant=$1
namespace=$2
duration=10

for ((k=1; k<=n_tenant; k++)); do
    t_namespace="" 
    if [ "$namespace" == "default" ]; then 
        t_namespace=$namespace
    else
        t_namespace="tenant$k"
    fi
    worker "$k" "$duration" "$t_namespace" &
    pids[$k]=$!
done

for pid in "${pids[@]}"; do
    wait "$pid"
done

echo "All tests completed."
