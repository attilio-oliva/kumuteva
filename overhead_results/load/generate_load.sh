#!/bin/bash

worker() {
    id=$1
    duration=$2
    namespace=$3
    result_file=$4

    # --- UNIQUE IDENTIFIERS ---
    # We append the worker ID to the deployment name.
    # 'kubectl create deployment' automatically adds the label 'app=nginx-$id' to the pods.
    DEPLOY_NAME="nginx-$id"
    LABEL_SELECTOR="app=$DEPLOY_NAME"
    
    # Common flags for brevity
    KUBE_FLAGS="--kubeconfig=/tmp/kubeconfig-tenant$id -n $namespace"

    cycles=0

    # Wait for cluster connectivity before starting
    while ! kubectl get po $KUBE_FLAGS &> /dev/null; do
        sleep 1
    done

    start=$(date +%s)

    while [ $(( $(date +%s) - start )) -lt "$duration" ]; do
        
        # --- 1. CREATE ---
        # Create deployment with a unique name per worker
        kubectl create deployment "$DEPLOY_NAME" --image=nginx $KUBE_FLAGS 
        
        # Wait for the Deployment Controller to observe the change
        kubectl rollout status "deployment/$DEPLOY_NAME" $KUBE_FLAGS 
        
        # Wait for this specific worker's Pods to be Ready
        kubectl wait --for=condition=ready pod -l "$LABEL_SELECTOR" --timeout=60s $KUBE_FLAGS  

        # --- 2. CONFIGMAP ---
        # We also suffix the configmap to prevent collisions if using the same namespace
        kubectl create configmap "example-config-$id" --from-literal=key1=value1 $KUBE_FLAGS  

        # --- 3. SCALE ---
        kubectl scale "deployment/$DEPLOY_NAME" --replicas=2 $KUBE_FLAGS  
        
        # Wait for the scaled Pods (specifically ours) to be Ready
        kubectl wait --for=condition=ready pod -l "$LABEL_SELECTOR" --timeout=60s $KUBE_FLAGS  

        # --- 4. DELETE RESOURCES ---
        kubectl delete configmap "example-config-$id" $KUBE_FLAGS 
        
        kubectl delete deployment "$DEPLOY_NAME" $KUBE_FLAGS  

        # --- 5. WAIT FOR DELETION ---
        # Wait specifically for OUR pods to disappear
        kubectl wait --for=delete pod -l "$LABEL_SELECTOR" --timeout=60s $KUBE_FLAGS  

        ((cycles++))
    done

    echo "$cycles" > "$result_file"
}


echo "Running tests..."
n_tenant=$1
namespace=$2
time=$4
out_file=$3

cur_time=$(date +"%Y%m%d_%H%M%S")

declare -A pids
declare -A results

for ((k=1; k<=n_tenant; k++)); do
    if [ "$namespace" == "default" ]; then
        t_namespace=$namespace
    else
        t_namespace="tenant$k"
    fi

    result_file=$(mktemp)
    results[$k]=$result_file

    worker "$k" "$time" "$t_namespace" "$result_file" &
    pids[$k]=$!
done

total_cycles=0

for k in "${!pids[@]}"; do
    wait "${pids[$k]}"
    cycles=$(cat "${results[$k]}")
    rm -f "${results[$k]}"

    echo "Tenant $k cycles: $cycles"
    ((total_cycles+=cycles))
done

end_time=$(date +"%Y%m%d_%H%M%S")

echo "$cur_time,$end_time,$n_tenant,$total_cycles" >> "$out_file"

echo "All tests completed."