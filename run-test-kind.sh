#!/bin/bash
OUT_DIR=$1
SOLUTIONS=$2 # comma-separated list of solutions to test, e.g. "solution1,solution2"
TYPES=$3 # comma-separated list of test types to run, e.g. "control-plane,network,storage,workload" or "all"
CLUSTER_NAME="kumuteva"

if [[ -z $SOLUTIONS ]]; then
    echo "No solutions specified. Please provide a comma-separated list of solutions to test."
    exit 1
fi

if [[ -z $OUT_DIR ]]; then
    echo "No output directory specified. Please provide an output directory for the test results."
    exit 1
fi

mkdir -p $OUT_DIR

TYPES_ARRAY=()
if [[ "$TYPES" == "all" ]]; then
    TYPES_ARRAY=("control-plane" "network" "storage" "workload")
else
    IFS=',' read -ra TYPES_ARRAY <<< "$TYPES"
fi

echo "Running tests for solutions: $SOLUTIONS"
echo "Test types: ${TYPES_ARRAY[*]}"

for SOLUTION in $(echo $SOLUTIONS | tr "," "\n"); do
    echo "Running tests for solution: $SOLUTION"
    echo "Setting up tenant1 and tenant2 for $SOLUTION"
    ./kumuteva setup -t $SOLUTION --cluster $CLUSTER_NAME
    sleep 15 # Wait for the setup to complete

    # Run the fairness test for the control plane
    mkdir -p $OUT_DIR/$SOLUTION

    if [[ "${TYPES_ARRAY[*]}" =~ "control-plane" ]]; then
        echo "Running fairness test for control plane of $SOLUTION"
        ./kumuteva fairness /tmp/tenant1-kumuteva-$SOLUTION.kubeconfig /tmp/tenant2-kumuteva-$SOLUTION.kubeconfig -f fairness-config.yaml -o $OUT_DIR/$SOLUTION --control-plane --load-multiplier 20 --cp-requesters 10 > $OUT_DIR/$SOLUTION/control-plane.log
        sleep 15 # Wait for the test to clean up
    fi

    if [[ "${TYPES_ARRAY[*]}" =~ "network" ]]; then
        echo "Running fairness test for data plane of $SOLUTION"
        ./kumuteva fairness /tmp/tenant1-kumuteva-$SOLUTION.kubeconfig /tmp/tenant2-kumuteva-$SOLUTION.kubeconfig -f fairness-config.yaml -o $OUT_DIR/$SOLUTION --network> $OUT_DIR/$SOLUTION/network.log
        sleep 15 # Wait for the test to clean up
    fi

    if [[ "${TYPES_ARRAY[*]}" =~ "storage" ]]; then
        echo "Running fairness test for storage of $SOLUTION"
        ./kumuteva fairness /tmp/tenant1-kumuteva-$SOLUTION.kubeconfig /tmp/tenant2-kumuteva-$SOLUTION.kubeconfig -f fairness-config.yaml -o $OUT_DIR/$SOLUTION --storage > $OUT_DIR/$SOLUTION/storage.log
        sleep 15 # Wait for the test to clean up
    fi

    if [[ "${TYPES_ARRAY[*]}" =~ "workload" ]]; then
        echo "Running fairness test for workload of $SOLUTION"
        ./kumuteva fairness /tmp/tenant1-kumuteva-$SOLUTION.kubeconfig /tmp/tenant2-kumuteva-$SOLUTION.kubeconfig -f fairness-config.yaml -o $OUT_DIR/$SOLUTION --workload > $OUT_DIR/$SOLUTION/workload.log
        sleep 15 # Wait for the test to clean up
    fi

    kind delete cluster --name $CLUSTER_NAME-$SOLUTION
    sleep 5 # Wait for the cluster to be deleted before starting the next one
done
