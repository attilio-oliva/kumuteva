#!/bin/bash

usage() {
    echo "Usage: $0 <kubeconfig_path> <output_path> <tenant_name> <action>"
    echo "  kubeconfig_path: Path to kubeconfig file"
    echo "  output_path: Path to save the tenant cluster kubeconfig"
    echo "  tenant_name: Name of the tenant (namespace) to create the cluster in"
    echo "  action: [install,uninstall]"
    exit 1
}

REGISTRY="harbor.crownlabs.polito.it/cloud-sandbox/stefano-galantino"

wait_or_delete_pod() {
    local namespace="$1"
    local sleep_seconds="${2:-2}"

    while true; do
        # Get non-terminating pods
        mapfile -t pods < <(
            kubectl get pods -n "$namespace" -o json |
            jq -r '
                .items[]
                | select(.metadata.deletionTimestamp == null)
                | .metadata.name
            ' 2>/dev/null
        )

        # No active pods yet
        if [[ ${#pods[@]} -eq 0 ]]; then
            sleep "$sleep_seconds"
            continue
        fi

        # Check phases of active pods
        running=0
        failed=0

        for pod in "${pods[@]}"; do
            phase=$(kubectl get pod "$pod" -n "$namespace" \
                -o jsonpath='{.status.phase}')

            case "$phase" in
                Running)
                    ((running++))
                    ;;
                Failed|Unknown)
                    failed=1
                    ;;
                *)
                    ;;
            esac

            # Check container-level errors
            reason=$(kubectl get pod "$pod" -n "$namespace" \
                -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)

            if [[ "$reason" == "CrashLoopBackOff" || "$reason" == "ImagePullBackOff" ]]; then
                failed=1
            fi
        done

        # Success condition: exactly one active pod Running
        if [[ "$running" -eq 1 && "$failed" -eq 0 ]]; then
            return 0
        fi

        # Failure condition: any active pod in error
        if [[ "$failed" -eq 1 ]]; then
            kubectl delete pod "${pods[@]}" -n "$namespace"
            return 1
        fi

        sleep "$sleep_seconds"
    done
}


create_cluster() {
    # Create a Kubevirt Cluster from the provided YAML file
    export CLUSTER_NAME=${TENANT_NAME}-kv
    export NAMESPACE=${TENANT_NAME}
    export NODE_VM_IMAGE_TEMPLATE="quay.io/capk/ubuntu-2404-container-disk:v1.32.1"
    export CONTROL_PLANE_MACHINE_COUNT=1
    export WORKER_MACHINE_COUNT=1
    export KUBERNETES_VERSION="v1.32.1"
    export CRI_PATH="/run/containerd/containerd.sock"

    kubectl create namespace "$NAMESPACE" --kubeconfig "$KUBECONFIG_PATH"

    # save the applied YAML file to this directory
    envsubst < "$THIS_DIR"/tenant-cluster.yaml > "$CLUSTER_NAME"-applied.yaml

    # Replace variables and apply
    envsubst < "$THIS_DIR"/tenant-cluster.yaml | kubectl apply -f - --kubeconfig "$KUBECONFIG_PATH"

    # wait for secret to be created
    echo "Waiting for kubeconfig secret for cluster $CLUSTER_NAME in namespace $NAMESPACE..."
    MAX_ATTEMPTS=20
    ATTEMPT=0
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if kubectl get secret "${CLUSTER_NAME}-kubeconfig" -n $TENANT_NAME --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
            echo "Kubeconfig secret for cluster $CLUSTER_NAME found!"
            break
        fi

        echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Kubeconfig secret not found yet, waiting..."
        sleep 5
        ATTEMPT=$((ATTEMPT + 1))
    done

    # Extract the kubeconfig file from the Kubevirt cluster
    kubectl get secret "${CLUSTER_NAME}-kubeconfig" -n $TENANT_NAME -o jsonpath='{.data.value}' | base64 -d > "$OUTPUT_PATH"

    #wait_or_delete_pod "$TENANT_NAME"
    while true; do
        MAX_ATTEMPTS=20
        ATTEMPT=0
        while true; do
            if kubectl get nodes --kubeconfig "$OUTPUT_PATH" &>/dev/null; then
                break
            fi
            echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Waiting for nodes to be ready..."
            sleep 15
            ATTEMPT=$((ATTEMPT + 1))
            if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
                break
            fi
        done
        if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
            kubectl delete pod -n $TENANT_NAME --all
        else
            break
        fi
    done

    # try to apply the CNI until it works
    echo "Applying CNI plugin to the Kubevirt cluster..."
    # curl -O https://raw.githubusercontent.com/projectcalico/calico/v3.30.5/manifests/tigera-operator.yaml
    # sed -ie "s?quay.io?$REGISTRY?g" tigera-operator.yaml
    # curl -O https://raw.githubusercontent.com/projectcalico/calico/v3.30.5/manifests/custom-resources.yaml
    MAX_ATTEMPTS=20
    ATTEMPT=0
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if kubectl apply -f tigera-operator.yaml --kubeconfig "$OUTPUT_PATH"; then
            echo "CNI operator applied successfully!"
            break
        fi
        echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Failed to apply CNI operator, retrying..."
        sleep 15
        ATTEMPT=$((ATTEMPT + 1))
    done

    MAX_ATTEMPTS=20
    ATTEMPT=0
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if kubectl apply -f custom-resources.yaml --kubeconfig "$OUTPUT_PATH"; then
            echo "CNI resource applied successfully!"
            break
        fi
        echo "Attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS: Failed to apply CNI resource, retrying..."
        sleep 15
        ATTEMPT=$((ATTEMPT + 1))
    done

    kubectl taint node --kubeconfig "$OUTPUT_PATH" node-role.kubernetes.io/control-plane:NoSchedule- --all
}

delete_cluster() {
    kubectl delete cluster -n $TENANT_NAME --kubeconfig "$KUBECONFIG_PATH"
    kubectl delete namespace "$TENANT_NAME" --kubeconfig "$KUBECONFIG_PATH"
}

# check the number of arguments
if [ "$#" -ne 4 ]; then
    usage
fi

KUBECONFIG_PATH="$1"
OUTPUT_PATH="$2"
TENANT_NAME="$3"
API_SERVER_PORT=6443
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $4 == "uninstall" ]; then
    echo "Uninstalling KubeVirt..."
    delete_cluster
elif [ $4 == "install" ]; then
    echo "Installing KubeVirt..."
    create_cluster
else
    echo "Invalid action. Use 'install' or 'uninstall'."
    exit 1
fi