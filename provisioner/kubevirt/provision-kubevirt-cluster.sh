#!/bin/bash
set -ex
KUBECONFIG_PATH="$1"
EXPOSED_API_SERVER_PORT_T1=$2
EXPOSED_API_SERVER_PORT_T1=${EXPOSED_API_SERVER_PORT_T1:-6443}
EXPOSED_API_SERVER_PORT_T2=$3
EXPOSED_API_SERVER_PORT_T2=${EXPOSED_API_SERVER_PORT_T2:-6444}

if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

# If a kind cluster is used, a CNI different from the default one is required.
# Install any CNI plugin at this point in that case.
sleep 20 # wait for the kindnet to be ready

./deploy-kubevirt.sh "$1"
./deploy-capi-provider.sh "$1"

./create-kubevirt-cluster.sh  "$1" "/tmp/kubevirt-cluster-tenant1.yaml" "tenant1" ${EXPOSED_API_SERVER_PORT_T1}
./create-kubevirt-cluster.sh  "$1" "/tmp/kubevirt-cluster-tenant2.yaml" "tenant2" ${EXPOSED_API_SERVER_PORT_T2}
