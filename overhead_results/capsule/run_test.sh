#!/bin/bash

usage() {
    echo "Usage: $0 <action> <n_tenant> <kubeconfig_path>"
    echo "  n_tenant: Number of tenats to generate"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
}

move_kubeconfig() {
    TENANT_NAME=$1

    mv ${TENANT_NAME}-admin-${TENANT_NAME}.kubeconfig /tmp/kubeconfig-${TENANT_NAME}
    mv ${TENANT_NAME}-admin-${TENANT_NAME}.crt /tmp/${TENANT_NAME}-admin-${TENANT_NAME}.crt
    mv ${TENANT_NAME}-admin-${TENANT_NAME}.key /tmp/${TENANT_NAME}-admin-${TENANT_NAME}.key
}

create_users() {
    echo "Creating $1 tenants"
    for j in $(seq 1 "$1"); do
        TENANT_NAME="tenant${j}"

        echo " - Provisioning capsule for $NAMESPACE"

        ./create-user.sh ${TENANT_NAME}-admin ${TENANT_NAME} &> /dev/null

        move_kubeconfig ${TENANT_NAME}
        kubectl create ns $TENANT_NAME --kubeconfig /tmp/kubeconfig-${TENANT_NAME} &> /dev/null
    done
}

delete_users_namespace() {
    for j in $(seq 1 "$1"); do
        kubectl delete ns $TENANT_NAME &> /dev/null
    done
}

# Check arguments
if [ $# -ne 2 ]; then
    usage
fi

# logic here
for i in $(seq 1 "$1"); do
    ./deploy-capsule.sh "install" $2

    create_users $i

    ../load/generate_load.sh "$i" "tenant"

    delete_users_namespace $i

    ./deploy-capsule.sh "uninstall" $2
done

