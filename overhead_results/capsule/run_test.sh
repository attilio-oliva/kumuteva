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

        echo " - Provisioning capsule for $TENANT_NAME"

        ./create-user.sh ${TENANT_NAME}-admin ${TENANT_NAME} &> /dev/null

        move_kubeconfig ${TENANT_NAME}
        kubectl create ns $TENANT_NAME --kubeconfig /tmp/kubeconfig-${TENANT_NAME} &> /dev/null
        sleep 1
    done
}

delete_users_namespace() {
    for j in $(seq 1 "$1"); do
        kubectl delete ns $TENANT_NAME &> /dev/null
        sleep 1
    done
}

# Check arguments
if [ $# -ne 2 ]; then
    usage
fi

# Check if overhead file exists, if not create and add header
if [ ! -f ../results/overhead_capsule.csv ]; then
    touch ../results/overhead_capsule.csv
else
    rm ../results/overhead_capsule.csv
fi

echo "Start,End,Num_Tenants" > ../results/overhead_capsule.csv

# logic here
for i in $(seq 5 5 "$1"); do
    ./deploy-capsule.sh "install" $2

    create_users $i

    sleep 300

    ../load/generate_load.sh "$i" "tenant" "../results/overhead_capsule.csv"

    delete_users_namespace $i

    ./deploy-capsule.sh "uninstall" $2
done

