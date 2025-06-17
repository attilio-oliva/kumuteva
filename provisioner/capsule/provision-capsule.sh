set -e
TENANT1_NAME="tenant1"
TENANT2_NAME="tenant2"
KUBECONFIG_PATH="${1:-$HOME/.kube/config}"

./deploy-capsule.sh

./create-user.sh ${TENANT1_NAME}-admin ${TENANT1_NAME}
./create-user.sh ${TENANT2_NAME}-admin ${TENANT2_NAME}

./move-kubeconfig.sh ${TENANT1_NAME}-admin ${TENANT1_NAME} "${KUBECONFIG_PATH}"
./move-kubeconfig.sh ${TENANT2_NAME}-admin ${TENANT2_NAME} "${KUBECONFIG_PATH}"