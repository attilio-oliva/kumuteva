#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: $0 <action> <kubeconfig_path>"
    echo "  action: Action to perform [install, uninstall]"
    echo "  kubeconfig_path: Path to kubeconfig file"
    exit 1
}

install_capsule() {
    # Check if Capsule is already installed
    if helm list -n "${CAPSULE_NAMESPACE}" --filter "${CHART}" --kubeconfig $1 &> /dev/null | grep -q "${CHART}"; then
        echo "Capsule is already installed, skipping installation"
        exit 0
    fi

    echo "Installing Capsule..."
    helm install "${CHART}" "${CHART_PATH}" \
        --version "${CAPSULE_VERSION}" \
        -n "${CAPSULE_NAMESPACE}" \
        --create-namespace --kubeconfig "${1}" &> /dev/null

    echo "Capsule installation completed"
}

uninstall_capsule() {
    echo "Uninstalling Capsule..."
    helm uninstall "${CHART}" -n "${CAPSULE_NAMESPACE}" --kubeconfig "$1" &> /dev/null
    kubectl delete ns capsule-system &> /dev/null
    echo "Capsule uninstallation completed"
}

# Check arguments
if [ $# -ne 2 ]; then
    usage
fi

REPO_NAME="projectcapsule"
REPO_URL="https://projectcapsule.github.io/charts"
CHART="capsule"
CHART_PATH="${REPO_NAME}/${CHART}"
CAPSULE_NAMESPACE="capsule-system"
CAPSULE_VERSION="0.7.0"

helm repo add "${REPO_NAME}" "${REPO_URL}" &> /dev/null


if [ "$1" == "install" ] ; then
    install_capsule $2
elif [ "$1" == "uninstall" ] ; then
    uninstall_capsule $2
else
    usage
fi



