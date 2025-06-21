# scripts/install-capsule.sh
#!/bin/bash
set -euo pipefail

REPO_NAME="projectcapsule"
REPO_URL="https://projectcapsule.github.io/charts"
CHART="capsule"
CHART_PATH="${REPO_NAME}/${CHART}"
CAPSULE_NAMESPACE="capsule-system"
CAPSULE_VERSION="0.7.0"

echo "Adding Capsule Helm repository..."
helm repo add "${REPO_NAME}" "${REPO_URL}"

# Check if Capsule is already installed
if helm list -n "${CAPSULE_NAMESPACE}" --filter "${CHART}" | grep -q "${CHART}"; then
    echo "Capsule is already installed, skipping installation"
    exit 0
fi

echo "Installing Capsule..."
helm install "${CHART}" "${CHART_PATH}" \
    --version "${CAPSULE_VERSION}" \
    -n "${CAPSULE_NAMESPACE}" \
    --create-namespace

echo "Capsule installation completed"