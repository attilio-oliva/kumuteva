# scripts/deploy-vcluster.sh
#!/bin/bash
set -euo pipefail

NAMESPACE="$1"
RELEASE_NAME="vcluster-${NAMESPACE}"
CHART_NAME="vcluster"
VALUES_FILE="vcluster-config.yaml"
REPO_URL="https://charts.loft.sh"
KUBECONFIG_PATH="$2"

echo "Deploying vCluster in namespace: ${NAMESPACE}"

# Deploy vCluster using Helm
helm upgrade --install "${RELEASE_NAME}" "${CHART_NAME}" \
    --values "${VALUES_FILE}" \
    --repo "${REPO_URL}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --kubeconfig "${KUBECONFIG_PATH}"

# Wait for the vCluster pod to be ready
kubectl wait --for=condition=ready pod -l app=vcluster \
    --namespace "${NAMESPACE}" \
    --timeout=300s \
    --kubeconfig "${KUBECONFIG_PATH}"

echo "vCluster deployment completed for namespace: ${NAMESPACE}"