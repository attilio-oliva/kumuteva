KUBECONFIG_PATH="$1"
if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

# if capi is already installed, exit
if kubectl get ns capi-system --kubeconfig "$KUBECONFIG_PATH" &>/dev/null; then
    echo "CAPI is already installed. Exiting."
    exit 0
fi

# clusterctl init --infrastructure kubevirt
helm repo add capi-operator https://kubernetes-sigs.github.io/cluster-api-operator
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update

helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true --wait --timeout 90s --kubeconfig "$KUBECONFIG_PATH"

helm install capi-operator capi-operator/cluster-api-operator --create-namespace -n capi-operator-system --set infrastructure.kubevirt.enabled=true --set cert-manager.enabled=true --wait --timeout 300s --kubeconfig "$KUBECONFIG_PATH"

kubectl rollout status deployment/capi-kubeadm-bootstrap-controller-manager -n capi-kubeadm-bootstrap-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
kubectl rollout status deployment/capi-kubeadm-control-plane-controller-manager -n capi-kubeadm-control-plane-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
kubectl rollout status deployment/capi-controller-manager -n capi-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
kubectl rollout status deployment/capk-controller-manager -n kubevirt-infrastructure-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
