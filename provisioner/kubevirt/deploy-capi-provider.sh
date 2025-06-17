KUBECONFIG_PATH="$1"
if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

clusterctl init --infrastructure kubevirt

kubectl rollout status deployment/capi-kubeadm-bootstrap-controller-manager -n capi-kubeadm-bootstrap-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
kubectl rollout status deployment/capi-kubeadm-control-plane-controller-manager -n capi-kubeadm-control-plane-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
kubectl rollout status deployment/capi-controller-manager -n capi-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
kubectl rollout status deployment/capk-controller-manager -n capk-system --timeout=10m --kubeconfig "$KUBECONFIG_PATH"
