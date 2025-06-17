KV_VER="1.3.0"
USE_NESTED_VIRTUALIZATION="n"
KUBECONFIG_PATH="$1"
if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

# deploy required CRDs
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-operator.yaml" --kubeconfig "$KUBECONFIG_PATH"
# deploy the KubeVirt custom resource
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-cr.yaml" --kubeconfig "$KUBECONFIG_PATH"

kubectl wait -n kubevirt kv kubevirt --for=condition=Available --timeout=10m --kubeconfig "$KUBECONFIG_PATH"

if [ $USE_NESTED_VIRTUALIZATION == "y" ]; then
    kubectl -n kubevirt patch kubevirt kubevirt --type=merge --patch '{"spec":{"configuration":{"developerConfiguration":{"useEmulation":true}}}}' --kubeconfig "$KUBECONFIG_PATH"
fi