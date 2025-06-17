TENANT_ADMIN_USER="${1}"
TENANT_NAME="${2}"
KUBECONFIG_PATH="${3:-$HOME/.kube/config}"

# Move all the generated files to the kubeconfig path
GENERATED_FILES_PREFIX="${TENANT_ADMIN_USER}-${TENANT_NAME}"

# Define the files to move
KUBECONFIG_FILES=(
    "${GENERATED_FILES_PREFIX}.kubeconfig"
    "${GENERATED_FILES_PREFIX}.crt"
    "${GENERATED_FILES_PREFIX}.key"
)

# Move each file to its destination
for file in "${KUBECONFIG_FILES[@]}"; do
    if [[ "$file" == *.kubeconfig ]]; then
        # Move .kubeconfig file to the kubeconfig path
        mv "$file" "$KUBECONFIG_PATH"
    else
        # Move .crt and .key files to the same directory as kubeconfig
        DEST_DIR=$(dirname "$KUBECONFIG_PATH")
        mv "$file" "$DEST_DIR/$(basename "$file")"
    fi
done