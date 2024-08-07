#!/bin/bash

set -e

ns=simpaas

if ! ./tools/gen-crds.sh; then
  ./tools/install-crds.sh
fi

if [ -f .local/values.yaml ]; then
  set_values=(--values .local/values.yaml)
fi

helm upgrade \
  -n $ns \
  --create-namespace \
  --install \
  --values .config/orbstack.yaml \
  "${set_values[@]}" \
  simpaas \
  charts/simpaas-stack
kubectl -n $ns apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: simpaas-gmail
type: Opaque
data:
  password: $(echo -n "$GMAIL_PASSWORD" | base64)
  user: $(echo -n "$GMAIL_USER" | base64)
EOF
