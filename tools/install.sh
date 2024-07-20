#!/bin/bash

set -e

ns=simpaas

if ! ./tools/gen-crds.sh; then
  for crd in $(kubectl get crds -oname | grep simpaas); do
    kubectl delete $crd
  done
  find charts/simpaas/crds -name '*.yaml' -exec kubectl apply -f {} \;
fi

helm upgrade \
  -n $ns \
  --create-namespace \
  --install \
  --values config/local.yaml \
  simpaas \
  charts/simpaas
kubectl -n $ns apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: simpaas-gmail
type: Opaque
data:
  password: $(echo -n $GMAIL_PASSWORD | base64)
  user: $(echo -n $GMAIL_USER | base64)
EOF
