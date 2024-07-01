#!/bin/bash

set -e

ns=simpaas

for crd in $(kubectl get crds -oname | grep simpaas); do
  kubectl delete $crd
done
./sh/gen-crds.sh || true
find charts/simpaas/crds -name '*.yaml' -exec kubectl apply -f {} \;

helm upgrade \
  -n $ns \
  --create-namespace \
  --install \
  --values config/local.yaml \
  simpaas charts/simpaas
kubectl create \
  secret generic simpaas-smtp \
  -n $ns \
  --from-literal=gmailUser=$GMAIL_USER \
  --from-literal=gmailPassword="$GMAIL_PASSWORD" \
  -o yaml \
  --dry-run=client \
  | kubectl apply -f -
