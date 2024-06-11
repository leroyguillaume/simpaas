#!/bin/bash

set -e

ns=simpaas

for crd in $(kubectl get crds -oname | grep simpaas); do
  kubectl delete $crd
done
if kubectl get ns $ns > /dev/null 2>&1; then
  kubectl delete ns $ns
fi

helm install \
  -n $ns \
  --create-namespace \
  --values config/local.yaml \
  simpaas charts/simpaas
kubectl create secret generic simpaas-smtp \
  -n $ns \
  --from-literal=gmailUser=$GMAIL_USER \
  --from-literal=gmailPassword="$GMAIL_PASSWORD"
