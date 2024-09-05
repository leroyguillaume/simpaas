#!/bin/bash

set -e

./tools/generate-crds.sh || true
for crd in $(kubectl get crds -oname | grep simpaas); do
  kubectl delete "$crd"
done
find charts/simpaas/crds -name '*.yaml' -exec kubectl apply -f {} \;
