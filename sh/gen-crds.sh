#!/bin/bash

set -e

mkdir -p charts/simpaas/crds
for crd in app invit role user; do
  cargo run -- crd $crd > charts/simpaas/crds/$crd.yaml
done
git diff --exit-code charts/simpaas/crds/*.yaml
