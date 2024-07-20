#!/bin/bash

set -e

cargo build
mkdir -p charts/simpaas/crds
for crd in app invit role user; do
  target/debug/simpaas crd $crd > charts/simpaas/crds/$crd.yaml
done
git diff --exit-code charts/simpaas/crds/*.yaml
