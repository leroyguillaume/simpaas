#!/bin/bash

set -e

dir=charts/simpaas/crds
rm -rf $dir
cargo run -F crds --bin crds -- $dir
git diff --exit-code -- $dir
