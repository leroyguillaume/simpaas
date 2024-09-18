#!/bin/bash

set -e

create_namespace() {
  if ! kubectl get ns "$1" > /dev/null 2>&1; then
    kubectl create ns "$1"
  fi
}

create_namespace postgresql
create_namespace nginx
kubectl apply -f examples/service/postgresql.yaml
kubectl apply -f examples/service-instance/postgresql.yaml
kubectl apply -f examples/database/postgresql.yaml
kubectl apply -f examples/application/nginx.yaml
