#!/bin/bash

set -e

create_namespace() {
  if ! kubectl get ns "$1" > /dev/null 2>&1; then
    kubectl create ns "$1"
  fi
}

nginx_ns=my-nginx
pg_inst_name=my-pg
simpaas_ns=simpaas

create_namespace $pg_inst_name
create_namespace $nginx_ns
kubectl -n $simpaas_ns apply -f examples/service/postgresql.yaml
kubectl -n $pg_inst_name apply -f examples/service-instance/postgresql.yaml
kubectl -n $pg_inst_name apply -f examples/database/postgresql.yaml
kubectl -n $nginx_ns apply -f examples/application/nginx.yaml
