#!/bin/bash

set -e

docker build -t gleroy/simpaas-api --target api .
docker build -t gleroy/simpaas-op --target op .
docker push gleroy/simpaas-api
docker push gleroy/simpaas-op
