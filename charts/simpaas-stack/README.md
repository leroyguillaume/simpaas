# simpaas-stack

This script will install SimPaaS and all required softwares.

## Getting started

```bash
helm repo add simpaas https://leroyguillaume.github.io/simpaas
helm install simpaas simpaas/simpaas-stack
```

## Minimal configuration

```yaml
grafana:
  grafana.ini:
    server:
      domain: &domain simpaas.k8s.orb.local

simpaas:
  ingress:
    domain: *domain
```

## SwaggerUI

If you enable feature `swaggerUi`, you need to set environment variable `SWAGGER_JSON_URL` to OpenAPI endpoint (`/_doc`).
