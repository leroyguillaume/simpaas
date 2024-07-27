# simpaas-stack

This script will install SimPaaS and all required softwares.

## Getting started

```bash
helm repo add simpaas https://leroyguillaume.github.io/simpaas
helm install simpaas simpaas/simpaas-stack
```

## Minimal configuration

```yaml
swaggerUi:
  apiUrl: https://simpaas.k8s.orb.local/api/_doc

grafana:
  grafana.ini:
    server:
      domain: &domain simpaas.k8s.orb.local

simpaas:
  ingress:
    domain: *domain
```
