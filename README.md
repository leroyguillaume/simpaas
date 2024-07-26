# simpaas

SimPaaS is a Platform as a Service (PaaS) based on [Kubernetes](https://kubernetes.io/) and [Helm](https://helm.sh/).

## Install

### Using bundle script

This script installs a turnkey Kubernetes cluster with SimPaaS (monitoring, TLS, etc.).

```bash
curl -sfL https://raw.githubusercontent.com/leroyguillaume/simpaas/main/get-simpaas | bash -
```

The script will source a `.env` file if it exists.

Note that the script is idempotent.

All the environment variables are optional but we recommend to define [`SIMPAAS_DOMAIN`](#simpaas_domain) otherwise SimPaaS will not be accessible outside the cluster.

#### `SIMPAAS_CERT_MANAGER_EMAIL`

Specify an email to receive alerts about certificates expiration.

#### `SIMPAAS_CONFIG`

Path to SimPaaS configuration file. You can find a complete example [here](charts/simpaas/values.yaml).

#### `SIMPAAS_DOMAIN`

Domain on which to expose SimPaaS. If it is not defined, it will not be exposed outside the cluster.

#### `SIMPAAS_GMAIL_RELAY_ENABLED`

Configure SimPaaS to use GMail as SMTP relay. If it is enabled, you need to define two environment variables:
- `GMAIL_USER`: your email address
- `GMAIL_PASSWORD`: a valid [app password](https://support.google.com/accounts/answer/185833)


#### `SIMPAAS_VERSION`

Specify SimPaaS version.

### Using Helm chart

```bash
helm repo add simpaas https://leroyguillaume.github.io/simpaas
```

#### simpaas-stack

This chart will install SimPaaS and all required softwares.

```bash
helm install simpaas simpaas/simpaas-stack
```

You can find values reference [here](charts/simpaas-stack/values.yaml).

#### simpaas

This chart will install SimPaaS only.

```bash
helm install simpaas simpaas/simpaas
```

You can find values reference [here](charts/simpaas/values.yaml).

## Architecture

SimPaas is composed by two services.

### API

The API interracts with the operator thru CRDs.

### Operator

The operator deploys/undeploys services when an associated CRD is created/updated/deleted.

## Contributing

cf. [CONTRIBUTING.md](CONTRIBUTING.md).
