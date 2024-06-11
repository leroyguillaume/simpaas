# simpaas

SimPaaS is a Platform as a Service (PaaS) based on [Kubernetes](https://kubernetes.io/) and [Helm](https://helm.sh/).

## Getting started

### I don't have any Kubernetes cluster

This command will:
- install [k3s](https://docs.k3s.io/)
- install [cert-manager](https://cert-manager.io/) and will configure it to use [letsencrypt](https://letsencrypt.org/)
- install SMTP server
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- install SimPaaS

```bash
curl -sfL https://raw.githubusercontent.com/leroyguillaume/simpaas/main/sh/install.sh | sudo bash
```

You can customize installation with environment variables. The script will source `.env` file if it exists.

#### Configuration examples

##### SimPaas for side projects

This `.env` will install SimPaaS to deploy easily your side projects.

This configuration uses SMTP as GMail relay and you need to [generate a token](https://support.google.com/accounts/answer/185833).

```bash
export SIMPAAS_DOMAIN=simpaas.example.com
export SIMPAAS_SMTP_GMAIL_ENABLED=true
export GMAIL_USER=john.doe@gmail.com
export GMAIL_PASSWORD=mytoken
```

#### Configuration reference

##### `GMAIL_PASSWORD`

*Required if `SIMPAAS_SMTP_GMAIL_ENABLED` is `true`.*

GMail token.

To create a token, see [Google documentation](https://support.google.com/accounts/answer/185833).

##### `GMAIL_USER`

*Required if `SIMPAAS_SMTP_GMAIL_ENABLED` is `true`.*

GMail address.

##### `SIMPAAS_DOMAIN`

*Optional.*

The domain on which expose SimPaaS (ex: `simpaas.example.com`).

If it not specified, SimPaaS will be not exposed.

##### `SIMPAAS_LETSENCRYPT_EMAIL`

*Optional.*

The email used to notify you about TLS certificate (by example, if a renewal failed).

##### `SIMPAAS_SMTP_ALIASES`

*Optional.*

Semicolon-separated list of aliases to puth authentication data.

##### `SIMPAAS_SMTP_HOST`

*Required if `SIMPAAS_SMTP_GENERIC_RELAY_ENABLED` is `true`.*

Host of SMTP server.

##### `SIMPAAS_SMTP_PORT`

*Optional. Default: `25`.*

Port of SMTP server.

##### `SIMPAAS_SMTP_PASSWORD`

*Optional.*

SMTP password.

##### `SIMPAAS_SMTP_USER`

*Optional.*

SMTP user.

##### `SIMPAAS_SMTP_GENERIC_RELAY_ENABLED`

*Required if `SIMPAAS_SMTP_GMAIL_ENABLED` is `false`.*

Configure SMTP as relay.

##### `SIMPAAS_SMTP_GMAIL_ENABLED`

*Required if `SIMPAAS_SMTP_GENERIC_RELAY_ENABLED` is `false`.*

Configure SMTP as relay to GMail.

**You need to define `GMAIL_USER` and `GMAIL_PASSWORD` environment variables.**

##### `SIMPAAS_VERSION`

*Optional.*

Override SimPaaS version.

If not defined, the latest stable version is used.

### I'm already a Kubernetes boss

You can find Helm chart documentation [here](charts/simpaas/).

## Architecture

SimPaas is composed by two services.

### API

The API interracts with the operator thru CRDs.

### Operator

The operator deploys/undeploys services when an associated CRD is created/updated/deleted.

## Contributing

cf. [CONTRIBUTING.md](CONTRIBUTING.md).
