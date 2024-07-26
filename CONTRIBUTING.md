# Contributing

## Prerequisites
- [pre-commit](https://pre-commit.com/)
- [Rust](https://rustup.rs/)

## Getting started

```bash
git clone https://github.com/leroyguillaume/simpaas
cd simpaas
pre-commit install
```

## How to build

```bash
cargo build
```

## How to test

```bash
cargo test
```

## How to run

You need to have a local Kubernetes cluster (as K3S, Minikube, kind...).

You can install the [Helm chart](charts/simpaas).

### Orbstack

If you're using Orbstack, you can use orbstrack-install script directly. It will install the complete stack by using chart [simpaas-stack](charts/simpaas-stack) and a [dedicated configuration](.config/orbstack.yaml).

You can customize configuration by creating a file `.local/values.yaml`.

To use SMTP locally, you can use SMTP server as relay to GMail.

You need to create [app password](https://support.google.com/accounts/answer/185833).

```bash
export GMAIL_USER=your email
export GMAIL_PASSWORD=your token
./tools/orbstack-install.sh
```

### API

```bash
cargo run -- api
```

### Operator

If you run the operator locally, it is strongly recommend to set number of replicas to `0` for operator.

```bash
cargo run -- op
```
