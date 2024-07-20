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

To use SMTP locally, we recommand to use SMTP server as relay to GMail.

You need to create [app password](https://support.google.com/accounts/answer/185833).

```bash
export GMAIL_USER=your email
export GMAIL_PASSWORD=your token
./tools/install.sh
```

### API

```bash
cargo run -- api
```

### Operator

```bash
cargo run -- op
```
