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

### API

```bash
cargo run --package simpaas-api
```

### Operator

```bash
cargo run --package simpaas-operator
```
