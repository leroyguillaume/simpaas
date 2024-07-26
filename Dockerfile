ARG rust_version=1.78.0-buster

FROM rust:$rust_version AS rust-deps

WORKDIR /opt/simpaas

COPY Cargo.* .

RUN <<EOF /bin/sh -e
mkdir src
echo "fn main() {}" > src/main.rs
cargo build -r
rm target/release/simpaas* target/release/deps/simpaas*
EOF

FROM rust:$rust_version AS rust-build

WORKDIR /opt/simpaas

COPY Cargo.* .
COPY resources resources
COPY src src
COPY --from=rust-deps /opt/simpaas/target target/

RUN cargo build -r

FROM debian:buster-20240612-slim AS rust-run

WORKDIR /opt/simpaas

RUN <<EOF /bin/sh -e
mkdir -p bin
groupadd -rg 1000 simpaas
useradd -Mrd /opt/simpaas -u 1000 -g 1000 simpaas
EOF

COPY --from=rust-build --chown=1000:1000 /opt/simpaas/target/release/simpaas bin/

USER simpaas

ENTRYPOINT ["bin/simpaas"]

FROM rust-run AS api

USER root

RUN <<EOF /bin/bash -eo pipefail
apt update
apt install -y libssl1.1
apt-get clean
EOF

USER simpaas

CMD ["api"]

FROM rust-run AS op

USER root

RUN <<EOF /bin/bash -eo pipefail
apt update
apt install -y apt-transport-https ca-certificates curl gpg libssl1.1
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | tee /etc/apt/sources.list.d/helm-stable-debian.list
apt update
apt install -y helm=3.15.1-1
apt-get clean
EOF

COPY --chown=1000:1000 charts/simpaas-app charts/simpaas-app

USER simpaas

CMD ["op"]
