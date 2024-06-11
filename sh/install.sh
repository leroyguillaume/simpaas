#!/bin/bash

set -eo pipefail

log_file=/var/log/simpaas-install.log
sudo rm -f $log_file

echo "starting simpaas installation, logs will be written to $log_file"

if [ -f ".env" ]; then
  echo -n "sourcing .env... "
  . .env
  echo "done"
fi

if command -v k3s > /dev/null; then
  echo "k3s seems to be already installed, skipping installation"
else
  echo -n "installing k3s... "
  curl -sfL https://get.k3s.io 2>> $log_file | bash - >> $log_file 2>&1
  echo "done"
fi
mkdir -p ~/.kube
cp /etc/rancher/k3s/k3s.yaml ~/.kube/config

if command -v helm > /dev/null; then
  echo "helm seems to be already installed, skipping installation"
else
  echo -n "installing helm... "
  curl -sfL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 2>> $log_file | bash - >> $log_file 2>&1
  echo "done"
fi

api_path="/api"
cert_manager_part=""
issuer="letsencrypt"
release="simpaas"
simpaas_values=/tmp/simpaas.yaml
smtp_secret=simpaas-smtp
smtp_user_key=user
smtp_password_key=password
smtp_gmail_user_key=gmailUser
smtp_gmail_password_key=gmailPassword
traefik_middleware=$release-api

image_tag="~"
ingress_create=false
ns="simpaas"
smtp_port=25
if [ ! -z "$SIMPAAS_DOMAIN" ]; then
  ingress_create=true
fi
if [ ! -z "$SIMPAAS_SMTP_PORT" ]; then
  smtp_port=$SIMPAAS_SMTP_PORT
fi
if [ ! -z "$SIMPAAS_VERSION" ]; then
  image_tag="$SIMPAAS_VERSION"
fi
if [ "$SIMPAAS_SMTP_GMAIL_ENABLED" = "true" ]; then
  smtp_env="
  - name: GMAIL_USER
    valueFrom:
      secretKeyRef:
        name: $smtp_secret
        key: $smtp_gmail_user_key
  - name: GMAIL_PASSWORD
    valueFrom:
      secretKeyRef:
        name: $smtp_secret
        key: $smtp_gmail_password_key
"
elif [ "$SIMPAAS_SMTP_GENERIC_RELAY_ENABLED" = "true" ]; then
  smtp_env="
  - name: SMARTHOST_ADDRESS
    value: $SIMPAAS_SMTP_HOST
  - name: SMARTHOST_PORT
    value: '$smtp_port'
"
  if [ ! -z "$SIMPAAS_SMTP_ALIASES" ]; then
    smtp_env="
$smtp_env
  - name: SMARTHOST_ALIASES
    value: $SIMPAAS_SMTP_ALIASES
"
  fi
  if [ ! -z "$SIMPAAS_SMTP_USER" ]; then
    smtp_env="
$smtp_env
  - name: SMARTHOST_USER
    valueFrom:
      secretKeyRef:
        name: $smtp_secret
        key: $smtp_user_key
"
  fi
  if [ ! -z "$SIMPAAS_SMTP_PASSWORD" ]; then
    smtp_env="
$smtp_env
  - name: SMARTHOST_PASSWORD
    valueFrom:
      secretKeyRef:
        name: $smtp_secret
        key: $smtp_password_key
"
  fi
else
  2>&1 echo "SIMPAAS_SMTP_GMAIL_ENABLED or SIMPAAS_SMTP_GENERIC_RELAY_ENABLED must be true"
  exit 1
fi
echo -n "installing jetstack helm repository... "
helm repo add jetstack https://charts.jetstack.io >> $log_file 2>&1
echo "done"
echo -n "installing cert-manager... "
helm upgrade \
  -n cert-manager \
  --create-namespace \
  --install \
  --set crds.enabled=true \
  cert-manager \
  jetstack/cert-manager \
  >> $log_file 2>&1
echo "done"
echo -n "installing simpaas helm repository... "
helm repo add simpaas https://leroyguillaume.github.io/simpaas >> $log_file 2>&1
echo "done"

echo "
common:
  image:
    tag: $image_tag
api:
  ingress:
    tls: true
    path: $api_path
$api_smtp_values
op:
  chartValues:
    ingress:
      annotations:
        cert-manager.io/cluster-issuer: $issuer
webapp:
  ingress:
    tls: true
ingress:
  create: $ingress_create
  domain: $SIMPAAS_DOMAIN
  annotations:
    cert-manager.io/cluster-issuer: $issuer
    traefik.ingress.kubernetes.io/router.middlewares: $ns-$traefik_middleware@kubernetescrd
cert-manager:
  clusterIssuers:
  - name: $issuer
    spec:
      acme:
        email: $SIMPAAS_LETSENCRYPT_EMAIL
        server: https://acme-v02.api.letsencrypt.org/directory
        privateKeySecretRef:
          name: letsencrypt-privkey
        solvers:
        - http01:
            ingress: {}
opentelemetry-collector:
  enabled: true
smtp:
  enabled: true
  env:
  - name: DISABLE_IPV6
    value: '1'
  $smtp_env
traefik:
  middlewares:
  - name: $traefik_middleware
    spec:
      stripPrefix:
        prefixes:
        - $api_path
" > $simpaas_values
echo -n "installing simpaas... "
helm upgrade \
  -n $ns \
  --create-namespace \
  --install \
  --values $simpaas_values \
  $release \
  simpaas/simpaas \
  >> $log_file 2>&1
echo "done"

echo -n "creating smtp secret... "
kubectl create secret generic $smtp_secret \
  -n $ns \
  --from-literal=$smtp_user_key="$SIMPAAS_SMTP_USER" \
  --from-literal=$smtp_password_key="$SIMPAAS_SMTP_PASSWORD" \
  --from-literal=$smtp_gmail_user_key="$GMAIL_USER" \
  --from-literal=$smtp_gmail_password_key="$GMAIL_PASSWORD" \
  --dry-run \
  -o yaml \
  2>> $log_file \
  | kubectl apply -f - >> $log_file 2>&1
echo "done"

echo "simpaas installation succeeded!"
if [ ! -z "$SIMPAAS_DOMAIN" ]; then
  echo "you can open your favorite browser on https://$SIMPAAS_DOMAIN"
fi
