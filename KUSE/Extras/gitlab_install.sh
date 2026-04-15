#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-demo.sh
#
# Demo-Installation für ein KUSE-Lab:
# - ingress-nginx
# - optional cert-manager
# - GitLab
# - GitLab Runner
#
# Voraussetzungen:
# - funktionierendes Kubernetes-Cluster
# - lokales kubectl + helm
# - Zugriff mit cluster-admin
#
# Ziel:
# - einfache, reproduzierbare Lab-Umgebung
# - didaktisch geeignet für CI/CD, Registry, Runner, später Cosign
#
# WICHTIG:
# - Dies ist absichtlich eine Demo-/Lab-Installation
# - keine produktionsreife Sizing-/HA-/Backup-/Security-Defaults
###############################################################################

# ----------------------------- Config ---------------------------------

DEMO_DOMAIN="${DEMO_DOMAIN:-kuse.lab}"
GITLAB_HOST="${GITLAB_HOST:-gitlab.${DEMO_DOMAIN}}"

INSTALL_CERT_MANAGER="${INSTALL_CERT_MANAGER:-yes}"
INSTALL_RUNNER="${INSTALL_RUNNER:-yes}"

INGRESS_NGINX_VERSION="${INGRESS_NGINX_VERSION:-4.12.1}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.18.2}"
GITLAB_CHART_VERSION="${GITLAB_CHART_VERSION:-8.11.2}"
GITLAB_RUNNER_CHART_VERSION="${GITLAB_RUNNER_CHART_VERSION:-0.77.2}"

GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-gitlab}"
RUNNER_NAMESPACE="${RUNNER_NAMESPACE:-gitlab-runner}"
INGRESS_NAMESPACE="${INGRESS_NAMESPACE:-ingress-nginx}"
CERT_MANAGER_NAMESPACE="${CERT_MANAGER_NAMESPACE:-cert-manager}"

# Demo: selbstsigniert / Lab
CREATE_SELF_SIGNED_ISSUER="${CREATE_SELF_SIGNED_ISSUER:-yes}"
SELF_SIGNED_ISSUER_NAME="${SELF_SIGNED_ISSUER_NAME:-kuse-selfsigned}"

# GitLab Passwort:
# Entweder per ENV setzen:
#   export GITLAB_ROOT_PASSWORD='SuperSecret123!'
# oder das Script fragt interaktiv
if [[ -z "${GITLAB_ROOT_PASSWORD:-}" ]]; then
  read -rsp "GitLab root password: " GITLAB_ROOT_PASSWORD
  echo
  if [[ -z "${GITLAB_ROOT_PASSWORD}" ]]; then
    echo "ERROR: GITLAB_ROOT_PASSWORD must not be empty" >&2
    exit 1
  fi
fi

# Optional: Runner-Registrierungstoken
# Kann später auch manuell gesetzt werden, sobald GitLab läuft
RUNNER_REGISTRATION_TOKEN="${RUNNER_REGISTRATION_TOKEN:-}"

# Demo-Storagegrößen
GITLAB_STORAGE_CLASS="${GITLAB_STORAGE_CLASS:-}"
POSTGRES_SIZE="${POSTGRES_SIZE:-8Gi}"
REDIS_SIZE="${REDIS_SIZE:-2Gi}"
MINIO_SIZE="${MINIO_SIZE:-10Gi}"
GITALY_SIZE="${GITALY_SIZE:-20Gi}"
PROMETHEUS_SIZE="${PROMETHEUS_SIZE:-8Gi}"

# Ressourcen klein halten
INSTALL_MONITORING="${INSTALL_MONITORING:-no}"

# ----------------------------- Helpers --------------------------------

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

section() {
  echo
  echo "================================================="
  echo "$1"
  echo "================================================="
}

apply_ns() {
  local ns="$1"
  kubectl get ns "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"
}

wait_rollout() {
  local ns="$1"
  local kind="$2"
  local name="$3"
  kubectl -n "$ns" rollout status "$kind/$name" --timeout=300s
}

# ----------------------------- Checks ---------------------------------

require_cmd kubectl
require_cmd helm

section "🔎 Preflight"
kubectl version --client=true
helm version
kubectl get nodes -o wide

section "🧱 Ensure namespaces"
apply_ns "$INGRESS_NAMESPACE"
apply_ns "$CERT_MANAGER_NAMESPACE"
apply_ns "$GITLAB_NAMESPACE"
apply_ns "$RUNNER_NAMESPACE"

# ----------------------------- Repo setup -----------------------------

section "📚 Helm repositories"
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo add gitlab https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo add gitlab-runner https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo update

# ----------------------------- ingress-nginx --------------------------

section "🌐 Install ingress-nginx"

cat >/tmp/ingress-nginx-values.yaml <<'EOF'
controller:
  replicaCount: 1
  admissionWebhooks:
    enabled: true
  service:
    type: LoadBalancer
  watchIngressWithoutClass: true
  ingressClassResource:
    name: nginx
    enabled: true
    default: true
EOF

helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace "$INGRESS_NAMESPACE" \
  --version "$INGRESS_NGINX_VERSION" \
  -f /tmp/ingress-nginx-values.yaml

wait_rollout "$INGRESS_NAMESPACE" deployment ingress-nginx-controller

kubectl -n "$INGRESS_NAMESPACE" get pods -o wide
kubectl -n "$INGRESS_NAMESPACE" get svc

# ----------------------------- cert-manager ---------------------------

if [[ "$INSTALL_CERT_MANAGER" == "yes" ]]; then
  section "🔐 Install cert-manager"

  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace "$CERT_MANAGER_NAMESPACE" \
    --version "$CERT_MANAGER_VERSION" \
    --set crds.enabled=true

  wait_rollout "$CERT_MANAGER_NAMESPACE" deployment cert-manager
  wait_rollout "$CERT_MANAGER_NAMESPACE" deployment cert-manager-webhook
  wait_rollout "$CERT_MANAGER_NAMESPACE" deployment cert-manager-cainjector

  kubectl -n "$CERT_MANAGER_NAMESPACE" get pods -o wide

  if [[ "$CREATE_SELF_SIGNED_ISSUER" == "yes" ]]; then
    section "🪪 Create self-signed ClusterIssuer"

    cat >/tmp/selfsigned-issuer.yaml <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ${SELF_SIGNED_ISSUER_NAME}
spec:
  selfSigned: {}
EOF

    kubectl apply -f /tmp/selfsigned-issuer.yaml
    kubectl get clusterissuer
  fi
fi

# ----------------------------- GitLab values --------------------------

section "📝 Build GitLab values"

STORAGE_CLASS_BLOCK=""
if [[ -n "${GITLAB_STORAGE_CLASS}" ]]; then
  STORAGE_CLASS_BLOCK=$(cat <<EOF
global:
  hosts:
    domain: ${DEMO_DOMAIN}
  ingress:
    class: nginx
    configureCertmanager: ${INSTALL_CERT_MANAGER}
  edition: ce
  initialRootPassword:
    secret: gitlab-root-password
    key: password
  storage:
    class: ${GITLAB_STORAGE_CLASS}
EOF
)
else
  STORAGE_CLASS_BLOCK=$(cat <<EOF
global:
  hosts:
    domain: ${DEMO_DOMAIN}
  ingress:
    class: nginx
    configureCertmanager: ${INSTALL_CERT_MANAGER}
  edition: ce
  initialRootPassword:
    secret: gitlab-root-password
    key: password
EOF
)
fi

TLS_BLOCK=""
if [[ "$INSTALL_CERT_MANAGER" == "yes" && "$CREATE_SELF_SIGNED_ISSUER" == "yes" ]]; then
  TLS_BLOCK=$(cat <<EOF
  ingress:
    tls:
      enabled: true
    annotations:
      cert-manager.io/cluster-issuer: ${SELF_SIGNED_ISSUER_NAME}
EOF
)
fi

cat >/tmp/gitlab-values.yaml <<EOF
${STORAGE_CLASS_BLOCK}
${TLS_BLOCK}

certmanager:
  install: false

nginx-ingress:
  enabled: false

prometheus:
  install: ${INSTALL_MONITORING}

gitlab-runner:
  install: false

registry:
  enabled: true

minio:
  persistence:
    size: ${MINIO_SIZE}

redis:
  master:
    persistence:
      size: ${REDIS_SIZE}

postgresql:
  primary:
    persistence:
      size: ${POSTGRES_SIZE}

gitlab:
  gitaly:
    persistence:
      size: ${GITALY_SIZE}

gitlab-exporter:
  enabled: true

gitlab-shell:
  enabled: true

kas:
  enabled: false

pages:
  enabled: false
EOF

section "🔑 Create GitLab root password secret"
kubectl -n "$GITLAB_NAMESPACE" create secret generic gitlab-root-password \
  --from-literal=password="${GITLAB_ROOT_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -

# ----------------------------- Install GitLab -------------------------

section "🦊 Install GitLab"

helm upgrade --install gitlab gitlab/gitlab \
  --namespace "$GITLAB_NAMESPACE" \
  --version "$GITLAB_CHART_VERSION" \
  -f /tmp/gitlab-values.yaml

section "⏳ Wait for basic GitLab components"
kubectl -n "$GITLAB_NAMESPACE" get pods -w &
WATCH_PID=$!

sleep 10

# Basischecks statt auf alles ewig zu warten
for i in {1..90}; do
  READY_PODS="$(kubectl -n "$GITLAB_NAMESPACE" get pods --no-headers 2>/dev/null | awk '$2 !~ /^([0-9]+)\/\1$/ {bad++} END{print bad+0}')"
  TOTAL_PODS="$(kubectl -n "$GITLAB_NAMESPACE" get pods --no-headers 2>/dev/null | wc -l | awk '{print $1}')"

  echo "GitLab readiness check: total=${TOTAL_PODS}, not-fully-ready=${READY_PODS}"

  if [[ "${TOTAL_PODS}" -gt 0 && "${READY_PODS}" -eq 0 ]]; then
    echo "✅ GitLab pods appear ready"
    break
  fi

  sleep 10
done

kill "${WATCH_PID}" 2>/dev/null || true

section "📋 GitLab status"
kubectl -n "$GITLAB_NAMESPACE" get pods -o wide
kubectl -n "$GITLAB_NAMESPACE" get svc
kubectl -n "$GITLAB_NAMESPACE" get ingress

# ----------------------------- Runner install -------------------------

if [[ "$INSTALL_RUNNER" == "yes" ]]; then
  section "🏃 GitLab Runner preparation"

  if [[ -z "${RUNNER_REGISTRATION_TOKEN}" ]]; then
    cat <<EOF

Runner registration token is currently empty.

So gehst du weiter:
1. Öffne GitLab:
   https://${GITLAB_HOST}
   oder bei self-signed ggf. trotzdem mit Browser-Warnung

2. Login:
   user: root
   password: (das eben gesetzte Passwort)

3. Hole einen Runner Registration Token
   - entweder projektbezogen
   - oder gruppenbezogen
   - oder instanzweiten Runner anlegen

4. Danach Script erneut starten mit:
   RUNNER_REGISTRATION_TOKEN='TOKEN' INSTALL_CERT_MANAGER=${INSTALL_CERT_MANAGER} INSTALL_RUNNER=yes ./install-gitlab-demo.sh

GitLab bleibt installiert, nur Runner wird noch nicht eingerichtet.
EOF
  else
    section "🏃 Install GitLab Runner"

    cat >/tmp/gitlab-runner-values.yaml <<EOF
gitlabUrl: https://${GITLAB_HOST}/
runnerRegistrationToken: "${RUNNER_REGISTRATION_TOKEN}"
rbac:
  create: true
serviceAccount:
  create: true
runners:
  config: |
    [[runners]]
      name = "kuse-k8s-runner"
      url = "https://${GITLAB_HOST}/"
      token = "${RUNNER_REGISTRATION_TOKEN}"
      executor = "kubernetes"
      [runners.kubernetes]
        namespace = "${RUNNER_NAMESPACE}"
        image = "alpine:3.20"
        privileged = true
        pull_policy = "if-not-present"
        helper_image_flavor = "alpine"
      [runners.cache]
        Type = "s3"
concurrent: 2
checkInterval: 10
metrics:
  enabled: true
EOF

    helm upgrade --install gitlab-runner gitlab-runner/gitlab-runner \
      --namespace "$RUNNER_NAMESPACE" \
      --version "$GITLAB_RUNNER_CHART_VERSION" \
      -f /tmp/gitlab-runner-values.yaml

    kubectl -n "$RUNNER_NAMESPACE" rollout status deployment/gitlab-runner --timeout=300s || true
    kubectl -n "$RUNNER_NAMESPACE" get pods -o wide
  fi
fi

# ----------------------------- Summary --------------------------------

section "✅ Summary"

cat <<EOF
GitLab host:
  ${GITLAB_HOST}

GitLab namespace:
  ${GITLAB_NAMESPACE}

Runner namespace:
  ${RUNNER_NAMESPACE}

Ingress namespace:
  ${INGRESS_NAMESPACE}

cert-manager installed:
  ${INSTALL_CERT_MANAGER}

Runner installed:
  ${INSTALL_RUNNER}

Quick checks:
  kubectl -n ${GITLAB_NAMESPACE} get pods
  kubectl -n ${GITLAB_NAMESPACE} get ingress
  kubectl -n ${RUNNER_NAMESPACE} get pods
  helm ls -A

Lab note:
- Für eine echte Demo mit Cosign folgt als nächstes:
  1. Testprojekt in GitLab anlegen
  2. Container Registry nutzen
  3. Runner-Build aktivieren
  4. Cosign im CI-Job verwenden
EOF
