#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-demo-nodeport.sh
#
# Demo-Installation für ein KUSE-Lab auf Bare Metal OHNE MetalLB:
# - ingress-nginx via NodePort
# - optional cert-manager
# - GitLab
# - optional GitLab Runner
#
# Voraussetzungen:
# - funktionierendes Kubernetes-Cluster
# - lokales kubectl + helm
# - cluster-admin Rechte
#
# Idee:
# - kein LoadBalancer nötig
# - Zugriff über:
#     http://gitlab.<domain>:<NODEPORT_HTTP>
#   oder bei TLS:
#     https://gitlab.<domain>:<NODEPORT_HTTPS>
#
# WICHTIG:
# - Demo-/Lab-Setup
# - bewusst klein und pragmatisch
# - für produktive Nutzung nicht ausreichend gehärtet
###############################################################################

# ----------------------------- Config ---------------------------------

DEMO_DOMAIN="${DEMO_DOMAIN:-k8s.lan}"
GITLAB_SUBDOMAIN="${GITLAB_SUBDOMAIN:-gitlab}"
GITLAB_HOST="${GITLAB_SUBDOMAIN}.${DEMO_DOMAIN}"

INSTALL_CERT_MANAGER="${INSTALL_CERT_MANAGER:-no}"
INSTALL_RUNNER="${INSTALL_RUNNER:-yes}"

INGRESS_NGINX_VERSION="${INGRESS_NGINX_VERSION:-4.12.1}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.18.2}"
GITLAB_CHART_VERSION="${GITLAB_CHART_VERSION:-8.11.2}"
GITLAB_RUNNER_CHART_VERSION="${GITLAB_RUNNER_CHART_VERSION:-0.77.2}"

INGRESS_NAMESPACE="${INGRESS_NAMESPACE:-ingress-nginx}"
CERT_MANAGER_NAMESPACE="${CERT_MANAGER_NAMESPACE:-cert-manager}"
GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-gitlab}"
RUNNER_NAMESPACE="${RUNNER_NAMESPACE:-gitlab-runner}"

NODEPORT_HTTP="${NODEPORT_HTTP:-30080}"
NODEPORT_HTTPS="${NODEPORT_HTTPS:-30443}"

# Auf welchen Node zeigt dein Browser / /etc/hosts?
# Beispiel:
#   export ACCESS_IP=10.0.0.101
ACCESS_IP="${ACCESS_IP:-}"

# TLS im Lab:
# - mit cert-manager + self-signed ClusterIssuer
# - oder bewusst HTTP-only für maximale Einfachheit
ENABLE_TLS="${ENABLE_TLS:-no}"
CREATE_SELF_SIGNED_ISSUER="${CREATE_SELF_SIGNED_ISSUER:-yes}"
SELF_SIGNED_ISSUER_NAME="${SELF_SIGNED_ISSUER_NAME:-kuse-selfsigned}"

# Kleine Demo-Größen
INSTALL_MONITORING="${INSTALL_MONITORING:-no}"
GITLAB_STORAGE_CLASS="${GITLAB_STORAGE_CLASS:-}"

POSTGRES_SIZE="${POSTGRES_SIZE:-8Gi}"
REDIS_SIZE="${REDIS_SIZE:-2Gi}"
MINIO_SIZE="${MINIO_SIZE:-10Gi}"
GITALY_SIZE="${GITALY_SIZE:-20Gi}"

# GitLab root password
if [[ -z "${GITLAB_ROOT_PASSWORD:-}" ]]; then
  read -rsp "GitLab root password: " GITLAB_ROOT_PASSWORD
  echo
  if [[ -z "${GITLAB_ROOT_PASSWORD}" ]]; then
    echo "ERROR: GITLAB_ROOT_PASSWORD must not be empty" >&2
    exit 1
  fi
fi

# Runner Registration Token optional
RUNNER_REGISTRATION_TOKEN="${RUNNER_REGISTRATION_TOKEN:-}"

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

if [[ "${ENABLE_TLS}" == "yes" && "${INSTALL_CERT_MANAGER}" != "yes" ]]; then
  echo "ERROR: ENABLE_TLS=yes requires INSTALL_CERT_MANAGER=yes" >&2
  exit 1
fi

section "🧱 Ensure namespaces"
apply_ns "$INGRESS_NAMESPACE"
apply_ns "$CERT_MANAGER_NAMESPACE"
apply_ns "$GITLAB_NAMESPACE"
apply_ns "$RUNNER_NAMESPACE"

# ----------------------------- Repos ----------------------------------

section "📚 Helm repositories"
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo add gitlab https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo add gitlab-runner https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo update

# ----------------------------- ingress-nginx --------------------------

section "🌐 Install ingress-nginx as NodePort"

cat >/tmp/ingress-nginx-nodeport-values.yaml <<EOF
controller:
  replicaCount: 1
  admissionWebhooks:
    enabled: true
  watchIngressWithoutClass: true
  ingressClassResource:
    name: nginx
    enabled: true
    default: true
  service:
    type: NodePort
    nodePorts:
      http: ${NODEPORT_HTTP}
      https: ${NODEPORT_HTTPS}
EOF

helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace "$INGRESS_NAMESPACE" \
  --version "$INGRESS_NGINX_VERSION" \
  -f /tmp/ingress-nginx-nodeport-values.yaml

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

  if [[ "$ENABLE_TLS" == "yes" && "$CREATE_SELF_SIGNED_ISSUER" == "yes" ]]; then
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

if [[ -n "${GITLAB_STORAGE_CLASS}" ]]; then
  STORAGE_BLOCK=$(cat <<EOF
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
  STORAGE_BLOCK=$(cat <<EOF
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

TLS_EXTRA=""
if [[ "${ENABLE_TLS}" == "yes" ]]; then
  TLS_EXTRA=$(cat <<EOF
  ingress:
    tls:
      enabled: true
    annotations:
      cert-manager.io/cluster-issuer: ${SELF_SIGNED_ISSUER_NAME}
EOF
)
else
  TLS_EXTRA=$(cat <<EOF
  ingress:
    tls:
      enabled: false
EOF
)
fi

cat >/tmp/gitlab-nodeport-values.yaml <<EOF
${STORAGE_BLOCK}
${TLS_EXTRA}

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
  -f /tmp/gitlab-nodeport-values.yaml

section "⏳ Wait for GitLab pods"
for i in {1..90}; do
  TOTAL_PODS="$(kubectl -n "$GITLAB_NAMESPACE" get pods --no-headers 2>/dev/null | wc -l | awk '{print $1}')"
  NOT_READY="$(kubectl -n "$GITLAB_NAMESPACE" get pods --no-headers 2>/dev/null | awk '$2 !~ /^([0-9]+)\/\1$/ {bad++} END{print bad+0}')"

  echo "GitLab readiness check: total=${TOTAL_PODS}, not-fully-ready=${NOT_READY}"

  if [[ "${TOTAL_PODS}" -gt 0 && "${NOT_READY}" -eq 0 ]]; then
    echo "✅ GitLab pods appear ready"
    break
  fi

  sleep 10
done

section "📋 GitLab status"
kubectl -n "$GITLAB_NAMESPACE" get pods -o wide
kubectl -n "$GITLAB_NAMESPACE" get svc
kubectl -n "$GITLAB_NAMESPACE" get ingress

# ----------------------------- Runner ---------------------------------

if [[ "$INSTALL_RUNNER" == "yes" ]]; then
  section "🏃 GitLab Runner preparation"

  if [[ -z "${RUNNER_REGISTRATION_TOKEN}" ]]; then
    echo
    echo "Runner registration token is empty."
    echo "Installiere den Runner daher noch nicht."
    echo
    echo "Nach GitLab-Login kannst du das Script erneut starten mit:"
    echo "RUNNER_REGISTRATION_TOKEN='TOKEN' INSTALL_RUNNER=yes ./install-gitlab-demo-nodeport.sh"
  else
    if [[ "${ENABLE_TLS}" == "yes" ]]; then
      RUNNER_URL="https://${GITLAB_HOST}/"
    else
      RUNNER_URL="http://${GITLAB_HOST}:${NODEPORT_HTTP}/"
    fi

    section "🏃 Install GitLab Runner"

    cat >/tmp/gitlab-runner-values.yaml <<EOF
gitlabUrl: ${RUNNER_URL}
runnerRegistrationToken: "${RUNNER_REGISTRATION_TOKEN}"
rbac:
  create: true
serviceAccount:
  create: true
runners:
  config: |
    [[runners]]
      name = "kuse-k8s-runner"
      url = "${RUNNER_URL}"
      token = "${RUNNER_REGISTRATION_TOKEN}"
      executor = "kubernetes"
      [runners.kubernetes]
        namespace = "${RUNNER_NAMESPACE}"
        image = "alpine:3.20"
        privileged = true
        pull_policy = "if-not-present"
        helper_image_flavor = "alpine"
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

if [[ -n "${ACCESS_IP}" ]]; then
  echo "Add this to your local /etc/hosts:"
  echo "  ${ACCESS_IP} ${GITLAB_HOST}"
  echo
fi

if [[ "${ENABLE_TLS}" == "yes" ]]; then
  echo "GitLab URL:"
  echo "  https://${GITLAB_HOST}:${NODEPORT_HTTPS}"
  echo
  echo "Note:"
  echo "  With ingress-nginx NodePort, HTTPS runs on the configured NodePort."
  echo "  Browser warnings are expected with self-signed certificates."
else
  echo "GitLab URL:"
  echo "  http://${GITLAB_HOST}:${NODEPORT_HTTP}"
fi

cat <<EOF

Namespaces:
  ingress: ${INGRESS_NAMESPACE}
  gitlab:  ${GITLAB_NAMESPACE}
  runner:  ${RUNNER_NAMESPACE}

Quick checks:
  kubectl -n ${INGRESS_NAMESPACE} get svc
  kubectl -n ${GITLAB_NAMESPACE} get pods
  kubectl -n ${GITLAB_NAMESPACE} get ingress
  kubectl -n ${RUNNER_NAMESPACE} get pods
  helm ls -A

Example start:
  export ACCESS_IP=10.0.0.101
  export DEMO_DOMAIN=k8s.lan
  export GITLAB_ROOT_PASSWORD='SuperSecret123!'
  ./install-gitlab-demo-nodeport.sh

Then add locally:
  10.0.0.101 ${GITLAB_HOST}

And open:
EOF

if [[ "${ENABLE_TLS}" == "yes" ]]; then
  echo "  https://${GITLAB_HOST}:${NODEPORT_HTTPS}"
else
  echo "  http://${GITLAB_HOST}:${NODEPORT_HTTP}"
fi
