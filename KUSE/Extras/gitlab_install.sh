#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-demo-nodeport-v2.sh
#
# KUSE Demo-Setup für Bare-Metal-Labs OHNE DNS und OHNE MetalLB
#
# Enthalten:
# - local-path-provisioner als Default StorageClass
# - ingress-nginx via NodePort
# - GitLab per Helm
#
# Bewusste Designentscheidungen:
# - HTTP only (TLS aus) für maximale Lab-Robustheit
# - KEIN GitLab-cert-manager-Handling
# - KEIN GitLab-KAS
# - KEIN integrierter GitLab Runner im GitLab-Chart
# - StorageClass explizit auf local-path gesetzt
#
# Ziel:
# - GitLab erreichbar über:
#     http://gitlab.<domain>:30080
#
# Beispiel:
#   export ACCESS_IP=10.0.0.101
#   export DEMO_DOMAIN=k8s.lan
#   export GITLAB_ROOT_PASSWORD='SuperSecret123!'
#   ./install-gitlab-demo-nodeport-v2.sh
###############################################################################

# ----------------------------- Config ---------------------------------

DEMO_DOMAIN="${DEMO_DOMAIN:-k8s.lan}"
GITLAB_SUBDOMAIN="${GITLAB_SUBDOMAIN:-gitlab}"
GITLAB_HOST="${GITLAB_SUBDOMAIN}.${DEMO_DOMAIN}"

ACCESS_IP="${ACCESS_IP:-}"

INGRESS_NAMESPACE="${INGRESS_NAMESPACE:-ingress-nginx}"
GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-gitlab}"
LOCAL_PATH_NAMESPACE="${LOCAL_PATH_NAMESPACE:-local-path-storage}"

INGRESS_NGINX_VERSION="${INGRESS_NGINX_VERSION:-4.12.1}"
GITLAB_CHART_VERSION="${GITLAB_CHART_VERSION:-8.11.2}"

NODEPORT_HTTP="${NODEPORT_HTTP:-30080}"
NODEPORT_HTTPS="${NODEPORT_HTTPS:-30443}"

STORAGE_CLASS_NAME="${STORAGE_CLASS_NAME:-local-path}"

INSTALL_LOCAL_PATH="${INSTALL_LOCAL_PATH:-yes}"
INSTALL_INGRESS_NGINX="${INSTALL_INGRESS_NGINX:-yes}"
RESET_GITLAB="${RESET_GITLAB:-no}"

INSTALL_MONITORING="${INSTALL_MONITORING:-no}"

POSTGRES_SIZE="${POSTGRES_SIZE:-8Gi}"
REDIS_SIZE="${REDIS_SIZE:-2Gi}"
MINIO_SIZE="${MINIO_SIZE:-10Gi}"
GITALY_SIZE="${GITALY_SIZE:-20Gi}"

# Root password
if [[ -z "${GITLAB_ROOT_PASSWORD:-}" ]]; then
  read -rsp "GitLab root password: " GITLAB_ROOT_PASSWORD
  echo
  if [[ -z "${GITLAB_ROOT_PASSWORD}" ]]; then
    echo "ERROR: GITLAB_ROOT_PASSWORD must not be empty" >&2
    exit 1
  fi
fi

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

wait_for_storageclass() {
  local sc="$1"
  for i in {1..60}; do
    if kubectl get storageclass "$sc" >/dev/null 2>&1; then
      echo "✅ StorageClass '$sc' found"
      return 0
    fi
    sleep 2
  done
  echo "ERROR: StorageClass '$sc' not found" >&2
  return 1
}

show_gitlab_access_hint() {
  echo
  echo "GitLab URL:"
  echo "  http://${GITLAB_HOST}:${NODEPORT_HTTP}"
  echo
  if [[ -n "${ACCESS_IP}" ]]; then
    echo "Add this line to /etc/hosts on the client machine:"
    echo "  ${ACCESS_IP} ${GITLAB_HOST}"
  else
    echo "Set ACCESS_IP for a clearer hint, e.g.:"
    echo "  export ACCESS_IP=10.0.0.101"
  fi
}

# ----------------------------- Checks ---------------------------------

require_cmd kubectl
require_cmd helm

section "🔎 Preflight"
kubectl version --client=true
helm version
kubectl get nodes -o wide

# ----------------------------- Namespaces ------------------------------

section "🧱 Ensure namespaces"
apply_ns "$INGRESS_NAMESPACE"
apply_ns "$GITLAB_NAMESPACE"

# local-path namespace wird vom Manifest erzeugt, apply_ns ist aber unkritisch
apply_ns "$LOCAL_PATH_NAMESPACE"

# ----------------------------- Helm repos ------------------------------

section "📚 Helm repositories"
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
helm repo add gitlab https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo update

# ------------------------ local-path provisioner -----------------------

if [[ "${INSTALL_LOCAL_PATH}" == "yes" ]]; then
  section "💾 Install local-path provisioner"

  kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml

  wait_for_storageclass "${STORAGE_CLASS_NAME}"

  kubectl patch storageclass "${STORAGE_CLASS_NAME}" \
    -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' || true

  echo
  echo "StorageClasses:"
  kubectl get storageclass
fi

# -------------------------- ingress-nginx ------------------------------

if [[ "${INSTALL_INGRESS_NGINX}" == "yes" ]]; then
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
    --namespace "${INGRESS_NAMESPACE}" \
    --version "${INGRESS_NGINX_VERSION}" \
    -f /tmp/ingress-nginx-nodeport-values.yaml

  wait_rollout "${INGRESS_NAMESPACE}" deployment ingress-nginx-controller

  echo
  echo "Ingress services:"
  kubectl -n "${INGRESS_NAMESPACE}" get svc
fi

# ---------------------------- GitLab reset -----------------------------

if [[ "${RESET_GITLAB}" == "yes" ]]; then
  section "🧹 Reset previous GitLab installation"

  helm uninstall gitlab -n "${GITLAB_NAMESPACE}" || true
  kubectl -n "${GITLAB_NAMESPACE}" delete pvc --all || true
  kubectl -n "${GITLAB_NAMESPACE}" delete secret gitlab-root-password || true

  echo
  echo "Remaining resources in namespace ${GITLAB_NAMESPACE}:"
  kubectl -n "${GITLAB_NAMESPACE}" get all || true
fi

# ----------------------- GitLab root password --------------------------

section "🔑 Create GitLab root password secret"
kubectl -n "${GITLAB_NAMESPACE}" create secret generic gitlab-root-password \
  --from-literal=password="${GITLAB_ROOT_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -

# -------------------------- GitLab values ------------------------------

section "📝 Build GitLab values"

cat >/tmp/gitlab-nodeport-values-v2.yaml <<EOF
global:
  hosts:
    domain: ${DEMO_DOMAIN}
    https: false
  ingress:
    class: nginx
    configureCertmanager: false
    tls:
      enabled: false
  edition: ce
  initialRootPassword:
    secret: gitlab-root-password
    key: password
  storage:
    class: ${STORAGE_CLASS_NAME}

installCertmanager: false

certmanager:
  installCRDs: false

nginx-ingress:
  enabled: false

gitlab-runner:
  install: false

prometheus:
  install: ${INSTALL_MONITORING}

registry:
  enabled: true
  ingress:
    tls:
      enabled: false

minio:
  persistence:
    size: ${MINIO_SIZE}
  ingress:
    tls:
      enabled: false

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
  webservice:
    ingress:
      tls:
        enabled: false

gitlab-exporter:
  enabled: true

gitlab-shell:
  enabled: true

kas:
  enabled: false

pages:
  enabled: false
EOF

echo
echo "Generated values:"
cat /tmp/gitlab-nodeport-values-v2.yaml

# --------------------------- Install GitLab ----------------------------

section "🦊 Install GitLab"

helm upgrade --install gitlab gitlab/gitlab \
  --namespace "${GITLAB_NAMESPACE}" \
  --create-namespace \
  --version "${GITLAB_CHART_VERSION}" \
  -f /tmp/gitlab-nodeport-values-v2.yaml

# -------------------------- Wait / verify ------------------------------

section "⏳ Initial GitLab status"

echo "PVCs:"
kubectl -n "${GITLAB_NAMESPACE}" get pvc || true

echo
echo "Pods:"
kubectl -n "${GITLAB_NAMESPACE}" get pods -o wide || true

echo
echo "Ingress:"
kubectl -n "${GITLAB_NAMESPACE}" get ingress || true

section "📌 Access hints"
show_gitlab_access_hint

cat <<EOF

Useful checks:
  kubectl -n ${GITLAB_NAMESPACE} get pvc
  kubectl -n ${GITLAB_NAMESPACE} get pods -w
  kubectl -n ${GITLAB_NAMESPACE} get ingress
  kubectl -n ${INGRESS_NAMESPACE} get svc

Expected access:
  http://${GITLAB_HOST}:${NODEPORT_HTTP}

Local test:
  curl -I http://${GITLAB_HOST}:${NODEPORT_HTTP}

If you use /etc/hosts on the client:
EOF

if [[ -n "${ACCESS_IP}" ]]; then
  echo "  ${ACCESS_IP} ${GITLAB_HOST}"
else
  echo "  <NODE-IP> ${GITLAB_HOST}"
fi

echo
echo "🎉 Script finished"
echo "Now wait until the GitLab core pods become healthy."
