#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-demo-nodeport-v4.sh
#
# Funktionaler GitLab-Demo-Stand für Bare-Metal-Lab:
# - kein DNS nötig (nur /etc/hosts auf dem Client)
# - kein MetalLB nötig
# - ingress-nginx via NodePort
# - local-path Storage
# - GitLab 8.11.8
#
# Wichtige Designentscheidungen:
# - HTTP only
# - MinIO bleibt AN
# - Registry AUS
# - Pages AUS
# - Prometheus AUS
# - KAS global deaktiviert
# - Legacy-Bitnami-Repositories für PostgreSQL/Redis
# - Helm-Install darf fehlschlagen, wenn Kernpods danach trotzdem gesund sind
###############################################################################

DEMO_DOMAIN="${DEMO_DOMAIN:-k8s.lan}"
GITLAB_SUBDOMAIN="${GITLAB_SUBDOMAIN:-gitlab}"
GITLAB_HOST="${GITLAB_SUBDOMAIN}.${DEMO_DOMAIN}"
ACCESS_IP="${ACCESS_IP:-}"

INGRESS_NAMESPACE="${INGRESS_NAMESPACE:-ingress-nginx}"
GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-gitlab}"
LOCAL_PATH_NAMESPACE="${LOCAL_PATH_NAMESPACE:-local-path-storage}"

INGRESS_NGINX_VERSION="${INGRESS_NGINX_VERSION:-4.12.1}"
GITLAB_CHART_VERSION="${GITLAB_CHART_VERSION:-8.11.8}"

NODEPORT_HTTP="${NODEPORT_HTTP:-30080}"
NODEPORT_HTTPS="${NODEPORT_HTTPS:-30443}"
STORAGE_CLASS_NAME="${STORAGE_CLASS_NAME:-local-path}"

RESET_GITLAB="${RESET_GITLAB:-yes}"
INSTALL_LOCAL_PATH="${INSTALL_LOCAL_PATH:-yes}"
INSTALL_INGRESS_NGINX="${INSTALL_INGRESS_NGINX:-yes}"

POSTGRES_SIZE="${POSTGRES_SIZE:-8Gi}"
REDIS_SIZE="${REDIS_SIZE:-2Gi}"
GITALY_SIZE="${GITALY_SIZE:-20Gi}"
MINIO_SIZE="${MINIO_SIZE:-10Gi}"

HELM_TIMEOUT="${HELM_TIMEOUT:-15m}"

if [[ -z "${GITLAB_ROOT_PASSWORD:-}" ]]; then
  read -rsp "GitLab root password: " GITLAB_ROOT_PASSWORD
  echo
  [[ -n "${GITLAB_ROOT_PASSWORD}" ]] || {
    echo "ERROR: empty password" >&2
    exit 1
  }
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing command: $1" >&2
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
  kubectl get ns "$1" >/dev/null 2>&1 || kubectl create ns "$1"
}

wait_rollout() {
  kubectl -n "$1" rollout status "$2/$3" --timeout=300s
}

wait_for_namespace_deletion() {
  local ns="$1"
  for _ in {1..120}; do
    if ! kubectl get ns "$ns" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "ERROR: namespace '$ns' still exists after waiting" >&2
  return 1
}

print_access_hint() {
  echo
  echo "GitLab URL:"
  echo "  http://${GITLAB_HOST}:${NODEPORT_HTTP}"
  echo
  if [[ -n "${ACCESS_IP}" ]]; then
    echo "Client /etc/hosts:"
    echo "  ${ACCESS_IP} ${GITLAB_HOST}"
  else
    echo "Setze ACCESS_IP für den passenden /etc/hosts-Hinweis."
  fi
}

require_cmd kubectl
require_cmd helm

section "🔎 Preflight"
kubectl version --client=true
helm version
kubectl get nodes -o wide

section "🧱 Namespaces"
apply_ns "${INGRESS_NAMESPACE}"
apply_ns "${LOCAL_PATH_NAMESPACE}"

section "📚 Helm repos"
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
helm repo add gitlab https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo update

if [[ "${INSTALL_LOCAL_PATH}" == "yes" ]]; then
  section "💾 local-path provisioner"
  kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
  kubectl patch storageclass "${STORAGE_CLASS_NAME}" \
    -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' || true
  kubectl get storageclass
fi

if [[ "${INSTALL_INGRESS_NGINX}" == "yes" ]]; then
  section "🌐 ingress-nginx NodePort"

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
  kubectl -n "${INGRESS_NAMESPACE}" get svc
fi

if [[ "${RESET_GITLAB}" == "yes" ]]; then
  section "🧹 GitLab cleanup via namespace reset"
  helm uninstall gitlab -n "${GITLAB_NAMESPACE}" || true
  kubectl delete ns "${GITLAB_NAMESPACE}" --ignore-not-found=true
  wait_for_namespace_deletion "${GITLAB_NAMESPACE}" || true
fi

apply_ns "${GITLAB_NAMESPACE}"

section "🔑 root password secret"
kubectl -n "${GITLAB_NAMESPACE}" create secret generic gitlab-root-password \
  --from-literal=password="${GITLAB_ROOT_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -

section "📝 GitLab values"

cat >/tmp/gitlab-nodeport-values-v4.yaml <<EOF
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
  kas:
    enabled: false

installCertmanager: false

certmanager:
  installCRDs: false

nginx-ingress:
  enabled: false

gitlab-runner:
  install: false

prometheus:
  install: false

pages:
  enabled: false

registry:
  enabled: false

gitlab:
  gitaly:
    persistence:
      size: ${GITALY_SIZE}
  gitlab-exporter:
    enabled: true
  gitlab-shell:
    enabled: true
  webservice:
    ingress:
      tls:
        enabled: false

postgresql:
  image:
    repository: bitnamilegacy/postgresql
  volumePermissions:
    image:
      repository: bitnamilegacy/os-shell
  metrics:
    image:
      repository: bitnamilegacy/postgres-exporter
  primary:
    persistence:
      size: ${POSTGRES_SIZE}

redis:
  image:
    repository: bitnamilegacy/redis
  metrics:
    image:
      repository: bitnamilegacy/redis-exporter
  sentinel:
    image:
      repository: bitnamilegacy/redis-sentinel
  master:
    persistence:
      size: ${REDIS_SIZE}

minio:
  persistence:
    size: ${MINIO_SIZE}
EOF

cat /tmp/gitlab-nodeport-values-v4.yaml

section "🦊 Install GitLab"
set +e
helm upgrade --install gitlab gitlab/gitlab \
  --namespace "${GITLAB_NAMESPACE}" \
  --create-namespace \
  --version "${GITLAB_CHART_VERSION}" \
  -f /tmp/gitlab-nodeport-values-v4.yaml \
  --wait=false \
  --timeout "${HELM_TIMEOUT}"
HELM_RC=$?
set -e

echo
echo "Helm return code: ${HELM_RC}"
if [[ "${HELM_RC}" -ne 0 ]]; then
  echo "NOTE: Helm returned non-zero. Continuing with real pod/status checks."
fi

section "📌 Direktstatus"
kubectl -n "${GITLAB_NAMESPACE}" get pvc || true
kubectl -n "${GITLAB_NAMESPACE}" get pods -o wide || true
kubectl -n "${GITLAB_NAMESPACE}" get ingress || true
kubectl -n "${GITLAB_NAMESPACE}" get events --sort-by=.lastTimestamp | tail -n 40 || true
helm get values gitlab -n "${GITLAB_NAMESPACE}" || true
helm status gitlab -n "${GITLAB_NAMESPACE}" || true

print_access_hint

section "🩺 Nützliche Diagnosebefehle"
cat <<EOF
kubectl -n ${GITLAB_NAMESPACE} get pvc
kubectl -n ${GITLAB_NAMESPACE} get pods -w
kubectl -n ${GITLAB_NAMESPACE} get jobs
kubectl -n ${GITLAB_NAMESPACE} get ingress
kubectl -n ${GITLAB_NAMESPACE} logs -lapp=migrations --tail=100
kubectl -n ${GITLAB_NAMESPACE} describe pod gitlab-postgresql-0
kubectl -n ${GITLAB_NAMESPACE} describe pod gitlab-redis-master-0
kubectl -n ${INGRESS_NAMESPACE} get svc
curl -I http://${GITLAB_HOST}:${NODEPORT_HTTP}
EOF

echo
echo "🎉 Installation angestoßen."
echo "Warte jetzt, bis PostgreSQL, Redis, MinIO, Gitaly, Sidekiq und Webservice gesund sind."
echo "Ein Helm-Status 'failed' ist tolerierbar, wenn die Kernpods danach auf Running gehen."
