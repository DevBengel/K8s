#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-demo-nodeport-v3.sh
#
# Ziel:
# - GitLab Demo für Bare-Metal-Lab
# - kein DNS nötig (nur /etc/hosts auf dem Client)
# - kein MetalLB nötig
# - ingress-nginx via NodePort
# - local-path Storage
# - GitLab bewusst reduziert
#
# Wichtige Designentscheidungen:
# - HTTP only
# - kein cert-manager
# - kein kas
# - keine registry
# - kein pages
# - kein prometheus
# - Helm install mit --wait=false
# - danach gezielte Status- und Fehlerprüfung
###############################################################################

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

RESET_GITLAB="${RESET_GITLAB:-yes}"
INSTALL_LOCAL_PATH="${INSTALL_LOCAL_PATH:-yes}"
INSTALL_INGRESS_NGINX="${INSTALL_INGRESS_NGINX:-yes}"

POSTGRES_SIZE="${POSTGRES_SIZE:-8Gi}"
REDIS_SIZE="${REDIS_SIZE:-2Gi}"
GITALY_SIZE="${GITALY_SIZE:-20Gi}"

if [[ -z "${GITLAB_ROOT_PASSWORD:-}" ]]; then
  read -rsp "GitLab root password: " GITLAB_ROOT_PASSWORD
  echo
  [[ -n "${GITLAB_ROOT_PASSWORD}" ]] || { echo "ERROR: empty password"; exit 1; }
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
apply_ns "${GITLAB_NAMESPACE}"
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
  section "🧹 GitLab cleanup"
  helm uninstall gitlab -n "${GITLAB_NAMESPACE}" || true
  kubectl -n "${GITLAB_NAMESPACE}" delete pvc --all || true
  kubectl -n "${GITLAB_NAMESPACE}" delete ingress --all || true
  kubectl -n "${GITLAB_NAMESPACE}" delete secret gitlab-root-password || true
  kubectl -n "${GITLAB_NAMESPACE}" delete job --all || true
  kubectl -n "${GITLAB_NAMESPACE}" delete deploy --all || true
  kubectl -n "${GITLAB_NAMESPACE}" delete sts --all || true
fi

section "🔑 root password secret"
kubectl -n "${GITLAB_NAMESPACE}" create secret generic gitlab-root-password \
  --from-literal=password="${GITLAB_ROOT_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -

section "📝 GitLab values"

cat >/tmp/gitlab-nodeport-values-v3.yaml <<EOF
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
  install: false

kas:
  enabled: false

pages:
  enabled: false

registry:
  enabled: false

minio:
  enabled: false

gitlab:
  gitaly:
    persistence:
      size: ${GITALY_SIZE}
  webservice:
    ingress:
      tls:
        enabled: false

postgresql:
  primary:
    persistence:
      size: ${POSTGRES_SIZE}

redis:
  master:
    persistence:
      size: ${REDIS_SIZE}

gitlab-exporter:
  enabled: true

gitlab-shell:
  enabled: true
EOF

cat /tmp/gitlab-nodeport-values-v3.yaml

section "🦊 Install GitLab"
helm upgrade --install gitlab gitlab/gitlab \
  --namespace "${GITLAB_NAMESPACE}" \
  --create-namespace \
  --version "${GITLAB_CHART_VERSION}" \
  -f /tmp/gitlab-nodeport-values-v3.yaml \
  --wait=false

section "📌 Direktstatus"
kubectl -n "${GITLAB_NAMESPACE}" get pvc || true
kubectl -n "${GITLAB_NAMESPACE}" get pods -o wide || true
kubectl -n "${GITLAB_NAMESPACE}" get ingress || true
helm get values gitlab -n "${GITLAB_NAMESPACE}" || true

print_access_hint

section "🩺 Nützliche Diagnosebefehle"
cat <<EOF
kubectl -n ${GITLAB_NAMESPACE} get pvc
kubectl -n ${GITLAB_NAMESPACE} get pods -w
kubectl -n ${GITLAB_NAMESPACE} get jobs
kubectl -n ${GITLAB_NAMESPACE} logs -lapp=migrations --tail=100
kubectl -n ${GITLAB_NAMESPACE} describe pod gitlab-postgresql-0
kubectl -n ${GITLAB_NAMESPACE} describe pod gitlab-redis-master-0
kubectl -n ${INGRESS_NAMESPACE} get svc
curl -I http://${GITLAB_HOST}:${NODEPORT_HTTP}
EOF

echo
echo "🎉 Installation angestoßen."
echo "Warte jetzt, bis PostgreSQL, Redis und Gitaly gesund sind."
