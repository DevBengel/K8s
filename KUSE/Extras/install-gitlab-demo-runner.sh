#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-runner-autocache-v3.sh
#
# Ziel:
# - GitLab Runner im Cluster installieren
# - Runner Registration Token automatisch aus GitLab holen
# - Kubernetes Executor
# - privileged Builds
# - MinIO/S3 Cache verwenden
#
# Erkenntnisse:
# - Runner darf NICHT über gitlab.k8s.lan:30080 registrieren
# - Runner muss den internen Service nutzen:
#     http://gitlab-webservice-default.gitlab.svc:8181
# - Job-Pods brauchen clone_url auf den internen Service
# - Cache-Secret muss als existing secret via runners.cache.secretName
#   referenziert werden
# - metrics.podMonitor.enabled=false verhindert Helm-Nil-Fehler
###############################################################################

GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-gitlab}"
RUNNER_NAMESPACE="${RUNNER_NAMESPACE:-gitlab-runner}"

# Interner Service-Zugriff für Runner und Job-Pods
GITLAB_INTERNAL_HOST="${GITLAB_INTERNAL_HOST:-gitlab-webservice-default.${GITLAB_NAMESPACE}.svc}"
GITLAB_INTERNAL_PORT="${GITLAB_INTERNAL_PORT:-8181}"
GITLAB_URL="${GITLAB_URL:-http://${GITLAB_INTERNAL_HOST}:${GITLAB_INTERNAL_PORT}}"

RUNNER_RELEASE_NAME="${RUNNER_RELEASE_NAME:-gitlab-runner}"
RUNNER_NAME="${RUNNER_NAME:-k8s-runner}"
RUNNER_TAGS="${RUNNER_TAGS:-k8s,demo,privileged}"
RUNNER_CHART_VERSION="${RUNNER_CHART_VERSION:-0.77.2}"

MINIO_SERVER="${MINIO_SERVER:-gitlab-minio-svc.${GITLAB_NAMESPACE}.svc:9000}"
MINIO_BUCKET="${MINIO_BUCKET:-runner-cache}"
MINIO_INSECURE="${MINIO_INSECURE:-true}"

RUNNER_TOKEN="${RUNNER_TOKEN:-}"

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

get_toolbox_pod() {
  kubectl -n "${GITLAB_NAMESPACE}" get pod \
    -lapp=toolbox \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

discover_runner_token() {
  if [[ -n "${RUNNER_TOKEN}" ]]; then
    echo "ℹ️  Verwende vorgegebenen RUNNER_TOKEN"
    return
  fi

  local toolbox_pod
  toolbox_pod="$(get_toolbox_pod || true)"

  if [[ -z "${toolbox_pod}" ]]; then
    echo "ERROR: Konnte keinen toolbox Pod finden – Runner Token nicht automatisch ermittelbar" >&2
    exit 1
  fi

  echo "ℹ️  Versuche Runner Registration Token aus GitLab zu lesen ..."
  set +e
  RUNNER_TOKEN="$(
    kubectl -n "${GITLAB_NAMESPACE}" exec "${toolbox_pod}" -- \
      /bin/bash -lc "gitlab-rails runner 'puts Gitlab::CurrentSettings.current_application_settings.runners_registration_token'" \
      2>/dev/null | tail -n1 | tr -d '\r'
  )"
  local rc=$?
  set -e

  if [[ "${rc}" -ne 0 || -z "${RUNNER_TOKEN}" ]]; then
    echo "ERROR: Runner Token konnte nicht automatisch gelesen werden" >&2
    exit 1
  fi

  echo "✔ Runner Registration Token automatisch ermittelt"
}

discover_minio_credentials() {
  section "🔍 MinIO Credentials ermitteln"

  MINIO_ACCESS_KEY="$(
    kubectl -n "${GITLAB_NAMESPACE}" get secret gitlab-minio-secret \
      -o jsonpath='{.data.accesskey}' 2>/dev/null | base64 -d || true
  )"

  MINIO_SECRET_KEY="$(
    kubectl -n "${GITLAB_NAMESPACE}" get secret gitlab-minio-secret \
      -o jsonpath='{.data.secretkey}' 2>/dev/null | base64 -d || true
  )"

  if [[ -z "${MINIO_ACCESS_KEY}" || -z "${MINIO_SECRET_KEY}" ]]; then
    echo "ERROR: MinIO Credentials konnten nicht aus secret/gitlab-minio-secret gelesen werden" >&2
    exit 1
  fi

  echo "✔ MinIO Access Key und Secret Key gefunden"
}

require_cmd kubectl
require_cmd helm
require_cmd base64

section "🔎 Preflight"
kubectl version --client=true
helm version
kubectl -n "${GITLAB_NAMESPACE}" get pods >/dev/null

discover_runner_token
discover_minio_credentials

section "🧹 Runner Namespace reset"
kubectl delete ns "${RUNNER_NAMESPACE}" --ignore-not-found=true
wait_for_namespace_deletion "${RUNNER_NAMESPACE}" || true
kubectl create ns "${RUNNER_NAMESPACE}"

section "🔐 Cache Secret anlegen"
kubectl -n "${RUNNER_NAMESPACE}" create secret generic runner-cache-s3 \
  --from-literal=accesskey="${MINIO_ACCESS_KEY}" \
  --from-literal=secretkey="${MINIO_SECRET_KEY}"

section "📚 Helm Repo"
helm repo add gitlab https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo update

section "📝 Runner Values"

cat >/tmp/gitlab-runner-autocache-values-v3.yaml <<EOF
gitlabUrl: ${GITLAB_URL}
runnerRegistrationToken: "${RUNNER_TOKEN}"

rbac:
  create: true

serviceAccount:
  create: true

metrics:
  enabled: true
  podMonitor:
    enabled: false

runners:
  name: "${RUNNER_NAME}"
  tags: "${RUNNER_TAGS}"
  locked: false
  runUntagged: true
  protected: false

  cache:
    secretName: runner-cache-s3

  config: |
    [[runners]]
      name = "${RUNNER_NAME}"
      url = "${GITLAB_URL}"
      clone_url = "${GITLAB_URL}"
      token = "${RUNNER_TOKEN}"
      executor = "kubernetes"

      [runners.kubernetes]
        namespace = "${RUNNER_NAMESPACE}"
        image = "ubuntu:22.04"
        privileged = true
        poll_timeout = 600
        helper_image_flavor = "alpine"

      [runners.cache]
        Type = "s3"
        Path = "runner"
        Shared = true

        [runners.cache.s3]
          ServerAddress = "${MINIO_SERVER}"
          BucketName = "${MINIO_BUCKET}"
          BucketLocation = "us-east-1"
          Insecure = ${MINIO_INSECURE}
          AuthenticationType = "access-key"
EOF

cat /tmp/gitlab-runner-autocache-values-v3.yaml

section "🚀 Install GitLab Runner"
helm upgrade --install "${RUNNER_RELEASE_NAME}" gitlab/gitlab-runner \
  -n "${RUNNER_NAMESPACE}" \
  --version "${RUNNER_CHART_VERSION}" \
  -f /tmp/gitlab-runner-autocache-values-v3.yaml \
  --wait

section "📌 Status"
kubectl -n "${RUNNER_NAMESPACE}" get pods -o wide
kubectl -n "${RUNNER_NAMESPACE}" get deploy
helm ls -n "${RUNNER_NAMESPACE}"

section "🧪 Logs"
kubectl -n "${RUNNER_NAMESPACE}" logs deploy/"${RUNNER_RELEASE_NAME}" --tail=100 || true

section "🧪 Hinweise"
cat <<EOF
Interner GitLab-Zugriff des Runners:
  ${GITLAB_URL}

Runner Namespace:
  ${RUNNER_NAMESPACE}

MinIO Cache Endpoint:
  ${MINIO_SERVER}

MinIO Cache Bucket:
  ${MINIO_BUCKET}

Prüfen:
  kubectl -n ${RUNNER_NAMESPACE} get pods
  kubectl -n ${RUNNER_NAMESPACE} logs deploy/${RUNNER_RELEASE_NAME}

Beispiel-.gitlab-ci.yml:

stages:
  - test

test-job:
  stage: test
  tags:
    - k8s
  script:
    - echo "Runner funktioniert"
    - uname -a
EOF

echo
echo "🎉 Runner installiert."
