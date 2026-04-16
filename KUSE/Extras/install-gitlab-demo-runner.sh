#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# install-gitlab-runner-autocache.sh
#
# Ziel:
# - GitLab Runner im Cluster installieren
# - Registration Token nach Möglichkeit automatisch aus GitLab holen
# - Kubernetes Executor
# - privileged Builds
# - MinIO/S3 Cache verwenden
#
# Passend zu:
# - GitLab via Helm in Namespace gitlab
# - GitLab erreichbar über http://gitlab.k8s.lan:30080
# - MinIO im GitLab-Release aktiv
###############################################################################

GITLAB_NAMESPACE="${GITLAB_NAMESPACE:-gitlab}"
RUNNER_NAMESPACE="${RUNNER_NAMESPACE:-gitlab-runner}"

GITLAB_HOST="${GITLAB_HOST:-gitlab.k8s.lan}"
GITLAB_PORT="${GITLAB_PORT:-30080}"
GITLAB_URL="${GITLAB_URL:-http://${GITLAB_HOST}:${GITLAB_PORT}}"

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
    echo "⚠️  Konnte keinen toolbox Pod finden – Runner Token nicht automatisch ermittelbar"
    return
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
    echo "⚠️  Runner Token konnte nicht automatisch gelesen werden"
    RUNNER_TOKEN=""
  else
    echo "✔ Runner Registration Token automatisch ermittelt"
  fi
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

if [[ -z "${RUNNER_TOKEN}" ]]; then
  echo
  echo "👉 Bitte Runner Registration Token manuell aus GitLab setzen."
  echo "   Alternativ per ENV:"
  echo "   RUNNER_TOKEN='TOKEN' ./install-gitlab-runner-autocache.sh"
  echo
  echo "   GitLab UI: Admin / CI/CD / Runners"
  exit 1
fi

discover_minio_credentials

section "🧱 Namespace"
kubectl get ns "${RUNNER_NAMESPACE}" >/dev/null 2>&1 || kubectl create ns "${RUNNER_NAMESPACE}"

section "📚 Helm Repo"
helm repo add gitlab https://charts.gitlab.io >/dev/null 2>&1 || true
helm repo update

section "🔐 Cache Secret anlegen"
kubectl -n "${RUNNER_NAMESPACE}" create secret generic runner-cache-s3 \
  --from-literal=accesskey="${MINIO_ACCESS_KEY}" \
  --from-literal=secretkey="${MINIO_SECRET_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

section "📝 Runner Values"

cat >/tmp/gitlab-runner-autocache-values.yaml <<EOF
gitlabUrl: ${GITLAB_URL}
runnerRegistrationToken: "${RUNNER_TOKEN}"

rbac:
  create: true

serviceAccount:
  create: true

metrics:
  enabled: true

runners:
  name: "${RUNNER_NAME}"
  tags: "${RUNNER_TAGS}"
  locked: false
  runUntagged: true
  protected: false
  secret: runner-cache-s3

  config: |
    [[runners]]
      name = "${RUNNER_NAME}"
      url = "${GITLAB_URL}"
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

cat /tmp/gitlab-runner-autocache-values.yaml

section "🚀 Install GitLab Runner"
helm upgrade --install "${RUNNER_RELEASE_NAME}" gitlab/gitlab-runner \
  -n "${RUNNER_NAMESPACE}" \
  --version "${RUNNER_CHART_VERSION}" \
  -f /tmp/gitlab-runner-autocache-values.yaml \
  --wait

section "📌 Status"
kubectl -n "${RUNNER_NAMESPACE}" get pods -o wide
kubectl -n "${RUNNER_NAMESPACE}" get deploy
helm ls -n "${RUNNER_NAMESPACE}"

section "🧪 GitLab Hinweise"
cat <<EOF
GitLab:
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
