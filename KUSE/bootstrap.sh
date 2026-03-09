# ---------------------- Version policy ----------------------
# Modi:
#   VERSION_MODE=fixed   -> reproduzierbares Lab mit festem Release
#   VERSION_MODE=stable  -> zieht aktuelle stable.txt
VERSION_MODE="${VERSION_MODE:-fixed}"

# Feste, reproduzierbare Lab-Versionen
K8S_FIXED_VERSION="${K8S_FIXED_VERSION:-v1.35.2}"
CALICO_FIXED_VERSION="${CALICO_FIXED_VERSION:-v3.31.4}"

resolve_versions() {
  case "${VERSION_MODE}" in
    fixed)
      K8S_STABLE_VERSION="${K8S_FIXED_VERSION}"
      CALICO_VERSION="${CALICO_FIXED_VERSION}"
      ;;
    stable)
      K8S_STABLE_VERSION="$(curl -fsSL --retry 3 --retry-delay 1 https://dl.k8s.io/release/stable.txt)"
      CALICO_VERSION="${CALICO_FIXED_VERSION}"
      ;;
    *)
      echo "ERROR: Unsupported VERSION_MODE='${VERSION_MODE}' (allowed: fixed|stable)" >&2
      exit 1
      ;;
  esac

  if [[ ! "${K8S_STABLE_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid Kubernetes version '${K8S_STABLE_VERSION}'" >&2
    exit 1
  fi

  if [[ ! "${CALICO_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid Calico version '${CALICO_VERSION}'" >&2
    exit 1
  fi

  K8S_REPO_MINOR="$(sed -E 's/^(v[0-9]+\.[0-9]+)\..*/\1/' <<< "${K8S_STABLE_VERSION}")"
}

resolve_versions

echo
echo "================================================="
echo "🔎 Version policy"
echo "================================================="
echo "VERSION_MODE:          ${VERSION_MODE}"
echo "K8S_STABLE_VERSION:    ${K8S_STABLE_VERSION}"
echo "K8S_REPO_MINOR:        ${K8S_REPO_MINOR}"
echo "CALICO_VERSION:        ${CALICO_VERSION}"
