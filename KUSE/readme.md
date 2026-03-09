#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# bootstrap.sh — Vanilla Kubernetes (kubeadm) + Calico (Tigera) — LAB-robust
#
# Target nodes:
#   kube-1 10.0.0.101 (control-plane)
#   kube-2 10.0.0.102 (worker)
#   kube-3 10.0.0.103 (worker)
#
# Highlights:
# - Fester Versionsschalter für reproduzierbare Labs
# - Optionaler Stable-Modus
# - pkgs.k8s.io Minor-Repo wird aus der K8s-Version abgeleitet
# - Installiert/konfiguriert containerd (SystemdCgroup=true)
# - Idempotenteres /etc/hosts
# - Optionaler RESET-Modus für bestehende Cluster
# - kubeadm init mit expliziter --kubernetes-version
# - Calico via Tigera Operator
#
# Beispiele:
#   PASS='secret' bash ./bootstrap.sh
#   PASS='secret' RESET_CLUSTER=yes bash ./bootstrap.sh
#   PASS='secret' VERSION_MODE=fixed K8S_FIXED_VERSION=v1.35.2 CALICO_FIXED_VERSION=v3.31.4 bash ./bootstrap.sh
#   PASS='secret' VERSION_MODE=stable bash ./bootstrap.sh
###############################################################################

# ----------------------------- User input -----------------------------
read -rp "SSH Username: " USER

if [[ -z "${PASS:-}" ]]; then
  read -rsp "SSH Password: " PASS1; echo
  read -rsp "SSH Password (repeat): " PASS2; echo
  if [[ -z "$PASS1" ]]; then
    echo "ERROR: Empty password entered (input is hidden). Re-run." >&2
    exit 1
  fi
  if [[ "$PASS1" != "$PASS2" ]]; then
    echo "ERROR: Passwords do not match. Re-run." >&2
    exit 1
  fi
  PASS="$PASS1"
  unset PASS1 PASS2
else
  echo "(Using SSH password from environment PASS)"
fi
echo "PASSLEN=${#PASS}"

RESET_CLUSTER="${RESET_CLUSTER:-no}"

# ----------------------------- Topology ------------------------------
KUBE1_IP="10.0.0.101"; KUBE1_HOST="kube-1"
KUBE2_IP="10.0.0.102"; KUBE2_HOST="kube-2"
KUBE3_IP="10.0.0.103"; KUBE3_HOST="kube-3"

NODES=(
  "${KUBE1_IP}:${KUBE1_HOST}"
  "${KUBE2_IP}:${KUBE2_HOST}"
  "${KUBE3_IP}:${KUBE3_HOST}"
)

POD_CIDR="192.168.0.0/16"

# ---------------------------- Local deps -----------------------------
for cmd in ssh sshpass base64 curl sed awk grep; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: missing local command: $cmd" >&2
    exit 1
  }
done

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
      K8S_VERSION="${K8S_FIXED_VERSION}"
      CALICO_VERSION="${CALICO_FIXED_VERSION}"
      ;;
    stable)
      K8S_VERSION="$(curl -fsSL --retry 3 --retry-delay 1 https://dl.k8s.io/release/stable.txt)"
      CALICO_VERSION="${CALICO_FIXED_VERSION}"
      ;;
    *)
      echo "ERROR: Unsupported VERSION_MODE='${VERSION_MODE}' (allowed: fixed|stable)" >&2
      exit 1
      ;;
  esac

  if [[ ! "${K8S_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid Kubernetes version '${K8S_VERSION}'" >&2
    exit 1
  fi

  if [[ ! "${CALICO_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid Calico version '${CALICO_VERSION}'" >&2
    exit 1
  fi

  K8S_REPO_MINOR="$(sed -E 's/^(v[0-9]+\.[0-9]+)\..*/\1/' <<< "${K8S_VERSION}")"
}

echo
echo "================================================="
echo "🔎 Resolving versions"
echo "================================================="
resolve_versions
echo "VERSION_MODE:          ${VERSION_MODE}"
echo "K8S_VERSION:           ${K8S_VERSION}"
echo "K8S_REPO_MINOR:        ${K8S_REPO_MINOR}"
echo "CALICO_VERSION:        ${CALICO_VERSION}"
echo "RESET_CLUSTER:         ${RESET_CLUSTER}"

# ----------------------------- SSH opts ------------------------------
SSH_AUTH_OPTS=(
  -o PreferredAuthentications=password,keyboard-interactive
  -o PubkeyAuthentication=no
  -o KbdInteractiveAuthentication=yes
  -o NumberOfPasswordPrompts=1
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

SSH_NO_TTY=( "${SSH_AUTH_OPTS[@]}" )
SSH_TTY=( "${SSH_AUTH_OPTS[@]}" -t )

b64() {
  printf "%s" "$1" | base64 -w 0 2>/dev/null || printf "%s" "$1" | base64 | tr -d '\n'
}

ssh_exec() {
  local ip="$1"; shift
  echo
  echo "===================================================================="
  echo "➡️  [$ip] $*"
  echo "===================================================================="
  sshpass -p "$PASS" ssh "${SSH_NO_TTY[@]}" "${USER}@${ip}" "$@"
}

ssh_bash_tty() {
  local ip="$1"
  local content="$2"
  echo
  echo "===================================================================="
  echo "➡️  [$ip] bash -se (stdin, TTY)"
  echo "===================================================================="
  printf '%s' "$content" | sshpass -p "$PASS" ssh "${SSH_TTY[@]}" "${USER}@${ip}" "bash -se"
}

# ----------------------------- PHASE 0 -------------------------------
echo
echo "================================================="
echo "🚀 PHASE 0 – SSH Connectivity"
echo "================================================="
for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  ssh_exec "$ip" "echo Connected to \$(hostname) as \$(whoami)"
done

# ----------------------------- PHASE 1 -------------------------------
echo
echo "================================================="
echo "🧭 PHASE 1 – Hostnames & /etc/hosts"
echo "================================================="

HOSTS_BLOCK="${KUBE1_IP} ${KUBE1_HOST}
${KUBE2_IP} ${KUBE2_HOST}
${KUBE3_IP} ${KUBE3_HOST}"
HOSTS_B64="$(b64 "$HOSTS_BLOCK")"

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"

  REMOTE_HOSTS_SCRIPT="$(printf '%s\n' \
    'set -Eeuo pipefail' \
    'export DEBIAN_FRONTEND=noninteractive' \
    '' \
    "echo \"Setting hostname -> ${host}\"" \
    "sudo hostnamectl set-hostname \"${host}\"" \
    '' \
    'echo "Refreshing /etc/hosts kubernetes block idempotently"' \
    'TMPF="$(mktemp)"' \
    'cp /etc/hosts "$TMPF"' \
    'sed -i "/# BEGIN KUBERNETES CLUSTER/,/# END KUBERNETES CLUSTER/d" "$TMPF"' \
    'printf "\n# BEGIN KUBERNETES CLUSTER\n" >> "$TMPF"' \
    "echo \"${HOSTS_B64}\" | base64 -d >> \"\$TMPF\"" \
    'printf "\n# END KUBERNETES CLUSTER\n" >> "$TMPF"' \
    'sudo cp "$TMPF" /etc/hosts' \
    'rm -f "$TMPF"' \
    '' \
    'echo "Hostname now:"' \
    'hostname' \
    'echo "--- /etc/hosts (tail) ---"' \
    'tail -n 12 /etc/hosts || true' \
  )"

  ssh_bash_tty "$ip" "$REMOTE_HOSTS_SCRIPT"
done

# ----------------------------- PHASE 2 -------------------------------
echo
echo "================================================="
echo "📦 PHASE 2 – LAB fix + Kubernetes install on ALL nodes"
echo "================================================="

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"

  echo
  echo "==================== NODE $host ($ip) ===================="

  REMOTE_INSTALL_SCRIPT="$(printf '%s\n' \
    'set -Eeuo pipefail' \
    'export DEBIAN_FRONTEND=noninteractive' \
    '' \
    'echo "== [LAB FIX] /dev/disk/by-id =="' \
    'sudo mkdir -p /dev/disk/by-id' \
    'ROOTDEV="$(findmnt -n -o SOURCE / || true)"' \
    'ROOTDEV_REAL="$(readlink -f "$ROOTDEV" 2>/dev/null || true)"' \
    'if [ -n "$ROOTDEV_REAL" ] && [ -e "$ROOTDEV_REAL" ]; then sudo ln -sf "$ROOTDEV_REAL" /dev/disk/by-id/lab-root; fi' \
    'sudo ls -l /dev/disk/by-id || true' \
    '' \
    'echo "== [LAB FIX] shim-signed postinst (EFI/ESP missing in LAB) =="' \
    'POST=/var/lib/dpkg/info/shim-signed.postinst' \
    'DIV=${POST}.real' \
    'if [ -f "$POST" ] && [ ! -f "$DIV" ]; then sudo dpkg-divert --add --rename --divert "$DIV" "$POST" || true; fi' \
    'if [ -f "$POST" ]; then printf "#!/bin/sh\n# LAB: skip EFI/ESP mount\nexit 0\n" | sudo tee "$POST" >/dev/null; sudo chmod +x "$POST"; fi' \
    '' \
    'echo "== [A] Reset stale cluster state (optional) =="' \
    "if [ \"${RESET_CLUSTER}\" = \"yes\" ]; then" \
    '  echo "RESET_CLUSTER=yes -> cleaning previous kubeadm state"' \
    '  sudo kubeadm reset -f || true' \
    '  sudo systemctl stop kubelet || true' \
    '  sudo rm -rf /etc/cni/net.d/* || true' \
    '  sudo rm -rf /var/lib/cni/ || true' \
    '  sudo rm -rf /var/lib/kubelet/* || true' \
    '  sudo rm -rf /etc/kubernetes/* || true' \
    '  sudo ip link delete cni0 2>/dev/null || true' \
    '  sudo ip link delete flannel.1 2>/dev/null || true' \
    '  sudo ip link delete vxlan.calico 2>/dev/null || true' \
    '  sudo ip link delete tunl0 2>/dev/null || true' \
    '  sudo iptables -F || true' \
    '  sudo iptables -t nat -F || true' \
    '  sudo iptables -t mangle -F || true' \
    '  sudo iptables -X || true' \
    'fi' \
    '' \
    'echo "== [B] dpkg recovery =="' \
    'sudo dpkg --configure -a || true' \
    'sudo apt-get -f install -y || true' \
    '' \
    'echo "== [C] Base packages =="' \
    'sudo apt-get update' \
    'sudo apt-get install -y ca-certificates curl gpg apt-transport-https software-properties-common' \
    '' \
    'echo "== [D] Disable APT proxy for Kubernetes repos (DIRECT) =="' \
    'sudo tee /etc/apt/apt.conf.d/99-k8s-direct >/dev/null <<EOF' \
    'Acquire::http::Proxy::pkgs.k8s.io "DIRECT";' \
    'Acquire::https::Proxy::pkgs.k8s.io "DIRECT";' \
    'Acquire::http::Proxy::prod-cdn.packages.k8s.io "DIRECT";' \
    'Acquire::https::Proxy::prod-cdn.packages.k8s.io "DIRECT";' \
    'Acquire::http::Proxy::dl.k8s.io "DIRECT";' \
    'Acquire::https::Proxy::dl.k8s.io "DIRECT";' \
    'EOF' \
    '' \
    "echo \"== [E] Kubernetes repo (${K8S_REPO_MINOR}) ==\"" \
    'sudo rm -f /etc/apt/sources.list.d/kubernetes.list /etc/apt/sources.list.d/*kubernetes*.list || true' \
    'sudo rm -f /etc/apt/trusted.gpg.d/*kubernetes* || true' \
    'sudo mkdir -p /etc/apt/keyrings' \
    "curl -fsSL --retry 3 --retry-delay 1 https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/Release.key -o /tmp/k8s-release.key || true" \
    'test -s /tmp/k8s-release.key ||' \
    "curl -fsSL --retry 3 --retry-delay 1 https://prod-cdn.packages.k8s.io/repositories/isv:/kubernetes:/core:/stable:/${K8S_REPO_MINOR}/deb/Release.key -o /tmp/k8s-release.key" \
    'sudo gpg --dearmor --batch --yes --no-tty -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg /tmp/k8s-release.key' \
    'sudo chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg' \
    "echo \"deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/ /\" | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null" \
    '' \
    'echo "== [F] Disable swap =="' \
    'sudo swapoff -a || true' \
    "sudo sed -i '/^[^#].*\\sswap\\s/s/^/#/' /etc/fstab || true" \
    '' \
    'echo "== [G] Kernel modules =="' \
    'sudo modprobe overlay || true' \
    'sudo modprobe br_netfilter || true' \
    'printf "overlay\nbr_netfilter\n" | sudo tee /etc/modules-load.d/k8s.conf >/dev/null' \
    '' \
    'echo "== [H] sysctl =="' \
    "printf 'net.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nnet.ipv4.ip_forward = 1\n' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null" \
    'sudo sysctl --system >/dev/null || true' \
    '' \
    'echo "== [I] Install containerd =="' \
    'sudo apt-get update' \
    'sudo apt-get install -y containerd' \
    'sudo mkdir -p /etc/containerd' \
    'containerd config default | sed "s/SystemdCgroup = false/SystemdCgroup = true/" | sudo tee /etc/containerd/config.toml >/dev/null' \
    'sudo systemctl daemon-reload' \
    'sudo systemctl enable --now containerd' \
    'sudo systemctl restart containerd' \
    '' \
    'echo "== [J] Install Kubernetes packages =="' \
    'sudo apt-get update' \
    'sudo apt-get install -y kubeadm kubelet kubectl cri-tools' \
    'sudo apt-mark hold kubeadm kubelet kubectl || true' \
    '' \
    'echo "== [K] Enable kubelet =="' \
    'sudo systemctl enable kubelet || true' \
    'sudo systemctl restart kubelet || true' \
    '' \
    'echo "== [L] Preflight checks =="' \
    'echo "-- swap --"' \
    'swapon --show || true' \
    'echo "-- br_netfilter --"' \
    'lsmod | grep br_netfilter || true' \
    'echo "-- ip_forward --"' \
    'sysctl net.ipv4.ip_forward || true' \
    'echo "-- containerd --"' \
    'sudo systemctl is-active containerd || true' \
    'echo "-- kubelet --"' \
    'sudo systemctl is-enabled kubelet || true' \
    'sudo systemctl is-active kubelet || true' \
    '' \
    'echo "== [M] Versions =="' \
    'kubeadm version || true' \
    'kubelet --version || true' \
    'kubectl version --client=true || true' \
    'containerd --version || true' \
    '' \
    'echo "✅ INSTALL_OK"' \
  )"

  ssh_bash_tty "$ip" "$REMOTE_INSTALL_SCRIPT"
done

# ----------------------------- PHASE 3 -------------------------------
echo
echo "================================================="
echo "🧠 PHASE 3 – kubeadm init (kube-1)"
echo "================================================="

REMOTE_INIT_SCRIPT="$(printf '%s\n' \
  'set -Eeuo pipefail' \
  'export DEBIAN_FRONTEND=noninteractive' \
  'if [ -f /etc/kubernetes/admin.conf ]; then' \
  '  echo "⚠️ kubeadm already initialized – skipping init"' \
  'else' \
  '  echo "Running kubeadm preflight..."' \
  "  sudo kubeadm config images pull --kubernetes-version=${K8S_VERSION} --cri-socket=unix:///run/containerd/containerd.sock" \
  '  echo "Running kubeadm init..."' \
  "  sudo kubeadm init --kubernetes-version=${K8S_VERSION} --pod-network-cidr=${POD_CIDR} --cri-socket=unix:///run/containerd/containerd.sock" \
  'fi' \
)"
ssh_bash_tty "$KUBE1_IP" "$REMOTE_INIT_SCRIPT"

REMOTE_KUBECONFIG_SCRIPT="$(printf '%s\n' \
  'set -Eeuo pipefail' \
  'echo "Configuring kubectl for current SSH user using $HOME/.kube"' \
  'mkdir -p "$HOME/.kube"' \
  'sudo cp -f /etc/kubernetes/admin.conf "$HOME/.kube/config"' \
  'sudo chown -R "$(id -u)":"$(id -g)" "$HOME/.kube"' \
  'export KUBECONFIG="$HOME/.kube/config"' \
  'kubectl get nodes -o wide || true' \
)"
ssh_bash_tty "$KUBE1_IP" "$REMOTE_KUBECONFIG_SCRIPT"

# ----------------------------- PHASE 4 -------------------------------
echo
echo "================================================="
echo "🧩 PHASE 4 – Join worker nodes"
echo "================================================="

JOIN_CMD="$(
  sshpass -p "$PASS" ssh "${SSH_NO_TTY[@]}" "${USER}@${KUBE1_IP}" \
    "sudo kubeadm token create --print-join-command --ttl 2h" | tr -d '\r' | tail -n 1
)"

if [[ -z "${JOIN_CMD}" ]]; then
  echo "ERROR: Could not obtain join command from kube-1" >&2
  exit 1
fi

JOIN_CMD="${JOIN_CMD} --cri-socket unix:///run/containerd/containerd.sock"

echo
echo "➡️  Join command:"
echo "    ${JOIN_CMD}"
echo

for ip in "$KUBE2_IP" "$KUBE3_IP"; do
  REMOTE_JOIN_SCRIPT="$(printf '%s\n' \
    'set -Eeuo pipefail' \
    'if [ -f /etc/kubernetes/kubelet.conf ]; then' \
    '  echo "⚠️ Already joined – skipping"' \
    'else' \
    '  echo "Joining this node..."' \
    "  sudo ${JOIN_CMD}" \
    'fi' \
  )"
  ssh_bash_tty "$ip" "$REMOTE_JOIN_SCRIPT"
done

# ----------------------------- PHASE 5 -------------------------------
echo
echo "================================================="
echo "🌐 PHASE 5 – Install Calico (kube-1)"
echo "================================================="

CALICO_INSTALL_YAML="apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    linuxDataplane: Iptables
    ipPools:
    - cidr: ${POD_CIDR}
      blockSize: 26
      encapsulation: VXLAN
      natOutgoing: Enabled
      nodeSelector: all()
"
CALICO_B64="$(b64 "$CALICO_INSTALL_YAML")"

REMOTE_CALICO_SCRIPT="$(printf '%s\n' \
  'set -Eeuo pipefail' \
  'export KUBECONFIG=/etc/kubernetes/admin.conf' \
  "echo \"Applying Tigera operator (${CALICO_VERSION})\"" \
  "kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml" \
  'echo "Waiting for tigera-operator deployment to be Available..."' \
  'kubectl -n tigera-operator rollout status deploy/tigera-operator --timeout=180s' \
  'echo "Waiting for CRD installations.operator.tigera.io ..."' \
  'for i in {1..120}; do kubectl get crd installations.operator.tigera.io >/dev/null 2>&1 && break; sleep 2; done' \
  'kubectl get crd installations.operator.tigera.io >/dev/null 2>&1 || { echo "ERROR: CRD installations.operator.tigera.io not ready"; exit 1; }' \
  "echo \"Applying Installation CR (pod CIDR: ${POD_CIDR})\"" \
  "echo \"${CALICO_B64}\" | base64 -d | kubectl apply -f -" \
  'kubectl get pods -A -o wide || true' \
)"
ssh_bash_tty "$KUBE1_IP" "$REMOTE_CALICO_SCRIPT"

# ----------------------------- PHASE 6 -------------------------------
echo
echo "================================================="
echo "✅ PHASE 6 – Verification (kube-1)"
echo "================================================="

REMOTE_VERIFY_SCRIPT="$(printf '%s\n' \
  'set -Eeuo pipefail' \
  'export KUBECONFIG=/etc/kubernetes/admin.conf' \
  'echo "Waiting for calico-node DaemonSet to appear..."' \
  'for i in {1..60}; do kubectl get ds -A 2>/dev/null | grep -q "calico-node" && break; sleep 5; done' \
  'kubectl get ds -A | grep -E "calico-node|NAME" || true' \
  'echo "Waiting for all nodes Ready (max ~5 min)..."' \
  'for i in {1..60}; do notready=$(kubectl get nodes --no-headers 2>/dev/null | awk '\''$2!="Ready"{c++} END{print c+0}'\''); if [ "$notready" -eq 0 ]; then echo "✅ All nodes are Ready"; break; fi; echo "Still not ready nodes: $notready"; kubectl get nodes -o wide || true; sleep 5; done' \
  'echo "--- FINAL STATUS (nodes) ---"' \
  'kubectl get nodes -o wide' \
  'echo "--- FINAL STATUS (pods) ---"' \
  'kubectl get pods -A -o wide' \
)"
ssh_bash_tty "$KUBE1_IP" "$REMOTE_VERIFY_SCRIPT"

echo
echo "🎉 BOOTSTRAP COMPLETE"
echo "Next: ssh ${USER}@${KUBE1_IP} and run: kubectl get pods -A"
