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
# - Alte Kubernetes-APT-Quellen werden VOR dem ersten apt-get update entfernt
# - Kubernetes-Repo-Keyring wird frisch aufgebaut
# - unattended-upgrades / apt-daily werden im Lab deaktiviert
# - APT/DPKG-Lock-Handling
# - Ubuntu-Mirror-/BADSIG-Recovery für jammy-backports / nova.clouds
# - containerd mit SystemdCgroup=true
# - Idempotenteres /etc/hosts
# - Optionaler RESET-Modus
# - kubeadm init mit expliziter --kubernetes-version
# - Calico via Tigera Operator
# - PHASE 7: lokales kubectl passend zur Cluster-Version + kubeconfig
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
for cmd in ssh scp sshpass base64 curl sed awk grep sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: missing local command: $cmd" >&2
    exit 1
  }
done

# ---------------------- Version policy ----------------------
VERSION_MODE="${VERSION_MODE:-fixed}"
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

  [[ "${K8S_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "ERROR: Invalid Kubernetes version '${K8S_VERSION}'" >&2
    exit 1
  }

  [[ "${CALICO_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "ERROR: Invalid Calico version '${CALICO_VERSION}'" >&2
    exit 1
  }

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
SCP_OPTS=( "${SSH_AUTH_OPTS[@]}" )

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
    'wait_for_apt() {' \
    '  echo "Waiting for APT/DPKG locks to be released..."' \
    '  for i in {1..60}; do' \
    '    LOCKPID=""' \
    '    LOCKFILE=""' \
    '    for f in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do' \
    '      if sudo fuser "$f" >/dev/null 2>&1; then' \
    '        LOCKPID="$(sudo fuser "$f" 2>/dev/null | awk "{print \$1}")"' \
    '        LOCKFILE="$f"' \
    '        break' \
    '      fi' \
    '    done' \
    '    if [ -z "$LOCKPID" ]; then' \
    '      echo "APT/DPKG locks are free."' \
    '      return 0' \
    '    fi' \
    '    echo "  lock busy: $LOCKFILE (pid: $LOCKPID)"' \
    '    ps -p "$LOCKPID" -o pid=,ppid=,cmd= 2>/dev/null || true' \
    '    sleep 5' \
    '  done' \
    '  echo "ERROR: Timed out waiting for APT/DPKG locks."' \
    '  return 1' \
    '}' \
    '' \
    'force_clear_apt() {' \
    '  echo "Force-clearing unattended apt jobs for lab..."' \
    '  sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true' \
    '  sudo systemctl disable unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true' \
    '  sudo systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true' \
    '  echo '\''APT::Periodic::Enable "0";'\'' | sudo tee /etc/apt/apt.conf.d/10disable-periodic >/dev/null' \
    '  echo '\''Acquire::Retries "3";'\'' | sudo tee /etc/apt/apt.conf.d/80-retries >/dev/null' \
    '  sudo pkill -f unattended-upgrade 2>/dev/null || true' \
    '  sudo pkill -f apt.systemd.daily 2>/dev/null || true' \
    '  sleep 2' \
    '  sudo dpkg --configure -a || true' \
    '  sudo apt-get -f install -y || true' \
    '}' \
    '' \
    'fix_ubuntu_repo_badsig() {' \
    '  echo "Attempting Ubuntu repository recovery..."' \
    '' \
    '  echo "-- time --"' \
    '  date || true' \
    '  timedatectl status 2>/dev/null || true' \
    '  sudo timedatectl set-ntp true 2>/dev/null || true' \
    '' \
    '  echo "-- clean apt state --"' \
    '  sudo rm -rf /var/lib/apt/lists/*' \
    '  sudo apt-get clean' \
    '' \
    '  echo "-- disable jammy-backports for lab robustness --"' \
    '  sudo sed -i '\''/^[[:space:]]*deb .* jammy-backports / s/^/# /'\'' /etc/apt/sources.list 2>/dev/null || true' \
    '  sudo find /etc/apt/sources.list.d -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -r sudo sed -i '\''/^[[:space:]]*deb .* jammy-backports / s/^/# /'\'' || true' \
    '' \
    '  echo "-- replace nova.clouds mirror with archive.ubuntu.com --"' \
    '  sudo sed -i '\''s|http://nova.clouds.archive.ubuntu.com/ubuntu|http://archive.ubuntu.com/ubuntu|g'\'' /etc/apt/sources.list 2>/dev/null || true' \
    '  sudo find /etc/apt/sources.list.d -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -r sudo sed -i '\''s|http://nova.clouds.archive.ubuntu.com/ubuntu|http://archive.ubuntu.com/ubuntu|g'\'' || true' \
    '' \
    '  echo "-- apt sources after normalization --"' \
    '  sudo grep -R "ubuntu" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true' \
    '}' \
    '' \
    'apt_update_resilient() {' \
    '  wait_for_apt || force_clear_apt' \
    '  wait_for_apt' \
    '' \
    '  if sudo apt-get update; then' \
    '    return 0' \
    '  fi' \
    '' \
    '  echo "First apt-get update failed -> running repo recovery"' \
    '  fix_ubuntu_repo_badsig' \
    '  wait_for_apt || force_clear_apt' \
    '  wait_for_apt' \
    '  sudo apt-get update' \
    '}' \
    '' \
    'echo "== [PRE] Disable unattended upgrades for lab environment =="' \
    'sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true' \
    'sudo systemctl disable unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true' \
    'sudo systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true' \
    'echo '\''APT::Periodic::Enable "0";'\'' | sudo tee /etc/apt/apt.conf.d/10disable-periodic >/dev/null' \
    'echo '\''Acquire::Retries "3";'\'' | sudo tee /etc/apt/apt.conf.d/80-retries >/dev/null' \
    'sudo pkill -f unattended-upgrade 2>/dev/null || true' \
    'sudo pkill -f apt.systemd.daily 2>/dev/null || true' \
    'sleep 2' \
    'wait_for_apt || force_clear_apt' \
    'wait_for_apt' \
    '' \
    'echo "== [PRE] Clean old Kubernetes APT sources before first apt run =="' \
    'sudo rm -f /etc/apt/sources.list.d/kubernetes.list /etc/apt/sources.list.d/*kubernetes*.list || true' \
    'sudo find /etc/apt/sources.list.d -maxdepth 1 -type f -name "*kubernetes*" -delete 2>/dev/null || true' \
    'sudo sed -i "/pkgs.k8s.io/d;/prod-cdn.packages.k8s.io/d;/isv:\/kubernetes/d" /etc/apt/sources.list 2>/dev/null || true' \
    'sudo rm -f /etc/apt/keyrings/kubernetes-apt-keyring.gpg || true' \
    'sudo rm -f /etc/apt/trusted.gpg.d/*kubernetes* || true' \
    'sudo apt-get clean' \
    'sudo rm -rf /var/lib/apt/lists/*' \
    '' \
    'echo "== [PRE] Configure Kubernetes repo ('"${K8S_REPO_MINOR}"') before first apt run =="' \
    'sudo mkdir -p /etc/apt/keyrings' \
    "curl -fsSL --retry 3 --retry-delay 1 https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/Release.key | sudo gpg --dearmor --batch --yes --no-tty -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg" \
    'test -s /etc/apt/keyrings/kubernetes-apt-keyring.gpg' \
    'sudo chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg' \
    "echo \"deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/ /\" | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null" \
    'echo "--- Kubernetes repo before first apt update ---"' \
    'sudo grep -R "pkgs.k8s.io\|prod-cdn.packages.k8s.io\|isv:/kubernetes" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true' \
    '' \
    'echo "== [B] dpkg recovery =="' \
    'wait_for_apt || force_clear_apt' \
    'wait_for_apt' \
    'sudo dpkg --configure -a || true' \
    'wait_for_apt || force_clear_apt' \
    'wait_for_apt' \
    'sudo apt-get -f install -y || true' \
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
    'echo "== [C] Base packages =="' \
    'apt_update_resilient' \
    'wait_for_apt || force_clear_apt' \
    'wait_for_apt' \
    'sudo apt-get install -y ca-certificates curl gpg apt-transport-https software-properties-common psmisc ubuntu-keyring' \
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
    'apt_update_resilient' \
    'wait_for_apt || force_clear_apt' \
    'wait_for_apt' \
    'sudo apt-get install -y containerd' \
    'sudo mkdir -p /etc/containerd' \
    'containerd config default | sed "s/SystemdCgroup = false/SystemdCgroup = true/" | sudo tee /etc/containerd/config.toml >/dev/null' \
    'sudo systemctl daemon-reload' \
    'sudo systemctl enable --now containerd' \
    'sudo systemctl restart containerd' \
    '' \
    'echo "== [J] Install Kubernetes packages =="' \
    'apt_update_resilient' \
    'wait_for_apt || force_clear_apt' \
    'wait_for_apt' \
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
  "echo \"Applying Tigera operator (${CALICO_VERSION})\"" \
  "sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml" \
  'echo "Waiting for tigera-operator deployment to be Available..."' \
  'sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n tigera-operator rollout status deploy/tigera-operator --timeout=180s' \
  'echo "Waiting for CRD installations.operator.tigera.io ..."' \
  'for i in {1..120}; do sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get crd installations.operator.tigera.io >/dev/null 2>&1 && break; sleep 2; done' \
  'sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get crd installations.operator.tigera.io >/dev/null 2>&1 || { echo "ERROR: CRD installations.operator.tigera.io not ready"; exit 1; }' \
  "echo \"Applying Installation CR (pod CIDR: ${POD_CIDR})\"" \
  "echo \"${CALICO_B64}\" | base64 -d | sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f -" \
  'sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get pods -A -o wide || true' \
)"
ssh_bash_tty "$KUBE1_IP" "$REMOTE_CALICO_SCRIPT"

# ----------------------------- PHASE 6 -------------------------------
echo
echo "================================================="
echo "✅ PHASE 6 – Verification (kube-1)"
echo "================================================="

REMOTE_VERIFY_SCRIPT="$(printf '%s\n' \
  'set -Eeuo pipefail' \
  'echo "Waiting for calico-node DaemonSet to appear..."' \
  'for i in {1..60}; do sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get ds -A 2>/dev/null | grep -q "calico-node" && break; sleep 5; done' \
  'sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get ds -A | grep -E "calico-node|NAME" || true' \
  'echo "Waiting for all nodes Ready (max ~5 min)..."' \
  'for i in {1..60}; do notready=$(sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get nodes --no-headers 2>/dev/null | awk '\''$2!="Ready"{c++} END{print c+0}'\''); if [ "$notready" -eq 0 ]; then echo "✅ All nodes are Ready"; break; fi; echo "Still not ready nodes: $notready"; sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get nodes -o wide || true; sleep 5; done' \
  'echo "--- FINAL STATUS (nodes) ---"' \
  'sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get nodes -o wide' \
  'echo "--- FINAL STATUS (pods) ---"' \
  'sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl get pods -A -o wide' \
)"
ssh_bash_tty "$KUBE1_IP" "$REMOTE_VERIFY_SCRIPT"

# ----------------------------- PHASE 7 -------------------------------
echo
echo "================================================="
echo "💻 PHASE 7 – Local kubectl install + kubeconfig"
echo "================================================="

echo "== [7A] Current local kubectl =="
if command -v kubectl >/dev/null 2>&1; then
  which kubectl || true
  kubectl version --client=true || true
else
  echo "No local kubectl currently found"
fi

echo
echo "== [7B] Remove old local kubectl =="
if [ -x /usr/local/bin/kubectl ]; then
  echo "Removing old kubectl from /usr/local/bin/kubectl"
  sudo rm -f /usr/local/bin/kubectl
fi

hash -r || true

echo
echo "== [7C] Install matching local kubectl ${K8S_VERSION} =="
curl -fsSL --retry 3 --retry-delay 1 -o /tmp/kubectl "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl"
curl -fsSL --retry 3 --retry-delay 1 -o /tmp/kubectl.sha256 "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl.sha256"
echo "$(cat /tmp/kubectl.sha256)  /tmp/kubectl" | sha256sum -c -
sudo install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl
rm -f /tmp/kubectl /tmp/kubectl.sha256
hash -r || true

echo
echo "== [7D] Verify local kubectl =="
which kubectl
kubectl version --client=true

echo
echo "== [7E] Fetch kubeconfig from kube-1 =="
mkdir -p "$HOME/.kube"
chmod 700 "$HOME/.kube"

sshpass -p "$PASS" scp "${SCP_OPTS[@]}" \
  "${USER}@${KUBE1_IP}:.kube/config" "$HOME/.kube/config"

chmod 600 "$HOME/.kube/config"

echo
echo "== [7F] Local cluster access test =="
kubectl get nodes -o wide || true
kubectl get pods -A -o wide || true

echo
echo "🎉 BOOTSTRAP COMPLETE"
echo "Local kubectl is ready. Test with: kubectl get nodes -o wide"
