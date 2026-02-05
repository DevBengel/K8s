cat > bootstrap.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# bootstrap.sh — kubeadm + Calico (LAB-robust, verbose)
#
# Nodes:
#   kube-1 10.0.0.101 (control-plane)
#   kube-2 10.0.0.102 (worker)
#   kube-3 10.0.0.103 (worker)
#
# Fixes:
# - Password prompt robust (double entry, PASSLEN)
# - SSH connectivity uses NO-TTY (sshpass friendly)
# - Remote install uses TTY (debconf/postinst)
# - LAB: shim-signed postinst fails due to missing EFI/ESP -> dpkg-divert to no-op
# - LAB: /dev/disk/by-id missing -> create dir + dummy link
# - LAB: APT proxy may 403 pkgs.k8s.io -> force DIRECT for those hosts
# - Kubernetes repo v1.32
# - Pod CIDR 192.168.0.0/16
# - Calico via Tigera operator v3.30.2 (VXLAN)
###############################################################################

# -------- Credentials --------
read -rp "SSH Username: " USER

# Allow passing PASS via env: PASS='...' bash ./bootstrap.sh
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

# -------- Topology --------
KUBE1_IP="10.0.0.101"
KUBE2_IP="10.0.0.102"
KUBE3_IP="10.0.0.103"

KUBE1_HOST="kube-1"
KUBE2_HOST="kube-2"
KUBE3_HOST="kube-3"

NODES=(
  "${KUBE1_IP}:${KUBE1_HOST}"
  "${KUBE2_IP}:${KUBE2_HOST}"
  "${KUBE3_IP}:${KUBE3_HOST}"
)

POD_CIDR="192.168.0.0/16"
K8S_REPO_MINOR="v1.32"
CALICO_VERSION="v3.30.2"

# -------- Local requirements --------
for cmd in ssh sshpass base64; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing local command: $cmd" >&2; exit 1; }
done

# SSH behavior:
# - For phase 0 connectivity: NO TTY (often more stable with sshpass)
# - For remote install: TTY needed (debconf/postinst)
SSH_AUTH_OPTS=(
  -o PreferredAuthentications=password,keyboard-interactive
  -o PubkeyAuthentication=no
  -o KbdInteractiveAuthentication=yes
  -o NumberOfPasswordPrompts=1
)

SSH_OPTS_NO_TTY=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

SSH_OPTS_TTY=(
  -t
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

b64() {
  printf "%s" "$1" | base64 -w 0 2>/dev/null || printf "%s" "$1" | base64 | tr -d '\n'
}

ssh_do_notty() {
  local ip="$1"; shift
  echo
  echo "===================================================================="
  echo "➡️  [$ip] $*"
  echo "===================================================================="
  sshpass -p "$PASS" ssh "${SSH_AUTH_OPTS[@]}" "${SSH_OPTS_NO_TTY[@]}" "${USER}@${ip}" "$@"
}

ssh_bash_stdin_tty() {
  local ip="$1"
  local content="$2"
  echo
  echo "===================================================================="
  echo "➡️  [$ip] bash -se  (remote script via stdin, TTY)"
  echo "===================================================================="
  # Pipe ensures stdin closes -> remote bash exits -> no interactive prompt
  printf '%s' "$content" | sshpass -p "$PASS" ssh "${SSH_AUTH_OPTS[@]}" "${SSH_OPTS_TTY[@]}" "${USER}@${ip}" "bash -se"
}

###############################################################################
# PHASE 0 – Connectivity
###############################################################################
echo
echo "================================================="
echo "🚀 PHASE 0 – SSH Connectivity"
echo "================================================="
for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  ssh_do_notty "$ip" "echo Connected to \$(hostname) as \$(whoami)"
done

###############################################################################
# PHASE 1 – Hostnames & /etc/hosts (robust base64 transport)
###############################################################################
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

  REMOTE_HOSTS_SCRIPT="$(
    printf '%s\n' \
      'set -Eeuo pipefail' \
      'export DEBIAN_FRONTEND=noninteractive' \
      '' \
      "echo \"Setting hostname -> ${host}\"" \
      "sudo hostnamectl set-hostname \"${host}\"" \
      '' \
      'echo "Appending /etc/hosts (lab-friendly; may duplicate on reruns)"' \
      'printf "\n# kubernetes cluster\n" | sudo tee -a /etc/hosts >/dev/null' \
      "echo \"${HOSTS_B64}\" | base64 -d | sudo tee -a /etc/hosts >/dev/null" \
      'printf "\n" | sudo tee -a /etc/hosts >/dev/null' \
      '' \
      'echo "Hostname now:"' \
      'hostname'
  )"

  ssh_bash_stdin_tty "$ip" "$REMOTE_HOSTS_SCRIPT"
done

###############################################################################
# PHASE 2 – LAB fix + Kubernetes install (all nodes)
###############################################################################
echo
echo "================================================="
echo "📦 PHASE 2 – LAB fix + Kubernetes install on ALL nodes"
echo "================================================="

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"
  echo
  echo "==================== NODE $host ($ip) ===================="

  REMOTE_INSTALL_SCRIPT="$(
    printf '%s\n' \
      'set -Eeuo pipefail' \
      'export DEBIAN_FRONTEND=noninteractive' \
      '' \
      'echo "== [LAB FIX] Ensure /dev/disk/by-id exists (shim/grub scripts expect it) == "' \
      'sudo mkdir -p /dev/disk/by-id' \
      'ROOTDEV="$(findmnt -n -o SOURCE / || true)"' \
      'ROOTDEV_REAL="$(readlink -f "$ROOTDEV" 2>/dev/null || true)"' \
      'if [ -n "$ROOTDEV_REAL" ] && [ -e "$ROOTDEV_REAL" ]; then' \
      '  sudo ln -sf "$ROOTDEV_REAL" /dev/disk/by-id/lab-root' \
      'elif [ -e /dev/loop0 ]; then' \
      '  sudo ln -sf /dev/loop0 /dev/disk/by-id/lab-loop0' \
      'else' \
      '  sudo ln -sf /dev/null /dev/disk/by-id/lab-null' \
      'fi' \
      'sudo ls -l /dev/disk/by-id || true' \
      '' \
      'echo "== [LAB FIX] Neutralize shim-signed postinst (EFI/ESP missing in LAB) == "' \
      'POST=/var/lib/dpkg/info/shim-signed.postinst' \
      'DIV=${POST}.real' \
      'if [ ! -f "$DIV" ]; then' \
      '  sudo dpkg-divert --add --rename --divert "$DIV" "$POST" || true' \
      'fi' \
      'printf "#!/bin/sh\n# LAB: skip EFI/ESP mount\nexit 0\n" | sudo tee "$POST" >/dev/null' \
      'sudo chmod +x "$POST"' \
      '' \
      'echo "== [LAB] dpkg recovery (best effort) == "' \
      'sudo dpkg --configure -a || true' \
      'sudo apt-get -f install -y || true' \
      '' \
      'echo "== [A] Remove old Kubernetes repo entries (e.g. v1.28) == "' \
      'sudo rm -f /etc/apt/sources.list.d/kubernetes.list' \
      'sudo rm -f /etc/apt/sources.list.d/*kubernetes*.list || true' \
      'sudo rm -f /etc/apt/trusted.gpg.d/*kubernetes* || true' \
      '' \
      'echo "== [B] Base packages (repo tooling) == "' \
      'sudo apt-get update' \
      'sudo apt-get install -y ca-certificates curl gpg apt-transport-https' \
      '' \
      'echo "== [C0] Disable APT proxy for Kubernetes repos (LAB proxy may 403) == "' \
      'sudo tee /etc/apt/apt.conf.d/99-k8s-direct >/dev/null <<EOF' \
      'Acquire::http::Proxy::pkgs.k8s.io "DIRECT";' \
      'Acquire::https::Proxy::pkgs.k8s.io "DIRECT";' \
      'Acquire::http::Proxy::prod-cdn.packages.k8s.io "DIRECT";' \
      'Acquire::https::Proxy::prod-cdn.packages.k8s.io "DIRECT";' \
      'EOF' \
      '' \
      "echo \"== [C] Configure Kubernetes repo (${K8S_REPO_MINOR}) == \"" \
      'sudo mkdir -p /etc/apt/keyrings' \
      # Key fetch with fallback:
      'curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key -o /tmp/k8s-release.key || curl -fsSL https://prod-cdn.packages.k8s.io/repositories/isv:/kubernetes:/core:/stable:/v1.32/deb/Release.key -o /tmp/k8s-release.key' \
      'sudo gpg --dearmor --batch --yes --no-tty -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg /tmp/k8s-release.key' \
      'sudo chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg' \
      'echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null' \
      '' \
      'echo "== [D] apt-get update (should be clean now) == "' \
      'sudo apt-get update' \
      '' \
      'echo "== [E] Install kubeadm/kubelet/kubectl/cri-tools == "' \
      'sudo apt-get install -y kubeadm kubelet kubectl cri-tools' \
      'sudo apt-mark hold kubeadm kubelet kubectl || true' \
      '' \
      'echo "== [F] Disable swap (required by kubelet) == "' \
      'sudo swapoff -a || true' \
      "sudo sed -i '/ swap / s/^/#/' /etc/fstab || true" \
      '' \
      'echo "== [G] Kernel modules == "' \
      'sudo modprobe br_netfilter || true' \
      'sudo modprobe overlay || true' \
      '' \
      'echo "== [H] sysctl for Kubernetes networking == "' \
      "printf 'net.bridge.bridge-nf-call-iptables  = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nnet.ipv4.ip_forward                 = 1\n' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null" \
      'sudo sysctl --system || true' \
      '' \
      'echo "== [I] Enable kubelet == "' \
      'sudo systemctl enable --now kubelet || true' \
      '' \
      'echo "== [J] Quick versions == "' \
      'kubeadm version || true' \
      'kubelet --version || true' \
      'kubectl version --client=true || true' \
      '' \
      'echo "✅ INSTALL_OK"'
  )"

  ssh_bash_stdin_tty "$ip" "$REMOTE_INSTALL_SCRIPT"
done

###############################################################################
# PHASE 3 – kubeadm init (kube-1)
###############################################################################
echo
echo "================================================="
echo "🧠 PHASE 3 – kubeadm init (kube-1)"
echo "================================================="

REMOTE_INIT_SCRIPT="$(
  printf '%s\n' \
    'set -Eeuo pipefail' \
    'if [ -f /etc/kubernetes/admin.conf ]; then' \
    '  echo "⚠️ kubeadm already initialized – skipping init"' \
    'else' \
    "  echo \"Running kubeadm init (pod CIDR: ${POD_CIDR})\"" \
    "  sudo kubeadm init --pod-network-cidr=${POD_CIDR}" \
    'fi'
)"
ssh_bash_stdin_tty "$KUBE1_IP" "$REMOTE_INIT_SCRIPT"

REMOTE_KUBECONFIG_SCRIPT="$(
  printf '%s\n' \
    'set -Eeuo pipefail' \
    'echo "Configuring kubectl for current SSH user ($USER) using $HOME/.kube"' \
    'mkdir -p "$HOME/.kube"' \
    'sudo cp -f /etc/kubernetes/admin.conf "$HOME/.kube/config"' \
    'sudo chown -R "$(id -u)":"$(id -g)" "$HOME/.kube"' \
    '' \
    'echo "Current node status (expect NotReady until CNI is installed):"' \
    'kubectl get nodes -o wide || true'
)"
ssh_bash_stdin_tty "$KUBE1_IP" "$REMOTE_KUBECONFIG_SCRIPT"

###############################################################################
# PHASE 4 – Join workers
###############################################################################
echo
echo "================================================="
echo "🧩 PHASE 4 – Join worker nodes"
echo "================================================="

JOIN_CMD="$(sshpass -p "$PASS" ssh "${SSH_AUTH_OPTS[@]}" "${SSH_OPTS_NO_TTY[@]}" "${USER}@${KUBE1_IP}" "sudo kubeadm token create --print-join-command" | tr -d '\r' | tail -n 1)"
if [[ -z "${JOIN_CMD}" ]]; then
  echo "ERROR: Could not obtain join command from kube-1" >&2
  exit 1
fi

echo
echo "➡️  Join command:"
echo "    ${JOIN_CMD}"
echo

for ip in "$KUBE2_IP" "$KUBE3_IP"; do
  REMOTE_JOIN_SCRIPT="$(
    printf '%s\n' \
      'set -Eeuo pipefail' \
      'if [ -f /etc/kubernetes/kubelet.conf ]; then' \
      '  echo "⚠️ Already joined – skipping"' \
      'else' \
      '  echo "Joining this node..."' \
      "  sudo ${JOIN_CMD}" \
      'fi'
  )"
  ssh_bash_stdin_tty "$ip" "$REMOTE_JOIN_SCRIPT"
done

###############################################################################
# PHASE 5 – Calico install (kube-1)
###############################################################################
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
    ipPools:
    - cidr: ${POD_CIDR}
      blockSize: 26
      encapsulation: VXLAN
      natOutgoing: Enabled
      nodeSelector: all()
"
CALICO_B64="$(b64 "$CALICO_INSTALL_YAML")"

REMOTE_CALICO_SCRIPT="$(
  printf '%s\n' \
    'set -Eeuo pipefail' \
    'export KUBECONFIG=/etc/kubernetes/admin.conf' \
    '' \
    "echo \"Applying Tigera operator (${CALICO_VERSION})\"" \
    "kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml" \
    '' \
    "echo \"Applying Installation CR (pod CIDR: ${POD_CIDR})\"" \
    "echo \"${CALICO_B64}\" | base64 -d | kubectl apply -f -" \
    '' \
    'echo "Pods snapshot:"' \
    'kubectl get pods -A -o wide || true'
)"
ssh_bash_stdin_tty "$KUBE1_IP" "$REMOTE_CALICO_SCRIPT"

###############################################################################
# PHASE 6 – Verify
###############################################################################
echo
echo "================================================="
echo "✅ PHASE 6 – Verification (kube-1)"
echo "================================================="

REMOTE_VERIFY_SCRIPT="$(
  printf '%s\n' \
    'set -Eeuo pipefail' \
    'export KUBECONFIG=/etc/kubernetes/admin.conf' \
    '' \
    'echo "Waiting for calico-node DaemonSet to appear..."' \
    'for i in {1..60}; do kubectl get ds -A 2>/dev/null | grep -q "calico-node" && break; sleep 5; done' \
    'kubectl get ds -A | grep -E "calico-node|NAME" || true' \
    '' \
    'echo "Waiting for all nodes Ready (max ~5 min)..."' \
    'for i in {1..60}; do notready=$(kubectl get nodes --no-headers 2>/dev/null | awk '\''$2!="Ready"{c++} END{print c+0}'\''); if [ "$notready" -eq 0 ]; then echo "✅ All nodes are Ready"; break; fi; echo "Still not ready nodes: $notready"; kubectl get nodes -o wide || true; sleep 5; done' \
    '' \
    'echo "--- FINAL STATUS (nodes) ---"' \
    'kubectl get nodes -o wide' \
    '' \
    'echo "--- FINAL STATUS (pods) ---"' \
    'kubectl get pods -A -o wide'
)"
ssh_bash_stdin_tty "$KUBE1_IP" "$REMOTE_VERIFY_SCRIPT"

echo
echo "🎉 BOOTSTRAP COMPLETE"
echo "Next: ssh ${USER}@${KUBE1_IP} and run: kubectl get pods -A"
EOF

chmod +x bootstrap.sh
