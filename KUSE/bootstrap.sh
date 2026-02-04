#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# bootstrap-k8s-calico-lab-verbose.sh (heredoc-free local script)
#
# Fixes the recurring "syntax error near unexpected token '('" issue by
# removing local here-doc blocks (EOF/EOS), which are very sensitive to
# copy/paste / CRLF / stray spaces.
#
# It still runs remote multi-line scripts, but those are embedded as Bash
# $'...' strings (no local heredocs).
###############################################################################

read -rp "SSH Username: " USER
read -rsp "SSH Password: " PASS
echo

KUBE1_IP="10.0.0.101"
KUBE2_IP="10.0.0.102"
KUBE3_IP="10.0.0.103"

KUBE1_HOST="kube-1"
KUBE2_HOST="kube-2"
KUBE3_HOST="kube-3"

# Array syntax requires bash (this script must be run with bash)
NODES=(
  "${KUBE1_IP}:${KUBE1_HOST}"
  "${KUBE2_IP}:${KUBE2_HOST}"
  "${KUBE3_IP}:${KUBE3_HOST}"
)

POD_CIDR="192.168.0.0/16"
K8S_REPO_MINOR="v1.32"
CALICO_VERSION="v3.30.2"

for cmd in ssh sshpass; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing local command: $cmd" >&2; exit 1; }
done

# -tt: give remote commands a pseudo-tty (needed for some postinst scripts)
SSH_OPTS=(
  -tt
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_do() {
  local ip="$1"; shift
  echo
  echo "===================================================================="
  echo "➡️  [$ip] $*"
  echo "===================================================================="
  sshpass -p "$PASS" ssh "${SSH_OPTS[@]}" "${USER}@${ip}" "$@"
}

echo
echo "================================================="
echo "🚀 PHASE 0 – SSH Connectivity"
echo "================================================="
for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  ssh_do "$ip" "echo Connected to \$(hostname) as \$(whoami)"
done

echo
echo "================================================="
echo "🧭 PHASE 1 – Hostnames & /etc/hosts"
echo "================================================="

# heredoc-free hosts block
HOSTS_BLOCK="${KUBE1_IP} ${KUBE1_HOST}
${KUBE2_IP} ${KUBE2_HOST}
${KUBE3_IP} ${KUBE3_HOST}"

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"
  ssh_do "$ip" "bash -lc $(printf %q "$(
    printf '%s\n' \
'set -Eeuo pipefail' \
'export DEBIAN_FRONTEND=noninteractive' \
'' \
"echo \"Setting hostname -> ${host}\"" \
"sudo hostnamectl set-hostname \"${host}\"" \
'' \
'echo "Appending /etc/hosts (lab-friendly; may duplicate on reruns)"' \
"printf \"\\n# kubernetes cluster\\n%s\\n\" \"${HOSTS_BLOCK}\" | sudo tee -a /etc/hosts >/dev/null" \
'' \
'echo "Hostname now:"' \
'hostname'
  )")"
done

echo
echo "================================================="
echo "📦 PHASE 2 – LAB fix + Kubernetes install on ALL nodes"
echo "================================================="

REMOTE_INSTALL=$'set -Eeuo pipefail\n\
export DEBIAN_FRONTEND=noninteractive\n\
\n\
echo "== [LAB FIX] Ensure /dev/disk/by-id exists (shim-signed expects it) ==" \n\
sudo mkdir -p /dev/disk/by-id\n\
ROOTDEV="$(findmnt -n -o SOURCE / || true)"\n\
ROOTDEV_REAL="$(readlink -f "$ROOTDEV" 2>/dev/null || true)"\n\
if [ -n "$ROOTDEV_REAL" ] && [ -e "$ROOTDEV_REAL" ]; then\n\
  sudo ln -sf "$ROOTDEV_REAL" /dev/disk/by-id/lab-root\n\
elif [ -e /dev/loop0 ]; then\n\
  sudo ln -sf /dev/loop0 /dev/disk/by-id/lab-loop0\n\
else\n\
  sudo ln -sf /dev/null /dev/disk/by-id/lab-null\n\
fi\n\
sudo ls -l /dev/disk/by-id || true\n\
\n\
echo "== [LAB] dpkg recovery (best effort) ==" \n\
sudo dpkg --configure -a || true\n\
sudo apt-get -f install -y || true\n\
\n\
echo "== [A] Remove old Kubernetes repo entries (e.g. v1.28) ==" \n\
sudo rm -f /etc/apt/sources.list.d/kubernetes.list\n\
sudo rm -f /etc/apt/sources.list.d/*kubernetes*.list || true\n\
sudo rm -f /etc/apt/trusted.gpg.d/*kubernetes* || true\n\
\n\
echo "== [B] Base packages (repo tooling) ==" \n\
sudo apt-get update\n\
sudo apt-get install -y ca-certificates curl gpg apt-transport-https\n\
\n\
echo "== [C] Configure Kubernetes repo ('"$K8S_REPO_MINOR"') ==" \n\
sudo mkdir -p /etc/apt/keyrings\n\
curl -fsSL https://pkgs.k8s.io/core:/stable:/'"$K8S_REPO_MINOR"'/deb/Release.key -o /tmp/k8s-release.key\n\
sudo gpg --dearmor --batch --yes --no-tty -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg /tmp/k8s-release.key\n\
sudo chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg\n\
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/'"$K8S_REPO_MINOR"'/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null\n\
\n\
echo "== [D] apt-get update (should be clean now) ==" \n\
sudo apt-get update\n\
\n\
echo "== [E] Install kubeadm/kubelet/kubectl/cri-tools ==" \n\
sudo apt-get install -y kubeadm kubelet kubectl cri-tools\n\
sudo apt-mark hold kubeadm kubelet kubectl || true\n\
\n\
echo "== [F] Disable swap (required by kubelet) ==" \n\
sudo swapoff -a || true\n\
sudo sed -i \'/ swap / s/^/#/\' /etc/fstab || true\n\
\n\
echo "== [G] Kernel modules ==" \n\
sudo modprobe br_netfilter || true\n\
sudo modprobe overlay || true\n\
\n\
echo "== [H] sysctl for Kubernetes networking ==" \n\
sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null <<\'EOF\'\n\
net.bridge.bridge-nf-call-iptables  = 1\n\
net.bridge.bridge-nf-call-ip6tables = 1\n\
net.ipv4.ip_forward                 = 1\n\
EOF\n\
sudo sysctl --system >/dev/null || true\n\
\n\
echo "== [I] Enable kubelet ==" \n\
sudo systemctl enable --now kubelet || true\n\
\n\
echo "== [J] Quick versions ==" \n\
kubeadm version || true\n\
kubelet --version || true\n\
kubectl version --client=true || true\n\
\n\
echo "✅ INSTALL_OK"\n'

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"
  echo
  echo "==================== NODE $host ($ip) ===================="
  # Quote the remote script safely for bash -lc
  ssh_do "$ip" "bash -lc $(printf %q "$REMOTE_INSTALL")"
done

echo
echo "================================================="
echo "🧠 PHASE 3 – kubeadm init (kube-1)"
echo "================================================="

REMOTE_INIT=$'set -Eeuo pipefail\n\
if [ -f /etc/kubernetes/admin.conf ]; then\n\
  echo "⚠️ kubeadm already initialized – skipping init"\n\
else\n\
  echo "Running kubeadm init (pod CIDR: '"$POD_CIDR"')"\n\
  sudo kubeadm init --pod-network-cidr='"$POD_CIDR"'\n\
fi\n'

ssh_do "$KUBE1_IP" "bash -lc $(printf %q "$REMOTE_INIT")"

REMOTE_KUBECONFIG=$'set -Eeuo pipefail\n\
echo "Configuring kubectl for user '"$USER"'" \n\
mkdir -p /home/'"$USER"'/.kube\n\
sudo cp -f /etc/kubernetes/admin.conf /home/'"$USER"'/.kube/config\n\
sudo chown -R '"$USER"':'"$USER"' /home/'"$USER"'/.kube\n\
echo "Current node status (expect NotReady until CNI is installed):"\n\
kubectl get nodes -o wide || true\n'

ssh_do "$KUBE1_IP" "bash -lc $(printf %q "$REMOTE_KUBECONFIG")"

echo
echo "================================================="
echo "🧩 PHASE 4 – Join worker nodes"
echo "================================================="

JOIN_CMD=$(sshpass -p "$PASS" ssh "${SSH_OPTS[@]}" "${USER}@${KUBE1_IP}" "sudo kubeadm token create --print-join-command" | tr -d '\r' | tail -n 1)
if [[ -z "${JOIN_CMD}" ]]; then
  echo "ERROR: Could not obtain join command from kube-1" >&2
  exit 1
fi

echo
echo "➡️  Join command:"
echo "    ${JOIN_CMD}"
echo

for ip in "$KUBE2_IP" "$KUBE3_IP"; do
  REMOTE_JOIN=$'set -Eeuo pipefail\n\
if [ -f /etc/kubernetes/kubelet.conf ]; then\n\
  echo "⚠️ Already joined – skipping"\n\
else\n\
  echo "Joining this node..."\n\
  sudo '"$JOIN_CMD"'\n\
fi\n'
  ssh_do "$ip" "bash -lc $(printf %q "$REMOTE_JOIN")"
done

echo
echo "================================================="
echo "🌐 PHASE 5 – Install Calico (kube-1)"
echo "================================================="

REMOTE_CALICO=$'set -Eeuo pipefail\n\
export KUBECONFIG=/etc/kubernetes/admin.conf\n\
echo "Applying Tigera operator ('"$CALICO_VERSION"')"\n\
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/'"$CALICO_VERSION"'/manifests/tigera-operator.yaml\n\
\n\
echo "Applying Installation CR (pod CIDR: '"$POD_CIDR"')"\n\
kubectl apply -f - <<\'EOF\'\n\
apiVersion: operator.tigera.io/v1\n\
kind: Installation\n\
metadata:\n\
  name: default\n\
spec:\n\
  calicoNetwork:\n\
    ipPools:\n\
    - cidr: '"$POD_CIDR"'\n\
      blockSize: 26\n\
      encapsulation: VXLAN\n\
      natOutgoing: Enabled\n\
      nodeSelector: all()\n\
EOF\n\
\n\
echo "Pods snapshot:"\n\
kubectl get pods -A -o wide || true\n'

ssh_do "$KUBE1_IP" "bash -lc $(printf %q "$REMOTE_CALICO")"

echo
echo "================================================="
echo "✅ PHASE 6 – Verification (kube-1)"
echo "================================================="

REMOTE_VERIFY=$'set -Eeuo pipefail\n\
export KUBECONFIG=/etc/kubernetes/admin.conf\n\
echo "Waiting for calico-node DaemonSet to appear..."\n\
for i in {1..60}; do\n\
  kubectl get ds -A 2>/dev/null | grep -q "calico-node" && break\n\
  sleep 5\n\
done\n\
kubectl get ds -A | grep -E "calico-node|NAME" || true\n\
\n\
echo "Waiting for all nodes Ready (max ~5 min)..." \n\
for i in {1..60}; do\n\
  notready=$(kubectl get nodes --no-headers 2>/dev/null | awk \'$2!="Ready"{c++} END{print c+0}\')\n\
  if [ "$notready" -eq 0 ]; then\n\
    echo "✅ All nodes are Ready"\n\
    break\n\
  fi\n\
  echo "Still not ready nodes: $notready"\n\
  kubectl get nodes -o wide || true\n\
  sleep 5\n\
done\n\
\n\
echo "--- FINAL STATUS (nodes) ---"\n\
kubectl get nodes -o wide\n\
echo\n\
echo "--- FINAL STATUS (pods) ---"\n\
kubectl get pods -A -o wide\n'

ssh_do "$KUBE1_IP" "bash -lc $(printf %q "$REMOTE_VERIFY")"

echo
echo "🎉 BOOTSTRAP COMPLETE"
echo "Next: ssh ${USER}@${KUBE1_IP} and run: kubectl get pods -A"
