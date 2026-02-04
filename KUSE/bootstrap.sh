#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# bootstrap-k8s-calico-lab-verbose.sh
#
# Purpose:
#   Bootstrap a 3-node Kubernetes lab cluster over SSH (password auth) with:
#     - kube-1 (10.0.0.101) as control-plane
#     - kube-2 (10.0.0.102) worker
#     - kube-3 (10.0.0.103) worker
#   Then install Calico via Tigera Operator (VXLAN) using POD_CIDR=192.168.0.0/16
#
# Lab findings handled:
#   1) Some nodes may have dpkg blocked by shim-signed postinst when run non-TTY.
#      -> We FORCE a TTY for SSH sessions (-tt).
#      -> We run a dpkg recovery step early (best effort).
#   2) Old pkgs.k8s.io repos (e.g. v1.28) may exist and cause EXPKEYSIG.
#      -> We remove old kubernetes list files and key remnants, then re-add v1.32.
#   3) gpg can fail without /dev/tty when piped.
#      -> We download key to file, then gpg --dearmor --batch --no-tty.
#
# Requirements on the machine you run this script from:
#   - ssh
#   - sshpass
#
# Assumptions on nodes:
#   - User exists on all nodes and can sudo (password prompt ok)
#   - Ubuntu Jammy-like environment with apt
#   - container runtime is already present OR provided by lab (not installed here)
#
# NOTE:
#   This is a LAB-focused script. It prioritizes progress and verbosity.
###############################################################################

# ---- Ask for credentials
read -rp "SSH Username: " USER
read -rsp "SSH Password: " PASS
echo

# ---- Nodes
KUBE1_IP="10.0.0.101"
KUBE2_IP="10.0.0.102"
KUBE3_IP="10.0.0.103"

KUBE1_HOST="kube-1"
KUBE2_HOST="kube-2"
KUBE3_HOST="kube-3"

NODES=(
  "$KUBE1_IP:$KUBE1_HOST"
  "$KUBE2_IP:$KUBE2_HOST"
  "$KUBE3_IP:$KUBE3_HOST"
)

# ---- Cluster config
POD_CIDR="192.168.0.0/16"
K8S_REPO_MINOR="v1.32"
CALICO_VERSION="v3.30.2"

# ---- Local prereqs
for cmd in ssh sshpass; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing local command: $cmd" >&2; exit 1; }
done

# ---- SSH settings
# -tt is CRITICAL for shim-signed/debconf postinst scripts that expect /dev/tty.
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

###############################################################################
# PHASE 0 – Connectivity
###############################################################################
echo
echo "================================================="
echo "🚀 PHASE 0 – SSH Connectivity"
echo "================================================="
for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  ssh_do "$ip" "echo Connected to \$(hostname) as \$(whoami)"
done

###############################################################################
# PHASE 1 – Hostnames + /etc/hosts
###############################################################################
echo
echo "================================================="
echo "🧭 PHASE 1 – Hostnames & /etc/hosts"
echo "================================================="

HOSTS_BLOCK=$(cat <<EOF
$KUBE1_IP $KUBE1_HOST
$KUBE2_IP $KUBE2_HOST
$KUBE3_IP $KUBE3_HOST
EOF
)

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"
  ssh_do "$ip" "bash -lc '
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

echo \"Setting hostname -> ${host}\"
sudo hostnamectl set-hostname \"${host}\"

echo \"Appending /etc/hosts (lab-friendly; may duplicate on reruns)\"
printf \"\n# kubernetes cluster\n%s\n\" \"${HOSTS_BLOCK}\" | sudo tee -a /etc/hosts >/dev/null

echo \"Hostname now:\"
hostname
'"
done

###############################################################################
# PHASE 2 – Prepare dpkg (LAB) + Install Kubernetes packages on all nodes
###############################################################################
echo
echo "================================================="
echo "📦 PHASE 2 – dpkg recovery (LAB) + Kubernetes install on ALL nodes"
echo "================================================="

REMOTE_INSTALL=$(cat <<EOS
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== [LAB] dpkg recovery (best effort) =="
# If shim-signed is half-configured, dpkg may be stuck. With TTY (-tt) this often succeeds.
sudo dpkg --configure -a || true
sudo apt-get -f install -y || true

echo "== [A] Remove old Kubernetes repo entries (e.g. v1.28) =="
sudo rm -f /etc/apt/sources.list.d/kubernetes.list
sudo rm -f /etc/apt/sources.list.d/*kubernetes*.list || true
sudo rm -f /etc/apt/trusted.gpg.d/*kubernetes* || true

echo "== [B] Base packages (repo tooling) =="
sudo apt-get update
sudo apt-get install -y ca-certificates curl gpg apt-transport-https

echo "== [C] Configure Kubernetes repo (${K8S_REPO_MINOR}) =="
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/Release.key -o /tmp/k8s-release.key

# Non-interactive gpg (no /dev/tty needed)
sudo gpg --dearmor --batch --yes --no-tty \\
  -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg /tmp/k8s-release.key

sudo chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/ /" \\
  | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null

echo "== [D] apt-get update (should be clean now) =="
sudo apt-get update

echo "== [E] Install kubeadm/kubelet/kubectl/cri-tools =="
sudo apt-get install -y kubeadm kubelet kubectl cri-tools
sudo apt-mark hold kubeadm kubelet kubectl || true

echo "== [F] Disable swap (required by kubelet) =="
sudo swapoff -a || true
sudo sed -i '/ swap / s/^/#/' /etc/fstab || true

echo "== [G] Kernel modules =="
sudo modprobe br_netfilter || true
sudo modprobe overlay || true

echo "== [H] sysctl for Kubernetes networking =="
cat <<'EOF' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sudo sysctl --system >/dev/null || true

echo "== [I] Enable kubelet =="
sudo systemctl enable --now kubelet || true

echo "== [J] Quick versions =="
kubeadm version || true
kubelet --version || true
kubectl version --client=true || true

echo "✅ INSTALL_OK"
EOS
)

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  host="${n##*:}"
  echo
  echo "==================== NODE $host ($ip) ===================="
  ssh_do "$ip" "bash -s" <<<"$REMOTE_INSTALL"
done

###############################################################################
# PHASE 3 – kubeadm init on kube-1
###############################################################################
echo
echo "================================================="
echo "🧠 PHASE 3 – kubeadm init (kube-1)"
echo "================================================="

ssh_do "$KUBE1_IP" "bash -lc '
set -Eeuo pipefail

if [ -f /etc/kubernetes/admin.conf ]; then
  echo \"⚠️ kubeadm already initialized – skipping init\"
else
  echo \"Running kubeadm init (pod CIDR: ${POD_CIDR})\"
  sudo kubeadm init --pod-network-cidr=${POD_CIDR}
fi
'"

ssh_do "$KUBE1_IP" "bash -lc '
set -Eeuo pipefail
echo \"Configuring kubectl for user ${USER}\"
mkdir -p /home/${USER}/.kube
sudo cp -f /etc/kubernetes/admin.conf /home/${USER}/.kube/config
sudo chown -R ${USER}:${USER} /home/${USER}/.kube

echo \"Current node status (expect NotReady until CNI is installed):\"
kubectl get nodes -o wide || true
'"

###############################################################################
# PHASE 4 – Join kube-2/kube-3
###############################################################################
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
  ssh_do "$ip" "bash -lc '
set -Eeuo pipefail
if [ -f /etc/kubernetes/kubelet.conf ]; then
  echo \"⚠️ Already joined – skipping\"
else
  echo \"Joining this node...\"
  sudo ${JOIN_CMD}
fi
'"
done

###############################################################################
# PHASE 5 – Install Calico on kube-1
###############################################################################
echo
echo "================================================="
echo "🌐 PHASE 5 – Install Calico (kube-1)"
echo "================================================="

ssh_do "$KUBE1_IP" "bash -lc '
set -Eeuo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf

echo \"Applying Tigera operator (${CALICO_VERSION})\"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml

echo \"Applying Installation CR (pod CIDR: ${POD_CIDR})\"
cat <<EOF | kubectl apply -f -
apiVersion: operator.tigera.io/v1
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
EOF

echo \"Pods snapshot:\"
kubectl get pods -A -o wide || true
'"

###############################################################################
# PHASE 6 – Verify (wait for Ready)
###############################################################################
echo
echo "================================================="
echo "✅ PHASE 6 – Verification (kube-1)"
echo "================================================="

ssh_do "$KUBE1_IP" "bash -lc '
set -Eeuo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf

echo \"Waiting for calico-node DaemonSet to appear...\"
for i in {1..60}; do
  kubectl get ds -A 2>/dev/null | grep -q \"calico-node\" && break
  sleep 5
done
kubectl get ds -A | grep -E \"calico-node|NAME\" || true

echo \"Waiting for all nodes Ready (max ~5 min)...\"
for i in {1..60}; do
  notready=\$(kubectl get nodes --no-headers 2>/dev/null | awk '\''\$2!=\"Ready\"{c++} END{print c+0}'\'')
  if [ \"\$notready\" -eq 0 ]; then
    echo \"✅ All nodes are Ready\"
    break
  fi
  echo \"Still not ready nodes: \$notready\"
  kubectl get nodes -o wide || true
  sleep 5
done

echo
echo \"--- FINAL STATUS (nodes) ---\"
kubectl get nodes -o wide

echo
echo \"--- FINAL STATUS (pods) ---\"
kubectl get pods -A -o wide
'"

echo
echo "🎉 BOOTSTRAP COMPLETE"
echo "Next: ssh ${USER}@${KUBE1_IP} and run: kubectl get pods -A"
