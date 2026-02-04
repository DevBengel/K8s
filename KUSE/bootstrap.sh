#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# INTERAKTIVE ZUGANGSDATEN
############################################
read -rp "SSH Username: " USER
read -rsp "SSH Password: " PASS
echo

############################################
# CLUSTER SETTINGS
############################################
KUBE1_IP="10.0.0.101"
KUBE2_IP="10.0.0.102"
KUBE3_IP="10.0.0.103"

KUBE1_HOST="kube-1"
KUBE2_HOST="kube-2"
KUBE3_HOST="kube-3"

POD_CIDR="192.168.0.0/16"
K8S_REPO_MINOR="v1.32"
CALICO_VERSION="v3.30.2"

NODES=(
  "$KUBE1_IP:$KUBE1_HOST"
  "$KUBE2_IP:$KUBE2_HOST"
  "$KUBE3_IP:$KUBE3_HOST"
)

############################################
# PRECHECKS
############################################
echo "================================================="
echo "🔍 Preflight checks"
echo "================================================="

for cmd in ssh sshpass; do
  if ! command -v "$cmd" >/dev/null; then
    echo "❌ Required command missing: $cmd"
    exit 1
  fi
done

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_do() {
  local ip="$1"; shift
  echo
  echo "-------------------------------------------------"
  echo "➡️  [$ip] EXEC:"
  echo "    $*"
  echo "-------------------------------------------------"
  sshpass -p "$PASS" ssh "${SSH_OPTS[@]}" "${USER}@${ip}" "$@"
}

############################################
# PHASE 0 – CONNECTIVITY
############################################
echo
echo "================================================="
echo "🚀 PHASE 0 – SSH Connectivity"
echo "================================================="

for n in "${NODES[@]}"; do
  ip="${n%%:*}"
  ssh_do "$ip" "echo Connected to \$(hostname) as \$(whoami)"
done

############################################
# PHASE 1 – HOSTNAMES + /etc/hosts
############################################
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
  ssh_do "$ip" "
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
echo 'Setting hostname to $host'
sudo hostnamectl set-hostname $host

echo 'Updating /etc/hosts'
printf '\n# kubernetes cluster\n%s\n' \"$HOSTS_BLOCK\" | sudo tee -a /etc/hosts >/dev/null

echo 'Hostname now:'
hostname
"
done

############################################
# PHASE 2 – KUBERNETES INSTALLATION (robust repo/key)
############################################
echo
echo "================================================="
echo "📦 PHASE 2 – Kubernetes installation (repo/key robust, non-tty)"
echo "================================================="

REMOTE_INSTALL=$(cat <<EOS
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== [A] Remove old Kubernetes repo entries (e.g. v1.28) =="
sudo rm -f /etc/apt/sources.list.d/kubernetes.list
sudo rm -f /etc/apt/sources.list.d/*kubernetes*.list || true
sudo rm -f /etc/apt/trusted.gpg.d/*kubernetes* || true

echo "== [B] Base packages =="
sudo apt-get update
sudo apt-get install -y ca-certificates curl gpg apt-transport-https

echo "== [C] Configure Kubernetes repo (${K8S_REPO_MINOR}) =="
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/Release.key -o /tmp/k8s-release.key

sudo gpg --dearmor --batch --yes --no-tty \\
  -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg /tmp/k8s-release.key

sudo chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_REPO_MINOR}/deb/ /" \\
  | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null

echo "== [D] apt-get update (should be clean now) =="
sudo apt-get update

echo "== [E] Install kubeadm/kubelet/kubectl/cri-tools =="
sudo apt-get install -y kubeadm kubelet kubectl cri-tools
sudo apt-mark hold kubeadm kubelet kubectl

echo "== [F] Disable swap =="
sudo swapoff -a
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

sudo sysctl --system

echo "== [I] Enable kubelet =="
sudo systemctl enable --now kubelet

echo "== [J] Versions =="
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

############################################
# PHASE 3 – KUBEADM INIT (kube-1)
############################################
echo
echo "================================================="
echo "🧠 PHASE 3 – kubeadm init (kube-1)"
echo "================================================="

ssh_do "$KUBE1_IP" "
set -Eeuo pipefail
if [ -f /etc/kubernetes/admin.conf ]; then
  echo '⚠️ kubeadm already initialized – skipping init'
else
  echo 'Running kubeadm init...'
  sudo kubeadm init --pod-network-cidr=${POD_CIDR}
fi
"

ssh_do "$KUBE1_IP" "
set -Eeuo pipefail
echo 'Configuring kubectl for user ${USER}'
mkdir -p /home/${USER}/.kube
sudo cp /etc/kubernetes/admin.conf /home/${USER}/.kube/config
sudo chown -R ${USER}:${USER} /home/${USER}/.kube

echo 'Current node status:'
kubectl get nodes -o wide || true
"

############################################
# PHASE 4 – JOIN WORKERS
############################################
echo
echo "================================================="
echo "🧩 PHASE 4 – Join worker nodes"
echo "================================================="

JOIN_CMD=$(ssh_do "$KUBE1_IP" "sudo kubeadm token create --print-join-command" | tail -n 1)
echo
echo "➡️  Join command from kube-1:"
echo "    $JOIN_CMD"

for ip in "$KUBE2_IP" "$KUBE3_IP"; do
  ssh_do "$ip" "
set -Eeuo pipefail
if [ -f /etc/kubernetes/kubelet.conf ]; then
  echo '⚠️ Node already joined – skipping'
else
  echo 'Joining node to cluster...'
  sudo ${JOIN_CMD}
fi
"
done

############################################
# PHASE 5 – CALICO
############################################
echo
echo "================================================="
echo "🌐 PHASE 5 – Install Calico"
echo "================================================="

ssh_do "$KUBE1_IP" "
set -Eeuo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf

echo 'Installing Tigera operator (${CALICO_VERSION})'
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml

echo 'Applying Calico Installation CR (POD_CIDR=${POD_CIDR})'
cat <<'EOF' | kubectl apply -f -
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

echo 'Current pods (watch for calico-node appearing):'
kubectl get pods -A -o wide || true
"

############################################
# PHASE 6 – VERIFY (mit Timeout)
############################################
echo
echo "================================================="
echo "✅ PHASE 6 – Verification (wait for Ready)"
echo "================================================="

ssh_do "$KUBE1_IP" '
set -Eeuo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf

echo "Waiting for calico-node DS to appear..."
for i in {1..60}; do
  kubectl get ds -A 2>/dev/null | grep -q "calico-node" && break
  sleep 5
done
kubectl get ds -A | grep -E "calico-node|NAME" || true

echo "Waiting for all nodes to be Ready..."
for i in {1..60}; do
  notready=$(kubectl get nodes --no-headers 2>/dev/null | awk '\''$2!="Ready"{c++} END{print c+0}'\'')
  if [ "$notready" -eq 0 ]; then
    echo "✅ All nodes Ready"
    break
  fi
  echo "Still not ready nodes: $notready"
  kubectl get nodes -o wide || true
  sleep 5
done

echo
echo "--- FINAL STATUS ---"
kubectl get nodes -o wide
echo
kubectl get pods -A -o wide
'

echo
echo "🎉 CLUSTER BOOTSTRAP COMPLETE"
echo "Next: SSH to kube-1 and run: kubectl get pods -A"
