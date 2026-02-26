Um das Cluster vorzubereiten einfach die unten stehende Befehle per Copy & Paste auf die Student Workstation kopieren.

```sh
git clone https://github.com/DevBengel/K8s.git
chmod +x ./K8s/KUSE/bootstrap.sh
./K8s/KUSE/bootstrap.sh
```

Username und Passwort erfahren Sie vom Trainer

```sh
# ================================
# Kubernetes kubectl Installation
# Debian / Bookworm – v1.32
# ================================

# 1️⃣ Keyring-Verzeichnis anlegen
sudo mkdir -p /etc/apt/keyrings

# 2️⃣ Kubernetes GPG Key hinzufügen
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | \
sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

# 3️⃣ Kubernetes Repository hinzufügen
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | \
sudo tee /etc/apt/sources.list.d/kubernetes.list

# 4️⃣ Paketliste aktualisieren
sudo apt-get update

# 5️⃣ kubectl installieren
sudo apt-get install -y kubectl

# 6️⃣ Alte manuelle kubectl-Version entfernen (falls vorhanden)
if [ -f /usr/local/bin/kubectl ]; then
  sudo rm -f /usr/local/bin/kubectl
fi

# 7️⃣ Bash-Cache zurücksetzen
hash -r

# 8️⃣ Installation überprüfen
which kubectl
kubectl version --client
```

```sh
mkdir -p ~/.kube
sudo cp /etc/kubernetes/admin.conf ~/.kube/config
```
sudo chown $USER:$USER ~/.kube/config
