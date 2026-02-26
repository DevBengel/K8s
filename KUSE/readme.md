Um das Cluster vorzubereiten einfach die unten stehende Befehle per Copy & Paste auf die Student Workstation kopieren.

```sh
git clone https://github.com/DevBengel/K8s.git
chmod +x ./K8s/KUSE/bootstrap.sh
./K8s/KUSE/bootstrap.sh
```

Username und Passwort erfahren Sie vom Trainer

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | \
sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] \
https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | \
sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubectl
