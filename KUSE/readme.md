Um das Cluster vorzubereiten einfach die unten stehende Befehle per Copy & Paste 
in den Terminal Student Workstation kopieren.

```sh
git clone https://github.com/DevBengel/K8s.git
chmod +x ./K8s/KUSE/bootstrap.sh
./K8s/KUSE/bootstrap.sh
```

Nur auf Anforderung installieren wie Option 2

```sh
rm -rf K8s

git clone https://github.com/DevBengel/K8s.git && \
chmod +x ./K8s/KUSE/bootstrap_helm.sh && \
./K8s/KUSE/bootstrap_helm.sh && \
chmod +x ./K8s/KUSE/Extras/install-gitlab-demo-nodeport-v5.sh && \
ACCESS_IP=$(ip route get 1 | awk '{print $7; exit}') \
./K8s/KUSE/Extras/install-gitlab-demo-nodeport-v5.sh
```
