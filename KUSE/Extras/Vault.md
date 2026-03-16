# Kubernetes + Vault Lab

## Vault läuft auf der Student Workstation

Diese Demo zeigt, wie ein Kubernetes Pod **Secrets aus HashiCorp Vault**
bezieht, anstatt sie als Kubernetes Secret im Cluster zu speichern.

Die Vault-Instanz läuft **lokal auf der Student Workstation (Docker)**.

------------------------------------------------------------------------

# Architektur

    Student Workstation
    │
    ├─ Docker Container: Vault (Port 8200)
    │
    └─ Kubernetes Cluster
         │
         └─ Pod (demo-client)
               │
               └─ Authentifiziert sich mit ServiceAccount Token bei Vault

------------------------------------------------------------------------

# Voraussetzungen

Benötigt:

-   Kubernetes Cluster erreichbar via `kubectl`
-   Docker auf der Student Workstation
-   Internetzugriff

Test:

``` bash
kubectl get nodes
docker ps
```

------------------------------------------------------------------------

# 1 Namespace erstellen

``` bash
kubectl create namespace vault-demo
```

------------------------------------------------------------------------

# 2 Beispiel Kubernetes Secret erstellen (Vergleich)

``` bash
kubectl -n vault-demo create secret generic app-secret \
  --from-literal=username=appuser \
  --from-literal=password='SuperSecret123!'
```

Anzeigen:

``` bash
kubectl -n vault-demo get secret app-secret -o yaml
```

------------------------------------------------------------------------

# 3 Vault lokal starten (Docker Dev Mode)

``` bash
docker rm -f vault-demo 2>/dev/null || true

docker run -d \
  --name vault-demo \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  hashicorp/vault
```

------------------------------------------------------------------------

# 4 Prüfen ob Vault läuft

``` bash
curl http://127.0.0.1:8200/v1/sys/health
```

------------------------------------------------------------------------

# 5 Vault CLI Zugriff (Docker exec)

Variable definieren:

``` bash
VCLI="docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root vault-demo vault"
```

Test:

``` bash
$VCLI status
```

------------------------------------------------------------------------

# 6 KV Secret Engine aktivieren

``` bash
$VCLI secrets enable -path=kv kv-v2
```

------------------------------------------------------------------------

# 7 Secret in Vault speichern

``` bash
$VCLI kv put kv/app/config \
  username=appuser \
  password='SuperSecret123!'
```

Test:

``` bash
$VCLI kv get kv/app/config
```

------------------------------------------------------------------------

# 8 ServiceAccount für Vault Auth erstellen

``` bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-auth
  namespace: vault-demo
EOF
```

------------------------------------------------------------------------

# 9 RBAC für TokenReview

``` bash
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vault-auth-tokenreview
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: vault-auth
  namespace: vault-demo
EOF
```

------------------------------------------------------------------------

# 10 ServiceAccount für Demo Pod

``` bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: demo-client
  namespace: vault-demo
EOF
```

------------------------------------------------------------------------

# 11 Kubernetes Auth in Vault aktivieren

``` bash
$VCLI auth enable kubernetes
```

------------------------------------------------------------------------

# 12 Kubernetes API Parameter ermitteln

``` bash
export KUBE_HOST="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

export KUBE_CA_CERT="$(kubectl config view --raw --minify --flatten \
-o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
| base64 -d)"

export TOKEN_REVIEW_JWT="$(kubectl -n vault-demo create token vault-auth)"
```

------------------------------------------------------------------------

# 13 Vault Kubernetes Auth konfigurieren

``` bash
$VCLI write auth/kubernetes/config \
  token_reviewer_jwt="$TOKEN_REVIEW_JWT" \
  kubernetes_host="$KUBE_HOST" \
  kubernetes_ca_cert="$KUBE_CA_CERT" \
  disable_iss_validation=true
```

------------------------------------------------------------------------

# 14 Vault Policy erstellen

``` bash
cat <<EOF > demo-policy.hcl
path "kv/data/app/config" {
  capabilities = ["read"]
}
EOF
```

Policy installieren:

``` bash
docker cp demo-policy.hcl vault-demo:/tmp/demo-policy.hcl
$VCLI policy write demo-policy /tmp/demo-policy.hcl
```

------------------------------------------------------------------------

# 15 Vault Role erstellen

``` bash
$VCLI write auth/kubernetes/role/demo-role \
  bound_service_account_names=demo-client \
  bound_service_account_namespaces=vault-demo \
  policies=demo-policy \
  ttl=1h
```

------------------------------------------------------------------------

# 16 Host IP der Student Workstation ermitteln

Pods müssen Vault erreichen können.

``` bash
export VAULT_HOST_IP=$(hostname -I | awk '{print $1}')
echo $VAULT_HOST_IP
```

------------------------------------------------------------------------

# 17 Demo Pod starten

``` bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: demo-client
  namespace: vault-demo
spec:
  serviceAccountName: demo-client
  restartPolicy: Never
  containers:
  - name: client
    image: alpine:3.20
    command: ["/bin/sh", "-c"]
    args:
      - |
        apk add --no-cache curl jq

        VAULT_ADDR="http://${VAULT_HOST_IP}:8200"

        JWT=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

        LOGIN=\$(curl -s --request POST \
          --header "Content-Type: application/json" \
          --data "{\"jwt\":\"\$JWT\",\"role\":\"demo-role\"}" \
          \$VAULT_ADDR/v1/auth/kubernetes/login)

        TOKEN=\$(echo \$LOGIN | jq -r '.auth.client_token')

        SECRET=\$(curl -s \
          --header "X-Vault-Token: \$TOKEN" \
          \$VAULT_ADDR/v1/kv/data/app/config)

        echo "Secret from Vault:"
        echo \$SECRET | jq .

        USERNAME=\$(echo \$SECRET | jq -r '.data.data.username')
        PASSWORD=\$(echo \$SECRET | jq -r '.data.data.password')

        echo "username=\$USERNAME"
        echo "password=\$PASSWORD"

        echo "Demo finished."
EOF
```

------------------------------------------------------------------------

# 18 Logs anzeigen

``` bash
kubectl -n vault-demo logs demo-client -f
```

Erwartete Ausgabe:

    username=appuser
    password=SuperSecret123!
    Demo finished.

------------------------------------------------------------------------

# 19 Aufräumen

``` bash
kubectl delete namespace vault-demo
kubectl delete clusterrolebinding vault-auth-tokenreview
docker rm -f vault-demo
rm demo-policy.hcl
```

------------------------------------------------------------------------

# Fazit

Der Pod hat:

1.  sein Kubernetes ServiceAccount Token gelesen\
2.  sich damit bei Vault authentifiziert\
3.  ein Vault Token erhalten\
4.  das Secret aus Vault gelesen

Damit liegt das Secret **nicht als Kubernetes Secret im Cluster**,
sondern **im externen Vault**.
