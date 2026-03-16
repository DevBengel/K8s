# Kubernetes + Vault Demo

## Secret aus Vault statt Kubernetes Secret beziehen

Diese Demo zeigt den Unterschied zwischen:

-   **klassischen Kubernetes Secrets**
-   **Secrets aus einem externen Key Vault**

Am Ende läuft ein Pod, der **sein Secret nicht aus Kubernetes**, sondern
**direkt aus Vault** holt.

------------------------------------------------------------------------

# Architektur

    +---------------------------+
    | Kubernetes Cluster        |
    |                           |
    | Pod (demo-client)         |
    |    │                      |
    |    │ ServiceAccount JWT   |
    |    ▼                      |
    +---------------------------+
               │
               ▼
    +---------------------------+
    | HashiCorp Vault           |
    | (Docker Dev Mode)         |
    |                           |
    | KV Secret Engine          |
    +---------------------------+

------------------------------------------------------------------------

# Voraussetzungen

Benötigt:

-   Kubernetes Cluster
-   kubectl mit Admin-Rechten
-   Docker
-   Internetzugriff

Alle Befehle werden auf einem Host ausgeführt, der Zugriff hat auf:

    Kubernetes API
    Docker
    Vault Port 8200

------------------------------------------------------------------------

# 1 Namespace erstellen

``` bash
kubectl create namespace vault-demo
```

------------------------------------------------------------------------

# 2 Klassisches Kubernetes Secret erstellen

``` bash
kubectl -n vault-demo create secret generic app-secret \
  --from-literal=username=appuser \
  --from-literal=password='SuperSecret123!'
```

Secret anzeigen:

``` bash
kubectl -n vault-demo get secret app-secret -o yaml
```

------------------------------------------------------------------------

# 3 Vault starten (Dev Mode)

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

# 4 Warten bis Vault läuft

``` bash
until curl -s http://127.0.0.1:8200/v1/sys/health >/dev/null; do
  echo "Waiting for Vault..."
  sleep 2
done
```

------------------------------------------------------------------------

# 5 Vault Zugriff konfigurieren

``` bash
export VAULT_ADDR=http://10.0.0.50:8200
export VAULT_TOKEN=root
```

------------------------------------------------------------------------

# 6 Vault CLI Alias erstellen

``` bash
alias vcli='docker exec -e VAULT_ADDR=http://10.0.0.50:8200 -e VAULT_TOKEN=root vault-demo vault'
```

Test:

``` bash
vcli status
```

------------------------------------------------------------------------

# 7 KV Secret Engine aktivieren

``` bash
vcli secrets enable -path=kv kv-v2
```

Überprüfen:

``` bash
vcli secrets list
```

------------------------------------------------------------------------

# 8 Secret in Vault speichern

``` bash
vcli kv put kv/app/config \
  username=appuser \
  password='SuperSecret123!'
```

Secret prüfen:

``` bash
vcli kv get kv/app/config
```

------------------------------------------------------------------------

# 9 ServiceAccount für Vault Auth erstellen

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

# 10 RBAC für TokenReview

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

# 11 Client ServiceAccount erstellen

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

# 12 Kubernetes Auth in Vault aktivieren

``` bash
vcli auth enable kubernetes
```

------------------------------------------------------------------------

# 13 Kubernetes API Parameter ermitteln

``` bash
export KUBE_HOST="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

export KUBE_CA_CERT="$(kubectl config view --raw --minify --flatten \
-o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
| base64 -d)"

export TOKEN_REVIEW_JWT="$(kubectl -n vault-demo create token vault-auth)"
```

------------------------------------------------------------------------

# 14 Kubernetes Auth konfigurieren

``` bash
vcli write auth/kubernetes/config \
  token_reviewer_jwt="$TOKEN_REVIEW_JWT" \
  kubernetes_host="$KUBE_HOST" \
  kubernetes_ca_cert="$KUBE_CA_CERT" \
  disable_iss_validation=true
```

------------------------------------------------------------------------

# 15 Vault Policy erstellen

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

vcli policy write demo-policy /tmp/demo-policy.hcl
```

------------------------------------------------------------------------

# 16 Vault Role erstellen

``` bash
vcli write auth/kubernetes/role/demo-role \
  bound_service_account_names=demo-client \
  bound_service_account_namespaces=vault-demo \
  policies=demo-policy \
  ttl=1h
```

------------------------------------------------------------------------

# 17 Host IP ermitteln

``` bash
export VAULT_HOST_IP=$(hostname -I | awk '{print $1}')
```

------------------------------------------------------------------------

# 18 Demo Pod erstellen

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

        JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

        LOGIN=$(curl -s --request POST \
          --header "Content-Type: application/json" \
          --data "{\"jwt\":\"$JWT\",\"role\":\"demo-role\"}" \
          $VAULT_ADDR/v1/auth/kubernetes/login)

        TOKEN=$(echo $LOGIN | jq -r '.auth.client_token')

        SECRET=$(curl -s \
          --header "X-Vault-Token: $TOKEN" \
          $VAULT_ADDR/v1/kv/data/app/config)

        echo "Secret from Vault:"
        echo $SECRET | jq .

        USERNAME=$(echo $SECRET | jq -r '.data.data.username')
        PASSWORD=$(echo $SECRET | jq -r '.data.data.password')

        echo "username=$USERNAME"
        echo "password=$PASSWORD"

        echo "Demo finished."
EOF
```

------------------------------------------------------------------------

# 19 Pod Logs anzeigen

``` bash
kubectl -n vault-demo logs demo-client -f
```

------------------------------------------------------------------------

# 20 Aufräumen

``` bash
kubectl delete namespace vault-demo
kubectl delete clusterrolebinding vault-auth-tokenreview
docker rm -f vault-demo
rm demo-policy.hcl
```

------------------------------------------------------------------------

# Ergebnis

Der Pod hat:

1.  sein Kubernetes ServiceAccount Token gelesen\
2.  sich damit bei Vault authentifiziert\
3.  ein Vault Token erhalten\
4.  das Secret aus Vault gelesen

Damit liegt das Secret **nicht mehr als Kubernetes Secret im Cluster**.

------------------------------------------------------------------------

# Merksatz

    Kubernetes Secret = Secret im Cluster
    Vault Secret = Secret außerhalb des Clusters
