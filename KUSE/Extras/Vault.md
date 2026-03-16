# Kubernetes + Vault Lab
## Vault läuft im Cluster (ohne Docker auf der Student-Workstation)

Diese Demo zeigt, wie ein Kubernetes Pod **Secrets aus HashiCorp Vault** bezieht, anstatt sie als Kubernetes Secret im Cluster zu speichern.

In dieser Variante läuft Vault **direkt im Kubernetes-Cluster** auf `kube-1` als Pod/Service.  
Dadurch entfallen Probleme mit:

- Docker auf der Student-Workstation
- Host-Firewalls
- Routing zur Workstation-IP
- externem Zugriff vom Pod auf den Teilnehmer-PC

---

# Ziel

Am Ende läuft ein Pod, der:

1. sein Kubernetes ServiceAccount Token verwendet
2. sich damit bei Vault authentifiziert
3. ein Vault Token erhält
4. ein Secret direkt aus Vault liest

---

# Architektur

```text
+------------------------------------------------------+
| Kubernetes Cluster                                   |
|                                                      |
|  Namespace: vault-demo                               |
|                                                      |
|  +------------------+      +----------------------+  |
|  | Pod: demo-client | ---> | Service: vault      |  |
|  | ServiceAccount   |      | Port 8200           |  |
|  +------------------+      +----------------------+  |
|             |                          |             |
|             v                          v             |
|        Kubernetes Auth            Pod: vault         |
|                                   (Dev Mode)         |
+------------------------------------------------------+
```

---

# Voraussetzungen

Benötigt:

- funktionierendes `kubectl`
- Cluster-Admin-Rechte
- Internetzugriff des Clusters auf Container-Images

Test:

```bash
kubectl get nodes
```

---

# 1 Namespace erstellen

```bash
kubectl create namespace vault-demo
```

---

# 2 Vergleich: klassisches Kubernetes Secret anlegen

```bash
kubectl -n vault-demo create secret generic app-secret \
  --from-literal=username=appuser \
  --from-literal=password='SuperSecret123!'
```

Anzeigen:

```bash
kubectl -n vault-demo get secret app-secret -o yaml
```

---

# 3 Vault im Cluster starten

Wir nutzen absichtlich **Vault Dev Mode**, damit die Demo einfach bleibt.

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: vault
  namespace: vault-demo
  labels:
    app: vault
spec:
  containers:
  - name: vault
    image: hashicorp/vault:1.21
    args:
      - "server"
      - "-dev"
      - "-dev-root-token-id=root"
      - "-dev-listen-address=0.0.0.0:8200"
    ports:
    - containerPort: 8200
    env:
    - name: VAULT_DEV_ROOT_TOKEN_ID
      value: root
    - name: VAULT_DEV_LISTEN_ADDRESS
      value: 0.0.0.0:8200
    securityContext:
      capabilities:
        add: ["IPC_LOCK"]
EOF
```

Warten bis der Pod läuft:

```bash
kubectl -n vault-demo wait --for=condition=Ready pod/vault --timeout=120s
```

Logs prüfen:

```bash
kubectl -n vault-demo logs vault --tail=20
```

---

# 4 Vault Service anlegen

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: vault
  namespace: vault-demo
spec:
  selector:
    app: vault
  ports:
  - port: 8200
    targetPort: 8200
EOF
```

Test:

```bash
kubectl -n vault-demo get svc vault
```

---

# 5 Vault intern testen

```bash
kubectl -n vault-demo run curltest --rm -it --restart=Never \
  --image=curlimages/curl:8.8.0 -- \
  curl -s http://vault:8200/v1/sys/health
```

Erwartung: JSON-Antwort von Vault.

---

# 6 Hilfsvariable für Vault CLI setzen

Wir nutzen die Vault CLI direkt **im Vault-Pod**.

```bash
VCLI="kubectl -n vault-demo exec vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault"
```

Test:

```bash
$VCLI status
```

---

# 7 KV-v2 Engine aktivieren

```bash
$VCLI secrets enable -path=kv kv-v2
```

Prüfen:

```bash
$VCLI secrets list
```

---

# 8 Secret in Vault speichern

```bash
$VCLI kv put kv/app/config \
  username=appuser \
  password='SuperSecret123!'
```

Prüfen:

```bash
$VCLI kv get kv/app/config
```

---

# 9 ServiceAccount für Vault TokenReview anlegen

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-auth
  namespace: vault-demo
EOF
```

---

# 10 RBAC für TokenReview vergeben

```bash
cat <<'EOF' | kubectl apply -f -
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

---

# 11 ServiceAccount für Demo-Pod anlegen

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: demo-client
  namespace: vault-demo
EOF
```

---

# 12 Kubernetes Auth in Vault aktivieren

Falls die Auth Method schon existiert, ist das nicht schlimm.

```bash
$VCLI auth enable kubernetes || true
```

Prüfen:

```bash
$VCLI auth list
```

---

# 13 Kubernetes API Parameter ermitteln

```bash
export KUBE_HOST="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

export KUBE_CA_CERT="$(kubectl config view --raw --minify --flatten \
-o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)"

export TOKEN_REVIEW_JWT="$(kubectl -n vault-demo create token vault-auth)"
```

Kontrolle:

```bash
echo "$KUBE_HOST"
```

---

# 14 Vault Kubernetes Auth konfigurieren

```bash
$VCLI write auth/kubernetes/config \
  token_reviewer_jwt="$TOKEN_REVIEW_JWT" \
  kubernetes_host="$KUBE_HOST" \
  kubernetes_ca_cert="$KUBE_CA_CERT" \
  disable_iss_validation=true
```

---

# 15 Vault Policy anlegen

Für KV v2 muss der Policy-Pfad auf `kv/data/...` zeigen.

```bash
cat <<'EOF' | kubectl -n vault-demo exec -i vault -- \
  env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  vault policy write demo-policy -
path "kv/data/app/config" {
  capabilities = ["read"]
}
EOF
```

Prüfen:

```bash
$VCLI policy read demo-policy
```

---

# 16 Vault Role anlegen

```bash
$VCLI write auth/kubernetes/role/demo-role \
  bound_service_account_names=demo-client \
  bound_service_account_namespaces=vault-demo \
  policies=demo-policy \
  ttl=1h
```

Prüfen:

```bash
$VCLI read auth/kubernetes/role/demo-role
```

---

# 17 Demo-Pod erstellen

Der Pod spricht Vault jetzt **über den Kubernetes Service** an:

```text
http://vault.vault-demo.svc.cluster.local:8200
```

```bash
kubectl -n vault-demo delete pod demo-client --ignore-not-found

cat <<'EOF' | kubectl apply -f -
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
        set -e
        apk add --no-cache curl jq >/dev/null

        VAULT_ADDR="http://vault.vault-demo.svc.cluster.local:8200"
        JWT="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

        echo "== Login bei Vault =="

        LOGIN="$(curl -s --request POST \
          --header "Content-Type: application/json" \
          --data "{\"jwt\":\"$JWT\",\"role\":\"demo-role\"}" \
          "$VAULT_ADDR/v1/auth/kubernetes/login")"

        echo "$LOGIN" | jq .

        TOKEN="$(echo "$LOGIN" | jq -r '.auth.client_token')"

        if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
          echo "Kein Vault-Token erhalten"
          exit 1
        fi

        echo "== Secret aus Vault lesen =="

        SECRET="$(curl -s \
          --header "X-Vault-Token: $TOKEN" \
          "$VAULT_ADDR/v1/kv/data/app/config")"

        echo "$SECRET" | jq .

        USERNAME="$(echo "$SECRET" | jq -r '.data.data.username')"
        PASSWORD="$(echo "$SECRET" | jq -r '.data.data.password')"

        echo "username=$USERNAME"
        echo "password=$PASSWORD"
        echo "Demo finished."
EOF
```

---

# 18 Logs des Demo-Pods anzeigen

```bash
kubectl -n vault-demo logs demo-client -f
```

Erwartete Ausgabe sinngemäß:

```text
== Login bei Vault ==
{
  "auth": {
    "client_token": "..."
  }
}

== Secret aus Vault lesen ==
{
  "data": {
    "data": {
      "username": "appuser",
      "password": "SuperSecret123!"
    }
  }
}

username=appuser
password=SuperSecret123!
Demo finished.
```

---

# 19 Vergleich: Kubernetes Secret vs Vault

## Kubernetes Secret

```bash
kubectl -n vault-demo get secret app-secret -o yaml
```

- liegt im Cluster
- landet in etcd
- wird durch Kubernetes verwaltet

## Vault Secret

```bash
$VCLI kv get kv/app/config
```

- liegt in Vault
- wird zur Laufzeit geholt
- wird über Auth + Policy geschützt

---

# 20 Troubleshooting

## `path is already in use at kubernetes/`

Die Auth Method wurde bereits aktiviert.  
Einfach weitermachen.

```bash
$VCLI auth list
```

---

## Demo-Pod bekommt kein Token

Prüfen:

```bash
$VCLI read auth/kubernetes/role/demo-role
$VCLI policy read demo-policy
kubectl -n vault-demo create token demo-client
```

---

## Login klappt, aber Secret lesen nicht

Bei KV v2 muss die Policy auf `kv/data/...` zeigen:

```hcl
path "kv/data/app/config" {
  capabilities = ["read"]
}
```

---

## Vault Pod läuft nicht

Prüfen:

```bash
kubectl -n vault-demo get pods -o wide
kubectl -n vault-demo describe pod vault
kubectl -n vault-demo logs vault
```

---

## Service nicht erreichbar

Prüfen:

```bash
kubectl -n vault-demo get svc vault
kubectl -n vault-demo get endpoints vault
```

---

# 21 Aufräumen

```bash
kubectl delete namespace vault-demo
kubectl delete clusterrolebinding vault-auth-tokenreview
```

---

# Fazit

Der Demo-Pod hat:

1. sein Kubernetes ServiceAccount Token gelesen
2. sich damit bei Vault authentifiziert
3. ein Vault Token erhalten
4. das Secret aus Vault gelesen

Damit liegt das Secret **nicht mehr nur als Kubernetes Secret im Cluster**, sondern in einem separaten Secret Store.

---

# Merksatz

```text
Kubernetes Secret = Secret im Cluster
Vault Secret = Secret im Vault, Abruf zur Laufzeit
```

Diese In-Cluster-Variante ist für Labs deutlich robuster als eine Vault auf der Student-Workstation.
