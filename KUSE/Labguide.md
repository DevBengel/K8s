# Kubernetes Security Labs

## Voraussetzungen
Um mit dem folgenden Labguide arbeiten zu können, sind nur wenige Vorbereitungen notwendig.
Nachdem Sie sich mit dem Online Lab verbunden haben, öffnen Sie bitte zunächst ein Shell auf Ihrer Workstation.

Führen Sie folgende Befehle aus:

```sh
git clone https://github.com/DevBengel/K8s.git
chmod +x ./K8s/KUSE/bootstrap.sh
./K8s/KUSE/bootstrap.sh
```

Die User/Password Kombination wird ihnen im Kurs mitgeteilt

Nach wenigen Minuten ist das Labor vorbereitet und das K8s Cluster steht.

Alle weiteren Befehle führen wir auf dem System "kube-1" aus.
Verbinden Sie sich mit dem System via ssh.

ssh student@kube-1 

---

# 🧪 Lab 1 – RBAC & Identitäten

**Dauer:** ~20 Min 
**Ziel:** RBAC als API-Zugriffskontrolle verstehen; User vs. ServiceAccount; `pods/exec`

## Lernziele
- Authentifizierung (AuthN) vs. Autorisierung (AuthZ) unterscheiden
- RBAC: **wer** darf **welche** API-Aktion?
- ServiceAccounts als Maschinenidentität erkennen
- `kubectl exec` als **privilegierten** API-Zugriff einordnen

---

## 0) Vorbereitung

Der bewusste Umgang mit Namespaces ist ein zentrales Gestaltungselement in Kubernetes-Clustern.
Obwohl der default-Namespace technisch voll funktionsfähig ist, wird sein Einsatz außerhalb von Testszenarien nicht empfohlen.

Der Hauptgrund hierfür liegt in der Kopplung von Workloads an Sicherheitsmechanismen wie Role-Based Access Control (RBAC). Eine klare Namespace-Struktur erleichtert sowohl die Verwaltung als auch die spätere Analyse von Berechtigungen erheblich.

Im weiteren Verlauf dieses Labs verwenden wir daher den Namespace demo, den wir zunächst anlegen und anschließend für Übungen nutzen.

```bash
kubectl create namespace demo
```

---

## 1.1 RBAC ein erster Test

Prüfen Sie zunächst einmal, welche Default Rollen und Bindings in einem Cluster exstieren

```bash
kubectl get clusterroles | head -n 10
kubectl get rolebindings -A | head -n 10
```

**Fragen:**
- Warum gibt es RBAC-Objekte, obwohl wir noch nichts angelegt haben?
- Wo ist der Unterschied `Role` vs. `ClusterRole`?

<https://kubernetes.io/docs/reference/access-authn-authz/rbac/>


---

### 1.2 Der User - Alice

Das Kubernetes-API bewertet in der Autorisierungsphase den „User“ zunächst nur als Identität in Form einer Zeichenkette. Für RBAC ist dabei nicht entscheidend, ob dieser Benutzer tatsächlich im Cluster „angelegt“ wurde oder aus welchem Authentifizierungsmechanismus er stammt (z. B. Client-Zertifikat, OIDC, Proxy-Header). Entscheidend ist allein: Welche RBAC-Regeln matchen auf diesen Namen.

Um diesen Effekt sichtbar zu machen, simulieren wir im nächsten Schritt den Benutzer alice über --as. Damit lassen wir Kubernetes so entscheiden, als ob die Anfrage von alice käme, und prüfen anschließend, ob sie Pods lesen oder Secrets abrufen dürfte.


```bash
kubectl auth can-i get pods -n demo --as alice
kubectl auth can-i get secrets -n demo --as alice
```

Erwartung: `no` / `no`

---

## 1.3 Role + RoleBinding erstellen (Pods lesen)

Als Nächstes legen wir eine Role an, die gezielt Berechtigungen für Pods vergibt. Konkret erlauben wir damit die Verben get und list auf der Ressource pods im Namespace demo. Damit schaffen wir eine klar abgegrenzte Grundlage, um anschließend über ein RoleBinding genau zu steuern, wer diese Rechte erhält.

### 1.3.1 Role erstellen

```bash
cat <<'EOF' > role-pod-reader.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: demo
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
EOF
```

Nun wird die zuvor definierte Role dem Kubernetes-Cluster bekannt gemacht.
Um sicherzustellen, dass die Ressource korrekt angelegt wurde, rufen wir sie anschließend mit dem get-Verb über kubectl ab.

Dass Sie diesen Befehl ausführen dürfen, ist kein Zufall: Ihr aktueller Kontext verfügt über ausreichende Berechtigungen, um RBAC-Objekte zu lesen. In der Regel arbeiten Sie hier entweder mit einem Cluster-Administrator-Kontext oder mit einer Rolle, die mindestens das Lesen (get, list) von RBAC-Ressourcen erlaubt.

Genau dieser Umstand verdeutlicht einen wichtigen Punkt: RBAC wirkt immer aus Sicht der anfragenden Identität. Während wir die Role anlegen und inspizieren dürfen, heißt das noch lange nicht, dass andere Benutzer – wie etwa der zuvor simulierte User alice – diese Rechte ebenfalls besitzen.

```bash
kubectl apply -f role-pod-reader.yaml
kubectl get role pod-reader -n demo
```

### 1.3.2 RoleBinding für alice

Das bloße Anlegen einer Role reicht noch nicht aus, um Berechtigungen wirksam werden zu lassen.
Eine Role beschreibt lediglich welche Aktionen auf welche Ressourcen erlaubt sind – sie ist zunächst nur eine Definition ohne Zuordnung zu einer Identität.

Erst durch ein RoleBinding wird diese Rolle einem konkreten Subjekt zugewiesen, etwa einem Benutzer, einer Gruppe oder einem ServiceAccount. Mit dem folgenden RoleBinding verknüpfen wir die zuvor angelegte Role gezielt mit dem simulierten Benutzer alice im Namespace demo.

Nach dem Anwenden der Konfiguration prüfen wir abschließend, ob das RoleBinding korrekt im Cluster registriert wurde. Damit ist die Berechtigung technisch wirksam, auch wenn der Benutzer selbst weiterhin nur als Zeichenkette existiert.

```bash
cat <<'EOF' > rolebinding-alice.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-read-pods
  namespace: demo
subjects:
- kind: User
  name: alice
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

```bash
kubectl apply -f rolebinding-alice.yaml
kubectl get rolebinding alice-read-pods -n demo
```

### 1.3.3 Re-Test

Nachdem die Rolle nun über ein RoleBinding an den Benutzer alice gebunden wurde, prüfen wir erneut die effektiven Berechtigungen.
Der Befehl kubectl auth can-i eignet sich hierfür besonders gut, da er die Autorisierungsentscheidung des Kubernetes-API exakt simuliert, ohne tatsächlich eine Ressource anzufassen.

Im Re-Test sehen wir nun den gewünschten Effekt:
alice darf Pods im Namespace demo lesen (get), erhält jedoch weiterhin keinen Zugriff auf Secrets. Damit wird deutlich, dass RBAC-Berechtigungen feingranular, explizit und standardmäßig restriktiv wirken – erlaubt ist nur das, was zuvor ausdrücklich definiert und gebunden wurde.


```bash
kubectl auth can-i get pods -n demo --as alice
kubectl auth can-i get secrets -n demo --as alice
```

Erwartung: `yes` / `no`

**Fragen:**
- Warum bleiben Secrets verboten?
- Wo „existiert“ alice in Kubernetes?

---

## 1.4 Secrets freigeben?

Mit dem nächsten Schritt erweitern wir die Rolle bewusst um den Zugriff auf Secrets. Das ist in der Praxis ein kritischer Eingriff, weil Secrets häufig Zugangsdaten, Tokens oder Zertifikate enthalten und damit direkt zur Privilege Escalation oder zum Zugriff auf externe Systeme führen können.

### 1.4.1 Neue Role inkl. Secrets

```bash
cat <<'EOF' > role-pod-secret-reader.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-secret-reader
  namespace: demo
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
EOF
```

```bash
kubectl apply -f role-pod-secret-reader.yaml
```

### 1.4.2 RoleBinding auf neue Role umstellen

```bash
cat <<'EOF' > rolebinding-alice.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-read-pods
  namespace: demo
subjects:
- kind: User
  name: alice
roleRef:
  kind: Role
  name: pod-secret-reader
  apiGroup: rbac.authorization.k8s.io
EOF
```

```bash
kubectl delete rolebinding alice-read-pods -n demo
kubectl apply -f rolebinding-alice.yaml
```

### 1.4.3 Re-Test

```bash
kubectl auth can-i get secrets -n demo --as alice
```

Erwartung: `yes`

**Fragen:**
- Warum ist Secret-Read oft „Game Over“?
- Was kann ein Angreifer mit Secrets tun?

---

## 1.5 ServiceAccounts

Im nächsten Abschnitt wechseln wir die Perspektive: Statt eines „klassischen“ Users wie alice betrachten wir ServiceAccounts. ServiceAccounts sind die Standard-Identität für Pods, also für Anwendungen, die aus dem Cluster heraus mit der Kubernetes-API sprechen.

Jeder Namespace besitzt automatisch einen default ServiceAccount. Starten Sie einen Pod ohne weitere Angaben, nutzt Kubernetes genau diesen Account. Das ist praktisch, kann aber auch schnell zu unklaren Berechtigungsverhältnissen führen: Ein Pod „hat dann eben irgendeine Identität“ und je nachdem, welche RoleBindings existieren, kann das mehr Rechte bedeuten als beabsichtigt.

Darum schauen wir uns zunächst an, welche ServiceAccounts im Namespace demo existieren und wie der default-ServiceAccount konfiguriert ist. Anschließend starten wir einen Test-Pod ohne expliziten ServiceAccount, um zu beobachten, dass er automatisch unter dem default-ServiceAccount läuft.

### 1.5.1 ServiceAccounts anzeigen

```bash
kubectl get serviceaccounts -n demo
kubectl describe serviceaccount default -n demo
```

### 1.5.2 Pod starten (Default-SA)

```bash
kubectl run sa-test \
  --image=busybox \
  --restart=Never \
  -n demo \
  --command -- sleep 3600
```

```bash
kubectl get pods -n demo -o wide
```

### 1.5.3 In den Pod gehen (Hinweis: **-it**)

Nachdem der Pod gestartet ist, wechseln wir nun in den laufenden Container. Der interaktive Zugriff (-it) ist hier entscheidend, da wir direkt im Pod untersuchen möchten, welche Identitätsinformationen Kubernetes automatisch bereitstellt.

Innerhalb des Pods finden wir unter /var/run/secrets/kubernetes.io/serviceaccount mehrere Dateien. Dabei handelt es sich um das ServiceAccount-Token, das Kubernetes jedem Pod zur Verfügung stellt, sofern dies nicht explizit unterbunden wurde. Dieses Token ist namespace-gebunden und eindeutig dem ServiceAccount zugeordnet, unter dem der Pod läuft.


```bash
kubectl exec -it -n demo sa-test -- sh
```

Im Pod führen Sie aus:

```sh
ls /var/run/secrets/kubernetes.io/serviceaccount
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

```sh
exit
```

**Fragen:**
- Wer stellt dieses Token aus?
- Wofür nutzt der Pod dieses Token?

---

## 1.6 `kubectl exec` braucht eigenes RBAC-Recht (`pods/exec`)

kubectl exec wirkt auf den ersten Blick wie ein „Lesen“ oder „Debuggen“ eines Pods – technisch ist es aber ein eigener API-Subresource-Aufruf: pods/exec.
Und genau deshalb greift hier auch ein eigenes RBAC-Recht: Selbst wenn ein Benutzer Pods lesen darf (get, list), bedeutet das noch lange nicht, dass er auch interaktiv in Container „hineinspringen“ darf.

Im ersten Schritt prüfen wir daher die effektive Berechtigung von alice. Erwartungsgemäß ist das Ergebnis no, weil bislang keine Regel existiert, die pods/exec erlaubt.

Anschließend erstellen wir eine dedizierte Role, die exakt das Nötige freigibt: create auf pods/exec im Namespace demo. Dieses „create“ ist dabei nicht intuitiv, aber korrekt: Ein exec startet serverseitig eine neue interaktive Session (vergleichbar mit dem Erzeugen eines neuen Streams), und wird deshalb als „create“ autorisiert.

Damit ist die Grundlage gelegt. Erst ein anschließendes RoleBinding würde diese Fähigkeit konkret an alice binden.

### 1.6.1 Prüfen, ob alice exec darf

```bash
kubectl auth can-i create pods/exec -n demo --as alice
```

Erwartung: `no`

### 1.6.2 Role für exec erstellen

```bash
cat <<'EOF' > role-pod-exec.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-exec
  namespace: demo
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
EOF
```

```bash
kubectl apply -f role-pod-exec.yaml
```

### 1.6.3 RoleBinding für alice

```bash
cat <<'EOF' > rolebinding-alice-exec.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-exec
  namespace: demo
subjects:
- kind: User
  name: alice
roleRef:
  kind: Role
  name: pod-exec
  apiGroup: rbac.authorization.k8s.io
EOF
```

```bash
kubectl apply -f rolebinding-alice-exec.yaml
```

### 1.6.4 Re-Test

```bash
kubectl auth can-i create pods --subresource=exec -n demo --as alice
```

Erwartung: `yes`

**Fragen:**
- Warum ist `exec` eine Subresource?
- Warum ist das Verb `create`?

<kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources>

---

## Abschlussfragen Lab 1
1. Was schützt RBAC – und was nicht? 
2. Warum sind ServiceAccounts riskanter als „User“? 
3. Warum ist `exec` besonders kritisch?

---

---

# 🧪 Lab 2 – Admission Control & Pod Security (mit Checkpoints)

**Dauer:** ~20–25 Min 
**Ziel:** Admission (Inhaltskontrolle) vs. RBAC; Pod Security Standards als Baseline

## Lernziele
- RBAC entscheidet **wer**, Admission entscheidet **was**
- Admission greift **nach RBAC, vor etcd**
- Pod Security `restricted` erzwingt explizite Security-Attribute
- Unterschied Admission vs. Runtime verstehen



---

## 2.1 Unsicheren Pod deployen (Baseline)

Mit diesem ersten Schritt schaffen wir bewusst eine unsichere Ausgangsbasis. Der folgende Pod ist aus Sicht von Kubernetes formal korrekt, enthält jedoch sicherheitskritische Eigenschaften. Insbesondere wird der Container mit dem Attribut privileged: true gestartet, wodurch er nahezu uneingeschränkten Zugriff auf den darunterliegenden Node erhält.

Wichtig ist hierbei die Einordnung:
RBAC entscheidet lediglich, wer diesen Pod anlegen darf. Solange der anfragende Benutzer die entsprechenden Rechte besitzt, lässt RBAC den Request passieren. Ob der Pod inhaltlich akzeptabel ist, spielt an dieser Stelle noch keine Rolle.

Genau hier setzt Admission Control an. Admission Controller prüfen den Inhalt eines Objekts, bevor es dauerhaft im Cluster gespeichert wird. In diesem Baseline-Schritt existiert jedoch noch keine aktive Einschränkung, sodass der Pod erfolgreich erstellt wird. Dieses Verhalten dient als Referenzpunkt für die folgenden Schritte, in denen wir Admission-Regeln gezielt aktivieren und deren Wirkung beobachten werden.

```bash
cat <<'EOF' > insecure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: demo
spec:
  containers:
  - name: app
    image: busybox
    securityContext:
      privileged: true
    command: ["sleep", "3600"]
EOF
```

```bash
kubectl apply -f insecure-pod.yaml
kubectl get pod insecure-pod -n demo
```

**Fragen:** 
- Wurde der Inhalt geprüft? Wenn ja, wo?

---

## 2.2 Pod Security `restricted` aktivieren

Mit diesem Schritt aktivieren wir nun eine harte Inhaltskontrolle für den Namespace demo: Pod Security Admission (PSA) im Modus enforce=restricted. Ab jetzt gilt nicht mehr nur „darf der Benutzer Pods anlegen?“, sondern zusätzlich: „Erfüllt der Pod die geforderte Sicherheitsbaseline?“

Die Pod Security Standards sind dabei bewusst als Policy-Profil definiert. restricted ist die strengste der drei Stufen (privileged → baseline → restricted) und verlangt, dass sicherheitsrelevante Attribute explizit gesetzt und riskante Optionen unterbunden werden. Ein Pod, der privileged: true nutzt, verstößt klar gegen diese Vorgaben.

Wenn wir den unsicheren Pod nun erneut anwenden, passiert Folgendes:

RBAC kann weiterhin „ja“ sagen (wer darf anlegen).

Pod Security Admission prüft danach den Inhalt des PodSpecs.

Der Request wird abgewiesen, bevor das Objekt in etcd gespeichert wird.

Die erwartete Reaktion ist daher ein Rejected (Forbidden) mit einer Meldung, die auf PodSecurity und die verletzten Anforderungen hinweist.

```bash
kubectl label namespace demo \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

Erneut anwenden:

```bash
kubectl delete pod insecure-pod -n demo --ignore-not-found
kubectl apply -f insecure-pod.yaml
```

Erwartung: **Error from server (Forbidden)** durch PodSecurity.

---

## 2.3 Sicherer Pod – Checkpoint 1 (seccompProfile)

Mit diesem Checkpoint nähern wir uns Schritt für Schritt dem restricted-Profil an. Der Pod ist bereits deutlich gehärtet: Er läuft nicht als Root, erlaubt keine Privilege Escalation und entfernt alle Linux-Capabilities. Damit erfüllen wir zentrale Anforderungen, die in vielen Baselines ohnehin Standard sein sollten.

Trotzdem ist diese Variante absichtlich noch unvollständig. Unter pod-security.kubernetes.io/enforce=restricted verlangt Kubernetes zusätzlich ein explizites Seccomp-Profil. Hintergrund: Seccomp steuert, welche Systemaufrufe ein Prozess überhaupt ausführen darf – und ist damit eine wichtige zweite Verteidigungslinie, selbst wenn ein Container kompromittiert wird.

Beim Anwenden erwarten wir daher, dass Pod Security Admission den Request ablehnt und bemängelt, dass seccompProfile fehlt. Im nächsten Schritt ergänzen wir das Profil (typischerweise RuntimeDefault), bis der Pod die Anforderungen vollständig erfüllt.

### 2.3.1 Erste (unvollständige) sichere Variante

```bash
cat <<'EOF' > secure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: demo
spec:
  containers:
  - name: app
    image: busybox
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    command: ["sleep", "3600"]
EOF
```

```bash
kubectl apply -f secure-pod.yaml
```

**Erwarteter Fehler (Checkpoint):**
- PodSecurity verlangt `seccompProfile` (RuntimeDefault oder Localhost)

### 2.3.2 Fix: seccompProfile explizit setzen (Pod-Ebene)

Bevor wir den Pod erneut deployen, ergänzen wir die Konfiguration um ein entscheidendes Sicherheitsmerkmal. Unter dem Pod-Security-Profil restricted genügt es nicht, sich auf implizite Defaults zu verlassen – sicherheitsrelevante Einstellungen müssen explizit gesetzt werden.

Eine dieser Anforderungen betrifft Seccomp. Seccomp legt fest, welche Systemaufrufe ein Container überhaupt ausführen darf, und bildet damit eine zusätzliche Schutzschicht auf Betriebssystemebene. Fehlt diese Angabe, lehnt Pod Security Admission den Pod konsequent ab.

Im folgenden Schritt setzen wir daher ein seccompProfile auf Pod-Ebene und definieren mit RuntimeDefault ein sicheres, vom System bereitgestelltes Standardprofil. Damit erfüllen wir die letzte noch offene Voraussetzung, um den Pod unter dem restricted-Profil erfolgreich auszuführen.

```bash
cat <<'EOF' > secure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: demo
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: busybox
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    command: ["sleep", "3600"]
EOF
```

```bash
kubectl apply -f secure-pod.yaml
```

---

## 2.4 Checkpoint 2 (runAsNonRoot vs. Image)

Nach dem seccomp-Fix kann Folgendes passieren:

- Pod wird erstellt, aber kubelet meldet:
 `container has runAsNonRoot and image will run as root`

### 2.4.1 Fix: explizit Non-Root-UID setzen

Nach dem erfolgreichen Seccomp-Fix stoßen wir auf einen wichtigen, oft missverstandenen Grenzfall zwischen Policy und Realität. Pod Security Admission akzeptiert den Pod, da die Konfiguration formal den Anforderungen des restricted-Profils entspricht. Damit ist die Admission-Phase abgeschlossen.

Erst anschließend kommt jedoch das kubelet ins Spiel. Das kubelet prüft nicht mehr die Absicht der Konfiguration, sondern die tatsächlichen Eigenschaften des Images zur Laufzeit. Viele Images – darunter auch busybox – sind so gebaut, dass sie standardmäßig als Root starten. In Kombination mit runAsNonRoot: true entsteht dadurch ein Widerspruch, den das kubelet korrekt als Fehler meldet.

Um diesen Konflikt aufzulösen, setzen wir im nächsten Schritt explizit eine nicht-privilegierte User-ID (runAsUser). Damit stellen wir sicher, dass sowohl die Admission-Regeln als auch die reale Ausführung des Containers konsistent sind. Der Pod sollte anschließend erfolgreich in den Zustand Running wechseln.

Der zentrale Lernpunkt an dieser Stelle lautet: Admission kontrolliert die Konfiguration – das kubelet erzwingt die Realität.

```bash
cat <<'EOF' > secure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: demo
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: busybox
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    command: ["sleep", "3600"]
EOF
```

```bash
kubectl delete pod secure-pod -n demo --ignore-not-found
kubectl apply -f secure-pod.yaml
kubectl get pods -n demo
```

Erwartung: `secure-pod` **Running**

**Lernpunkt:** Admission prüft Konfiguration; kubelet prüft Image-Realität.

---

## 2.5 Pod Security Settings im Cluster finden

Zum Abschluss von Lab 2 schauen wir uns noch einmal die wirksamen Pod-Security-Einstellungen im Namespace an und fassen die Kernerkenntnisse zusammen.

Mit den gezeigten Befehlen machen wir transparent, welche Labels tatsächlich aktiv sind und damit, welche Sicherheitsregeln Pod Security Admission im Namespace demo erzwingt. Diese Sicht ist in der Praxis essenziell, um Fehlverhalten nicht zu „raten“, sondern gezielt zu erklären.

```bash
kubectl get namespace demo --show-labels
kubectl describe namespace demo
```

---

Die in diesem Lab eingesetzten Pod Security Standards leisten einen wichtigen Beitrag zur Basishärtung von Workloads. Sie prüfen zuverlässig, wie ein Pod konfiguriert ist, und erzwingen sicherheitsrelevante Attribute direkt am PodSpec. Gleichzeitig werden in diesem Abschnitt jedoch auch die klaren Grenzen dieses Ansatzes sichtbar.

Pod Security trifft keinerlei Aussagen darüber, aus welcher Registry ein Container-Image stammt. Ob ein Image aus einer vertrauenswürdigen Unternehmens-Registry oder aus einer beliebigen öffentlichen Quelle bezogen wird, bleibt für Pod Security vollkommen irrelevant. Ebenso wenig können Image-Tags bewertet oder eingeschränkt werden. Die Verwendung von :latest oder nicht reproduzierbaren Tags wird nicht verhindert.

Darüber hinaus kennt Pod Security keine organisatorischen oder unternehmensspezifischen Regeln. Namenskonventionen, verpflichtende Labels, Team-Zuordnungen oder Freigabeprozesse lassen sich mit Pod Security nicht abbilden. Die Kontrolle endet bewusst an der technischen Sicherheitsbaseline eines einzelnen Pods.

Genau an dieser Stelle entsteht der Bedarf nach einer erweiterten Policy-Ebene. Werkzeuge wie Kyverno setzen hier an und ermöglichen es, über reine Pod-Sicherheitsattribute hinauszugehen – hin zu kontextabhängigen, organisationsweiten und nachvollziehbaren Regeln für den gesamten Cluster.

---

# 🧪 Lab 3 – Netzwerksegmentierung mit NetworkPolicies (Ost–West-Traffic)

> **Cluster:** Vanilla Kubernetes (3 Nodes) 
> **CNI:** Flannel **oder** Calico 
> **Namespace-Setup:** `frontend`, `backend`, `db`

---

## Lernziele

In diesem Lab untersuchen wir die Netzwerkkommunikation innerhalb eines Kubernetes-Clusters. Im Mittelpunkt steht dabei die sogenannte Ost–West-Kommunikation, also der Datenverkehr zwischen Pods und Services innerhalb des Clusters. Ziel ist es, das standardmäßige Verhalten zu verstehen und dieses anschließend gezielt einzuschränken.

Nach Abschluss dieses Labs sollten Sie in der Lage sein:
- das Default-Allow-Verhalten von Kubernetes-Netzwerken einzuordnen 
- NetworkPolicies als **deklarative Firewall-Regeln** zu lesen und zu schreiben 
- zwischen Namespace-Strukturierung und tatsächlicher Isolation zu unterscheiden 
- NetworkPolicies klar von Admission-Mechanismen abzugrenzen 
- die sicherheitliche Bedeutung von Runtime-Netzwerkkontrollen zu bewerten 

---

## 🧠 Einordnung

Kubernetes verfolgt im Netzwerkbereich einen bewusst funktionalen Ansatz. Standardmäßig existiert **keine Isolation** zwischen Pods. Jeder Pod kann jeden anderen Pod erreichen – unabhängig davon, in welchem Namespace er läuft. Dieses Verhalten erleichtert die Entwicklung verteilter Anwendungen erheblich, bringt jedoch ohne zusätzliche Maßnahmen keine Sicherheitsgarantien mit sich.

NetworkPolicies setzen genau an dieser Stelle an. Sie verändern das Verhalten **nicht global**, sondern selektiv und deklarativ. Wichtig ist dabei die zeitliche Einordnung: NetworkPolicies greifen **zur Laufzeit**. Sie verhindern keine Deployments und prüfen keine YAML-Dateien, sondern filtern aktiv den Netzwerkverkehr zwischen Pods.

Ebenso entscheidend ist die technische Voraussetzung: NetworkPolicies wirken nur dann, wenn das eingesetzte Container Network Interface (CNI) diese Funktion unterstützt. Lösungen wie Calico oder Cilium setzen Policies vollständig um, während einfache CNIs ohne Erweiterungen wirkungslos bleiben.

---

## 0) Vorbereitung – Namespaces anlegen

Um Kommunikationsbeziehungen nachvollziehbar und strukturiert abzubilden, trennen wir die beteiligten Komponenten zunächst logisch. Wir verwenden drei Namespaces, die typische Schichten einer Anwendung repräsentieren: Frontend, Backend und Datenbank.

Diese Trennung allein stellt **noch keine Sicherheitsgrenze** dar, bildet jedoch die notwendige Grundlage für gezielte NetworkPolicies.

```bash
kubectl create namespace frontend || true
kubectl create namespace backend || true
kubectl create namespace db || true
```

Zur Kontrolle prüfen wir die vorhandenen Namespace-Labels, die später für Selektoren relevant sein können:

```bash
kubectl get ns --show-labels
```

---

## 3.1 Ausgangslage: Alles darf mit allem sprechen

Bevor wir Regeln definieren, machen wir das Default-Verhalten sichtbar. Ohne NetworkPolicies existiert keinerlei Einschränkung des Netzwerkverkehrs zwischen Pods.

### 3.1.1 DB-Service deployen (nginx als Platzhalter)

Im Namespace `db` deployen wir einen einfachen HTTP-Dienst. Der konkrete Dienst ist dabei nebensächlich – er dient lediglich als erreichbares Ziel für Netzwerktests. Entscheidend ist, dass ein Pod existiert, der über einen Kubernetes-Service angesprochen werden kann.

```bash
cat <<'EOF' > db.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: db
  namespace: db
spec:
  replicas: 1
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
EOF

kubectl apply -f db.yaml
```

Anschließend legen wir einen Service an, der den Pod unter einem stabilen DNS-Namen erreichbar macht:

```bash
cat <<'EOF' > db-svc.yaml
apiVersion: v1
kind: Service
metadata:
  name: db
  namespace: db
spec:
  selector:
    app: db
  ports:
  - port: 80
    targetPort: 80
EOF

kubectl apply -f db-svc.yaml
```

---

### 3.1.2 Backend-Pod starten (Client)

Im Namespace `backend` starten wir nun einen minimalen Client-Pod. Dieser Pod repräsentiert eine Anwendungskomponente, die auf den Datenbank-Service zugreifen möchte.

```bash
kubectl run backend   --image=busybox   --namespace backend   --command -- sleep 3600
```

---

### 3.1.3 Verbindung testen (soll funktionieren)

Nun testen wir explizit die Erreichbarkeit des Datenbank-Services aus dem Backend-Namespace.

```bash
kubectl exec -n backend backend -- wget -qO- http://db.db.svc.cluster.local
```

**Erwartung: ** Die HTML-Ausgabe von nginx wird angezeigt.

Dieser Test bestätigt das Default-Allow-Modell: Ohne NetworkPolicies ist Ost–West-Traffic uneingeschränkt möglich.

---

## 3.2 Default-Deny: Datenbank isolieren

> **Hinweis:** Sobald **eine** NetworkPolicy in einem Namespace existiert, gilt für die selektierten Pods ein implizites *deny-by-default*.

Nun führen wir eine erste NetworkPolicy ein, die sämtlichen eingehenden Traffic auf Pods im Namespace `db` blockiert. Ziel ist es, den bisherigen offenen Zustand bewusst zu durchbrechen.

### 3.2.1 Default-Deny-Ingress-Policy im DB-Namespace

```bash
cat <<'EOF' > db-deny-all.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: db
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

kubectl apply -f db-deny-all.yaml
```

---

### 3.2.2 Verbindung erneut testen

```bash
kubectl exec -n backend backend -- wget -qO- http://db.db.svc.cluster.local || echo "BLOCKED"
```

**Erwartung: ** Timeout oder BLOCKED.

Der Datenbank-Pod ist nun effektiv vom restlichen Cluster isoliert. Kommunikation ist erst wieder möglich, wenn sie explizit erlaubt wird.

---

## 3.3 Gezielt erlauben: Backend → DB

In realen Umgebungen ist vollständige Isolation selten das Ziel. Stattdessen definieren wir gezielte, nachvollziehbare Freigaben.

### 3.3.1 Erlaubende NetworkPolicy erstellen

Die folgende Policy erlaubt ausschließlich Pods aus dem Namespace `backend`, auf Pods mit dem Label `app: db` im Namespace `db` zuzugreifen – und das nur über TCP Port 80.

```bash
cat <<'EOF' > db-allow-backend.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-backend-ingress
  namespace: db
spec:
  podSelector:
    matchLabels:
      app: db
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: backend
    ports:
    - protocol: TCP
      port: 80
EOF

kubectl apply -f db-allow-backend.yaml
```

---

### 3.3.2 Verbindung testen

```bash
kubectl exec -n backend backend -- wget -qO- http://db.db.svc.cluster.local
```

**Erwartung: ** Zugriff ist wieder möglich.

Damit haben wir eine kontrollierte Ost–West-Kommunikation umgesetzt.

---

## Abschluss Lab 3

Dieses Lab zeigt deutlich:
- Kubernetes-Netzwerke sind **offen per Design**
- NetworkPolicies sind **deklarative Laufzeitregeln**
- Isolation entsteht ausschließlich durch explizite Policies
- Namespaces allein stellen keine Sicherheitsgrenze dar

# 🧪 Lab 4 – Kyverno (Validate): Organisationsregeln als Admission Policy

**Dauer:** ~25–35 Min 
## Lernziele

In diesem Lab lernen Sie Kyverno als zentrales Werkzeug für Governance im Kubernetes-Cluster kennen. Der Fokus liegt darauf, Richtlinien nicht nur technisch, sondern auch organisatorisch durchzusetzen. Dabei ist Kyverno nur ein mögliches, exemplarisches Werkzeug.

Nach Abschluss dieses Labs sollten Sie:
- Kyverno als Admission Controller und Policy Engine einordnen können 
- den Unterschied zwischen Audit- und Enforce-Modus praktisch verstehen 
- eine Namespaced Policy schreiben und anwenden 
- Policy-Verstöße über Events und Statusmeldungen nachvollziehen 
- typische Installations- und Konfigurationsfehler erkennen und einordnen 

---

## 0) Vorbereitung

### 0.1 Namespace für Übungen

Wir arbeiten bewusst in einem dedizierten Namespace, um Governance-Regeln klar von anderen Labs zu trennen.

```bash
kubectl get ns kyverno-lab || kubectl create ns kyverno-lab
```

### 0.2 Kontext prüfen (optional)

Ein kurzer Blick auf Cluster-Version und Nodes hilft bei der späteren Einordnung von Verhalten und Fehlermeldungen.

```bash
kubectl get nodes -o wide
kubectl version
```

---

## 4.1 Warum Kyverno? – Kurz-Demo ohne Kyverno

Bevor wir Kyverno einsetzen, erzeugen wir bewusst eine weit verbreitete Supply-Chain-Unsitte: die Verwendung des Image-Tags `:latest`. Dieses Beispiel zeigt, welche Lücke ohne zusätzliche Governance-Mechanismen existiert.

```bash
cat <<'EOF' > nginx-latest.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-latest
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-latest
  template:
    metadata:
      labels:
        app: nginx-latest
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
EOF
```

```bash
kubectl apply -f nginx-latest.yaml
kubectl get deploy -n kyverno-lab
kubectl get pods  -n kyverno-lab -o wide
```

**Beobachtung: ** Deployment und Pod werden problemlos akzeptiert.

**Einordnung:** 
Weder RBAC noch Pod Security Standards bewerten Image-Tags. Kubernetes akzeptiert den Workload, obwohl er aus Governance-Sicht problematisch ist.

---

## 4.2 Kyverno installieren (ohne Helm)

### 4.2.1 Warum server-side apply?

Kyverno besteht aus umfangreichen Manifests inklusive CustomResourceDefinitions (CRDs). Bei client-side `kubectl apply` kann es dabei zu Fehlern kommen, etwa durch zu große `last-applied-configuration`-Annotations.

Die Verwendung von **server-side apply** umgeht dieses Problem zuverlässig und ist daher für Schulungs- und Produktionsumgebungen die robustere Variante.

### 4.2.2 Installation

Wir verwenden bewusst eine feste Version, um reproduzierbares Verhalten im Kurs sicherzustellen.

```bash
KYVERNO_VER="v1.17.0"
kubectl apply --server-side -f "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VER}/install.yaml"
```

Warten, bis Kyverno vollständig gestartet ist:

```bash
kubectl get pods -n kyverno -w
```

**Erwartung: ** Alle Kyverno-Pods sind `Running` und `Ready`.

### 4.2.3 CRDs prüfen

```bash
kubectl get crd | grep -E 'policies.kyverno.io|clusterpolicies.kyverno.io|policyreports.wgpolicyk8s.io' || true
```

Sind diese CRDs vorhanden, ist Kyverno korrekt installiert.

---

## 4.3 Erste Kyverno Policy – `:latest` beobachten (Audit)

### 4.3.1 Policy erstellen (Namespaced)

Wir beginnen bewusst im **Audit-Modus**. Verstöße werden sichtbar gemacht, ohne den Betrieb zu unterbrechen. Das ist besonders wertvoll für bestehende Umgebungen.

```bash
cat <<'EOF' > deny-latest-tag.yaml
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: deny-latest-tag
  namespace: kyverno-lab
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: block-latest-tag
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Images mit dem Tag ':latest' sind im Namespace kyverno-lab nicht erlaubt."
      pattern:
        spec:
          containers:
          - image: "!*:latest"
EOF
```

```bash
kubectl apply -f deny-latest-tag.yaml
kubectl get policy -n kyverno-lab
```

### 4.3.2 Verstoß erzeugen

```bash
kubectl rollout restart deploy/nginx-latest -n kyverno-lab
```

### 4.3.3 Verstöße auswerten

```bash
kubectl get events -n kyverno-lab --sort-by=.lastTimestamp | tail -n 20
```

**Beobachtung: ** Warnungen werden erzeugt, der Pod läuft jedoch weiter.

---

# Audit → Enforce: Kyverno Policy ändern (vi-Anleitung)

## 4.4 Audit → Enforce: Regel wirklich durchsetzen

Nachdem die Auswirkungen im **Audit-Modus** sichtbar sind, wechseln wir in den **Enforce-Modus**, damit Verstöße **hart blockiert** werden.

---

## Schritt 1: Policy im Editor öffnen

```bash
kubectl edit policy deny-latest-tag -n kyverno-lab
```

Kubernetes öffnet die Policy im Standard-Editor **vi**.

---

## Schritt 2: Wert ändern (vi-Bedienung)

### In den Einfügemodus wechseln
```text
i
```

### Zeile ändern

Von:

```yaml
validationFailureAction: Audit
```

Zu:

```yaml
validationFailureAction: Enforce
```

---

## Schritt 3: Speichern und Beenden

1. Einfügemodus verlassen:
```text
ESC
```

2. Speichern und beenden:
```text
:wq
```

(Enter drücken)

---

## Hinweise (vi)

- Ohne Speichern beenden:
```text
ESC
:q!
```

- Nur speichern:
```text
ESC
:w
```

---

## Schritt 4: Ergebnis prüfen

```bash
kubectl get policy deny-latest-tag -n kyverno-lab
```

Oder gezielt:

```bash
kubectl get policy deny-latest-tag -n kyverno-lab -o yaml | grep validationFailureAction
```

Erwartung: ```text
validationFailureAction: Enforce
```


---

## Lernpunkte

- **Audit** = melden, nicht blockieren
- **Enforce** = Admission blockiert Verstöße
- `kubectl edit` ist gut für Demos, aber nicht GitOps-tauglich


### 4.4.1 Re-Test

```bash
kubectl delete deploy nginx-latest -n kyverno-lab --ignore-not-found
kubectl apply -f nginx-latest.yaml
```

**Erwartung: ** Die Admission wird von Kyverno blockiert.

---

## 4.5 Fix: Version pinnen

Als Gegenprobe korrigieren wir das Deployment, indem wir eine feste Image-Version verwenden.

```bash
cat <<'EOF' > nginx-pinned.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-pinned
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-pinned
  template:
    metadata:
      labels:
        app: nginx-pinned
    spec:
      containers:
      - name: nginx
        image: nginx:1.29
        ports:
        - containerPort: 80
EOF
```

```bash
kubectl apply -f nginx-pinned.yaml
kubectl get pods -n kyverno-lab -o wide
```

**Ergebnis:** Pod wird erfolgreich erstellt.

---

## Abschluss Lab 4

Dieses Lab zeigt:
- Governance-Regeln liegen außerhalb von RBAC und Pod Security 
- Kyverno schließt diese Lücke auf Admission-Ebene 
- Audit ermöglicht risikofreie Einführung neuer Regeln 
- Enforce sorgt für verbindliche, nachvollziehbare Durchsetzung 

Kyverno macht Richtlinien transparent, erklärbar und organisationsweit konsistent.

# 🧪 Lab 5 – Kyverno (Validate): Registry Allowlist (Supply-Chain Governance)

**Dauer:** ~25–35 Min 
**Ziel:** Verstehen, warum die Herkunft von Container-Images ein zentraler Bestandteil der Supply Chain ist – und wie sich mit Kyverno eine verbindliche **Registry-Allowlist** durchsetzen lässt. 
**Schwerpunkt:** Validate Policies mit **Audit → Enforce** und klaren, sprechenden Fehlermeldungen.

> **Hinweis:** Dieses Lab baut auf Lab 4 auf. Kyverno ist bereits im Cluster installiert und funktionsfähig. 
> **Namespace im Lab:** `kyverno-lab`

---

## 🧠 Warum dieses Lab?

Pod Security Standards konzentrieren sich auf die **Laufzeit-Eigenschaften** eines Pods. Sie stellen sicher, dass Container nicht privilegiert laufen, dass Seccomp genutzt wird oder dass Prozesse nicht als Root starten. 
Viele reale Angriffe setzen jedoch **früher** an – noch bevor ein Container überhaupt gestartet wird.

Typische Risiken in der Supply Chain sind:
- Images aus unbekannten oder nicht kontrollierten Registries 
- kompromittierte Images in Dritt- oder Community-Registries 
- Typosquatting (z. B. `ngnix` statt `nginx`) 
- direkter Pull aus dem Internet statt aus einer internen oder freigegebenen Quelle 

Daraus ergibt sich eine klassische Organisationsregel:

> **„In produktiven Clustern dürfen nur Images aus freigegebenen Registries verwendet werden.“**

Diese Regel lässt sich weder mit RBAC noch mit Pod Security Standards umsetzen. Sie ist eine **Governance- und Supply-Chain-Frage** – und genau hier kommt Kyverno ins Spiel.

---

## Lernziele

In diesem Lab lernen Sie:
- Registry-Policies als Teil von Supply-Chain-Security einzuordnen 
- eine Kyverno Validate Policy zu schreiben, die nur bestimmte Registries erlaubt 
- den Unterschied zwischen **Audit** und **Enforce** praktisch zu erleben 
- typische Stolperfallen bei Registry-Policies zu vermeiden (Namespace, Autogen, Debugging) 

---

## 0) Vorbereitung

### 0.1 Namespace prüfen

```bash
kubectl get ns kyverno-lab --show-labels
```

### 0.2 Aktive Policies anzeigen

```bash
kubectl get policy -n kyverno-lab
```

---

## 5.1 Ausgangslage: Registry-Herkunft ist egal

Ohne explizite Governance-Regeln ist Kubernetes vollkommen agnostisch gegenüber der Herkunft eines Images. 
Im folgenden Beispiel verwenden wir bewusst ein Image aus der GitHub Container Registry (`ghcr.io`).

```bash
cat <<'EOF' > lab5-bad.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lab5-bad
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lab5-bad
  template:
    metadata:
      labels:
        app: lab5-bad
    spec:
      containers:
      - name: app
        image: ghcr.io/stefanprodan/podinfo:6.7.1
EOF

```

```bash
kubectl apply -f lab5-bad.yaml
kubectl get pods -n kyverno-lab -l app=lab5-bad -w
```

---

## 5.2 Registry-Allowlist-Policy erstellen (Audit)

```bash
cat <<'EOF' > allowlist-registry.yaml
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: allowlist-registry
  namespace: kyverno-lab
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: only-dockerhub-library
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Nur Images aus docker.io/library/* sind im Namespace kyverno-lab erlaubt."
      pattern:
        spec:
          containers:
          - image: "docker.io/library/*"
EOF
```

```bash
kubectl apply -f allowlist-registry.yaml
kubectl get policy -n kyverno-lab
```

---

## 5.3 Audit → Enforce

```bash
kubectl edit policy allowlist-registry -n kyverno-lab
```

```yaml
validationFailureAction: Enforce
```

---

## 5.4 Test (muss blockieren)

```bash
kubectl delete deploy lab5-bad -n kyverno-lab --ignore-not-found
kubectl apply -f lab5-bad.yaml
```

---

## Abschluss Lab 5

- Registry-Kontrolle ist ein zentraler Bestandteil der Supply Chain Security 
- Pod Security Standards adressieren dieses Problem nicht 
- Kyverno ergänzt Kubernetes um organisationsweite Governance-Regeln 
- Audit ermöglicht eine sichere Einführung neuer Policies

# 🧪 Lab 6 – Kyverno (Validate): Immutable Images mit Digests

**Dauer:** ~30–40 Min 
**Ziel:** Verstehen, warum **Tags keine stabile Referenz** sind und wie man mit **Image-Digests** echte Reproduzierbarkeit erzwingt. 
**Schwerpunkt:** Validate Policy → *Images müssen per Digest referenziert werden*.

> **Einordnung im Kurs:** 
> Lab 4: *Was* darf deployt werden (`:latest` verbieten) 
> Lab 5: *Woher* darf deployt werden (Registry-Allowlist) 
> **Lab 6:** *Welche exakte Version* darf laufen (Immutable Reference)

Namespace im Lab: `kyverno-lab`

---

## Lernziele

- Unterschied **Tag vs. Digest** verstehen
- Warum `nginx:1.29` **nicht reproduzierbar** ist
- Image-Digests lesen und nutzen
- Kyverno-Policy schreiben: *Digest erzwingen*
- Typische Stolperfallen erkennen (Autogen, Background Scan, bestehende Pods)

---

In diesem Lab geht es um eine Eigenschaft von Container-Images, die in der Praxis häufig unterschätzt wird: Tags sind keine stabile Referenz. Ein Image-Tag wie nginx:1.29 bezeichnet keine feste Version, sondern lediglich einen Namen, der jederzeit auf ein anderes Image zeigen kann.

Für reproduzierbare Deployments und eine belastbare Sicherheits-Governance ist dieses Verhalten problematisch. Kubernetes erzwingt von sich aus keine Unveränderlichkeit von Image-Referenzen – selbst in sicher gehärteten Clustern.

Mit Kyverno nutzen wir daher eine Admission-Policy, die ausschließlich immutable Image-Referenzen über Digests erlaubt. Schrittweise beobachten wir zunächst die Auswirkungen im Audit-Modus und erzwingen das Verhalten anschließend verbindlich. Damit stellen wir sicher, dass im Cluster nur exakt definierte Image-Versionen ausgeführt werden.

---

## 0) Vorbereitung

### 0.1 Aktuellen Zustand prüfen

```bash
kubectl get policy -n kyverno-lab
kubectl get deploy -n kyverno-lab
```

> Die Registry-Allowlist aus Lab 5 darf aktiv bleiben.

---

## 6.1 Ausgangslage: Tag-basierte Images sind erlaubt

Wir nutzen ein **erlaubtes Registry-Image**, aber **ohne Digest**.

```bash
cat <<'EOF' > lab6-tagged.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lab6-tagged
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lab6-tagged
  template:
    metadata:
      labels:
        app: lab6-tagged
    spec:
      containers:
      - name: app
        image: docker.io/library/nginx:1.29
EOF
```

```bash
kubectl apply -f lab6-tagged.yaml
kubectl get pods -n kyverno-lab -l app=lab6-tagged -o wide
```

✅ **Erwartung: ** Pod läuft.

### Reflexion
- Ist dieses Deployment reproduzierbar?
- Kann jemand das Image hinter dem Tag austauschen?

---

## 6.2 Digest eines Images ermitteln (praxisnah)

### 6.2.1 Image lokal pullen (containerd / crictl)

> **Hinweis:** `crictl` spricht direkt mit dem Container Runtime Interface (CRI). 
> Warnungen zu fehlender Config sind **harmlos**, können aber unterdrückt werden (siehe 6.2.3).

```bash
sudo crictl pull docker.io/library/nginx:1.29
```

### 6.2.2 Digest anzeigen

```bash
sudo crictl inspecti docker.io/library/nginx:1.29 | grep -n "repoDigests" -A2
```

Beispielausgabe:

```
"repoDigests": [
  "docker.io/library/nginx@sha256:d0ef59cae4570338..."
]
```

 **Das ist die stabile Referenz.**

### 6.2.3 (Optional) Warnungen vermeiden

Erstelle `/etc/crictl.yaml`:

```bash
sudo tee /etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
EOF
```

---

## 6.3 Kyverno Policy: Digest erzwingen (Audit)

### 6.3.1 Policy erstellen

```bash
cat <<'EOF' > require-image-digest.yaml
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: require-image-digest
  namespace: kyverno-lab
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: images-must-use-digest
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Images müssen per Digest referenziert werden (…@sha256:…)."
      pattern:
        spec:
          containers:
          - image: "*@sha256:*"
EOF
```

```bash
kubectl apply -f require-image-digest.yaml
kubectl get policy require-image-digest -n kyverno-lab
```

---

## 6.4 Audit beobachten (bestehende Deployments)

### 6.4.1 Background Scan erzeugt Warnings

```bash
kubectl describe deploy lab6-tagged -n kyverno-lab | sed -n '/Events:/,$p'
```

🟡 **Erwartung: ** 
`PolicyViolation` – Image ohne Digest (Audit).

### Lernpunkt
- Kyverno prüft auch **bestehende Ressourcen** (`background: true`)
- Ideal für Bestandscluster / Migration

---

## 6.5 Audit → Enforce

### 6.5.1 Policy verschärfen

```bash
kubectl edit policy require-image-digest -n kyverno-lab
```

Ändere:

```yaml
validationFailureAction: Enforce
```

### 6.5.2 Re-Test: Tag-basiertes Image (soll blocken)

```bash
kubectl delete deploy lab6-tagged -n kyverno-lab --ignore-not-found
kubectl apply -f lab6-tagged.yaml
```

❌ **Erwartung: ** Admission blockiert Deployment.

---

## 6.6 Fix: Deployment mit Digest

### 6.6.1 Deployment mit Digest erstellen

> Ersetze den Digest durch **den bei Ihnen ermittelten**.

```bash
cat <<'EOF' > lab6-digest.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lab6-digest
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lab6-digest
  template:
    metadata:
      labels:
        app: lab6-digest
    spec:
      containers:
      - name: app
        image: docker.io/library/nginx@sha256:d0ef59cae4570338REPLACE_ME
EOF
```

```bash
kubectl apply -f lab6-digest.yaml
kubectl get pods -n kyverno-lab -l app=lab6-digest -o wide
```

✅ **Erwartung: ** Pod läuft.

---

## 6.7 Typische Anfängerfragen & Stolperfallen

### 6.7.1 „Warum blockt Kyverno trotz korrektem Digest?“

- Falsches Pattern (`*@sha256:*`)
- Image hat mehrere Container
- Autogen-Regeln greifen (Deployment → Pod)

Policy-Status prüfen:

```bash
kubectl get policy require-image-digest -n kyverno-lab -o yaml | sed -n '/status:/,$p'
```

---

### 6.7.2 „Warum nutzt Kyverno nicht automatisch den Digest?“

➡️ **Validate ≠ Mutate** 
Kyverno kann *prüfen* oder *verändern*. 
In diesem Lab **erzwingen** wir Verhalten – **nicht auto-fixen**.

(Mutation kommt in einem anderen Kontext.)

---

## Abschlussfragen Lab 6

1. Warum sind Tags keine Sicherheitsgarantie?
2. Welche Vorteile haben Digests für Incident Response?
3. Warum ist `background: true` wichtig?
4. Wo würden Sie Digests im CI/CD erzeugen?

---

## Aufräumen 

```bash
kubectl delete -f lab6-tagged.yaml --ignore-not-found
kubectl delete -f lab6-digest.yaml --ignore-not-found
kubectl delete deploy lab5-ghcr-demo -n kyverno-lab --ignore-not-found
# require-image-digest bleibt für Lab 7 aktiv
```

---

# 🧪 Lab 7 – Vertrauenswürdige Images ohne Runtime-Tools

**Dauer:** \~25–30 Minuten\
**Voraussetzung:** Lab 5 (Registry-Allowlist), Lab 6 (Image Digest)\
**Namespace:** `kyverno-lab`

---

## Lernziele

- Unterschied **Digest ≠ Vertrauen** verstehen
- Warum Signaturen meist **außerhalb** des Clusters geprüft werden
- Wie Kyverno als **Governance Gate** für geprüfte Artefakte eingesetzt wird
- Warum stabile Kurse keine Runtime-Tool-Demos benötigen

---

## 🧠 Einordnung

Ein Image-Digest garantiert Unveränderlichkeit, aber nicht Herkunft oder Verantwortung. In der Praxis werden Images **vor** dem Cluster geprüft (CI, Registry) und der Cluster vertraut nur noch **freigegebenen Artefakten**.

Dieses Lab erzwingt genau dieses Modell.

---

## 7.1 Ausgangslage prüfen

```bash
kubectl get policy -n kyverno-lab
```

Erwartung: Registry-Allowlist + Digest-Policy sind aktiv.

---

## 7.2 Governance-Regel

> Nur Images aus `docker.io/library` **mit Digest** sind erlaubt.

---

## 7.3 Kyverno-Policy erstellen

```bash
cat <<'EOF' > require-trusted-image-path.yaml
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: require-trusted-image-path
  namespace: kyverno-lab
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: trusted-image-path-with-digest
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Nur freigegebene Images (Pfad + Digest) sind erlaubt."
      pattern:
        spec:
          containers:
          - image: "docker.io/library/*@sha256:*"
EOF
```

```bash
kubectl apply -f require-trusted-image-path.yaml
kubectl get policy -n kyverno-lab
```

---

## 7.4 Positiver Test (freigegeben)

Digest ermitteln:

```bash
sudo crictl pull docker.io/library/nginx:1.28
sudo crictl inspecti docker.io/library/nginx:1.28 | grep repoDigests -A2
```

Deployment:

```bash
cat <<'EOF' > lab7-trusted.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lab7-trusted
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lab7-trusted
  template:
    metadata:
      labels:
        app: lab7-trusted
    spec:
      containers:
      - name: app
        image: docker.io/library/nginx@sha256:REPLACE_ME
EOF
```

```bash
kubectl apply -f lab7-trusted.yaml
kubectl get pods -n kyverno-lab -l app=lab7-trusted
```

---

## 7.5 Negativer Test (nicht freigegeben)

```bash
cat <<'EOF' > lab7-untrusted.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lab7-untrusted
  namespace: kyverno-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lab7-untrusted
  template:
    metadata:
      labels:
        app: lab7-untrusted
    spec:
      containers:
      - name: app
        image: docker.io/library/nginx:1.28
EOF
```

```bash
kubectl apply -f lab7-untrusted.yaml
```

Erwartung: Admission wird blockiert.

---

## 🧠 Kernerkenntnisse

- Digest = unveränderlich, aber nicht vertrauenswürdig
- Vertrauen entsteht **vor** dem Cluster
- Admission ist ein Gate, kein Kryptolabor

---

## Abschlussfragen

1. Warum ist Admission der falsche Ort für komplexe Signaturprüfung?
2. Wo sollte Vertrauen technisch entstehen?
3. Wie würden Sie dieses Modell in einer Firma umsetzen?


---

# 🧪 Lab 8 – Runtime Security mit Falco (Detection & Visibility)

**Dauer:** ~30–40 Minuten 
**Zielgruppe:** Teilnehmer mit Grundkenntnissen in Kubernetes 
**Namespace:** `default`

---

## Ziel dieses Labs

In diesem Lab lernst Sie, warum **Runtime Security** ein unverzichtbarer Bestandteil moderner Kubernetes-Sicherheitskonzepte ist – selbst dann, wenn Admission Policies, Pod Security Standards und Image-Scans korrekt umgesetzt sind.

Sie installieren **Falco** als Runtime-Sensor im Cluster, erzeugst gezielt sicherheitsrelevantes Verhalten und beobachtest, wie Falco dieses Verhalten erkennt und sichtbar macht. 
Im Bonus-Teil werden die erkannten Events zusätzlich über **Falcosidekick** in einer Web-Oberfläche dargestellt.

---

## 🧠 Einordnung: Warum Runtime Security?

Bisherige Sicherheitsmechanismen in Kubernetes wirken **vor** oder **während** des Deployments:

- RBAC entscheidet, *wer* etwas darf
- Admission Controller prüfen, *was* deployed werden darf
- Image-Scanning bewertet, *woher* Images stammen

All diese Kontrollen greifen **nicht mehr**, sobald ein Pod läuft.

**Falco setzt genau hier an.**

Falco beobachtet Systemaufrufe (Syscalls) direkt am Kernel und erkennt:
- das Starten interaktiver Shells
- Paketinstallationen zur Laufzeit
- Netzwerk-Listener in Containern
- Schreibzugriffe in kritische Verzeichnisse

➡️ **Runtime Security beantwortet nicht „Darf das?“, sondern „Was passiert gerade?“**

---

## Lernziele

Nach diesem Lab können Sie:

- Admission Security und Runtime Security klar unterscheiden
- Falco im Kubernetes-Sicherheitsmodell einordnen
- typische Falco-Events interpretieren
- die Grenzen von Runtime Detection benennen
- Falco-Events zentral sichtbar machen

---

## 🧱 Architektur-Überblick

| Phase | Mechanismus |
|------|-------------|
| API Request | RBAC |
| Admission | Pod Security, Kyverno |
| Scheduling | kube-scheduler |
| **Runtime** | **Falco** |
| Alerting | Sidekick, UI, SIEM |

---

## ✅ Voraussetzungen

- Funktionsfähiger Kubernetes-Cluster
- `kubectl` ist konfiguriert
- **Helm ist installiert**

Falls Helm noch fehlt:

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
```

---

## 8.1 Falco per Helm installieren

Wir installieren Falco bewusst **per Helm**, um eine saubere und reproduzierbare Installation zu gewährleisten.

### Helm-Repository hinzufügen

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

### Falco installieren (inkl. Sidekick & UI, kurs-sicher)

```bash
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false
```

> **Hinweis:** 
> Redis wird hier bewusst **ohne Persistent Volume** betrieben, um Abhängigkeiten von StorageClasses zu vermeiden.

### Status prüfen

```bash
kubectl -n falco get pods -o wide
```

**Erwartung: ** 
Alle Pods befinden sich im Status `Running`.

---

## 8.2 Falco-Logs beobachten

Öffnen Sie ein **zweites Terminal** und beobachte die Falco-Logs kontinuierlich:

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco -f
```

Diese Ansicht bleibt während des gesamten Labs geöffnet.

---

## 8.3 Demo-Pod starten

Wir starten einen bewusst einfachen Pod, der zur Laufzeit manipuliert wird.

```bash
cat <<'EOF' > runtime-demo.yaml
apiVersion: v1
kind: Pod
metadata:
  name: runtime-demo
spec:
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "3600"]
EOF

kubectl apply -f runtime-demo.yaml
kubectl get pod runtime-demo
```

---

## 8.4 Interaktive Shell öffnen

```bash
kubectl exec -it runtime-demo -- sh
```

Ab jetzt erzeugt **jede Aktion** Runtime-Signale.

---

## 8.5 Verdächtiges Verhalten auslösen

Führen Sie im Container folgende Befehle aus:

```sh
apk add curl
sh
apk add busybox-extras
nc -l -p 4444
```

Wechseln Sie dabei regelmäßig in das Falco-Log-Terminal.

---

## 8.6 Falco-Events verstehen

Ein typisches Falco-Event sieht so aus:

```
Critical Executing binary not part of base image
k8s_pod_name=runtime-demo
container_image_repository=docker.io/library/alpine
```

**Bedeutung:**
- Severity: kritisch
- Aktion: neues Binary zur Laufzeit
- Kontext: betroffener Pod, Image, Namespace

Falco blockiert nichts – es **beobachtet und meldet**.

---

## Bonus – Falcosidekick UI nutzen

### Service erreichbar machen

```bash
kubectl -n falco patch svc falco-falcosidekick-ui -p '{"spec":{"type":"NodePort"}}'
kubectl -n falco get svc falco-falcosidekick-ui
```

NodePort ermitteln:

```bash
NODEPORT=$(kubectl -n falco get svc falco-falcosidekick-ui -o jsonpath='{.spec.ports[0].nodePort}')
echo $NODEPORT
```

### Im Browser öffnen

```
http://<NODE-IP>:<NODEPORT>
```

### Event prüfen

In der UI sollte nun ein Event zum Pod `runtime-demo` sichtbar sein.

---

## 🧠 Kernerkenntnisse

- Präventive Security endet beim Deploy
- Runtime Security macht tatsächliches Verhalten sichtbar
- Falco ist ein Sensor, kein Blocker
- Sichtbarkeit ist Voraussetzung für Reaktion

---


## ❓ Reflexionsfragen

1. Welche Falco-Events wären in deiner Umgebung besonders kritisch?
2. Wo würden Sie Falco-Events weiterleiten?
3. Warum ist Runtime Detection kein Ersatz für Admission Security?


# Bonus 2 – Falco Alerts per Webhook (Sidekick → HTTP Endpoint)

**Dauer:** ~15–25 Min 
**Voraussetzung:** Falco läuft (Lab 8), Falcosidekick ist installiert (Bonus Sidekick/UI). 
**Namespace:** `falco` (Falco + Sidekick), Demo-Workload in `default`

---

## Ziel

Sie leiten Falco-Events **automatisch** an einen Webhook weiter, statt sie nur im Log oder in der UI zu sehen.

Am Ende haben Sie:

- einen kleinen **Webhook-Receiver** im Cluster (zeigt empfangene Requests)
- Falcosidekick so konfiguriert, dass es **jedes Falco-Event per HTTP POST** sendet
- einen reproduzierbaren **Demo-Trigger**, der sicher ein Event erzeugt

---

## 🧠 Einordnung

Falco erzeugt Events → Sidekick empfängt Events → Sidekick „Outputs“ verschicken Events an Ziele.

Webhook ist der „kleinste gemeinsame Nenner“:
- Teams/Slack/SIEM sind am Ende auch nur Webhooks oder APIs
- Sie können später jederzeit den Receiver gegen **Slack**, **Teams**, **Elastic**, **Splunk**, **Webhook-Forwarder** tauschen

---

## 1) Webhook-Receiver deployen

Wir starten einen simplen HTTP-Echo-Server, der Requests annimmt und Log-Ausgaben macht.
Der Pod läuft im Namespace `default`, damit Sie nichts im `falco` Namespace verwechselst.

```bash
cat <<'EOF' > webhook-receiver.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-receiver
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook-receiver
  template:
    metadata:
      labels:
        app: webhook-receiver
    spec:
      containers:
      - name: http-echo
        image: ealen/echo-server:0.9.2
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: webhook-receiver
  namespace: default
spec:
  selector:
    app: webhook-receiver
  ports:
  - name: http
    port: 80
    targetPort: 80
EOF

kubectl apply -f webhook-receiver.yaml
kubectl rollout status deploy/webhook-receiver -n default
kubectl get pod -n default -l app=webhook-receiver -o wide
```

### Receiver-Logs öffnen (zweite Session empfohlen)

```bash
kubectl logs -n default -l app=webhook-receiver -f
```

**Erwartung: ** Sie sehen später eingehende Requests mit Headers + Body.

---

## 2) Falcosidekick für Webhook konfigurieren (per Helm)

Falcosidekick ist Teil der Falco-Helm-Installation. Wir ändern **nur Values**, kein YAML-Hacking.

### 2.1 Prüfen, wie die Helm-Release heißt

```bash
helm -n falco list
```

In den meisten Labs heißt das Release einfach `falco`. 
Falls es anders heißt, ersetze im nächsten Schritt den Namen entsprechend.

### 2.2 Upgrade mit Webhook-Output

Wir aktivieren den Output `webhook` und setzen die Ziel-URL auf unseren Receiver-Service:

- Service-DNS im Cluster: `http://webhook-receiver.default.svc.cluster.local/`

```bash
helm -n falco upgrade falco falcosecurity/falco \
  --reuse-values \
  --set falcosidekick.config.webhook.address="http://webhook-receiver.default.svc.cluster.local/" \
  --set falcosidekick.config.webhook.minimumpriority="debug"
```

> **Hinweis (didaktisch):** `minimumpriority=debug` sorgt dafür, dass Sie praktisch alles siehst. 
> In der Praxis würden Sie eher `warning` oder `error` wählen.

### 2.3 Sidekick neu starten (damit Config sofort aktiv ist)

```bash
kubectl -n falco rollout restart deploy -l app.kubernetes.io/name=falcosidekick
kubectl -n falco rollout status deploy -l app.kubernetes.io/name=falcosidekick
```

---

## 3) Funktionstest: Falco Event auslösen

Falls der Demo-Pod aus Lab 8 nicht mehr existiert, deploye ihn neu:

```bash
cat <<'EOF' > runtime-demo.yaml
apiVersion: v1
kind: Pod
metadata:
  name: runtime-demo
  namespace: default
spec:
  containers:
  - name: app
    image: alpine:3.20
    command: ["sh","-c","sleep 3600"]
EOF

kubectl apply -f runtime-demo.yaml
kubectl get pod -n default runtime-demo -o wide
```

Jetzt erzeugen wir im Pod eine Aktion, die sehr häufig ein Falco-Event triggert:

```bash
kubectl exec -n default -it runtime-demo -- sh -lc 'apk add --no-cache curl'
```

---

## 4) Verifizieren: kommt der Webhook an?

### 4.1 Receiver-Logs (default Namespace)

In der Receiver-Log-Session solltest Sie **eingehende POSTs** sehen, inklusive JSON Payload.

### 4.2 Sidekick-Logs (falco Namespace)

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falcosidekick --tail=200
```

**Erwartung: ** Ein Log-Eintrag, dass ein Webhook-Request gesendet wurde.

### 4.3 Falco-Logs (optional)

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco --tail=200
```

---

## 5) Payload kurz lesen (was kommt da eigentlich?)

Falcosidekick schickt typischerweise einen JSON-Body mit Feldern wie:
- `rule`, `priority`, `output`, `time`
- Kubernetes-Kontext (`k8s.ns.name`, `k8s.pod.name`, …) – abhängig von Falco Setup

Sie brauchst für den Kurs nicht jedes Feld, aber merke Ihnen:

> **In der Praxis ist das der Moment, wo Sie mappst:** 
> Rule → Severity → Routing (PagerDuty/Slack/SIEM) → Ticket/Incident

---

## 6) Aufräumen (optional)

```bash
kubectl delete -f webhook-receiver.yaml --ignore-not-found
kubectl delete pod -n default runtime-demo --ignore-not-found
```

---

## Abschlussfragen

1. Welche Falco-Regeln würden Sie per Webhook **sofort** eskalieren (High Signal)?
2. Wo würden Sie „Noise“ bewusst filtern (minimumpriority, rule allowlist)?
3. Was wäre Ihr nächster Schritt: Slack/Teams oder SIEM?

