# Helm Playground -- kurze n-tier-Demo

Diese Demo zeigt, wie sich eine kleine **3-Tier-Anwendung effizient mit
einem Helm-Chart verwalten** lässt.

**Direkt im Helm Playground öffnen:**\
<https://helm-playground.com/#t=N7C0AICcEMDsHMCm4AktoFtEBpUBcBLRScALgF5wA6ANWgBsBXRAZysOJfAF9uAoUIL7QADgRqcCAe1ilwokSwD0ANwCMfANYFYAEzkARRCPpSAnllh4%2BWPNF3Q7pPuHDosckKioAlRPURoFkQqADlMZF5QLzQInn4WEUQAY2dXSGN6AmSgz2B8IkgqDJNsoPiXcGCA5LwpSDTXcAxHZIALABloACN-Fkam%2BRERPO8-AKCQ8Kx46PzYmd5KvEQME0dEAebEOwcnSsH6Hr6twYVRlF9-QOCwuKiY90j%2BQcSU0-BkmTsdTg-XCBPC5PCqDMHgAgtJAXDhFSHQJCg8FNET1PD9A7IgGfb7QX6QAAKaJhhSoqMgeAqIAgBAAZgViFRELAVEiscyVM5qVA4IiUJpEGZcCgVAxmGRKChYUyWWyseBARELgKzHL5eBRUxNuAYprxQAfKCZaDJZAAIh8AFEOpaAIIAZUtZrG10mdxmhoAjowpCsqWBwMzdP6IEGKoJQMIxBJICxpLINRptHo5PbiCpsogbDt7I5oI0gTr5lcJrdps85qgQUs3qlKtUUnUGpjzkWXaWpvduJWFs9KuT0VsIAOSYzgpAM6aiRS1eA7JAkHhp3hR0UByHA3oKkA&v=C4SwpgTgzgXAUAAgQMwgewHbDBgJvJJEAWwEMBzMGBDckDADxgEYA6AJgA5FCIwAHADYgAxqVgJ2PJPzQRg1TgAZpCKJABuosAAU5ChMtU4NBQkgBCAQQDCAaQCiAOQAiAfQCqAJQAy1ABbAwPwwAPShXg4%2BDlYAyg4AtABGpCIA1jj4ykY8KemZZkRklNS09ExsXKp8QqLi1FLmsvKKSkbm6hBaIrr6re2EJoWELhZuABIA8rEAKtSR0XGJuKTApCnqqkijbjqTXnMIAEQArAAsAMzsR3A8K2sbVKokFFQIslDA5HywzADs1QEwjEEmYqmaBnOV1UnW6vRaCChUiAA>

## Architektur

Die Anwendung besteht aus drei Tiers:

``` text
frontend
   │
   │ BACKEND_URL
   ▼
backend
   │
   │ DB_HOST / DB_PORT
   ▼
database
```

Für jedes Tier erzeugt Helm automatisch ein **Deployment** und einen
**Service**.

Bei drei Tiers entstehen somit sechs Kubernetes-Ressourcen:

``` text
<release>-frontend   Deployment
<release>-frontend   Service

<release>-backend    Deployment
<release>-backend    Service

<release>-database   Deployment
<release>-database   Service
```


## Gegenbeispiel: dieselbe Anwendung ohne Helm

Bevor Helm die Wiederholungen abstrahiert, lohnt sich ein Blick auf dieselbe Anwendung mit **reinen Kubernetes-Manifesten**.

Eine mögliche Verzeichnisstruktur wäre:

```text
k8s/
├── frontend-deployment.yaml
├── frontend-service.yaml
├── backend-deployment.yaml
├── backend-service.yaml
├── database-deployment.yaml
└── database-service.yaml
```

### Frontend ohne Helm

`frontend-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp-frontend
  template:
    metadata:
      labels:
        app: myapp-frontend
    spec:
      containers:
        - name: frontend
          image: nginx:1.28
          ports:
            - containerPort: 80
          env:
            - name: BACKEND_URL
              value: "http://myapp-backend:8080"
```

`frontend-service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myapp-frontend
spec:
  selector:
    app: myapp-frontend
  ports:
    - port: 80
      targetPort: 80
```

### Backend ohne Helm

`backend-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp-backend
  template:
    metadata:
      labels:
        app: myapp-backend
    spec:
      containers:
        - name: backend
          image: nginx:1.28
          ports:
            - containerPort: 8080
          env:
            - name: DB_HOST
              value: "myapp-database"
            - name: DB_PORT
              value: "5432"
```

`backend-service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myapp-backend
spec:
  selector:
    app: myapp-backend
  ports:
    - port: 8080
      targetPort: 8080
```

### Datenbank ohne Helm

`database-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-database
spec:
  replicas: 1
  selector:
    matchLabels:
      app: myapp-database
  template:
    metadata:
      labels:
        app: myapp-database
    spec:
      containers:
        - name: database
          image: postgres:17
          ports:
            - containerPort: 5432
```

`database-service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myapp-database
spec:
  selector:
    app: myapp-database
  ports:
    - port: 5432
      targetPort: 5432
```

### Wo entsteht die Wiederholung?

Alle drei Deployments besitzen praktisch dieselbe Grundstruktur:

```text
Deployment
├── metadata.name
├── replicas
├── selector.matchLabels
├── template.metadata.labels
└── containers
    ├── name
    ├── image
    └── ports
```

Auch die Services unterscheiden sich fast nur in Namen und Ports.

Die Unterschiede sind eigentlich nur **Daten**:

```text
             frontend       backend        database
------------------------------------------------------
replicas     2              2              1
image        nginx:1.28     nginx:1.28     postgres:17
port         80             8080           5432
```

Genau hier setzt die Helm-Demo an: Die gemeinsame Struktur wandert ins Template, die Unterschiede nach `values.yaml`.

### Noch deutlicher bei mehreren Umgebungen

Wenn `dev`, `test` und `prod` unterschiedliche Replica-Zahlen, Images oder Konfigurationen benötigen, könnte man ohne weitere Werkzeuge schnell bei einer Struktur wie dieser landen:

```text
k8s/
├── dev/
│   ├── frontend-deployment.yaml
│   ├── frontend-service.yaml
│   ├── backend-deployment.yaml
│   ├── backend-service.yaml
│   ├── database-deployment.yaml
│   └── database-service.yaml
├── test/
│   └── ...
└── prod/
    └── ...
```

Aus sechs Manifesten werden damit potenziell 18 Dateien mit vielen identischen Abschnitten.

Mit Helm kann die gemeinsame Struktur dagegen einmal beschrieben und die Umgebung beispielsweise über unterschiedliche Values-Dateien konfiguriert werden:

```text
ntier-app/
├── Chart.yaml
├── values.yaml
├── values-dev.yaml
├── values-test.yaml
├── values-prod.yaml
└── templates/
    ├── deployment.yaml
    └── service.yaml
```

### Direktvergleich

| Ohne Helm | Mit Helm |
|---|---|
| Kubernetes-YAML wird konkret ausgeschrieben | Kubernetes-YAML wird aus Templates erzeugt |
| ähnliche Ressourcen werden wiederholt | gemeinsame Struktur wird einmal beschrieben |
| Werte und Struktur sind vermischt | Werte liegen überwiegend in `values.yaml` |
| Änderungen können mehrere Dateien betreffen | gemeinsame Änderungen erfolgen am Template |
| Umgebungsvarianten erzeugen leicht Duplikate | Varianten können über Values beschrieben werden |
| sehr transparent und Kubernetes-nah | zusätzliche Template-Abstraktion muss verstanden werden |

### Aber: Helm ist nicht automatisch besser

Für zwei oder drei kleine, statische Ressourcen ohne Varianten können normale Kubernetes-Manifeste sogar die bessere Lösung sein.

```text
wenige Ressourcen
+ keine Umgebungsvarianten
+ keine Wiederholung
+ keine optionalen Komponenten
= Helm bringt möglicherweise mehr Komplexität als Nutzen
```

Helm wird besonders interessant, wenn mindestens eines dieser Probleme auftritt:

- viele ähnliche Ressourcen
- mehrere Umgebungen
- mehrere Installationen derselben Anwendung
- optionale Komponenten
- konfigurierbare Images, Ports oder Replica-Zahlen
- wiederkehrende Labels und Namenskonventionen
- eine Anwendung soll als installierbares Paket verteilt werden

Die entscheidende Frage lautet daher nicht:

> **Wie kann ich möglichst viel YAML durch Helm ersetzen?**

Sondern:

> **Welche Wiederholung und Variabilität lohnt es sich zu abstrahieren?**

---

## Ziel der Demo

Statt für Frontend, Backend und Datenbank jeweils nahezu identische
Kubernetes-Manifeste zu schreiben, werden die Komponenten als Daten in
`values.yaml` beschrieben.

Ein generisches Helm-Template verarbeitet anschließend alle Tiers.

Damit demonstriert die Übung gleichzeitig:

-   strukturierte Values
-   `range` über eine Map
-   Template-Variablen
-   den Root-Kontext `$`
-   verschachtelte `range`-Blöcke
-   dynamische Deployments und Services
-   interne Kubernetes-Service-Namen
-   Environment-Variablen
-   Wiederverwendung eines Templates für mehrere Komponenten

## values.yaml

``` yaml
tiers:
  frontend:
    image: nginx:1.28
    replicas: 2
    port: 80
    servicePort: 80
    env:
      BACKEND_URL: http://RELEASE-backend:8080

  backend:
    image: nginx:1.28
    replicas: 2
    port: 8080
    servicePort: 8080
    env:
      DB_HOST: RELEASE-database
      DB_PORT: "5432"

  database:
    image: postgres:17
    replicas: 1
    port: 5432
    servicePort: 5432
```

Die Architektur wird damit weitgehend **deklarativ als Datenstruktur**
beschrieben.

## Iteration über die Tiers

Das Template beginnt mit:

``` gotemplate
{{- range $name, $tier := .Values.tiers }}
```

Helm durchläuft damit die drei Einträge `frontend`, `backend` und
`database`.

Dabei gilt beispielsweise für das Frontend:

``` text
$name = frontend

$tier =
  image: nginx:1.28
  replicas: 2
  port: 80
  servicePort: 80
  ...
```

Die expliziten Variablen `$name` und `$tier` machen das Template
übersichtlicher als ein ausschließlicher Zugriff über `.`.

## Dynamisches Deployment

Der Name des Deployments wird aus Release und Tier gebildet:

``` gotemplate
name: {{ $.Release.Name }}-{{ $name }}
```

Bei einem Release-Namen `myapp` entstehen beispielsweise:

``` text
myapp-frontend
myapp-backend
myapp-database
```

Der Zugriff auf den Release erfolgt über:

``` gotemplate
$.Release.Name
```

`$` verweist auf den ursprünglichen Root-Kontext, obwohl wir uns
innerhalb eines `range` befinden.

### Merksatz

> **`.` beantwortet: Wo bin ich gerade? -- `$` beantwortet: Wo hat das
> Template angefangen?**

## Dynamischer Service

Für jedes Tier wird außerdem ein Service erzeugt.

Deployment und Service verwenden dasselbe Label:

``` gotemplate
app: {{ $.Release.Name }}-{{ $name }}
```

Dadurch kann der Service die Pods des zugehörigen Deployments auswählen.

Die Services erhalten ebenfalls vorhersagbare Namen:

``` text
myapp-frontend
myapp-backend
myapp-database
```

Diese Namen können innerhalb des Kubernetes-Clusters über DNS verwendet
werden.

## Beziehungen zwischen den Tiers

Das Frontend erhält die Adresse des Backends:

``` yaml
BACKEND_URL: http://RELEASE-backend:8080
```

Das Backend erhält die Adresse der Datenbank:

``` yaml
DB_HOST: RELEASE-database
DB_PORT: "5432"
```

Im Template wird der Platzhalter `RELEASE` ersetzt:

``` gotemplate
{{ $value | replace "RELEASE" $.Release.Name | quote }}
```

Bei einem Release `myapp` wird daraus beispielsweise:

``` yaml
BACKEND_URL: "http://myapp-backend:8080"
```

und:

``` yaml
DB_HOST: "myapp-database"
```

Damit werden die Beziehungen zwischen den Komponenten ebenfalls aus der
Helm-Konfiguration erzeugt.

## Verschachteltes `range`

Die Environment-Variablen eines Tiers werden mit einer zweiten Schleife
erzeugt:

``` gotemplate
{{- range $key, $value := $tier.env }}
  - name: {{ $key }}
    value: {{ $value | replace "RELEASE" $.Release.Name | quote }}
{{- end }}
```

Damit existieren während des Renderings mehrere Kontexte bzw. Variablen
gleichzeitig:

``` text
$                   Root-Kontext des Charts
$name               Name des aktuellen Tiers
$tier               Konfiguration des aktuellen Tiers
$key                Name der aktuellen Environment-Variable
$value              Wert der aktuellen Environment-Variable
```

Das macht die Demo auch zu einer guten Wiederholung des
Helm-Kontextmodells.

## Live-Übungen

### 1. Frontend skalieren

Nur in `values.yaml` ändern:

``` yaml
frontend:
  replicas: 5
```

Das Template muss nicht verändert werden.

### 2. Environment-Variable ergänzen

Beim Backend hinzufügen:

``` yaml
env:
  DB_HOST: RELEASE-database
  DB_PORT: "5432"
  LOG_LEVEL: debug
```

Die zusätzliche Environment-Variable wird automatisch gerendert.

### 3. Neues Tier hinzufügen

Beispielsweise:

``` yaml
cache:
  image: redis:8
  replicas: 1
  port: 6379
  servicePort: 6379
```

Ohne Änderung am Template entstehen automatisch:

``` text
Deployment <release>-cache
Service    <release>-cache
```

Das demonstriert besonders deutlich den datengetriebenen Ansatz.

## Kernaussage der Demo

Die Architektur steckt weitgehend in:

``` text
values.yaml
```

und die Generierungslogik in:

``` text
templates/
```

Das Template beschreibt nicht mehr konkret *Frontend*, *Backend* oder
*Database*, sondern:

> **Wie sieht ein Tier grundsätzlich aus?**

Die Values beschreiben dagegen:

> **Welche Tiers soll diese konkrete Anwendung besitzen?**

## Wo liegen die Grenzen?

Der generische `range`-Ansatz funktioniert gut, solange die Komponenten
strukturell ähnlich sind.

In realen Anwendungen unterscheiden sich Frontend, Backend und
insbesondere Datenbanken jedoch häufig deutlich:

-   unterschiedliche Probes
-   unterschiedliche Volumes
-   Secrets
-   StatefulSets statt Deployments
-   unterschiedliche Security Contexts
-   Ingress nur für bestimmte Komponenten
-   unterschiedliche Update-Strategien
-   unterschiedliche Release-Zyklen

Dann wird ein einziges generisches Template schnell voller Sonderfälle.

## Sinnvoller nächster Schritt: Umbrella Chart

Die nächste Evolutionsstufe könnte deshalb sein:

``` text
ntier-app/
├── Chart.yaml
├── values.yaml
└── charts/
    ├── frontend/
    ├── backend/
    └── database/
```

Frontend, Backend und Datenbank werden dann eigene Subcharts.

Das bietet einen guten didaktischen Übergang:

``` text
Ein generisches Template
        ↓
range + strukturierte Values
        ↓
Komponenten werden unterschiedlicher
        ↓
Subcharts
        ↓
Umbrella Chart
```

Die Demo zeigt damit nicht nur **wie** man mit Helm Duplikation
reduziert, sondern auch **wann man mit der Abstraktion aufhören
sollte**.
