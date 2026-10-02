# Lab: Container-Images mit Trivy untersuchen

## Ziel

In diesem Lab untersuchen wir Container-Images mit **Trivy** auf
bekannte Sicherheitsprobleme.

Nach dem Lab können die Teilnehmer:

-   Container-Images auf bekannte Schwachstellen (CVEs) untersuchen.
-   Findings nach Schweregrad filtern.
-   zwischen ungefixten und bereits behebbaren Schwachstellen
    unterscheiden.
-   unterschiedliche Base-Images vergleichen.
-   nach möglichen Secrets in Images suchen.
-   Trivy über Exit-Codes in eine CI/CD-Pipeline integrieren.
-   erklären, warum Image-Scanning Teil der Container Supply Chain sein
    sollte.

> **Merksatz:** Ein funktionierendes Container-Image ist nicht
> automatisch ein sicheres Container-Image.

------------------------------------------------------------------------

## 1. Trivy installieren

Auf dem Ubuntu-/Debian-Lab-System:

``` bash
sudo apt-get install -y wget gnupg

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list

sudo apt-get update
sudo apt-get install -y trivy
```

Installation prüfen:

``` bash
trivy --version
```

------------------------------------------------------------------------

## 2. Erstes Container-Image scannen

Wir untersuchen zunächst ein aktuelles nginx-Image:

``` bash
trivy image nginx:latest
```

Beim ersten Aufruf lädt Trivy die benötigte Vulnerability-Datenbank
herunter.

Achte in der Ausgabe insbesondere auf:

-   `Library`
-   `Vulnerability`
-   `Severity`
-   `Installed Version`
-   `Fixed Version`

Typische Schweregrade sind:

``` text
CRITICAL
HIGH
MEDIUM
LOW
```

### Aufgabe

Wie viele Schwachstellen findet Trivy?

Welche davon sind als **HIGH** oder **CRITICAL** eingestuft?

------------------------------------------------------------------------

## 3. Nur HIGH und CRITICAL anzeigen

Filtere die Ausgabe:

``` bash
trivy image \
  --severity HIGH,CRITICAL \
  nginx:latest
```

### Diskussionsfrage

Würdest du das Image aufgrund dieser Ausgabe produktiv einsetzen?

Die Anzahl der CVEs allein reicht für diese Entscheidung nicht aus.
Unter anderem müssen die tatsächliche Nutzung des betroffenen Pakets,
die Ausnutzbarkeit und verfügbare Updates berücksichtigt werden.

------------------------------------------------------------------------

## 4. Ungefixte Schwachstellen ausblenden

Wir konzentrieren uns nun auf Findings, für die bereits ein Fix
verfügbar ist:

``` bash
trivy image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  nginx:latest
```

### Aufgabe

Vergleiche die Ausgabe mit dem vorherigen Scan.

Was hat sich verändert?

------------------------------------------------------------------------

## 5. Zwei Images vergleichen

Scanne zunächst:

``` bash
trivy image --severity HIGH,CRITICAL nginx:latest
```

Danach:

``` bash
trivy image --severity HIGH,CRITICAL nginx:alpine
```

### Aufgabe

Vergleiche:

-   Anzahl der Findings
-   installierte Pakete
-   HIGH-Findings
-   CRITICAL-Findings

### Hintergrund

Ein Container-Image besteht unter anderem aus Base-Image,
Betriebssystempaketen, Libraries und der eigentlichen Anwendung.

Ein kleineres Base-Image enthält häufig weniger Komponenten und kann
dadurch die Angriffsfläche reduzieren.

> **Achtung:** Ein kleines Image ist nicht automatisch ein sicheres
> Image.

------------------------------------------------------------------------

## 6. Nach Secrets suchen

Trivy kann neben bekannten Schwachstellen auch nach möglichen Secrets
suchen:

``` bash
trivy image --scanners vuln,secret nginx:latest
```

### Warum ist das wichtig?

Container-Images bestehen aus mehreren Layern.

Beispiel:

``` dockerfile
FROM ubuntu

COPY password.txt /tmp/password.txt
RUN rm /tmp/password.txt
```

Obwohl `password.txt` im resultierenden Container-Dateisystem nicht mehr
sichtbar ist, kann die Datei weiterhin Bestandteil eines älteren
Image-Layers sein.

Vereinfacht:

``` text
IMAGE
├── Layer 1
│   └── tmp/password.txt
│
└── Layer 2
    └── Löschinformation
```

Das spätere Löschen einer Datei entfernt deren Inhalt nicht automatisch
aus bereits erzeugten Layern.

------------------------------------------------------------------------

## 7. Integration in eine CI/CD-Pipeline

Trivy kann über seinen Exit-Code signalisieren, ob bestimmte Findings
vorhanden sind.

``` bash
trivy image \
  --severity CRITICAL \
  --exit-code 1 \
  nginx:latest
```

Danach:

``` bash
echo $?
```

Mögliche Ergebnisse:

``` text
0 = kein entsprechendes Finding
1 = mindestens ein entsprechendes Finding gefunden
```

Damit kann beispielsweise eine CI/CD-Pipeline gestoppt werden.

Vereinfachter Ablauf:

``` text
Git
 │
 ▼
CI/CD Pipeline
 │
 ├── Container-Image bauen
 │
 ├── Trivy Scan
 │
 ├── SBOM / weitere Prüfungen
 │
 └── Image in Registry übertragen
 │
 ▼
Kubernetes
```

Das Image sollte möglichst **vor dem Deployment** untersucht werden.

------------------------------------------------------------------------

## 8. Abschlussfragen

Beantworte zum Abschluss folgende Fragen:

1.  Warum reicht es nicht aus, einem Container-Image aufgrund seines
    Namens oder Tags zu vertrauen?
2.  Warum kann ein gelöschtes Secret trotzdem noch Bestandteil eines
    Images sein?
3.  Was ist der Unterschied zwischen `HIGH`/`CRITICAL` und
    `--ignore-unfixed`?
4.  Warum eignet sich `--exit-code 1` für CI/CD-Pipelines?
5.  An welcher Stelle der Container Supply Chain sollte ein Image-Scan
    durchgeführt werden?

------------------------------------------------------------------------

## Optional: Weiterführender Kubernetes-Bezug

Image-Scanning ist nur ein Bestandteil der Container-Sicherheit.

Ein typischer nächster Schritt ist die Kombination mit Kubernetes
Admission Policies, beispielsweise mit **Kyverno**:

``` text
Build
  │
  ▼
Trivy Scan
  │
  ▼
Registry
  │
  ▼
Kubernetes API
  │
  ▼
Admission / Kyverno
  │
  ▼
Pod
```

Mögliche Policies können beispielsweise festlegen, aus welchen
Registries Images bezogen werden dürfen oder welche Anforderungen Images
und Workloads erfüllen müssen.

------------------------------------------------------------------------

## Referenz

Trivy-Dokumentation: https://trivy.dev/
