# Lab: Container-Images mit Trivy untersuchen

## Ziel

In diesem Lab untersuchen Sie Container-Images mit **Trivy** auf
bekannte Sicherheitsprobleme. Zusätzlich erstellen Sie selbst ein
bewusst ungeeignetes Demo-Image und untersuchen dieses anschließend.

Nach dem Lab können Sie:

-   Container-Images auf bekannte Schwachstellen (CVEs) untersuchen.
-   Findings nach Schweregrad filtern.
-   zwischen ungefixten und bereits behebbaren Schwachstellen
    unterscheiden.
-   erklären, warum alte Base-Images ein Sicherheitsrisiko darstellen
    können.
-   nach möglichen Secrets in Images suchen.
-   Trivy über Exit-Codes in eine CI/CD-Pipeline integrieren.
-   erklären, warum Image-Scanning Teil der Container Supply Chain sein
    sollte.

> **Merksatz:** Ein funktionierendes Container-Image ist nicht
> automatisch ein sicheres Container-Image.

------------------------------------------------------------------------

## 1. Docker installieren

Für die Erstellung des Demo-Images benötigen Sie Docker.

Installieren Sie Docker auf dem Ubuntu-/Debian-Lab-System:

``` bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo systemctl enable --now docker
```

Prüfen Sie anschließend den Status:

``` bash
sudo systemctl status docker --no-pager
```

Prüfen Sie die Docker-Version:

``` bash
sudo docker version
```

Testen Sie die Installation:

``` bash
sudo docker run --rm hello-world
```

> In diesem Lab werden Docker-Befehle mit `sudo` ausgeführt. Dadurch ist
> keine Änderung der Gruppenmitgliedschaft erforderlich.

------------------------------------------------------------------------

## 2. Trivy installieren

Installieren Sie zunächst die benötigten Pakete:

``` bash
sudo apt-get install -y wget gnupg
```

Importieren Sie den Schlüssel des Trivy-Repositories:

``` bash
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
```

Fügen Sie das Repository hinzu:

``` bash
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
```

Installieren Sie Trivy:

``` bash
sudo apt-get update
sudo apt-get install -y trivy
```

Prüfen Sie die Installation:

``` bash
trivy --version
```

------------------------------------------------------------------------

## 3. Ein bewusst schwaches Demo-Image erstellen

Für eine reproduzierbare Demonstration erstellen Sie nun selbst ein
Container-Image mit einem älteren Base-Image.

### Arbeitsverzeichnis anlegen

``` bash
mkdir -p ~/trivy-lab
cd ~/trivy-lab
```

### Dockerfile per Copy & Paste erzeugen

Führen Sie den folgenden Block vollständig aus:

``` bash
cat > Dockerfile <<'EOF'
FROM debian:10

RUN apt-get update && \
    apt-get install -y \
      curl \
      wget \
      openssl \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
EOF
```

Kontrollieren Sie den Inhalt:

``` bash
cat Dockerfile
```

### Image bauen

``` bash
sudo docker build -t vulnerable-demo:1.0 .
```

Prüfen Sie, ob das Image vorhanden ist:

``` bash
sudo docker images vulnerable-demo
```

> **Hinweis:** Das Image ist ausschließlich für das Security-Lab
> vorgesehen und sollte nicht produktiv eingesetzt werden. Die konkrete
> Anzahl gefundener CVEs kann sich mit dem Stand der
> Vulnerability-Datenbank verändern.

------------------------------------------------------------------------

## 4. Erstes Container-Image scannen

Untersuchen Sie das gerade erzeugte Image:

``` bash
trivy image vulnerable-demo:1.0
```

Beim ersten Aufruf lädt Trivy die benötigte Vulnerability-Datenbank
herunter.

Achten Sie in der Ausgabe insbesondere auf:

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

Ermitteln Sie:

1.  Wie viele Schwachstellen findet Trivy insgesamt?
2.  Wie viele davon sind als **HIGH** eingestuft?
3.  Wie viele davon sind als **CRITICAL** eingestuft?
4.  Für welche Findings wird eine `Fixed Version` angegeben?

------------------------------------------------------------------------

## 5. Nur HIGH und CRITICAL anzeigen

Reduzieren Sie die Ausgabe auf besonders relevante Schweregrade:

``` bash
trivy image \
  --severity HIGH,CRITICAL \
  vulnerable-demo:1.0
```

### Diskussionsfrage

Würden allein die Anzahl und der Schweregrad der gefundenen CVEs
ausreichen, um über einen produktiven Einsatz des Images zu entscheiden?

Berücksichtigen Sie unter anderem:

-   tatsächliche Nutzung der betroffenen Komponente
-   Ausnutzbarkeit der Schwachstelle
-   verfügbare Updates
-   Exposition der Anwendung
-   mögliche kompensierende Sicherheitsmaßnahmen

------------------------------------------------------------------------

## 6. Ungefixte Schwachstellen ausblenden

Konzentrieren Sie sich nun auf Findings, für die bereits ein Fix
verfügbar ist:

``` bash
trivy image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  vulnerable-demo:1.0
```

### Aufgabe

Vergleichen Sie die Ausgabe mit dem vorherigen Scan.

Welche Findings sind verschwunden?

Warum kann die Option `--ignore-unfixed` für die Priorisierung hilfreich
sein?

------------------------------------------------------------------------

## 7. Vergleich mit einem aktuellen Image

Scannen Sie nun zusätzlich ein aktuelles nginx-Image:

``` bash
trivy image \
  --severity HIGH,CRITICAL \
  nginx:latest
```

Vergleichen Sie anschließend beide Ergebnisse:

``` text
vulnerable-demo:1.0
        │
        │ Trivy
        ▼
   ältere Basis

        versus

nginx:latest
        │
        │ Trivy
        ▼
   aktuelle Basis
```

### Aufgabe

Vergleichen Sie:

-   Anzahl der Findings
-   HIGH-Findings
-   CRITICAL-Findings
-   betroffene Pakete
-   verfügbare Fixes

> **Wichtig:** Ein aktuelleres oder kleineres Image ist nicht
> automatisch sicher. Die Ergebnisse hängen vom konkreten Inhalt des
> Images und vom aktuellen Stand der Vulnerability-Datenbank ab.

------------------------------------------------------------------------

## 8. Image-Layer untersuchen

Container-Images bestehen aus mehreren Layern.

Zeigen Sie die Historie des Demo-Images an:

``` bash
sudo docker history vulnerable-demo:1.0
```

Zusätzliche Metadaten erhalten Sie mit:

``` bash
sudo docker inspect vulnerable-demo:1.0
```

### Hintergrund

Ein Dockerfile erzeugt schrittweise ein Image:

``` text
Base Image
    │
    ▼
Layer
    │
    ▼
Layer
    │
    ▼
...
    │
    ▼
Container Image
```

Dateien, die in einem Layer gespeichert wurden, können unter Umständen
weiterhin Bestandteil des Images sein, obwohl sie in einem späteren
Layer gelöscht werden.

------------------------------------------------------------------------

## 9. Nach Secrets suchen

Trivy kann neben bekannten Schwachstellen auch nach möglichen Secrets
suchen:

``` bash
trivy image \
  --scanners vuln,secret \
  vulnerable-demo:1.0
```

### Warum ist dies wichtig?

Betrachten Sie folgendes problematisches Dockerfile:

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

> **Praxisregel:** Speichern Sie Secrets nicht in Container-Images und
> nicht in Dockerfile-Layern.

------------------------------------------------------------------------

## 10. Integration in eine CI/CD-Pipeline

Trivy kann über seinen Exit-Code signalisieren, ob Findings eines
bestimmten Schweregrades vorhanden sind.

Führen Sie aus:

``` bash
trivy image \
  --severity CRITICAL \
  --exit-code 1 \
  vulnerable-demo:1.0
```

Prüfen Sie unmittelbar danach den Exit-Code:

``` bash
echo $?
```

Mögliche Ergebnisse:

``` text
0 = kein entsprechendes Finding
1 = mindestens ein entsprechendes Finding gefunden
```

Damit kann beispielsweise eine CI/CD-Pipeline abhängig vom Scan-Ergebnis
gestoppt werden.

Ein vereinfachter Ablauf:

``` text
Quellcode
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

## 11. Abschlussfragen

Beantworten Sie zum Abschluss folgende Fragen:

1.  Warum reicht es nicht aus, einem Container-Image aufgrund seines
    Namens oder Tags zu vertrauen?
2.  Welche Rolle spielt das Base-Image für die Sicherheit eines
    Containers?
3.  Warum kann ein gelöschtes Secret trotzdem noch Bestandteil eines
    Images sein?
4.  Was bewirkt `--ignore-unfixed`?
5.  Warum eignet sich `--exit-code 1` für CI/CD-Pipelines?
6.  An welcher Stelle der Container Supply Chain sollte ein Image-Scan
    durchgeführt werden?
7.  Warum bedeutet ein kleineres Container-Image nicht automatisch, dass
    es sicher ist?

------------------------------------------------------------------------

## 12. Optional: Kubernetes-Bezug

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

Policies können beispielsweise festlegen:

-   aus welchen Registries Images bezogen werden dürfen,
-   welche Security-Einstellungen Workloads erfüllen müssen,
-   ob bestimmte Image-Eigenschaften vorgeschrieben sind.

------------------------------------------------------------------------

## Referenzen

-   Trivy: https://trivy.dev/
-   Docker: https://docs.docker.com/
