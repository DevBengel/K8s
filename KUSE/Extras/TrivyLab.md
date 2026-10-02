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

# Ausschließlich für dieses Security-Lab:
RUN mkdir -p /opt/demo && \
    printf '%s\n' \
      '-----BEGIN OPENSSH PRIVATE KEY-----' \
      'LAB-DEMO-ONLY-NOT-A-REAL-PRIVATE-KEY' \
      'LAB-DEMO-ONLY-NOT-A-REAL-PRIVATE-KEY' \
      'LAB-DEMO-ONLY-NOT-A-REAL-PRIVATE-KEY' \
      '-----END OPENSSH PRIVATE KEY-----' \
      > /opt/demo/demo_private_key

# Löschen in einem späteren Layer
RUN rm /opt/demo/demo_private_key

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

## 9. Gelöschtes Fake-Secret in einem Image-Layer untersuchen

Das Demo-Image enthält bewusst ein **künstliches und nicht verwendbares
Demo-Secret**. Es wird in einem Image-Layer gespeichert und erst in
einem späteren Layer gelöscht.

Prüfen Sie zunächst das finale Container-Dateisystem:

``` bash
sudo docker run --rm vulnerable-demo:1.0 \
  sh -c 'ls -la /opt/demo; test ! -e /opt/demo/demo_private_key && echo "Secret-Datei ist im finalen Dateisystem gelöscht."'
```

Die Datei sollte nicht mehr vorhanden sein.

Zeigen Sie anschließend die Image-Historie an:

``` bash
sudo docker history --no-trunc vulnerable-demo:1.0
```

``` text
Layer n      Fake-Secret erzeugen
   │
   ▼
Layer n+1    Fake-Secret löschen
```

### Trivy Secret Scan

``` bash
trivy image \
  --scanners secret \
  vulnerable-demo:1.0
```

> **Hinweis:** Secret-Scanner verwenden Erkennungsregeln und
> Heuristiken. Ein künstliches Muster wird daher nicht zwingend von
> jeder Trivy-Version identisch erkannt. Der folgende direkte
> Layer-Nachweis funktioniert unabhängig davon.

### Gelöschten Inhalt direkt im Image nachweisen

Exportieren Sie das Image:

``` bash
sudo docker save vulnerable-demo:1.0 -o vulnerable-demo.tar
```

Entpacken Sie das Image:

``` bash
rm -rf image-export
mkdir image-export
tar -xf vulnerable-demo.tar -C image-export
```

Suchen Sie in allen exportierten Layern nach dem eindeutigen Demo-Text:

``` bash
grep -R -a \
  'LAB-DEMO-ONLY-NOT-A-REAL-PRIVATE-KEY' \
  image-export
```

Obwohl die Datei im laufenden Container nicht mehr vorhanden ist, sollte
der Text in einem älteren Image-Layer auffindbar sein.

### Was ist passiert?

``` text
IMAGE
│
├── Layer n
│     └── /opt/demo/demo_private_key
│             LAB-DEMO-ONLY-...
│
└── Layer n+1
      └── Datei gelöscht
```

Das zusammengeführte Container-Dateisystem berücksichtigt die
Löschinformation. Der Inhalt des bereits erzeugten älteren Layers wird
dadurch jedoch nicht rückwirkend entfernt.

### Sicherheitsrelevanz

Folgendes Vorgehen ist deshalb **nicht sicher**:

``` dockerfile
COPY secret.txt /tmp/secret.txt
RUN do-something-with-secret
RUN rm /tmp/secret.txt
```

Das spätere Löschen entfernt das Secret nicht aus vorherigen
Image-Layern.

> **Merksatz:** „Aus dem Container gelöscht" bedeutet nicht automatisch
> „aus dem Image entfernt".

### Aufgabe

Beantworten Sie:

1.  Ist `/opt/demo/demo_private_key` im gestarteten Container vorhanden?
2.  Kann der Demo-Inhalt trotzdem im exportierten Image gefunden werden?
3.  Warum reicht ein späteres `RUN rm ...` nicht aus?
4.  Welche Konsequenz ergibt sich daraus für Passwörter, API-Keys,
    Zertifikate und private Schlüssel beim Image-Build?

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
