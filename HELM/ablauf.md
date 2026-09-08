# Helm-Kurs – Trainer-Checkliste und Fortschritt

> **Zweck:** Arbeitsdokument zur Vorbereitung und Durchführung des 3-Tage-Helm-Kurses.  
> Checkboxen können direkt in GitHub abgehakt werden.

## Legende

- 🎓 **THEORIE** – Folien, Erklärung, Whiteboard oder Trainer-Demo
- 🧪 **PLAYGROUND** – kurze, gemeinsam geführte Template-Übung; typischerweise 5–15 Minuten
- 🛠️ **LAB** – größere, weitgehend selbstständige Teilnehmerübung; typischerweise 30–90 Minuten
- 🔎 **CHECKPOINT** – Verständnis prüfen / Ergebnis gemeinsam kontrollieren
- ⭐ **OPTIONAL** – nur bei ausreichender Zeit

**Playground-Quelle:** [HELM/links.md](https://github.com/DevBengel/K8s/blob/main/HELM/links.md)

> Zuordnung: P.1–P.6 = bisherige Demos 1–6, P.8 = bisherige Demo 7, P.9 = bisherige Demo 8. **P.7 (`with`) ist neu und hat noch keine URL.**

---

# Gesamtfortschritt

## Tag 1 – Helm verstehen und bedienen

- [ ] 🎓 Einführung und Kubernetes-Wiederholung
- [ ] 🎓 Helm-Grundlagen: Chart, Repository, Release
- [ ] 🎓 Helm Lifecycle
- [ ] 🛠️ **LAB L.1 – Erster Helm-Release**
- [ ] 🎓 Chart-Struktur
- [ ] 🛠️ **LAB L.2 – Eigenes minimales Chart**
- [ ] 🧪 **PLAYGROUND P.1 – `.Values` und `.Release`**
- [ ] 🧪 **PLAYGROUND P.2 – Pipelines**
- [ ] 🔎 Tages-Checkpoint

## Tag 2 – Template Engine

- [ ] 🎓 Templates und Built-in Objects
- [ ] 🛠️ **LAB L.3 – Deployment und Service**
- [ ] 🎓 Funktionen und Pipelines
- [ ] 🧪 **PLAYGROUND P.3 – `default`**
- [ ] 🎓 Control Structure `if`
- [ ] 🧪 **PLAYGROUND P.4 – `if`**
- [ ] 🛠️ **LAB L.4 – Bedingungen / Feature Toggle**
- [ ] 🎓 Control Structure `range`
- [ ] 🧪 **PLAYGROUND P.5 – `range`**
- [ ] 🧪 **PLAYGROUND P.6 – Kontext: `.` und `$`**
- [ ] 🎓 Control Structure `with`
- [ ] 🧪 **PLAYGROUND P.7 – `with` und Kontextwechsel**
- [ ] 🛠️ **LAB L.5 – Iteration, Funktionen und Kontext**
- [ ] 🎓 Wiederverwendung: `define`, `template`, `include`
- [ ] 🧪 **PLAYGROUND P.8 – mehrere Ressourcen mit `range`**
- [ ] 🧪 **PLAYGROUND P.9 – `toYaml` und `nindent`**
- [ ] 🛠️ **LAB L.6 – Wiederverwendbare Templates**
- [ ] 🎓 Values – Einstieg und Scopes
- [ ] 🔎 Tages-Checkpoint

## Tag 3 – Verwaltung, Integration und Automation

- [ ] 🎓 Subcharts und Dependencies
- [ ] 🛠️ **LAB L.7a – Subcharts und Dependencies**
- [ ] 🎓 Library Charts
- [ ] 🛠️ **LAB L.7b – Library Charts**
- [ ] 🎓 Values: global, Scopes und Prioritäten
- [ ] 🛠️ **LAB L.10 – 3-Tier-Anwendung**
- [ ] 🎓 Debugging und Testing
- [ ] 🛠️ **LAB L.9 – Troubleshooting Challenge**
- [ ] 🎓 Continuous Deployment / GitOps / GitLab
- [ ] 🛠️ **LAB L.8 – GitLab CI/CD**
- [ ] 🔎 Kursabschluss / offene Fragen

---

# Tag 1 – Helm verstehen und bedienen

**10:00–16:30 Uhr**

## 10:00–11:00 | 🎓 THEORIE – Einführung und Kubernetes-Wiederholung

### Kursinhalte

- [ ] 1 Einführung in HELM
- [ ] 1.1 Helm
- [ ] 1.2 Voraussetzungen und Installation
- [ ] 1.3 Kubernetes Wiederholung
- [ ] 1.3.1 Namespace
- [ ] 1.3.2 Pod
- [ ] 1.3.3 Deployment
- [ ] 1.3.4 Services
- [ ] 1.3.5 ConfigMaps

### Checkpoint

- [ ] Teilnehmer können Pod, Deployment, Service und ConfigMap voneinander abgrenzen.
- [ ] Zusammenhang Deployment → Pod ist klar.
- [ ] Zusammenhang Service → Pods/Labels ist klar.

**11:00–11:10 – Pause**

---

## 11:10–12:10 | 🎓 THEORIE – Helm-Grundlagen

- [ ] 2.1 Grundlagen der Paketverwaltung
- [ ] Chart erklären
- [ ] Repository erklären
- [ ] Release erklären
- [ ] Unterschied Chart ↔ Release herausarbeiten
- [ ] Speicherung der Releases im Cluster erklären
- [ ] Release Revisionen erklären

### Mentales Modell

- [ ] Dieses Modell gemeinsam entwickeln:

```text
Chart
  +-- Templates
  +-- Values
        |
        v
   Helm Rendering
        |
        v
Kubernetes-Manifeste
        |
        v
Kubernetes-Ressourcen
        |
        v
Helm verwaltet den Zustand als Release
```

**12:10–12:20 – Pause**

---

## 12:20–12:30 | 🎓 THEORIE/DEMO – Helm Lifecycle

- [ ] `helm create`
- [ ] `helm install`
- [ ] `helm list`
- [ ] `helm upgrade`
- [ ] `helm history`
- [ ] `helm rollback`
- [ ] `helm uninstall`

**12:30–13:30 – Mittagspause**

---

## 13:30–14:30 | 🛠️ LAB L.1 – Erster Helm-Release

**Arbeitsform:** Teilnehmer arbeiten selbstständig.

- [ ] Chart erzeugen
- [ ] Chart-Struktur untersuchen
- [ ] Release installieren
- [ ] erzeugte Kubernetes-Ressourcen prüfen
- [ ] Values verändern
- [ ] Release aktualisieren
- [ ] History untersuchen
- [ ] Rollback durchführen
- [ ] Release entfernen

### 🔎 Checkpoint L.1

- [ ] Unterschied Chart / Release verstanden
- [ ] Revisionen verstanden
- [ ] Upgrade verändert einen bestehenden Release
- [ ] Rollback erzeugt eine weitere Revision

**14:30–14:40 – Pause**

---

## 14:40–15:40 | 🎓 + 🛠️ LAB L.2 – Chart-Struktur

### 🎓 Theorie

- [ ] 2.3 Struktur eines Helm Charts
- [ ] `Chart.yaml`
- [ ] `values.yaml`
- [ ] `templates/`
- [ ] Minimalanforderungen eines Charts

### 🛠️ LAB L.2 – Eigenes minimales Chart

- [ ] Verzeichnisstruktur selbst erzeugen
- [ ] `Chart.yaml` erstellen
- [ ] `values.yaml` erstellen
- [ ] ConfigMap-Template erstellen
- [ ] Release installieren
- [ ] Values verändern
- [ ] Release upgraden

### Trainer-Zwischendemo

- [ ] `helm template dev-app webapp` zeigen
- [ ] Renderergebnis mit Template vergleichen

### 🔎 Checkpoint L.2

- [ ] Teilnehmer können Template und gerendertes Manifest unterscheiden.
- [ ] Teilnehmer verstehen den Datenfluss `.Values` → Template → Manifest.

**15:40–15:50 – Pause**

---

## 15:50–16:30 | 🧪 PLAYGROUND – Einstieg Template Engine

> Playground = gemeinsam, schnell, Fokus auf **eine** Idee. Kein großes Kubernetes-Lab.

### 🧪 P.1 – `.Values` und `.Release`

**Direkt öffnen:** [Helm Playground – P.1](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6ACOrois6lqmMFAgMmC6Cg4Szm4e4rHxicAUrnZBoeGRmhpAA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4AoKYDAGwnwEMBhGXEVNARiA)

- [ ] `.Values` demonstrieren
- [ ] `.Release.Name` demonstrieren
- [ ] vor dem Rendern Ergebnis schätzen lassen
- [ ] anschließend Renderergebnis zeigen

### 🧪 P.2 – Pipelines

**Direkt öffnen:** [Helm Playground – P.2](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XukQxaRYDJFjxEawFcoccaBCqW6AD7oAjo6IrOpapo4gILC2Eg4yzq7unuq%2B4ZEwPv6BwZoapjKIAO5R6KIxTi5uEUkZ%2BUXpvgFBIbl8MFCRXNH25QlVahltHazoAMwZjdlaQA&v=IYBxDlgWwUwLgAQGUCuIYCcDqMBGBBMIA)

- [ ] einfache Funktion zeigen
- [ ] gleiche Funktion als Pipeline schreiben
- [ ] Datenfluss von links nach rechts erklären

### 🔎 Tages-Checkpoint

- [ ] Chart
- [ ] Values
- [ ] Template
- [ ] Manifest
- [ ] Release
- [ ] Revision

---

# Tag 2 – Helm Template Engine

**09:00–16:30 Uhr**

## 09:00–10:00 | 🎓 + 🛠️ Templates und Built-in Objects

### 🎓 Theorie

- [ ] Tag 1 kurz wiederholen
- [ ] 3.1 Template Engine
- [ ] 3.2 Built-in Objects
- [ ] `.Values`
- [ ] `.Release`

### 🛠️ LAB L.3 – Deployment und Service

- [ ] Deployment parametrisieren
- [ ] Service parametrisieren
- [ ] `.Values.replicaCount`
- [ ] Image/Tag aus Values
- [ ] Service-Port / NodePort
- [ ] installieren
- [ ] upgraden
- [ ] History / Rollback anwenden

**10:00–10:10 – Pause**

---

## 10:10–11:10 | 🎓 + 🧪 Funktionen und Pipelines

### 🎓 Theorie

- [ ] 3.3 Funktionen und Pipelines
- [ ] Pipeline-Syntax
- [ ] `quote`
- [ ] `default`
- [ ] typische Funktionen einordnen

### 🧪 P.3 – `default`

**Direkt öffnen:** [Helm Playground – P.3](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6MRQlMCuMgEARKGYsogg-tFB6ACOrois6lqmMog0ADJQ8TIOEs5uHuL5RSWyqaHhkTFElIgpwRlZORpAA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4g)

- [ ] Value vorhanden → vorhandenen Wert verwenden
- [ ] Value fehlt → Default verwenden
- [ ] Ergebnis vor dem Rendern schätzen lassen

### 🛠️ L.3 abschließen

- [ ] offene Aufgaben abschließen
- [ ] Ergebnis gemeinsam kontrollieren

**11:10–11:20 – Pause**

---

## 11:20–12:20 | 🎓 + 🧪 + 🛠️ `if` und `range`

### 🎓 `if`

- [ ] Syntax erklären
- [ ] Wahrheitswerte erklären
- [ ] typische Feature-Toggle-Anwendung

### 🧪 P.4 – `if`

**Direkt öffnen:** [Helm Playground – P.4](https://helm-playground.com/#t=N7C0AIEsDNwOgGoEMA2BXApgZzljAnAN0gGMM4MA7JAIxQwBNwBfZgKCQAdIECtIA9pQBc4QgEY2Aa0iUGogMoFiZNgFsMAFyQMk24W3DhqG0SHgAlDPSR44AOSQaW7LJwwkDRzQE93Z4HhkdGxcZVJyX3cXQ3A8ehJNAXwvI3AuTgDLawxbckdnVljOZM0sVKMIEvxNLMRUTBw8Igi4as0YtLTtfABzLQAFUtEADgAGcbYQCComViA&v=M4UwTgbglgxiBcAoABMkA7AhgIwDYgBN5kAXMAVxBVIE8AHBZAYV3OBPAEkAFaugezAliADgAMQA)

- [ ] Ressource/Block bei `true` rendern
- [ ] Value auf `false` setzen
- [ ] Unterschied im Renderergebnis zeigen

### 🛠️ LAB L.4 – Bedingungen / Feature Toggle

- [ ] `featureToggle` verwenden
- [ ] mit `--set` überschreiben
- [ ] `helm get values`
- [ ] `--reset-values`

### 🎓 `range`

- [ ] Listen erklären
- [ ] Iteration erklären

### 🧪 P.5 – `range`

**Direkt öffnen:** [Helm Playground – P.5](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFpK81gFcYUOLk7dco7ehjBkNdeIjAZBk%2BL1cjJzRt7pRCQEWXxExcSgBACM5YnQAH3QARwNEVnUtS2FrSLitIA&v=GYUwhgLgrgTiDOAuAUAAlQWlQOzAWxEVQBsB7AcwEts11URcAjYkAEyIhihFq1wKIAHMAE8C2CLXQMwzNkWBhi8Huj75CqVmBgBrPKVaq6Mue1SduQA)

- [ ] über Liste iterieren
- [ ] aktuellen Kontext `.` beobachten

**12:20–12:30 – Zwischenfazit**

**12:30–13:30 – Mittagspause**

---

## 13:30–14:30 | 🎓 + 🧪 + 🛠️ Kontext und Scope

### 🧪 P.6 – Kontextfalle: `.` und `$`

**Direkt öffnen:** [Helm Playground – P.6](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFpFMTGADGUOLk7dco7ehjBkNdeIjAZAVxPi9B43E0be6KISAix%2BImJSsvKKKmroAD7oAI6uiKzqWpbC1lAkfkA&v=M4UwTgbglgxiwC4BQACFBaFA7AhgWxARQDMwB7LAFxCwBNUNt9CUAjHGAaxvrU1wJFaOSjnaggA)

- [ ] funktionierende Iteration zeigen
- [ ] `.Release.Name` innerhalb von `range` absichtlich verwenden
- [ ] Fehler / unerwarteten Kontext analysieren
- [ ] `$.Release.Name` als Lösung zeigen

### Merksatz

> `.` sagt: **Wo bin ich gerade?**  
> `$` sagt: **Wo hat das Template angefangen?**

### 🎓 `with`

- [ ] 3.4.3 `with`
- [ ] Kontextwechsel durch `with`
- [ ] Root-Kontext bleibt über `$` erreichbar

### 🧪 P.7 – `with`

> **Noch keine Playground-URL vorhanden.** P.7 (`with`) ist eine neue Ergänzung und sollte noch als eigener Playground angelegt werden.

- [ ] `.Values.application` als neuen Kontext setzen
- [ ] `.name` innerhalb von `with`
- [ ] Zugriff auf `$.Release.Name`

### 🧪 P.8 – mehrere Ressourcen mit `range`

**Direkt öffnen:** [Helm Playground – P.8](https://helm-playground.com/#t=N7C0AICcEMDsHMCm4B0A1aAbArogzitAA5F7gC%2B5AUKLVcQJZqKR4MD2sAXOMaQPQA3AIxUA1g1gATHgBFERTOwCeAW0SwALlXWboU6Hq5Vw4WNHU8Q4ACQoASokyJoeRCgByF5JVDWU5uoU1HhEiADGxqaQCpgM4a5WwKgxivGuwSbgbs7hmuyQUabgqobhABYAMtAARk54RcW8JEm2Dk4ubp7ewX7JAT2UWZqIqoqGiI0liHoGRllNmLX1U018rXaOzq7uXkG%2B-oE%2B1E2hEavg4Zx6kiwNC03gEEetA-snj00MpUg8CJIADy4-kEdw4sEyIAgGikwSAA&v=IYBxGcC4CgAJYLSwHbALYFNKwGYCcB7ZAFw2QBM55Y8MQAbASwGNgpYBmK%2BANwz3CMi2AEQBGAHQAmABwjoVJKkzYARsGYBrMpWo06TVuyndYfAUOSjJUgOzzFKdFljByaRslO0GLNtjFTc0FhWHFpADYRIA)

- [ ] mehrere Deployments/Ressourcen aus einer Liste erzeugen
- [ ] `---` zwischen YAML-Dokumenten
- [ ] Root-Kontext innerhalb der Schleife verwenden

### 🛠️ LAB L.5 – Iteration, Funktionen und Kontext

- [ ] `range`
- [ ] `default`
- [ ] Map-Iteration
- [ ] Kontext korrekt verwenden
- [ ] ⭐ `lookup` optional / fortgeschritten

**14:30–14:40 – Pause**

---

## 14:40–15:40 | 🎓 + 🧪 + 🛠️ Code-Wiederverwendung

### 🎓 Theorie

- [ ] 3.5 Code-Wiederverwendung
- [ ] `define`
- [ ] `template`
- [ ] `include`
- [ ] Unterschied `template` / `include`
- [ ] `nindent`
- [ ] `toYaml`

### 🧪 P.9 – `toYaml` und `nindent`

**Direkt öffnen:** [Helm Playground – P.9](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAJQjgegG4CMAUANZjIAmGAIlCADaICeAtlMgC5FsfAXC9URdOmTA2GAN6T0AOgBKUelGBwosgHLio6AL66icEFADGQkTDr0wJ1VJmyIwegFcocWZYY3gAYUQunHoGImrKJhyIMOYi6CwCJgAWADLAAEZKcDGxmCAg9nKKyqrqWmzBwugcUCwMAlDZcVC8-IKVOfTpmY05WAUKSipqmtoVOUamPegmKLzksFntOegAtKLaGMgA5uQAHkvL6GDxWw2iO8i7qASyAEwAHAfLlnABMCbuQtJViACa4vQ5E5XO5PO43h84OgAD6icgUdgcdAEW7BIA&v=E4UwDgNglgxghgYQPYFcB2AXAXAAgMwBQBoAzqsDCCVgTjqAI4pUbW104xgq4CMADPwC27OkJBCkwAJ58ATAA4AslHbQhUVjQ6duuAKyCRO8ZJkHeclUA)

- [ ] komplexe Values-Struktur rendern
- [ ] `toYaml` erklären
- [ ] falsche Einrückung zeigen
- [ ] mit `nindent` korrigieren

### 🛠️ LAB L.6 – Wiederverwendbare Templates

- [ ] Named Template definieren
- [ ] mit `template` verwenden
- [ ] mit `include` verwenden
- [ ] Pipeline mit `include`
- [ ] `nindent` korrekt einsetzen

### 🔎 Checkpoint

- [ ] Teilnehmer erklären, warum `include | nindent` in Charts häufig vorkommt.

**15:40–15:50 – Pause**

---

## 15:50–16:30 | 🎓 Values – Einstieg

- [ ] 5.1 Values
- [ ] 5.1.1 Variablen und Scopes
- [ ] 5.2 `values.yaml`
- [ ] Values aus Datei
- [ ] Values per CLI
- [ ] Vorbereitung auf Prioritäten

### 🔎 Tages-Checkpoint

- [ ] `.Values`
- [ ] `.Release`
- [ ] Pipeline
- [ ] `default`
- [ ] `if`
- [ ] `range`
- [ ] `with`
- [ ] `.`
- [ ] `$`
- [ ] `define`
- [ ] `include`
- [ ] `nindent`
- [ ] `toYaml`

---

# Tag 3 – Chart-Verwaltung, Integration, Debugging und CI/CD

**09:00–16:30 Uhr**

## 09:00–10:00 | 🎓 + 🛠️ Subcharts und Dependencies

### 🎓 Theorie

- [ ] 4.1 Chart-Quellen / Repositories
- [ ] 4.2 Chart-Verwaltung
- [ ] 4.2.1 Subcharts
- [ ] Dependencies
- [ ] Parent-/Child-Beziehung
- [ ] `Chart.yaml` Dependencies
- [ ] `Chart.lock`

### 🛠️ LAB L.7a – Subcharts und Dependencies

- [ ] Subchart einbinden
- [ ] Dependency definieren
- [ ] `helm dependency update`
- [ ] resultierende Chart-Struktur untersuchen

**10:00–10:10 – Pause**

---

## 10:10–11:10 | 🎓 + 🛠️ Library Charts und Values

### 🎓 Library Charts

- [ ] 4.2.2 Library Charts
- [ ] Unterschied Application Chart / Library Chart
- [ ] Wiederverwendung über Chart-Grenzen

### 🛠️ LAB L.7b – Library Charts

- [ ] Library Chart verwenden
- [ ] Helper bereitstellen
- [ ] Helper aus Application Chart einbinden

### 🎓 Values vertiefen

- [ ] globale Values
- [ ] Parent-/Subchart Values
- [ ] `-f custom-values.yaml`
- [ ] `--set`
- [ ] Priorität beim Überschreiben
- [ ] `helm get values`
- [ ] `--reset-values`

### 🔎 Checkpoint

```text
values.yaml
    ↓
Parent-/Subchart Values
    ↓
-f custom-values.yaml
    ↓
--set
```

**11:10–11:20 – Pause**

---

## 11:20–12:30 | 🛠️ LAB L.10 – 3-Tier-Anwendung

> **Integrationslab:** Hier werden mehrere bisher getrennt behandelte Konzepte zusammengeführt.

### Architektur

```text
Browser
   |
   | NodePort
   v
Frontend / NGINX x2
   |
   | ClusterIP Service
   v
Backend / Node.js x2
   |
   | ClusterIP Service
   v
Redis x1
```

### Aufgaben

- [ ] Chart-Struktur kontrollieren
- [ ] Frontend Deployment
- [ ] Frontend Service
- [ ] Frontend ConfigMap
- [ ] Backend Deployment
- [ ] Backend Service
- [ ] Backend ConfigMap
- [ ] Redis Deployment
- [ ] Redis Service
- [ ] `helm lint`
- [ ] `helm template`
- [ ] Release installieren
- [ ] Pods kontrollieren
- [ ] Services kontrollieren
- [ ] Anwendung aufrufen
- [ ] Backend-Aufruf testen
- [ ] Backend von 2 auf 4 Replicas skalieren
- [ ] `helm upgrade`
- [ ] wechselnde Backend-Pods beobachten
- [ ] gemeinsamen Redis-Zustand beobachten
- [ ] `helm history`

### ⭐ Optional

- [ ] `redis.enabled` ergänzen
- [ ] Redis-Ressourcen mit `if` konditional rendern
- [ ] `helm template` mit `true` / `false` vergleichen

### 🔎 Checkpoint L.10

- [ ] Teilnehmer können den Netzwerkweg Browser → Frontend → Backend → Redis erklären.
- [ ] Teilnehmer können erklären, welche Teile Kubernetes und welche Teile Helm betreffen.
- [ ] Teilnehmer können erklären, warum Backend-Skalierung den Redis-Zustand nicht verändert.

**12:30–13:30 – Mittagspause**

---

## 13:30–14:20 | 🎓 Debugging, Troubleshooting und Testing

### Theorie / Trainer-Demo

- [ ] 6.1 Debugging und Troubleshooting
- [ ] 6.2 `helm lint`
- [ ] 6.3 `helm template`
- [ ] `--debug`
- [ ] `--dry-run`
- [ ] 6.4 häufige Fehler
- [ ] 6.5 Testing und Validierung
- [ ] 6.5.1 Helm Tests

### Debugging-Reihenfolge

- [ ] Schritt 1:

```bash
helm lint troubleshooting
```

- [ ] Schritt 2:

```bash
helm template myapp troubleshooting -n prod
```

- [ ] Schritt 3:

```bash
helm template myapp troubleshooting -n prod --debug
```

- [ ] Schritt 4:

```bash
helm install myapp troubleshooting -n prod --dry-run --debug
```

- [ ] Schritt 5:

```bash
helm install myapp troubleshooting -n prod
```

**14:20–14:30 – Pause**

---

## 14:30–15:20 | 🛠️ LAB L.9 – Troubleshooting Challenge

**Arbeitsform:** möglichst selbstständig; Trainer hilft erst nach eigener Diagnose.

- [ ] Fehler 1 gefunden
- [ ] Fehler 2 gefunden
- [ ] Fehler 3 gefunden
- [ ] Fehler 4 gefunden
- [ ] Fehler 5 gefunden
- [ ] Fehler 6 gefunden
- [ ] Fehler 7 gefunden
- [ ] Fehler 8 gefunden
- [ ] Chart besteht `helm lint`
- [ ] Chart lässt sich rendern
- [ ] Chart lässt sich installieren

### 🔎 Checkpoint

- [ ] Nicht nur Fehler gelöst, sondern verwendeten Diagnoseweg besprechen.

**15:20–15:30 – Pause**

---

## 15:30–16:30 | 🎓 + 🛠️ Continuous Deployment / GitOps

### 🎓 Theorie

- [ ] 7.1 Continuous Deployment mit Helm
- [ ] 7.2 GitOps mit Helm
- [ ] 7.2.1 Übersicht
- [ ] 7.2.2 GitLab CI/CD Workflow
- [ ] 7.3 Pipeline
- [ ] 7.4 Stages und Jobs
- [ ] 7.4.1 Job-Ausführung
- [ ] 7.5 Variablen
- [ ] vordefinierte Variablen
- [ ] GitLab Runner
- [ ] Shared Runner
- [ ] Project Runner
- [ ] Kommunikation Runner ↔ GitLab ↔ Kubernetes

### Schwerpunkt

```text
Git
 |
 v
GitLab
 |
 v
Pipeline
 |
 +-- lint
 +-- test / render
 +-- deploy
        |
        v
       Helm
        |
        v
   Kubernetes
```

### 🛠️ LAB L.8 – GitLab CI/CD

- [ ] Repository vorbereiten
- [ ] Pipeline konfigurieren
- [ ] Pipeline starten
- [ ] erwarteten Fehler analysieren
- [ ] Kubernetes-Zugriff bereitstellen
- [ ] Pipeline erneut ausführen
- [ ] Helm Release im Cluster kontrollieren

### 🔎 Kursabschluss

- [ ] Chart ↔ Release
- [ ] Values-Prioritäten
- [ ] Template Rendering
- [ ] Kontext `.` ↔ `$`
- [ ] Dependencies
- [ ] Debugging-Workflow
- [ ] CI/CD-Workflow
- [ ] offene Fragen

---

# Separate Fortschrittsübersicht – Playground

| Status | ID | Playground | Schwerpunkt | Tag | Direkt |
|---|---|---|---|---:|---|
| [ ] | P.1 | `.Values` und `.Release` | Built-in Objects | 1 | [öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6ACOrois6lqmMFAgMmC6Cg4Szm4e4rHxicAUrnZBoeGRmhpAA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4AoKYDAGwnwEMBhGXEVNARiA) |
| [ ] | P.2 | Pipelines | Funktionen / Datenfluss | 1 | [öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XukQxaRYDJFjxEawFcoccaBCqW6AD7oAjo6IrOpapo4gILC2Eg4yzq7unuq%2B4ZEwPv6BwZoapjKIAO5R6KIxTi5uEUkZ%2BUXpvgFBIbl8MFCRXNH25QlVahltHazoAMwZjdlaQA&v=IYBxDlgWwUwLgAQGUCuIYCcDqMBGBBMIA) |
| [ ] | P.3 | `default` | Fallback-Werte | 2 | [öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6MRQlMCuMgEARKGYsogg-tFB6ACOrois6lqmMog0ADJQ8TIOEs5uHuL5RSWyqaHhkTFElIgpwRlZORpAA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4g) |
| [ ] | P.4 | `if` | Bedingungen | 2 | [öffnen](https://helm-playground.com/#t=N7C0AIEsDNwOgGoEMA2BXApgZzljAnAN0gGMM4MA7JAIxQwBNwBfZgKCQAdIECtIA9pQBc4QgEY2Aa0iUGogMoFiZNgFsMAFyQMk24W3DhqG0SHgAlDPSR44AOSQaW7LJwwkDRzQE93Z4HhkdGxcZVJyX3cXQ3A8ehJNAXwvI3AuTgDLawxbckdnVljOZM0sVKMIEvxNLMRUTBw8Igi4as0YtLTtfABzLQAFUtEADgAGcbYQCComViA&v=M4UwTgbglgxiBcAoABMkA7AhgIwDYgBN5kAXMAVxBVIE8AHBZAYV3OBPAEkAFaugezAliADgAMQA) |
| [ ] | P.5 | `range` | Iteration | 2 | [öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFpK81gFcYUOLk7dco7ehjBkNdeIjAZBk%2BL1cjJzRt7pRCQEWXxExcSgBACM5YnQAH3QARwNEVnUtS2FrSLitIA&v=GYUwhgLgrgTiDOAuAUAAlQWlQOzAWxEVQBsB7AcwEts11URcAjYkAEyIhihFq1wKIAHMAE8C2CLXQMwzNkWBhi8Huj75CqVmBgBrPKVaq6Mue1SduQA) |
| [ ] | P.6 | `.` und `$` | Kontext / Root Scope | 2 | [öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFpFMTGADGUOLk7dco7ehjBkNdeIjAZAVxPi9B43E0be6KISAix%2BImJSsvKKKmroAD7oAI6uiKzqWpbC1lAkfkA&v=M4UwTgbglgxiwC4BQACFBaFA7AhgWxARQDMwB7LAFxCwBNUNt9CUAjHGAaxvrU1wJFaOSjnaggA) |
| [ ] | P.7 | `with` | Kontextwechsel | 2 | *noch anzulegen* |
| [ ] | P.8 | mehrere Ressourcen | `range` in realer Struktur | 2 | [öffnen](https://helm-playground.com/#t=N7C0AICcEMDsHMCm4B0A1aAbArogzitAA5F7gC%2B5AUKLVcQJZqKR4MD2sAXOMaQPQA3AIxUA1g1gATHgBFERTOwCeAW0SwALlXWboU6Hq5Vw4WNHU8Q4ACQoASokyJoeRCgByF5JVDWU5uoU1HhEiADGxqaQCpgM4a5WwKgxivGuwSbgbs7hmuyQUabgqobhABYAMtAARk54RcW8JEm2Dk4ubp7ewX7JAT2UWZqIqoqGiI0liHoGRllNmLX1U018rXaOzq7uXkG%2B-oE%2B1E2hEavg4Zx6kiwNC03gEEetA-snj00MpUg8CJIADy4-kEdw4sEyIAgGikwSAA&v=IYBxGcC4CgAJYLSwHbALYFNKwGYCcB7ZAFw2QBM55Y8MQAbASwGNgpYBmK%2BANwz3CMi2AEQBGAHQAmABwjoVJKkzYARsGYBrMpWo06TVuyndYfAUOSjJUgOzzFKdFljByaRslO0GLNtjFTc0FhWHFpADYRIA) |
| [ ] | P.9 | `toYaml` + `nindent` | komplexe YAML-Strukturen | 2 | [öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAJQjgegG4CMAUANZjIAmGAIlCADaICeAtlMgC5FsfAXC9URdOmTA2GAN6T0AOgBKUelGBwosgHLio6AL66icEFADGQkTDr0wJ1VJmyIwegFcocWZYY3gAYUQunHoGImrKJhyIMOYi6CwCJgAWADLAAEZKcDGxmCAg9nKKyqrqWmzBwugcUCwMAlDZcVC8-IKVOfTpmY05WAUKSipqmtoVOUamPegmKLzksFntOegAtKLaGMgA5uQAHkvL6GDxWw2iO8i7qASyAEwAHAfLlnABMCbuQtJViACa4vQ5E5XO5PO43h84OgAD6icgUdgcdAEW7BIA&v=E4UwDgNglgxghgYQPYFcB2AXAXAAgMwBQBoAzqsDCCVgTjqAI4pUbW104xgq4CMADPwC27OkJBCkwAJ58ATAA4AslHbQhUVjQ6duuAKyCRO8ZJkHeclUA) |

---

# Separate Fortschrittsübersicht – Labs

| Status | Lab | Schwerpunkt | Tag | Richtzeit |
|---|---|---|---:|---:|
| [ ] | **L.1** | erster Release / Lifecycle | 1 | 60 min |
| [ ] | **L.2** | eigenes minimales Chart | 1 | 60 min |
| [ ] | **L.3** | Deployment / Service / Values | 2 | 60–90 min verteilt |
| [ ] | **L.4** | Bedingungen / Feature Toggle | 2 | 30–40 min |
| [ ] | **L.5** | `range`, Funktionen, Kontext | 2 | 30–45 min |
| [ ] | **L.6** | Wiederverwendung | 2 | 30–45 min |
| [ ] | **L.7a** | Subcharts / Dependencies | 3 | 30–40 min |
| [ ] | **L.7b** | Library Charts | 3 | 20–30 min |
| [ ] | **L.10** | 3-Tier-Integrationslab | 3 | 70 min |
| [ ] | **L.9** | Troubleshooting Challenge | 3 | 50 min |
| [ ] | **L.8** | GitLab CI/CD | 3 | 30–45 min |

---

# Vorbereitung vor dem Kurs

## Playground

- [ ] P.1 getestet
- [ ] P.2 getestet
- [ ] P.3 getestet
- [ ] P.4 getestet
- [ ] P.5 getestet
- [ ] P.6 getestet
- [ ] P.7 `with` ergänzt und getestet
- [ ] P.8 getestet
- [ ] P.9 getestet
- [ ] Renderergebnisse ggf. für Traineransicht vorbereitet

## Labs

- [ ] L.1 vollständig getestet
- [ ] L.2 vollständig getestet
- [ ] L.3 vollständig getestet
- [ ] L.4 vollständig getestet
- [ ] L.5 vollständig getestet
- [ ] L.6 vollständig getestet
- [ ] L.7 vollständig getestet
- [ ] L.8 GitLab/Runner/Kubernetes-Zugriff getestet
- [ ] L.9 Ausgangszustand und alle 8 Fehler getestet
- [ ] L.10 vollständig mit `helm lint` geprüft
- [ ] L.10 alle YAML-Blöcke auf Copy-&-Paste-Einrückung geprüft
- [ ] benötigte Container-Images auf Erreichbarkeit geprüft

---

# Kurzform des Lernpfads

```text
TAG 1
BEDIENEN
Chart → Release → Upgrade → Rollback
              |
              v
TAG 2
TEMPLATEN
Values → Funktionen → if → range → Scope → include
              |
              v
TAG 3
ANWENDEN
Dependencies → 3-Tier → Debugging → CI/CD
```

> **Bauen → Parametrisieren → Abstrahieren → Zusammensetzen → Debuggen → Automatisieren**
