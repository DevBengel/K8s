# Helm Playground -- Demo-Sammlung

Diese Sammlung enthält acht aufeinander aufbauende Demos für
**Helm-Templates**.\
Die Beispiele können direkt im [Helm
Playground](https://helm-playground.com/) geöffnet und verändert werden.

Die Reihenfolge führt von einfachem Zugriff auf Helm-Objekte und Values
über Pipelines und Kontrollstrukturen bis hin zu Kontextwechseln, der
Root-Variable `$` und der Übergabe kompletter YAML-Strukturen.

------------------------------------------------------------------------

## Demo 1 -- Values und Release-Kontext

**Playground:**\
https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6ACOrois6lqmMFAgMmC6Cg4Szm4e4rHxicAUrnZBoeGRmhpAA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4AoKYDAGwnwEMBhGXEVNARiA

### Inhalt

Die Einstiegsdemo zeigt die beiden wichtigsten Datenquellen eines
Helm-Templates:

-   `.Values` für Werte aus `values.yaml`
-   `.Release` für Informationen über die aktuelle Helm-Release-Instanz

Aus `environment` und `replicaCount` wird eine Kubernetes `ConfigMap`
erzeugt. Der Name der Ressource wird aus `.Release.Name` gebildet.

### Zentrale Konzepte

``` gotemplate
{{ .Release.Name }}
{{ .Values.environment }}
{{ .Values.replicaCount }}
```

Außerdem wird mit `quote` bereits eine einfache Template-Funktion
verwendet:

``` gotemplate
{{ .Values.environment | quote }}
```

### Lernziel

Die Teilnehmer verstehen, dass Helm nicht lediglich Platzhalter ersetzt.
Das Template erhält einen Kontext mit verschiedenen Objekten. `.Values`
ist nur ein Teil dieses Kontextes.

------------------------------------------------------------------------

## Demo 2 -- Pipelines und Sprig-Funktionen

**Playground:**\
https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XukQxaRYDJFjxEawFcoccaBCqW6AD7oAjo6IrOpapo4gILC2Eg4yzq7unuq%2B4ZEwPv6BwZoapjKIAO5R6KIxTi5uEUkZ%2BUXpvgFBIbl8MFCRXNH25QlVahltHazoAMwZjdlaQA&v=IYBxDlgWwUwLgAQGUCuIYCcDqMBGBBMIA

### Inhalt

Ein einzelner Value `appName` wird mehrfach verarbeitet. Dabei kommen
verschiedene Funktionen zum Einsatz:

``` gotemplate
{{ .Values.appName | quote }}
{{ .Values.appName | upper | quote }}
{{ .Values.appName | lower | quote }}
{{ .Values.appName | repeat 3 | quote }}
```

### Zentrale Konzepte

Die Demo führt **Pipelines** ein. Der Wert wird von links nach rechts
durch mehrere Funktionen geleitet:

``` text
.Values.appName
       |
       v
     upper
       |
       v
     quote
```

Helm stellt neben den Go-Template-Funktionen zahlreiche Funktionen aus
**Sprig** bereit.

### Lernziel

Die Teilnehmer erkennen, dass Template-Ausdrücke nicht nur Werte lesen,
sondern diese während des Renderings transformieren können.

------------------------------------------------------------------------

## Demo 3 -- Default-Werte

**Playground:**\
https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6MRQlMCuMgEARKGYsogg-tFB6ACOrois6lqmMog0ADJQ8TIOEs5uHuL5RSWyqaHhkTFElIgpwRlZORpAA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4g

### Inhalt

Die Demo zeigt die Funktion `default`.

In `values.yaml` ist lediglich definiert:

``` yaml
environment: production
```

Das Template erwartet zusätzlich `logLevel`, stellt dafür aber einen
Standardwert bereit:

``` gotemplate
{{ .Values.logLevel | default "info" | quote }}
```

### Ausprobieren

`logLevel` zunächst fehlen lassen und anschließend ergänzen:

``` yaml
logLevel: debug
```

### Lernziel

Charts können mit sinnvollen Standardwerten arbeiten, ohne dass jeder
mögliche Wert explizit gesetzt werden muss.

------------------------------------------------------------------------

## Demo 4 -- Bedingungen mit `if`

**Playground:**\
https://helm-playground.com/#t=N7C0AIEsDNwOgGoEMA2BXApgZzljAnAN0gGMM4MA7JAIxQwBNwBfZgKCQAdIECtIA9pQBc4QgEY2Aa0iUGogMoFiZNgFsMAFyQMk24W3DhqG0SHgAlDPSR44AOSQaW7LJwwkDRzQE93Z4HhkdGxcZVJyX3cXQ3A8ehJNAXwvI3AuTgDLawxbckdnVljOZM0sVKMIEvxNLMRUTBw8Igi4as0YtLTtfABzLQAFUtEADgAGcbYQCComViA&v=M4UwTgbglgxiBcAoABMkA7AhgIwDYgBN5kAXMAVxBVIE8AHBZAYV3OBPAEkAFaugezAliADgAMQA

### Inhalt

Eine komplette Kubernetes-`Service`-Ressource wird abhängig von einem
Value erzeugt:

``` gotemplate
{{- if .Values.service.enabled }}
...
{{- end }}
```

Die Values enthalten:

``` yaml
service:
  enabled: true
  type: ClusterIP
  port: 80
```

### Ausprobieren

``` yaml
enabled: false
```

setzen. Der komplette Service verschwindet aus dem gerenderten Ergebnis.

### Lernziel

Helm kann nicht nur Werte innerhalb einer Ressource verändern, sondern
abhängig von Konfigurationen ganze Kubernetes-Ressourcen erzeugen oder
weglassen.

Nebenbei lässt sich hier die Whitespace-Steuerung mit `{{-` und `-}}`
thematisieren.

------------------------------------------------------------------------

## Demo 5 -- Iteration mit `range`

**Playground:**\
https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFpK81gFcYUOLk7dco7ehjBkNdeIjAZBk%2BL1cjJzRt7pRCQEWXxExcSgBACM5YnQAH3QARwNEVnUtS2FrSLitIA&v=GYUwhgLgrgTiDOAuAUAAlQWlQOzAWxEVQBsB7AcwEts11URcAjYkAEyIhihFq1wKIAHMAE8C2CLXQMwzNkWBhi8Huj75CqVmBgBrPKVaq6Mue1SduQA

### Inhalt

Eine Liste von Features wird mit `range` durchlaufen:

``` yaml
features:
  - name: login
    enabled: true
  - name: payment
    enabled: false
  - name: darkmode
    enabled: true
```

Das Template:

``` gotemplate
{{- range .Values.features }}
  {{ .name }}: {{ .enabled | quote }}
{{- end }}
```

erzeugt daraus mehrere Einträge in einer ConfigMap.

### Der wichtige Kontextwechsel

Innerhalb von `range` verändert sich die Bedeutung von `.`.

Vor dem `range` ist `.` der ursprüngliche Helm-Kontext. Innerhalb der
Schleife ist `.` jeweils das aktuelle Listenelement.

Beim ersten Durchlauf entspricht `.` beispielsweise:

``` yaml
name: login
enabled: true
```

Deshalb kann innerhalb der Schleife direkt mit `.name` und `.enabled`
gearbeitet werden.

### Lernziel

`range` führt nicht nur eine Schleife aus, sondern verändert
gleichzeitig den aktuellen Template-Kontext.

------------------------------------------------------------------------

## Demo 6 -- Die Kontext-Falle bei `range`

**Playground:**\
https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFpFMTGADGUOLk7dco7ehjBkNdeIjAZAVxPi9B43E0be6KISAix%2BImJSsvKKKmroAD7oAI6uiKzqWpbC1lAkfkA&v=M4UwTgbglgxiwC4BQACFBaFA7AhgWxARQDMwB7LAFxCwBNUNt9CUAjHGAaxvrU1wJFaOSjnaggA

### Inhalt

Diese Demo ist **absichtlich fehlerhaft**.

Außerhalb des `range` funktioniert:

``` gotemplate
{{ .Release.Name }}
```

Innerhalb der Schleife wird jedoch versucht:

``` gotemplate
{{- range .Values.services }}
  {{ .name }}: {{ .Release.Name | quote }}
{{- end }}
```

### Warum schlägt das fehl?

Innerhalb von `range` ist `.` nicht mehr der Root-Kontext von Helm.

Für das erste Element entspricht `.` nur noch ungefähr:

``` yaml
name: frontend
```

Darin existiert kein Objekt `.Release`.

### Lösung

Der Root-Kontext ist über `$` erreichbar:

``` gotemplate
{{ $.Release.Name }}
```

### Lernziel

Diese Demo verdeutlicht die zentrale Unterscheidung:

``` text
.   aktueller Kontext
$   Root-Kontext
```

Sie eignet sich besonders gut als Fehlerdemo: zunächst rendern lassen,
Fehler betrachten und die Teilnehmer nach der Ursache fragen.

------------------------------------------------------------------------

## Demo 7 -- Aus einer Liste mehrere Deployments erzeugen

**Playground:**\
https://helm-playground.com/#t=N7C0AICcEMDsHMCm4B0A1aAbArogzitAA5F7gC%2B5AUKLVcQJZqKR4MD2sAXOMaQPQA3AIxUA1g1gATHgBFERTOwCeAW0SwALlXWboU6Hq5Vw4WNHU8Q4ACQoASokyJoeRCgByF5JVDWU5uoU1HhEiADGxqaQCpgM4a5WwKgxivGuwSbgbs7hmuyQUabgqobhABYAMtAARk54RcW8JEm2Dk4ubp7ewX7JAT2UWZqIqoqGiI0liHoGRllNmLX1U018rXaOzq7uXkG%2B-oE%2B1E2hEavg4Zx6kiwNC03gEEetA-snj00MpUg8CJIADy4-kEdw4sEyIAgGikwSAA&v=IYBxGcC4CgAJYLSwHbALYFNKwGYCcB7ZAFw2QBM55Y8MQAbASwGNgpYBmK%2BANwz3CMi2AEQBGAHQAmABwjoVJKkzYARsGYBrMpWo06TVuyndYfAUOSjJUgOzzFKdFljByaRslO0GLNtjFTc0FhWHFpADYRIA

### Inhalt

Die Values beschreiben drei Anwendungen:

``` yaml
apps:
  - name: frontend
    replicas: 3
    version: "1.28"

  - name: backend
    replicas: 2
    version: "1.27"

  - name: admin
    replicas: 1
    version: "1.26"
```

Ein einziges Template iteriert über diese Liste und erzeugt für jedes
Element ein eigenes Kubernetes `Deployment`.

### Kontext

Innerhalb von:

``` gotemplate
{{- range .Values.apps }}
```

beziehen sich:

``` gotemplate
{{ .name }}
{{ .replicas }}
{{ .version }}
```

auf die aktuelle Anwendung.

Für den Release-Namen muss dagegen auf den Root-Kontext zurückgegriffen
werden:

``` gotemplate
{{ $.Release.Name }}
```

### Mehrere YAML-Dokumente

Mit:

``` yaml
---
```

werden die erzeugten Deployments als getrennte YAML-Dokumente
ausgegeben.

### Lernziel

Die Demo verbindet mehrere zuvor eingeführte Konzepte:

-   `range`
-   Kontextwechsel von `.`
-   Root-Kontext `$`
-   dynamische Ressourcennamen
-   Generierung mehrerer Kubernetes-Ressourcen aus einer Datenstruktur

Damit wird sichtbar, warum Helm weit über einfache Variablensubstitution
hinausgeht.

------------------------------------------------------------------------

## Demo 8 -- Komplexe YAML-Strukturen mit `toYaml` und `nindent`

**Playground:**\
https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAJQjgegG4CMAUANZjIAmGAIlCADaICeAtlMgC5FsfAXC9URdOmTA2GAN6T0AOgBKUelGBwosgHLio6AL66icEFADGQkTDr0wJ1VJmyIwegFcocWZYY3gAYUQunHoGImrKJhyIMOYi6CwCJgAWADLAAEZKcDGxmCAg9nKKyqrqWmzBwugcUCwMAlDZcVC8-IKVOfTpmY05WAUKSipqmtoVOUamPegmKLzksFntOegAtKLaGMgA5uQAHkvL6GDxWw2iO8i7qASyAEwAHAfLlnABMCbuQtJViACa4vQ5E5XO5PO43h84OgAD6icgUdgcdAEW7BIA&v=E4UwDgNglgxghgYQPYFcB2AXAXAAgMwBQBoAzqsDCCVgTjqAI4pUbW104xgq4CMADPwC27OkJBCkwAJ58ATAA4AslHbQhUVjQ6duuAKyCRO8ZJkHeclUA

### Inhalt

Die Demo zeigt, wie eine komplette verschachtelte YAML-Struktur aus
`values.yaml` übernommen werden kann.

Die Values enthalten beispielsweise:

``` yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

Statt jeden einzelnen Wert separat in das Template einzubauen, wird die
komplette Struktur verarbeitet:

``` gotemplate
{{ toYaml .Values.resources | nindent 12 }}
```

### `toYaml`

`toYaml` serialisiert die Datenstruktur wieder zu gültigem YAML.

### `nindent`

`nindent 12` fügt einen Zeilenumbruch ein und rückt anschließend jede
erzeugte Zeile um zwölf Leerzeichen ein.

Das ist besonders wichtig, weil YAML-Strukturen von ihrer korrekten
Einrückung abhängen.

### Lernziel

Nicht jeder einzelne Wert muss separat templatisiert werden. Komplexe
Kubernetes-Strukturen können als zusammenhängende Datenstruktur in
`values.yaml` definiert und mit `toYaml` übernommen werden.

Typische Anwendungsfälle sind:

-   `resources`
-   `nodeSelector`
-   `tolerations`
-   `affinity`
-   zusätzliche Labels und Annotationen
-   Security Contexts

------------------------------------------------------------------------

# Empfohlener Demo-Ablauf

Die acht Beispiele bauen didaktisch aufeinander auf:

  -----------------------------------------------------------------------
  Demo                    Schwerpunkt             Kernaussage
  ----------------------- ----------------------- -----------------------
  1                       `.Values`, `.Release`   Helm besitzt einen
                                                  Template-Kontext

  2                       Pipelines               Werte können
                                                  verarbeitet werden

  3                       `default`               Charts können Fallbacks
                                                  definieren

  4                       `if`                    Ressourcen können
                                                  bedingt erzeugt werden

  5                       `range`                 Listen können dynamisch
                                                  verarbeitet werden

  6                       `.` vs. `$`             Kontextwechsel haben
                                                  Konsequenzen

  7                       mehrere Ressourcen      Datenstrukturen können
                                                  Ressourcen generieren

  8                       `toYaml`, `nindent`     Komplexe YAML-Blöcke
                                                  lassen sich elegant
                                                  übernehmen
  -----------------------------------------------------------------------

## Roter Faden

Die Beispiele können als schrittweise Erweiterung des
Helm-Verständnisses präsentiert werden:

``` text
Values einsetzen
      ↓
Werte transformieren
      ↓
Defaults definieren
      ↓
Programmfluss mit if
      ↓
Iteration mit range
      ↓
Kontext verstehen
      ↓
mehrere Ressourcen generieren
      ↓
komplexe YAML-Strukturen übernehmen
```

Besonders wichtig ist der Übergang von Demo 5 zu Demo 6. Hier wird
deutlich, dass der Punkt `.` in Go-Templates keine feste Bedeutung
besitzt, sondern immer den **aktuellen Kontext** bezeichnet.

Als Merksatz:

> **`.` sagt: Wo bin ich gerade? -- `$` sagt: Wo hat das Template
> angefangen?**
