# Helm Playground – Demo-Serie

Eine aufeinander aufbauende Sammlung von Helm-/Go-Template-Demos mit direkt vorkonfigurierten Links für helm-playground.com.

> **Hinweis zum Playground:** Die URLs enthalten Template und Values komprimiert im URL-Fragment. Der Playground stellt Helm-nahe Funktionen bereit, aber `include`, `tpl` und `required` sind in seiner Engine nur Platzhalter. Die Helper-Demo verwendet deshalb `define`/`template` aus Go Templates.

## Empfohlene Dramaturgie

`Values → Pipelines → default → if → with → Kontextfehler → $ → range → nested range → Variablen → dict → Helper → Debugging → toYaml`

## 01 – Values und Release-Kontext

Einstieg: Unterschied zwischen `.Values` und Helm-Kontext wie `.Release`.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDQFoAxlVq5O3XuijJMYGChbJWIseIjAZAVyhxx5y9eS3W6AA%2B6ACOrois6lqmMFAgMmC6Cg4Szm4e4rHxicAUrnZBoeGRmhq4QA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4AoKYDAGwnwEMBhGXEVNAZhKA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-config
data:
  environment: {{ .Values.environment | quote }}
  replicas: {{ .Values.replicaCount | quote }}
```

**values.yaml**

```yaml
environment: production
replicaCount: 3
```

**Live-Aufgabe:** Ändere `environment` und `replicaCount` und beobachte nur die gerenderten Stellen.

## 02 – Pipelines und Sprig

Werte durch Funktionen leiten: `upper`, `lower`, `repeat`, `quote`.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDMShNEuTt17pEMWkWAAbDAG8V6AHQQlAVyhwNoEADlBUdAB90ARx2JW5gL6PpOkCFir1W3fsPvTFkt0Nw8YYNt7Jxc%2BRUQAd090NU1tRT0DI0DzKzjE8KtIh3RnaRgoDy4oUmTvNIz-EzNg8srWdABmCLti0qA&v=IYBxDlgWwUwLgAQAkYBsoCUD2BjA1gM4BQQA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
data:
  original: {{ .Values.appName | quote }}
  upper: {{ .Values.appName | upper | quote }}
  lower: {{ .Values.appName | lower | quote }}
  repeated: {{ .Values.appName | repeat 3 | quote }}
```

**values.yaml**

```yaml
appName: HelmRocks
```

**Live-Aufgabe:** Erkläre die Pipeline gedanklich als Funktionsverkettung von links nach rechts.

## 03 – `default`

Fallback-Werte verwenden, wenn Values leer oder nicht gesetzt sind.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDMShNEuTt17ooyTGBgoWyVhgDea9ADoIwADYBXKHC2z5i5MtboAPuhGVgBvdYBEIzFD2IQV17fQARwNEVih0AF8I6W8aABkoTz11TR19IxNYhKSAhycXdFciSkR-O2DQ8KjcIA&v=KYOwbglgTg9iC2oAuAuABAB1gEwK4GMkI4AoIA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
data:
  environment: {{ .Values.environment | default "development" | quote }}
  logLevel: {{ .Values.logLevel | default "info" | quote }}
```

**values.yaml**

```yaml
environment: production
```

**Live-Aufgabe:** Füge `logLevel: debug` hinzu und entferne anschließend auch `environment`.

## 04 – `if` erzeugt oder entfernt Ressourcen

Kontrollfluss: eine komplette Kubernetes-Ressource optional rendern.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=N7C0AIEsDNwOgGoEMA2BXApgZzljAnAN0gGMM4MA7JAIxQwBNwBfZgKCQAdIECtIA9pQBc4QgEY2Aa0iUGogMoFiZNgFsMAFyQMk24W3DhqG0QwxqBbLJwwkDRzQE9bokPGTpsuZaXLPbFnYjTgF8TSwHI3AIUPC3YA9UTBw8Ij84OM0gthAIKiZWNiA&v=M4UwTgbglgxiBcAoABMkA7AhgIwDYgBN5kAXMAVxBVIE8AHBZAYV3OBPAEkAFaugezAliADgAMiIA)**

**template.yaml**

```yaml
{{- if .Values.service.enabled }}
apiVersion: v1
kind: Service
metadata:
  name: demo
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
{{- end }}
```

**values.yaml**

```yaml
service:
  enabled: true
  type: ClusterIP
  port: 80
```

**Live-Aufgabe:** Setze `enabled: false`. Nicht nur ein Feld, sondern die komplette Ressource verschwindet.

## 05 – `with` als Kontextwechsel

`with` verkürzt tiefe Pfade, verändert dafür aber die Bedeutung von `.`.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDMShNEuTt1wBvaQFp0AdzCsAFugB0EYABsArlDgbQIdAF8zvfoKgZZmgS3QAfdAEc9iVlHOW%2BUZEwwGBQWZFY7aU0AoJDkMNYXd09vXyswJmAaW3R7DQysqA0YKBBEBFZEGABPJI8vHwsZeXQA4jSgA&v=IYBxC4CgAJoO2AWwKbmgd2QIwM4AsB7EGaZOANwEsAnAuFOAFzRFoBMBXAY0crpMqJgAc1QlY1ZCAI5KjAtQCeaOMMpwAHpCA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
data:
{{- with .Values.app }}
  name: {{ .name | quote }}
  environment: {{ .environment | quote }}
  image: {{ .image.repository | quote }}
{{- end }}
```

**values.yaml**

```yaml
app:
  name: webshop
  environment: production
  image:
    repository: nginx
```

**Live-Aufgabe:** Zeige: innerhalb von `with` ist `.` gleich `.Values.app`.

## 06 – Boss Fight: `.Release` verschwindet in `with`

Absichtlicher Fehler: ein Kontextwechsel macht `.Release` relativ zum falschen Objekt.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDbk7dcogLToA7mFYALCRGAyArlDjjQITdr7ORY8QJboAPugAjraIrOpavOgwsvKKnhLScgpKqr4BwaHh2oboUCSuuEA&v=IYBxC4CgAJoO2AWwKbmgd2QIwM4AsB7ESIA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
data:
{{- with .Values.app }}
  app: {{ .name | quote }}
  release: {{ .Release.Name | quote }}
{{- end }}
```

**values.yaml**

```yaml
app:
  name: webshop
```

**Live-Aufgabe:** Warum funktioniert `.Release.Name` oben, aber innerhalb von `with` nicht?

## 07 – `$` rettet den Root-Kontext

Den Root-Kontext trotz `with` erreichen.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDAG9h6AHQAlKABsowOFHEA5QVHQBfDbk7dcogLToA7mFYALCRGAyArlDjjQITdr7ORY8QJboAPugAjraIrOpavOgwsvKKnugAJFIxCkqqvgHBoeHahuhQJK64QA&v=IYBxC4CgAJoO2AWwKbmgd2QIwM4AsB7ESIA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
data:
{{- with .Values.app }}
  app: {{ .name | quote }}
  release: {{ $.Release.Name | quote }}
{{- end }}
```

**values.yaml**

```yaml
app:
  name: webshop
```

**Live-Aufgabe:** Merksatz: `.` = wo bin ich gerade? `$` = wo hat das Template angefangen?

## 08 – `range`: Liste wird YAML

Listen iterieren; `.` wird zum aktuellen Listenelement.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDJShcArjChxcnbrgDe8gLToYwZDSjoAdBGAAbMVO0jxkuOgC%2Bl3ukU6BLK5Yz3tUAQCN9UYugA%2B6ACOYoisWtYKyugefpFAA&v=GYUwhgLgrgTiDOAuAUAAlQWlQOzAWxEVQBsB7AcwEts11URcAjYkAEyIhihFq1wKIAHMAE8C2CLXQMwzNkWBhi8Huj75CqVmBgBrPKVaq6Mue1SduyIA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: features
data:
{{- range .Values.features }}
  {{ .name }}: {{ .enabled | quote }}
{{- end }}
```

**values.yaml**

```yaml
features:
  - name: login
    enabled: true
  - name: payment
    enabled: false
  - name: darkmode
    enabled: true
```

**Live-Aufgabe:** Frage bei jedem Schleifendurchlauf: Was ist `.` gerade?

## 09 – Boss Fight: `.Release` in `range`

Absichtlicher Kontextfehler innerhalb einer Schleife.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDHFiYwAYyhxcnbrgDe8gLToYwZDSjoAdBGAAbAK5TtImGMlx0AX2u90inQJY3rGR9oBKUfVGAjtADlBLQAfdABHQ0RWLVsFZXQoEldcIA&v=M4UwTgbglgxiwC4BQACFBaFA7AhgWxARQDMwB7LAFxCwBNUNt9CUAjHGAaxvrU1wJEClMLGBIgA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: services
data:
{{- range .Values.services }}
  {{ .name }}: {{ .Release.Name | quote }}
{{- end }}
```

**values.yaml**

```yaml
services:
  - name: frontend
  - name: backend
  - name: metrics
```

**Live-Aufgabe:** Repariere die Demo, ohne den `range` zu entfernen.

## 10 – `range` mit Root `$`

Aktuelles Element über `.`, globale Helm-Daten über `$` nutzen.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDHFiYwAYyhxcnbrgDe8gLToYwZDSjoAdBGAAbAK5TtImGMlx0AX2u90inQJY3rGRwBJtAJSj6owCLaAHKCWgA%2B6ACOhoisWrYKyuhQJK64QA&v=M4UwTgbglgxiwC4BQACFBaFA7AhgWxARQDMwB7LAFxCwBNUNt9CUAjHGAaxvrU1wJEClMLGBIgA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: services
data:
{{- range .Values.services }}
  {{ .name }}: {{ $.Release.Name | quote }}
{{- end }}
```

**values.yaml**

```yaml
services:
  - name: frontend
  - name: backend
  - name: metrics
```

**Live-Aufgabe:** Stelle `.name` und `$.Release.Name` direkt gegenüber.

## 11 – `range` mit Index und Variablen

Index und aktuelles Element explizit in Variablen binden.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAIBuBGAUAazGQBMMBhFAMzAHMBZUXAWygBdhjh3Vd11lgLDHFiYwAYyhxcnbrgDe8gLToYwZDSjoAJEWJQAHgBodImGMnpUAXnQA6CMAA2AVyl2zFqegC%2BP3uieElBKijp6hr4%2BGGHaQZJ2AizoAD7oAI4uiKxafgrK6FAkUbhAA&v=M4UwTgbglgxiwC4BQACFBaFA7AhgWxARQDMwB7LAFxCwBNUNt9CUAjHGAaxvrU1wJEClMLGBIgA)**

**template.yaml**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: services
data:
{{- range $index, $service := .Values.services }}
  service-{{ $index }}: {{ $service.name | quote }}
{{- end }}
```

**values.yaml**

```yaml
services:
  - name: frontend
  - name: backend
  - name: metrics
```

**Live-Aufgabe:** Zeige, dass man für lesbare Templates nicht immer mit `.` arbeiten muss.

## 12 – Nested `range`: Context Boss Fight

Verschachtelte Schleifen machen sichtbar, wie `.` mehrfach seinen Bezug wechselt.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=N7C0AICcEMDsHMCm4B0A1aAbArogzitAA5GYCWAxtAC5kD2se4AvswFACCJ5VtDAXOBCpY0ALbJWbEBBgJkKInUjUmUgArLqg4ShbsupSjXqxQ0eNDKwdwEeMnsZ4RLAAm%2B6WBfvPQA&v=IYBxBsEsGNgF0gewHYGcBcAoABNgtNssALYCm62AZgE4pynIAmOu2Ii1cGLr%2B2AHAAYerAgBYxAZhYEiZCgCNg0ANYNmvdp269cBIUJF7sATkFnMQA)**

**template.yaml**

```yaml
{{- range .Values.applications }}
Application: {{ .name }}
{{- range .ports }}
Port: {{ . }}
Application-again: {{ .name }}
{{- end }}
{{- end }}
```

**values.yaml**

```yaml
applications:
  - name: frontend
    ports:
      - 80
      - 443
  - name: backend
    ports:
      - 8080
      - 9090
```

**Live-Aufgabe:** Absichtlich kaputt: Im inneren `range` ist `.` nur noch die Portnummer. Wie behalten wir die Application?

## 13 – Parent-Kontext in Variable sichern

Vor einem weiteren Kontextwechsel das Elternobjekt speichern.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=N7C0AICcEMDsHMCm4B0A1aAbArogzitAA5GYCWAxtAC5kD2se4AvswFAgQAkxR4AXAF5ULdgEES5KrQb9wIcDxIpY0ALbJWHMFDhJUROpGpMtABSPU5ClKLYTSlGvViho8aGVjXgi3ivVNdgAlRExEaDxEH0UUUPDIxBQAOUC7TnBEWAATdJ0s3K0gA&v=IYBxBsEsGNgF0gewHYGcBcAoABNgtNssALYCm62AZgE4pynIAmOu2Ii1cGLr%2B2AHAAYerAgBYxAZhYEiZCgCNg0ANYNmvdp269cBIUJF7sATkFnMQA)**

**template.yaml**

```yaml
{{- range .Values.applications }}
{{- $app := . }}
Application: {{ $app.name }}
{{- range .ports }}
Port: {{ . }}
Application-again: {{ $app.name }}
Release: {{ $.Release.Name }}
{{- end }}
{{- end }}
```

**values.yaml**

```yaml
applications:
  - name: frontend
    ports:
      - 80
      - 443
  - name: backend
    ports:
      - 8080
      - 9090
```

**Live-Aufgabe:** Drei Ebenen benennen: `$` = Root, `$app` = Parent, `.` = Port.

## 14 – Mehrere Deployments aus einer Datenstruktur

Eine Values-Liste in mehrere vollständige Kubernetes-Ressourcen überführen.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=N7C0AICcEMDsHMCm4B0A1aAbArogzitAA5F7gC%2B5AUKLVcQJZqKR4MD2sAXOMaQPQA3AIxUA1g1gATHgBFERTOwCeAW0SwALlXWboU6Hq5Vw4WNHU8Q4ACQoASokyJoeRCgByF5JVDWU5uoU1HhEiADGxqaQCpgM4a5WwKgxivGuwSbgbs7hmuyQUabgqobhABYAMtAARk54RcW8JEm2Dk4ubp7ewX7JAT2UWZqIqoqGiI0liHoGRllNmLX1U018rXaOzq7uXkG%2B-oE%2B1E2hEavg4Zx6kiwNC03gEEetA-snj00MpUg8CJIADy4-kEdw4sEyIAgGikmSAA&v=IYBxGcC4CgAJYLSwHbALYFNKwGYCcB7ZAFw2QBM55Y8MQAbASwGNgpYBmK%2BANwz3CMi2AEQBGAHQAmABwiqSVJmwAjYMwDWZStRp0mrdlO6w%2BAoclGSpAdnnxF6LLGDk0jZCdoMWbbGJMzQWFYcWkANnkgA)**

**template.yaml**

```yaml
{{- range .Values.apps }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $.Release.Name }}-{{ .name }}
spec:
  replicas: {{ .replicas }}
  selector:
    matchLabels:
      app: {{ $.Release.Name }}-{{ .name }}
  template:
    metadata:
      labels:
        app: {{ $.Release.Name }}-{{ .name }}
    spec:
      containers:
        - name: {{ .name }}
          image: nginx:{{ .version }}
{{- end }}
```

**values.yaml**

```yaml
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

**Live-Aufgabe:** Füge eine vierte App nur in `values.yaml` hinzu.

## 15 – `dict`: einen eigenen Kontext bauen

Mit `dict` gezielt Daten zu einem neuen Objekt zusammenstellen.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=N7C0AIBIGMBcA9wC4C84AmBLO4BEBDAB0N3ADoA1fAGwFcBTAZzKMLwCd7r79H7SyAJS48%2BZAHL4AtvXABfOQCgimCvXaNMAewB2ScADcAjIoDWmHen0BhXQDNMAcwCyRRTNj50%2BT0kXhwHWl6fRAoOHgyTm5eWQVFb19-cFZQ4HCEFmIyIJlwAB9wAEdaLVg4pQDCLXZYNIzI1jJq2oLi0vL5SvBo0RDwMJhM3ti2krKKxSA&v=IYBxC4CgAJoO2AWwKbmgd2QIwM4AsB7EGaEAgJwBc0AOABnsiA)**

**template.yaml**

```yaml
{{- $ctx := dict "app" .Values.app "release" .Release.Name }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ $ctx.release }}
data:
  app: {{ $ctx.app.name | quote }}
  port: {{ $ctx.app.port | quote }}
  release: {{ $ctx.release | quote }}
```

**values.yaml**

```yaml
app:
  name: webshop
  port: 8080
```

**Live-Aufgabe:** Erweitere `$ctx` um `environment` und greife anschließend darauf zu.

## 16 – Helper-Prinzip mit `define`, `template` und `dict`

Einen kleinen wiederverwendbaren Helper definieren und ihm bewusst Kontext übergeben.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=N7C0AIBMFMDMEsB21wCICGAHTA6ANugEbR4DOq4AvpQFDj3ha4DWArsQE7IAu0pO8APYB6ROgC20AFzgQ4HExxjJVWg0bYcbTjz4CRSUt3SIAxtNnB5HQYO44ASiWjpS0HADkJKanQbREADd4G0RJRG4ZOQVNAODQ8O5VGhAIAMhkmix4ADVoDlIhRBlAgEYaZiRIGQBhQUQEAHMAWSwaSWNIdGMpP2ULaKc8FzdPb1VQU3qmvwJiMl65XnFMAl40RTmScnAACkh4UyTUGzsKABIN7AocHPQ8Vj0mAEpkrp6-SVJSdEaLVAAFiRMPkoNBxIJUDQgA&v=IYBxC4CgAJoO2AWwKbmgd2QIwM4AsB7EGaZOANwEsAnAuFOAFzRFoBMBXAY0crsiA)**

**template.yaml**

```yaml
{{- define "app.labels" }}
    app.kubernetes.io/name: {{ .app.name }}
    app.kubernetes.io/instance: {{ .root.Release.Name }}
    environment: {{ .app.environment }}
{{- end }}

apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-config
  labels:
{{ template "app.labels" (dict "root" $ "app" .Values.app) }}
data:
  message: "helper demo"
```

**values.yaml**

```yaml
app:
  name: webshop
  environment: production
```

**Live-Aufgabe:** Im Helper ist `.` genau das `dict`, das beim Aufruf übergeben wurde. Vergleiche `.app` und `.root`.

## 17 – Debugging: aktuellen Kontext sichtbar machen

Mit `toJson` untersuchen, was `.` innerhalb verschiedener Blöcke tatsächlich enthält.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=E4exBcC4AIG9egOmgH2uEApAziAdqtAI4CuEAptAL5UBQ8AtNAO4CW4AFkgGoCGANiXLZEvAA5jqdNpwDC%2BcOQAeUOAmRoMOfIVIUp9WE3J4AJgcbRgvPAHNKiPoOGiJiAGble4EsGEHrO3J5PEUVGHgkQi1cAjQ9RQsjaBNzGlogA&v=IYBxC4CgAJoO2AWwKbmgd2QIwM4AsB7EGaAM2WABcBXAJ2RyllgFpoAbAgcwEs4TW0EMACeKOJUhA)**

**template.yaml**

```yaml
root: {{ . | toJson | quote }}
{{- with .Values.app }}
withContext: {{ . | toJson | quote }}
{{- end }}
{{- range .Values.app.features }}
rangeContext: {{ . | toJson | quote }}
{{- end }}
```

**values.yaml**

```yaml
app:
  name: webshop
  features:
    - login
    - payment
```

**Live-Aufgabe:** Ideal zum Live-Debugging: `toJson .` zeigt direkt, was der Punkt gerade repräsentiert.

## 18 – `toYaml` + `nindent` für komplexe Strukturen

Komplette YAML-Teilbäume aus Values übernehmen, statt jedes Feld einzeln zu templatisieren.

**[▶ Demo im Helm Playground öffnen](https://helm-playground.com/#t=IYBwlgagpgTgzmA9gOwFwAJQjgegG4CMAUANZjIAmGAIlCADaICeAtlMgC5FsfAXC9URdOmTA2GClBaIicEFADGQkR2kMBUFSPTyl2nekUpe5WHAOH0AWlHitogObkAHsKuGwLYI4fJnyC6oBAB0AEwAHO4eIjBQcIgArjCK8UIA3unoIRDA9InxIXEJyalw6AA%2B6ByIAJri9JWi5FKc6ARh6AC%2BXURAA&v=E4Uwzg9grsDG4C4BQACFoCOVwBczLTVgAcoEUBGABioFtVDaRaJgBPcigJgA4BZAJYMANgNoC8BQiTIoArDXqEUTFu3JzugpEA)**

**template.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.28
          resources:
{{ .Values.resources | toYaml | nindent 12 }}
```

**values.yaml**

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

**Live-Aufgabe:** Ergänze oder entferne Limits ausschließlich in `values.yaml`.

## Besonders geeignete Übungen

- **Demo 6:** Fehler erklären und mit `$` reparieren.
- **Demo 9:** Dasselbe Prinzip in `range` selbstständig übertragen.
- **Demo 12:** Nested-Range-Kontext ohne Lösung analysieren.
- **Demo 13:** `$`, `$app` und `.` gleichzeitig erklären.
- **Demo 16:** Bewusst entscheiden, welcher Kontext an einen Helper übergeben wird.
- **Demo 17:** `toJson .` als Debugging-Werkzeug einsetzen.

## Merksatz

> **`.` = Wo bin ich gerade? — `$` = Wo hat das Template angefangen?**
