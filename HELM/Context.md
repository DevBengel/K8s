# Helm Playground – Eskalierende Kontext-Demo

Eine Demo-Serie zum schrittweisen Verständnis von `.`, `$`, `with`, `range` und bewusst gesicherten Parent-Kontexten.

## Gemeinsame Values
```yaml
application:
  name: webshop
  environment: production
  teams:
    - name: frontend
      services:
        - name: web
          ports: [80, 443]
        - name: assets
          ports: [8080]
    - name: backend
      services:
        - name: api
          ports: [8080, 9090]
```

> **Merksatz:** `.` = aktueller Kontext · `$` = Root-Kontext · `$variable` = bewusst gesicherter Kontext

## 1 – Root-Kontext

`.` ist noch der Helm-Root.

**[▶ Demo öffnen](https://helm-playground.com/#t=E4UwNiCGDOIFwAIDeSEDoBK4qzQOUgFsQEBfUgKEgAdrEV0A1SMAVxGjRurAEsBjSABdeAewB2acURLkKIcQDdewCcXFD6qNMzYcutPoJES0C5avHqhZSkA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
release: {{ .Release.Name }}
app: {{ .Values.application.name }}
environment: {{ .Values.application.environment }}
```

## 2 – `with`: erster Kontextwechsel

Innerhalb von `with` ist `.` die Application; `$` bleibt Root.

**[▶ Demo öffnen](https://helm-playground.com/#t=E4exBcCUFMBtoIYGdoC4AEBvT6AkA6GeZafAOQQFtp0BfWgKGwFp0B3AS3AAt18A1BLACu0JPgQAHSbA4BjBOA4gAdnUZTJGbHxVUa9BtBUA3DqBXUV4bTnzGzFq%2BHUNQEIohQBBAOYIOFVs8QjgvUgpqVxZ0YwATVyA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
rootRelease: {{ $.Release.Name }}
{{- with .Values.application }}
app: {{ .name }}
environment: {{ .environment }}
rootReleaseAgain: {{ $.Release.Name }}
{{- end }}
```

## 3 – `range`: Teams

Im `range` ist `.` jeweils das aktuelle Team.

**[▶ Demo öffnen](https://helm-playground.com/#t=N7C0AIHcEsBcAtwDoBqBDANgVwKYGck0AHIjaAYzVmgHsA7cAX0YCgBBEsy6%2BgLnBDI6aALY4mrEBABOaOgHNxSWDlF4JLACqqR-QUmFiNAJRwZVeHHuDgAJElPm0lpADlR45iyngcdACYaPn6BXkA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
{{- with .Values.application }}
Application: {{ .name }}
{{- range .teams }}
Team: {{ .name }}
Release: {{ $.Release.Name }}
{{- end }}
{{- end }}
```

## 4 – Parent sichern

Application wird vor dem Kontextwechsel als `$app` gesichert.

**[▶ Demo öffnen](https://helm-playground.com/#t=N7C0AIHcEsBcAtwDoBqBDANgVwKYGck0AHIjaAYzVmgHsA7cAX0YCgQIASYo8ALgF5kTVu3AAnNHQDmOZLBxoAtnmEsAgiTKVq9XuBDguJJHSWzmLACoLFegybOqASjRqwnODArw47wQ0geXmg%2BSAByjhaiOHQAJqrRcapAA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
{{- with .Values.application }}
{{- $app := . }}
{{- range .teams }}
Application: {{ $app.name }}
Team: {{ .name }}
RootRelease: {{ $.Release.Name }}
{{- end }}
{{- end }}
```

## 5 – Nested Range

Jetzt gleichzeitig: `$`, `$app`, `$team` und `.`.

**[▶ Demo öffnen](https://helm-playground.com/#t=N7C0AIHcEsBcAtwDoBqBDANgVwKYGck0AHIjaAYzVmgHsA7cAX0YCgQIASYo8ALgF5kTVu3AAnNHQDmOZLBxoAtnmFsw4DvKV9BSVaInTZSPDjEA3CvlUBBEr3AgN3JHSWzmLACoLFDp5q%2Bru6qAMpmluQ4-sDIbooerABKOBgKpjEaSClpaKZIAHIhnqClahA4dAAm%2BuqVNZ6i9apAA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
{{- with .Values.application }}
{{- $app := . }}
{{- range .teams }}
{{- $team := . }}
{{- range .services }}
App: {{ $app.name }}
Team: {{ $team.name }}
Service: {{ .name }}
Release: {{ $.Release.Name }}
---
{{- end }}
{{- end }}
{{- end }}
```

## 6 – Boss Fight: Port ist `.`

Im innersten `range` ist `.` nur noch die Portnummer.

**[▶ Demo öffnen](https://helm-playground.com/#t=N7C0AIHcEsBcAtwDoBqBDANgVwKYGck0AHIjaAYzVmgHsA7cAX0YCgQIASYo8ALgF5kTVu3AAnNHQDmOZLBxoAtnmFsw4DvKV9BSVaInTZSPDjEA3Cvn3qOpi1Z1DmaiIZnIiNMbBUuxOBgKpvwgGkgASoHBOEgAckqyLtyhwBrcSHSJqlqKqRq5mdku9pbkOPl2ZmWxWYpJrF4%2B%2BXouoO2u4Dh0ACY2EN19LqKD-V29qkA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
{{- with .Values.application }}
{{- $app := . }}
{{- range .teams }}
{{- $team := . }}
{{- range .services }}
{{- $service := . }}
{{- range .ports }}
release={{ $.Release.Name }}
app={{ $app.name }}
team={{ $team.name }}
service={{ $service.name }}
port={{ . }}
---
{{- end }}
{{- end }}
{{- end }}
{{- end }}
```

## 7 – Absichtlich kaputt

Fehlerübung: Parent-Kontexte gingen verloren. Teilnehmer sollen Variablen und `$` einsetzen.

**[▶ Demo öffnen](https://helm-playground.com/#t=N7C0AIHcEsBcAtwDoBqBDANgVwKYGck0AHIjaAYzVmgHsA7cAX0YCgQIAnNOgcx2Vg40AWzxNW7cF178keHBwBuFfOLZgp3PsiI0OsMcxYAFPbABc4EMjUBlBcvI5L1pHRH8jAFSHCXwZHdhT1YAQRIySmp6f0CPNQAlHAwheVikJJS0eSQAOXijSRw6ABM1ItLyjWKywurKoyA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
{{- with .Values.application }}
{{- range .teams }}
{{- range .services }}
{{- range .ports }}
Port: {{ . }}
Service: {{ .name }}
Team: {{ .name }}
Application: {{ .name }}
Release: {{ .Release.Name }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
```

## 8 – Context Debugger

`toJson` zeigt live, was `.` auf jeder Ebene enthält.

**[▶ Demo öffnen](https://helm-playground.com/#t=EoeRBUF4G9oAgCRwD5wC4HsBSBnDA7FOARwFcM0BTOAXxoChYBaOAdwEs0ALOAOgDUAhgBtSlHL0EAHKcPYBjQWnYFaDAIIAFTQBkAkgGF14PSAByMeLyKZcq1GQrU6jaCwBOg-AHNqvKoIAtjhq9OAAouoAspZ8Nth4hA7kVKHMcJ4%2BfjiU7gBuCuKhAMrhwPyG4bHWqLaJRI6pLumZvnxSGO5oIS6aIMBQsHG1CfYkKc4MoBBMwOE6kaWxCLzAlMKUgjm8ZkHUyU6hTMeuLJT4ACZpbnDnV803d9dnl6FAA&v=IYBxBsEsGNgF0gewHYC4BQACTzgFsBTVTAdwICMBnAC0RC0wOQDdIAnFQ5OYkDgEwCu0BCgZwC%2BShmzYAtDnxFMAMw7cm-BrMyUCbVtALTtOzAtyFiZcqbOYQiNnGmYA2gA4ADABpMAFn8AZgBdO1kLJWJgSj0XcJ1HZ1dPL28wnUirTHJgaABrTXC9AxhjGXtzRWzQSATZJJdiVO8-AE4vDrCgA)**

```gotemplate
ROOT={{ $ | toJson | quote }}
{{- with .Values.application }}
APPLICATION={{ . | toJson | quote }}
{{- range .teams }}
TEAM={{ . | toJson | quote }}
{{- range .services }}
SERVICE={{ . | toJson | quote }}
{{- range .ports }}
PORT={{ . | toJson | quote }}
ROOT-RELEASE={{ $.Release.Name | quote }}
---
{{- end }}
{{- end }}
{{- end }}
{{- end }}
```
