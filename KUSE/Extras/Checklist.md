# 🔐 Kubernetes Security Assessment Framework (KUSE)

> Bewertungssystem für Kubernetes-Sicherheit basierend auf Defense in Depth

---

## 📊 Bewertungsmodell

| Score | Bedeutung |
|------|----------|
| 0 | ❌ Nicht umgesetzt |
| 1 | ⚠️ Teilweise umgesetzt |
| 2 | ✅ Standard umgesetzt |
| 3 | 🔒 Härtung / Best Practice |

👉 Ziel:
- < 40% → kritisch  
- 40–70% → mittel  
- > 70% → gut  

---

## 🔵 Control Plane Security

| Check | Score (0–3) |
|------|-----------|
| API nur über TLS erreichbar | [ ] |
| Starke Authentifizierung (keine Anonymous Requests) | [ ] |
| API-Zugriff eingeschränkt (Firewall / LB) | [ ] |
| etcd nicht öffentlich erreichbar | [ ] |
| etcd verschlüsselt (Encryption at Rest) | [ ] |

---

## 🟢 Node / Host Security

| Check | Score |
|------|------|
| Minimal OS installiert | [ ] |
| Regelmäßige Security Updates | [ ] |
| SSH Zugriff eingeschränkt | [ ] |
| Container Runtime aktuell | [ ] |
| Keine privilegierten Host Mounts | [ ] |

---

## 🟣 IAM / RBAC

| Check | Score |
|------|------|
| Least Privilege umgesetzt | [ ] |
| Keine unnötigen ClusterRoles | [ ] |
| Keine Cluster-Admin Nutzung im Alltag | [ ] |
| ServiceAccounts restriktiv | [ ] |
| kubectl auth can-i geprüft | [ ] |

---

## 🟠 Pod & Workload Security

| Check | Score |
|------|------|
| runAsNonRoot: true gesetzt | [ ] |
| securityContext definiert | [ ] |
| Pod Security = Restricted | [ ] |
| Keine unnötigen Capabilities | [ ] |
| Keine privileged Pods | [ ] |

---

## 🔴 Network Security (Zero Trust)

| Check | Score |
|------|------|
| Default Deny aktiv | [ ] |
| NetworkPolicies vorhanden | [ ] |
| Kommunikation explizit definiert | [ ] |
| Namespace Isolation vorhanden | [ ] |
| Keine IP-basierte Logik (nur Labels) | [ ] |

---

## 🟡 Secrets Management

| Check | Score |
|------|------|
| Secrets nicht im Klartext | [ ] |
| Zugriff restriktiv | [ ] |
| Rotation vorhanden | [ ] |
| Externer Secret Store (optional) | [ ] |

---

## 🟤 Supply Chain Security

| Check | Score |
|------|------|
| Keine :latest Images | [ ] |
| Image Scanning aktiv | [ ] |
| Vertrauenswürdige Registry | [ ] |
| Image Signaturen genutzt | [ ] |

---

## 🟦 Policy Enforcement

| Check | Score |
|------|------|
| Admission Controller aktiv | [ ] |
| Sicherheitsregeln definiert | [ ] |
| Unsichere Pods werden blockiert | [ ] |
| Policy Engine (z. B. Kyverno) im Einsatz | [ ] |

---

## 🔶 Runtime Security

| Check | Score |
|------|------|
| Runtime Monitoring aktiv | [ ] |
| Anomalieerkennung vorhanden | [ ] |
| Security Events sichtbar | [ ] |

---

## ⚫ Observability & Incident Response

| Check | Score |
|------|------|
| Audit Logs aktiviert | [ ] |
| Logs zentral gesammelt | [ ] |
| Alerting vorhanden | [ ] |
| Incident Response definiert | [ ] |

---

## 🟩 Backup & Disaster Recovery

| Check | Score |
|------|------|
| etcd Backups vorhanden | [ ] |
| PV Backups vorhanden | [ ] |
| Restore getestet | [ ] |

---

## ⚙️ Governance & Operations

| Check | Score |
|------|------|
| Deployment-Prozesse definiert | [ ] |
| Änderungen nachvollziehbar | [ ] |
| Patch-Management aktiv | [ ] |
| Konfigurationskontrolle vorhanden | [ ] |

---

## 🧠 Gesamtauswertung

Gesamtpunkte = Summe aller Checks  
Maximalpunkte = Anzahl Checks × 3  

Security Level = (Gesamtpunkte / Maximalpunkte) × 100  

---

## 🚦 Bewertung

| Score | Bewertung |
|------|----------|
| 🔴 < 40% | Kritisch |
| 🟡 40–70% | Verbesserungsbedarf |
| 🟢 > 70% | Gut |
| 🔒 > 85% | Enterprise Ready |

---

> Kubernetes ist nicht „sicher oder unsicher“ – sondern ein System, dessen Sicherheitsniveau sich direkt aus den getroffenen Architekturentscheidungen ergibt.
