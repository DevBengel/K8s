# Kubernetes Security – Linksammlung

Diese Sammlung enthält hilfreiche Ressourcen rund um Kubernetes Security, Hardening, Tools und reale Sicherheitsvorfälle.

---

# Grundlagen & Security Guides

| Thema | Link |
|------|------|
| OWASP Kubernetes Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html |
| Kubernetes Security Best Practices | https://kubernetes.io/docs/concepts/security/ |
| Kubernetes Security Announcements | https://kubernetes.io/docs/reference/issues-security/security/ |
| Kubernetes Security CVE Feed | https://kubernetes.io/docs/reference/issues-security/official-cve-feed/ |
| CIS Kubernetes Benchmark | https://www.cisecurity.org/benchmark/kubernetes |
| Kubernetes Hardening Guide | https://github.com/kubernetes/community/blob/master/contributors/devel/sig-security/security-hardening-guide.md |
| NSA / CISA Kubernetes Hardening Guidance | https://www.cisa.gov/news-events/analysis-reports/kubernetes-hardening-guidance |

---

# Kubernetes Security Tools

| Tool | Beschreibung | Link |
|-----|--------------|------|
| Falco | Runtime Security Detection für Container und Kubernetes | https://falco.org |
| Trivy | Container & Kubernetes Vulnerability Scanner | https://github.com/aquasecurity/trivy |
| kube-bench | CIS Benchmark Scanner für Kubernetes | https://github.com/aquasecurity/kube-bench |
| kube-hunter | Penetration Testing Tool für Kubernetes | https://github.com/aquasecurity/kube-hunter |
| Kubescape | Security Posture & Compliance Scanner | https://github.com/kubescape/kubescape |
| Checkov | IaC Security Scanner für Kubernetes Manifeste | https://github.com/bridgecrewio/checkov |

---

# Policy Engines & Governance

| Tool | Beschreibung | Link |
|-----|--------------|------|
| Kyverno | Kubernetes Policy Engine | https://kyverno.io |
| Open Policy Agent (OPA) | Policy Engine für Cloud-native Systeme | https://www.openpolicyagent.org |
| OPA Gatekeeper | OPA-basierter Admission Controller | https://github.com/open-policy-agent/gatekeeper |

---

# Pentesting & Security Analyse Tools

| Tool | Beschreibung | Link |
|-----|--------------|------|
| Peirates | Kubernetes Post-Exploitation Tool | https://github.com/inguardians/peirates |
| kdigger | Kubernetes Privilege Escalation Scanner | https://github.com/quarkslab/kdigger |
| KubiScan | RBAC Risk Analysis Tool | https://github.com/cyberark/KubiScan |

---

# Runtime Security & Observability

| Tool | Beschreibung | Link |
|-----|--------------|------|
| Falco Sidekick | Alert Forwarding für Falco | https://github.com/falcosecurity/falcosidekick |
| Tetragon | eBPF-basierte Runtime Security | https://github.com/cilium/tetragon |
| Cilium | Networking, eBPF Security & Observability | https://cilium.io |

---

# Supply Chain Security

| Tool | Beschreibung | Link |
|-----|--------------|------|
| Cosign | Container Image Signing | https://github.com/sigstore/cosign |
| Sigstore | Secure Software Supply Chain | https://www.sigstore.dev |
| SLSA Framework | Supply Chain Security Framework | https://slsa.dev |

---

# Reale Cloud & Kubernetes Security Incidents

| Quelle | Beschreibung | Link |
|------|--------------|------|
| Cloud Vulnerability Database | Sammlung realer Cloud Security Incidents | https://www.cloudvulndb.org |
| AWS Customer Security Incidents | Sammlung realer Cloud Incidents | https://github.com/ramimac/aws-customer-security-incidents |
| The Hacker News – Kubernetes | Aktuelle Kubernetes Angriffe | https://thehackernews.com/search/label/Kubernetes |
