# Kubernetes Security Reference

Diese Seite sammelt wichtige Referenzen, Guides und Tools rund um Kubernetes-Security.  
Die Links sind nach Security-Domänen strukturiert.

---

# 1. Security Frameworks & Hardening Guides

| Ressource | Beschreibung |
|-----------|--------------|
| [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html) | OWASP Best Practices zur Absicherung von Kubernetes-Clustern |
| [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) | Offizielle Kubernetes-Checkliste für grundlegende Sicherheitsmaßnahmen |
| [NSA / CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) | Hardening-Guide für Kubernetes-Cluster |
| [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) | Industriestandard für sichere Kubernetes-Konfiguration |
| [CNCF Kubernetes Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/CNCF_cloud-native-security-whitepaper-Nov2022.pdf) | Überblick über Security-Architekturen in Cloud-Native Umgebungen |

---

# 2. Kubernetes Native Security

| Ressource | Beschreibung |
|-----------|--------------|
| [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) | Offizielle Security-Dokumentation |
| [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) | Rollenbasierte Zugriffskontrolle |
| [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | Nachfolger von PodSecurityPolicy |
| [Secrets Management](https://kubernetes.io/docs/concepts/configuration/secret/) | Verwaltung sensibler Daten |
| [Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) | Kontrolle von Ressourcen beim Deployment |

---

# 3. Policy Enforcement

| Ressource | Beschreibung |
|-----------|--------------|
| [Kyverno](https://kyverno.io/) | Kubernetes-native Policy Engine |
| [Open Policy Agent](https://www.openpolicyagent.org/) | Policy Framework für Kubernetes |
| [Gatekeeper](https://github.com/open-policy-agent/gatekeeper) | OPA-basierte Policy Enforcement Engine |
| [Kyverno Policy Library](https://kyverno.io/policies/) | Sammlung von Security-Policies |

---

# 4. Container & Image Security

| Ressource | Beschreibung |
|-----------|--------------|
| [Trivy](https://github.com/aquasecurity/trivy) | Scanner für Container-Images und Filesysteme |
| [Clair](https://github.com/quay/clair) | Container Vulnerability Scanner |
| [Anchore](https://anchore.com/) | Container Security Plattform |
| [Docker Bench Security](https://github.com/docker/docker-bench-security) | Sicherheitschecks für Docker Hosts |

---

# 5. Supply Chain Security

| Ressource | Beschreibung |
|-----------|--------------|
| [Sigstore](https://sigstore.dev/) | Framework für sichere Softwarelieferketten |
| [Cosign](https://github.com/sigstore/cosign) | Signierung von Container-Images |
| [SLSA Framework](https://slsa.dev/) | Supply Chain Security Framework |
| [in-toto](https://in-toto.io/) | Nachverfolgbarkeit von Software-Artefakten |

---

# 6. Runtime Security

| Ressource | Beschreibung |
|-----------|--------------|
| [Falco](https://falco.org/) | Runtime Security Monitoring für Container |
| [Tetragon](https://github.com/cilium/tetragon) | eBPF-basierte Runtime Security |
| [Tracee](https://github.com/aquasecurity/tracee) | Runtime Security mit eBPF |
| [KubeArmor](https://github.com/kubearmor/KubeArmor) | Runtime Security Enforcement |

---

# 7. Cluster Security Scanning

| Ressource | Beschreibung |
|-----------|--------------|
| [kube-bench](https://github.com/aquasecurity/kube-bench) | Prüft Cluster gegen CIS Benchmark |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Simuliert Angriffe auf Kubernetes |
| [Polaris](https://github.com/FairwindsOps/polaris) | Best Practice Validator |
| [Kubescape](https://github.com/kubescape/kubescape) | Kubernetes Security Scanner |

---

# 8. Threat Modeling & Attack Frameworks

| Ressource | Beschreibung |
|-----------|--------------|
| [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) | Angriffstechniken für Container |
| [Kubernetes Threat Matrix](https://github.com/cncf/tag-security/tree/main/community/resources/threat-modeling) | Bedrohungsmodell für Kubernetes |
| [Container Security Threat Map](https://github.com/inguardians/container-threat-matrix) | Übersicht über Container-Angriffe |

---

# 9. Netzwerk Security

| Ressource | Beschreibung |
|-----------|--------------|
| [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | Segmentierung von Netzwerkverkehr |
| [Cilium](https://cilium.io/) | eBPF-basierte Netzwerk-Security |
| [Calico](https://www.tigera.io/project-calico/) | Network Policy und Netzwerk-Security |
| [Istio Security](https://istio.io/latest/docs/concepts/security/) | Service Mesh Security |

---

# 10. Secrets Management

| Ressource | Beschreibung |
|-----------|--------------|
| [HashiCorp Vault](https://www.vaultproject.io/) | Secret Management Plattform |
| [External Secrets Operator](https://external-secrets.io/) | Integration externer Secret-Stores |
| [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | Verschlüsselte Kubernetes Secrets |

---
