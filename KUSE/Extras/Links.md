# Kubernetes Security Landscape

Diese Übersicht sammelt wichtige Referenzen, Frameworks und Tools rund um Kubernetes-Security.  
Die Ressourcen sind nach Sicherheitsdomänen strukturiert.

---

# 1. Foundations, Hardening & Baselines

| Ressource | Beschreibung |
|-----------|--------------|
| [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) | Offizielle Sicherheits-Checkliste für Cluster-Betreiber |
| [Kubernetes Application Security Checklist](https://kubernetes.io/docs/concepts/security/application-security-checklist/) | Security-Empfehlungen für Anwendungen auf Kubernetes |
| [Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) | Praktische Anleitung zur Cluster-Absicherung |
| [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html) | Best Practices für Kubernetes-Sicherheit |
| [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) | Industriestandard für sichere Kubernetes-Konfiguration |
| [NSA / CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) | Hardening-Empfehlungen für produktive Kubernetes-Cluster |

---

# 2. Identity, Access & Control Plane Security

| Ressource | Beschreibung |
|-----------|--------------|
| [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) | Rollenbasierte Zugriffskontrolle |
| [Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) | Kontrolle und Validierung von Ressourcen |
| [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | Sicherheitsprofile für Pods |
| [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) | Native Verwaltung sensibler Daten |
| [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) | Überblick über Kubernetes-Sicherheitsfunktionen |

---

# 3. Policy Enforcement

| Tool | Beschreibung |
|------|--------------|
| [Kyverno](https://kyverno.io/) | Kubernetes-native Policy Engine |
| [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) | Framework zur Durchsetzung von Policies |
| [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) | Admission Controller für Policy Enforcement |
| [Kyverno Policy Library](https://kyverno.io/policies/) | Sammlung von Security-Policies |

---

# 4. Container & Image Security

| Tool | Beschreibung |
|------|--------------|
| [Trivy](https://github.com/aquasecurity/trivy) | Scanner für Container-Images und Kubernetes |
| [Clair](https://github.com/quay/clair) | Analyse von Container-Images auf Schwachstellen |
| [Anchore](https://anchore.com/) | Container Security Plattform |
| [Docker Bench Security](https://github.com/docker/docker-bench-security) | Best-Practice Checks für Docker Hosts |
| [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | Best Practices für Container-Sicherheit |

---

# 5. Supply Chain Security

| Tool / Framework | Beschreibung |
|------------------|--------------|
| [Sigstore](https://www.sigstore.dev/) | Framework für sichere Software-Lieferketten |
| [Cosign](https://docs.sigstore.dev/cosign/) | Signierung und Verifikation von Container-Images |
| [SLSA Framework](https://slsa.dev/) | Reifegradmodell für sichere Softwarelieferketten |
| [in-toto](https://in-toto.io/) | Nachvollziehbarkeit von Software-Build-Prozessen |

---

# 6. Runtime Security

| Tool | Beschreibung |
|------|--------------|
| [Falco](https://falco.org/) | Runtime Security Monitoring für Container |
| [Tetragon](https://github.com/cilium/tetragon) | eBPF-basierte Runtime Security |
| [Tracee](https://github.com/aquasecurity/tracee) | Laufzeit-Analyse von Container-Aktivitäten |
| [KubeArmor](https://github.com/kubearmor/KubeArmor) | Runtime Security Enforcement |

---

# 7. Cluster Security Scanning

| Tool | Beschreibung |
|------|--------------|
| [kube-bench](https://github.com/aquasecurity/kube-bench) | Prüfung gegen den CIS Kubernetes Benchmark |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Simulation von Angriffen auf Kubernetes |
| [Polaris](https://github.com/FairwindsOps/polaris) | Validierung von Kubernetes Best Practices |
| [Kubescape](https://github.com/kubescape/kubescape) | Kubernetes Security und Compliance Scanner |

---

# 8. Network Security

| Tool / Ressource | Beschreibung |
|------------------|--------------|
| [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | Netzwerksegmentierung im Cluster |
| [Cilium](https://cilium.io/) | eBPF-basierte Netzwerk-Security |
| [Calico](https://www.tigera.io/project-calico/) | Network Policies und Netzwerksegmentierung |
| [Istio Security](https://istio.io/latest/docs/concepts/security/) | Service Mesh Security und mTLS |

---

# 9. Secrets Management

| Tool | Beschreibung |
|------|--------------|
| [HashiCorp Vault](https://www.vaultproject.io/) | Plattform für Secret- und Key-Management |
| [External Secrets Operator](https://external-secrets.io/) | Integration externer Secret Stores |
| [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | Verschlüsselte Kubernetes-Secrets für GitOps |
| [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | Best Practices für Secrets |

---

# 10. Threat Modeling & Angriffstechniken

| Ressource | Beschreibung |
|-----------|--------------|
| [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) | Angriffstechniken für Container-Umgebungen |
| [CNCF Threat Modeling Resources](https://github.com/cncf/tag-security/tree/main/community/resources/threat-modeling) | Ressourcen für Bedrohungsanalysen |
| [Container Threat Matrix](https://github.com/inguardians/container-threat-matrix) | Übersicht über typische Container-Angriffe |

---

# 11. Security Advisories & Operations

| Ressource | Beschreibung |
|-----------|--------------|
| [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/) | Offizielle Kubernetes-Sicherheitsmeldungen |
| [Kubernetes Security Tutorials](https://kubernetes.io/docs/tutorials/security/) | Praxisnahe Sicherheits-Tutorials |
| [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) | Übersicht über Security-Funktionen |
