# Demo: Kubernetes Secret vs. Vault Secret (einfachste lauffähige Variante)

## Ziel

Diese Demo zeigt den Unterschied zwischen:

- **klassischen Kubernetes Secrets**
- **dynamischem Secret-Abruf aus Vault**

Am Ende läuft ein Pod, der **sein Secret nicht aus einem Kubernetes Secret**, sondern **direkt aus Vault** holt.

---

## Voraussetzungen

- Ein laufender Kubernetes-Cluster
- `kubectl` funktioniert mit Cluster-Admin-Rechten
- Docker ist installiert
- Internetzugriff zum Ziehen der Container-Images
- Die folgenden Befehle werden auf dem **Control-Plane-Host** oder einem Host mit Zugriff auf:
  - Kubernetes API
  - Docker
  - Vault-Port `8200`

> Diese Demo nutzt **Vault im Dev-Modus**.
> Das ist absichtlich einfach und **nicht produktionsgeeignet**.

---

## Architektur

```text
+---------------------------+
| Kubernetes Cluster        |
|                           |
|  Pod (demo-client)        |
|   |                       |
|   | ServiceAccount JWT    |
|   v                       |
+---------------------------+
            |
            v
+---------------------------+
| Vault (Docker, Dev Mode)  |
|   - Kubernetes Auth       |
|   - KV Secret             |
+---------------------------+
