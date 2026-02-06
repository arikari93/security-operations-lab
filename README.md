# Raspberry Pi Security Sentinel: NIDS & DNS-Hole Lab

A dedicated Network Security Monitoring (NSM) environment utilizing a Raspberry Pi 5 to provide deep packet inspection (DPI) and network-wide DNS filtering. This project demonstrates the transition from a passive hardware state to an active-detection NIDS.

## 🛡️ Technical Stack
* **Hardware:** Raspberry Pi 5 (8GB) with active cooling
* **OS:** Debian Bookworm
* **NIDS:** Suricata (Ingesting 48,140 ET Open Rules)
* **DNS Filter:** Pi-hole
* **Analysis:** EveBox

## 🛠️ Engineering Accomplishments

### 1. NIDS Engine Remediation (The "Silent Engine" Fix)
**Problem:** Initial deployment resulted in 0 active rules despite successful updates via `suricata-update`.
**Diagnosis:** Utilized verbose logging (`suricata -T`) to identify a path-ingestion mismatch between default configs and the ruleset destination.
**Resolution:** Reconfigured `suricata.yaml` with absolute paths for signature files.
**Result:** Successfully restored the engine to a 100% ingestion state (48,140 signatures).

### 2. Live Alert Validation & Analysis
Validated the detection pipeline by capturing real-world telemetry during a system update.

* **Detection:** `ET POLICY GNU/Linux APT User-Agent Outbound`
* **Context:** Detected standard Debian package management traffic from local node `192.168.1.177` to `deb.debian.org`.
* **Significance:** Confirms the engine is successfully parsing HTTP User-Agents and matching against the Emerging Threats (ET) policy ruleset.

## ❄️ Hardware & Thermal Management
To support continuous deep packet inspection, the Raspberry Pi 5 hardware has been optimized:
* **Thermal Control:** Custom PWM fan curves configured via `config.txt`.
* **Verification:** `vcgencmd measure_temp` used to ensure stable operation under high CPU load during signature matching.

---
**License:** MIT
**Project Lead:** Ari Said
