# Raspberry Pi Security Sentinel: NIDS & DNS-Hole Lab

A dedicated Network Security Monitoring (NSM) environment utilizing a Raspberry Pi 5 to provide deep packet inspection (DPI) and network-wide DNS filtering. This project demonstrates the transition from a passive hardware state to an active-detection NIDS and a hardened management gateway.

## 🛡️ Technical Stack
* **Hardware:** Raspberry Pi 5 (8GB) with active cooling
* **OS:** Debian Bookworm
* **NIDS:** Suricata (Ingesting 48,140 ET Open Rules)
* **DNS Filter:** Pi-hole v6.0 (Integrated FTL Engine)
* **Web Gateway:** Nginx (Reverse Proxy & TLS Termination)
* **Analysis:** EveBox

## 🛠️ Engineering Accomplishments

### 1. NIDS Engine Remediation (The "Silent Engine" Fix)
* **Problem:** Initial deployment resulted in 0 active rules despite successful updates.
* **Diagnosis:** Utilized verbose logging (`suricata -T`) to identify path-ingestion mismatch.
* **Resolution:** Reconfigured `suricata.yaml` with absolute paths for signature files.
* **Result:** Successfully restored the engine to a 100% ingestion state (48,140 signatures).

### 2. Secure Gateway & Service Orchestration
To resolve port contention and harden the management interface, the lab was evolved into a Reverse Proxy architecture.
* **Port Segregation:** Migrated Pi-hole to v6.0 and reconfigured the FTL web engine to listen on Port 8080, freeing Port 80/443 for external traffic.
* **TLS Implementation:** Generated and deployed a 2048-bit RSA self-signed certificate to enable HTTPS across all management interfaces.
* **Reverse Proxy:** Configured Nginx to encapsulate the Pi-hole dashboard via a secure tunnel, enabling access through `https://<IP>/admin` while isolating the internal port.

### 3. Live Alert Validation & Analysis
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
