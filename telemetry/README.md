# Telemetry Data Samples

This directory contains sanitized example logs and telemetry data demonstrating the detection and monitoring capabilities of the Raspberry Pi Security Operations Lab.

## 📊 Contents

### `sample-alerts.json`
**Purpose:** Example Suricata alert events from the NIDS  
**Source:** /var/log/suricata/eve.json (sanitized)  
**Period:** 48-hour sample (2026-02-09 to 2026-02-11)  
**Format:** JSON Lines (one alert per line)

**Alert Types Included:**
- PowerShell User-Agent detection (ET INFO)
- SSH scanning attempts (ET SCAN)
- APT package manager activity (ET POLICY)
- Suspicious user agents (ET USER_AGENTS)
- Local File Inclusion attempts (ET WEB_SERVER)
- Custom rule detections (CUSTOM rules SID 9000xxx)

**Data Sanitization:**
- All IP addresses anonymized to RFC1918 private ranges
- Timestamps preserved for temporal analysis
- Alert metadata and signatures retained
- Flow statistics included for context

---

### `sample-uptime-log.txt`
**Purpose:** Demonstrates uptime tracking and service monitoring  
**Source:** /var/log/nids-uptime.log (sanitized)  
**Period:** 7-day sample (2026-02-05 to 2026-02-11)  
**Check Interval:** Every 30 minutes

**Metrics Included:**
- Service status checks (Suricata, Wazuh, Pi-hole, Nginx)
- Operational status logging
- Failure detection example (1 brief Wazuh outage)
- Weekly summary statistics

**Calculated Metrics:**
- Total Checks: 336 over 7 days
- Successful: 335 (99.70% uptime)
- Failed: 1 (30-minute recovery time)
- MTBF: 168 hours
- MTTR: 30 minutes

**Demonstrates:**
- Consistent monitoring execution
- Failure detection capabilities
- Recovery tracking
- High availability (99.70% uptime)

---

### `sample-health-checks.txt`
**Purpose:** Example outputs from automated health check script  
**Source:** health-check.sh execution logs  
**States Shown:** Healthy, Degraded, Critical

**Example 1: HEALTHY State**
- All 15 component checks passing
- All services operational
- System resources normal
- Network capture active

**Example 2: DEGRADED State**
- 14 checks passing, 1 warning
- Promiscuous mode disabled (port mirroring issue)
- Services still operational
- Action required but not critical

**Example 3: CRITICAL State**
- 2 critical failures detected
- Suricata not running
- Log generation stopped
- Immediate action required

**Demonstrates:**
- Multi-component health verification
- Color-coded status indicators
- Severity classification
- Actionable status reporting

---

## 🔒 Privacy & Security

### Data Sanitization Applied:
✅ **IP Addresses:** All IPs changed to RFC1918 private ranges (192.168.x.x)  
✅ **Hostnames:** Generic names used (no real device identifiers)  
✅ **Timestamps:** Preserved for analysis but adjusted to sample period  
✅ **External IPs:** Public IPs retained only where necessary (testmyids.com)

### What's NOT Included:
❌ Real internal IP addresses  
❌ Actual network topology details  
❌ Production passwords or credentials  
❌ Full packet captures (privacy concern)  
❌ Personally identifiable information

---

## 📈 Usage

### For Portfolio Reviewers:
These samples demonstrate:
1. **Detection Capabilities:** Variety of alert types and signatures
2. **Monitoring Automation:** Consistent uptime tracking
3. **Health Verification:** Multi-component status checks
4. **Operational Maturity:** Production-grade logging and metrics

### For Lab Replication:
These samples show:
1. **Expected Output Formats:** What successful detection looks like
2. **Alert Volume:** Realistic traffic patterns
3. **System Behavior:** Normal vs. degraded vs. critical states
4. **Metric Collection:** Data points for uptime validation

### For Interview Preparation:
Use these samples to discuss:
1. **Signature Tuning:** Why certain alerts fired
2. **False Positive Analysis:** Distinguishing real threats from noise
3. **Troubleshooting:** How degraded states were identified
4. **Recovery Procedures:** MTTR and service restoration

---

## 🎯 Real-World Context

### Alert Statistics (7-Day Period)
- **Total Alerts:** 156 (avg 22/day)
- **Severity 1 (High):** 12 alerts (7.7%)
- **Severity 2 (Medium):** 45 alerts (28.8%)
- **Severity 3 (Low/Info):** 99 alerts (63.5%)

**Top Alert Categories:**
1. Potentially Bad Traffic: 58%
2. Attempted Information Leak: 18%
3. Web Application Attack: 12%
4. Policy Violation: 8%
5. Protocol Command Decode: 4%

**Custom Rule Performance:**
- SID 9000001 (PowerShell Download): 8 hits
- SID 9000002 (DNS Tunneling): 3 hits
- SID 9000003 (SMB Non-Standard Port): 2 hits

### System Reliability
- **Uptime:** 99.70% over 7 days
- **Downtime:** 30 minutes (single Wazuh agent restart)
- **MTBF:** 168 hours (7 days)
- **MTTR:** 30 minutes (automated recovery)

### Resource Utilization
- **CPU Temp:** 28-45°C (well within safe range)
- **Memory:** 24-32% (stable, no leaks)
- **Disk:** 8-11% (sustainable growth rate)
- **Log Size:** ~1GB/week (manageable)

---

## 📝 Notes

### About These Samples:
- These are **real outputs** from the actual lab environment
- Data has been **sanitized** for public sharing
- Timestamps are **adjusted** to a sample period for consistency
- Alert signatures and detection logic are **authentic**

### Limitations:
- Samples represent a **snapshot** of lab activity
- Not comprehensive coverage of all possible alert types
- Some rare/advanced detections may not be represented
- Production environments would have higher volume

### Future Additions:
Planned sample data to add:
- DNS query logs (Pi-hole telemetry)
- Traffic flow statistics
- Bandwidth utilization graphs
- Alert correlation examples
- Incident timeline reconstructions

---

## 🔗 Related Documentation

- **Detection Rules:** [../docs/DETECTION_RULES.md](../docs/DETECTION_RULES.md)
- **Analysis Report:** [../docs/ANALYSIS_REPORT.md](../docs/ANALYSIS_REPORT.md)
- **SOC Operations:** [../docs/SOC_DAILY_OPERATIONS.md](../docs/SOC_DAILY_OPERATIONS.md)
- **Troubleshooting:** [../docs/TROUBLESHOOTING.md](../docs/TROUBLESHOOTING.md)

---

## ⚖️ Disclaimer

This telemetry data is provided for **educational and portfolio purposes only**. All activity was conducted in an **authorized laboratory environment** on **privately-owned infrastructure**. No unauthorized network access or malicious activity was performed.

The detection signatures and monitoring capabilities demonstrated here are intended to showcase **defensive security operations** and **system reliability engineering** practices.

---

**Last Updated:** February 11, 2026  
**Lab Version:** 1.2  
**Data Period:** 7-day sample (Feb 5-11, 2026)
