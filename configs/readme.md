# Configuration Files

This directory contains sanitized configuration files demonstrating the key customizations made to the security lab infrastructure.

## 📁 Files Included

### `suricata.yaml`
**Purpose:** Network Intrusion Detection System configuration  
**Key Modifications:**
- Network ranges configured for lab environment (192.168.1.0/24)
- AF-PACKET optimized for SPAN port traffic capture
- Rule path fix (the "Silent Engine" solution)
- Performance tuning for Raspberry Pi hardware
- Community ID enabled for cross-tool correlation
- Disabled unused protocols (HTTP/2, Modbus, DNP3) to reduce CPU load

**Critical Settings:**
```yaml
# The fix that solved the zero-alert issue
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/custom/homelab.rules
```

---

### `nginx-homelab.conf`
**Purpose:** Reverse proxy for unified HTTPS gateway  
**Key Features:**
- TLS termination with self-signed certificates
- Reverse proxy to Pi-hole admin (port 8080)
- Reverse proxy to EveBox alerts (port 5636)
- Security headers (HSTS, X-Frame-Options, etc.)
- HTTP to HTTPS redirect
- Custom landing page at root URL

**Security Architecture:**
```
[Internet/LAN] → [Nginx :443 HTTPS] → [Localhost Services]
                                     ├─ Pi-hole :8080
                                     └─ EveBox :5636
```

All backend services bound to 127.0.0.1 (not externally accessible).

---

### `wazuh-ossec.conf`
**Purpose:** Wazuh agent configuration for SIEM integration  
**Key Features:**
- Suricata eve.json log forwarding (JSON format)
- Authentication log monitoring (SSH brute force detection)
- File integrity monitoring on critical directories
- System configuration assessment (SCA)
- Rootkit detection
- Custom labels for agent identification

**Critical Integration:**
```xml
<!-- This sends Suricata alerts to Wazuh SIEM -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

---

## 🔒 Security Notes

### Sanitization Applied:
✅ **Generic IP addresses** used (192.168.1.0/24 lab network)  
✅ **No real passwords** or API keys  
✅ **No unique hostnames** that could identify specific systems  
✅ **Standard ports** documented (publicly known defaults)

### What's Safe to Share:
- Configuration structure and syntax
- Performance tuning decisions
- Integration methods
- Troubleshooting approaches
- Security hardening techniques

### What's NOT Included:
- Real internal IP addresses
- Actual SSL certificates or private keys
- Specific hardware identifiers
- Production secrets or tokens

---

## 📚 Usage Guide

### How to Use These Configs:

1. **Review before deploying** - Understand each setting
2. **Customize for your environment:**
   - Update IP addresses to match your network
   - Adjust memory limits based on available RAM
   - Modify file paths if using different installation
3. **Test thoroughly** - Use `nginx -t` or `suricata -T` before applying
4. **Back up originals** - Always keep copies of default configs

### Quick Deployment:

```bash
# Suricata
sudo cp suricata.yaml /etc/suricata/suricata.yaml
sudo suricata -T -c /etc/suricata/suricata.yaml  # Test first!
sudo systemctl restart suricata

# Nginx
sudo cp nginx-homelab.conf /etc/nginx/sites-available/homelab
sudo ln -s /etc/nginx/sites-available/homelab /etc/nginx/sites-enabled/
sudo nginx -t  # Test first!
sudo systemctl reload nginx

# Wazuh
sudo cp wazuh-ossec.conf /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-control restart
```

---

## 🎯 Configuration Highlights

### Performance Optimizations:
- **Suricata:** Memory limits tuned for 8GB RAM (128MB stream/flow memcap)
- **Suricata:** Thread affinity configured for quad-core Pi
- **Nginx:** Connection limits and timeouts adjusted
- **Wazuh:** Buffer sizes optimized for event throughput

### Security Hardening:
- **Nginx:** Modern TLS protocols only (TLSv1.2+)
- **Nginx:** Security headers (HSTS, CSP, X-Frame-Options)
- **Suricata:** Promiscuous mode for SPAN port capture
- **Wazuh:** File integrity monitoring on critical paths

### Integration Points:
- **Suricata → Wazuh:** JSON event forwarding via eve.json
- **Pi-hole → Nginx:** Reverse proxy on port 8080
- **EveBox → Nginx:** Alert viewer on port 5636

---

## 🔧 Troubleshooting

### Common Issues:

**Suricata not generating alerts?**
- Check `default-rule-path` points to `/var/lib/suricata/rules`
- Verify rules loaded: `sudo suricatasc -c ruleset-stats`
- Ensure interface is in promiscuous mode: `ip link show eth0`

**Nginx 502 Bad Gateway?**
- Verify backend services are running: `systemctl status pihole-FTL`
- Check if ports are listening: `netstat -tulpn | grep 8080`
- Review error log: `tail -f /var/log/nginx/error.log`

**Wazuh agent not connecting?**
- Confirm manager IP is correct in ossec.conf
- Check firewall allows port 1514/tcp
- Verify agent status: `systemctl status wazuh-agent`
- Review logs: `tail -f /var/ossec/logs/ossec.log`

---

## 📖 Additional Resources

- **Suricata Documentation:** https://suricata.readthedocs.io/
- **Nginx Documentation:** https://nginx.org/en/docs/
- **Wazuh Documentation:** https://documentation.wazuh.com/
- **Project Setup Guide:** [../docs/SETUP.md](../docs/SETUP.md)
- **Troubleshooting Guide:** [../docs/TROUBLESHOOTING.md](../docs/TROUBLESHOOTING.md)

---

## ⚖️ License

These configuration files are provided under the MIT License as part of the Raspberry Pi Security Sentinel project. They are sanitized examples for educational purposes.

**Use responsibly and only in authorized lab environments.**
