# Snort Challenge — LFI, Credential Theft & Data Exfiltration Investigation

> **Scenario:** The SOC team at Oinksoft suspects that one of their web servers was compromised via a Local File Inclusion (LFI) vulnerability. DLP alerts triggered around the same timeframe, indicating sensitive file exfiltration. This investigation uses custom Snort IDS rules applied to a provided PCAP to reconstruct the full attack chain.

---

## Table of Contents

- [Environment & Tools](#environment--tools)
- [Attack Timeline](#attack-timeline)
- [Investigation](#investigation)
  - [Q1 — Suspicious User-Agent / Brute Force Tool](#q1--suspicious-user-agent--brute-force-tool)
  - [Q2 — Failed Login Attempts (HTTP 401)](#q2--failed-login-attempts-http-401)
  - [Q3 — Successful Login (HTTP 302) — UNIX Epoch Timestamp](#q3--successful-login-http-302--unix-epoch-timestamp)
  - [Q4 — LFI Directory Traversal Detection](#q4--lfi-directory-traversal-detection)
  - [Q5 — OpenSSH Private Key Exfiltration via HTTP](#q5--openssh-private-key-exfiltration-via-http)
  - [Q6 — Outbound FTP Exfiltration & ASN Lookup](#q6--outbound-ftp-exfiltration--asn-lookup)
- [IOC Table](#ioc-table)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Snort Rules Summary](#snort-rules-summary)
- [Detection Opportunities](#detection-opportunities)
- [Key Findings](#key-findings)

---

## Environment & Tools

| Tool | Purpose |
|------|---------|
| Snort 2.x | Custom IDS rule authoring and PCAP replay |
| Wireshark | Packet inspection, HTTP stream analysis, filter-based triage |
| tcpdump | Timestamp extraction, content grep, packet verification |
| whois / RIPE | ASN and IP attribution for external FTP server |

**Challenge file:** `snort_challenge.pcap`  
**Internal subnet:** `192.168.1.0/24`  
**Attacker IP:** `192.168.1.7`  
**Victim server IP:** `192.168.1.6` (port 80)

---

## Attack Timeline

```
23:19:58  Reconnaissance — first HTTP requests with suspicious User-Agent
23:20:00  Brute force begins — Hydra credential stuffing against /login.php
23:20:41  First successful login — HTTP 302 redirect (UNIX epoch: 1717795241)
23:21:29  LFI begins — directory traversal attempts on /admin.php?file=
23:21:38  LFI escalates — /etc/host, /etc/hosts, /etc/passwd targeted
23:22:09  SSH key stolen — /home/bill/.ssh/id_rsa exfiltrated via HTTP (200 OK)
23:22:37  FTP exfiltration — 192.168.1.6 connects outbound to 194.108.117.16:21
```

---

## Investigation

### Q1 — Suspicious User-Agent / Brute Force Tool

**Question:** What penetration testing tool did the attacker use to brute force the admin page?

**Wireshark filter used:**
```
http.user_agent
```

Inspecting the HTTP stream from `192.168.1.7:55864 → 192.168.1.6:80`, the raw packet payload revealed a distinctive User-Agent string:

```
User-Agent: Mozilla/4.0 (Hydra)
```

**Answer: `Hydra`**

The attacker used [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra), a parallelised login cracker. The tool's name is embedded directly in the User-Agent header, which is a strong IOC. Alongside Hydra, legitimate-looking Firefox User-Agents were also observed — consistent with a multi-phase attack where the attacker switches to manual browsing post-compromise.

**Screenshot:**

![Suspicious User-Agent](screenshots/01_suspicious_user-agent_I.png)
![User-Agent hex dump](screenshots/02_suspicious_user-agent_II.png)

---

### Q2 — Failed Login Attempts (HTTP 401)

**Question:** How many alerts were logged for HTTP 401 brute force attempts (10 attempts within 30 seconds)?

**Snort rule:**
```snort
alert tcp any 80 -> any any (
  msg:"HTTP 401 brute force - 10 attempts in 30s";
  flow:to_client,established;
  content:"401";
  http_stat_code;
  threshold:type threshold, track by_src, count 10, seconds 30;
  sid:100001; rev:1;
)
```

**Command:**
```bash
sudo snort -r snort_challenge.pcap -A console -c /etc/snort/snort.conf -q -k none | wc -l
```

**Answer: `1091` alerts**

The volume and speed of 401 responses confirms a fully automated credential stuffing campaign. The high alert count over a short timeframe is consistent with Hydra's parallel connection behaviour.

**Screenshot:**

![Brute force alerts](screenshots/03_brute_force.png)

---

### Q3 — Successful Login (HTTP 302) — UNIX Epoch Timestamp

**Question:** What is the UNIX epoch timestamp of the attacker's first successful login?

**Snort rule:**
```snort
alert tcp any 80 -> any any (
  msg:"HTTP 302 in UNIX epoch timestamp";
  content:"302";
  http_stat_code;
  flow:to_client,established;
  sid:1000001; rev:1;
)
```

**Commands:**
```bash
sudo snort -r snort_challenge.pcap -A console -c /etc/snort/snort.conf -q -k none

sudo tcpdump -tt -r /var/log/snort/snort.log.1781348650
```

The `-tt` flag on tcpdump outputs raw UNIX epoch timestamps. Two HTTP 302 redirects were captured:

```
1717795241.242056  192.168.1.6.http → snort.49700   HTTP/1.1 302 Found
1717795260.797559  192.168.1.6.http → snort.45014   HTTP/1.1 302 Found
```

**Answer: `1717795241.242056`**

**Screenshot:**

![UNIX epoch timestamp](screenshots/04_UNIX_epoch_timestamp.png)

---

### Q4 — LFI Directory Traversal Detection

**Question:** How many alerts were logged for LFI directory traversal attempts?

**Snort rule (with hex encoding as hinted):**
```snort
alert tcp any any -> any 80 (
  msg:"LFI payload - directory traversal in URI";
  flow:to_server,established;
  content:"|2E 2E 2F|";
  http_uri;
  sid:1000001; rev:1;
)
```

**Commands:**
```bash
sudo snort -r snort_challenge.pcap -A console -c /etc/snort/snort.conf -q -k none

sudo snort -r /var/log/snort/snort.log.1781430399 -q -d | grep "../"
```

**Answer: `5` alerts**

The five LFI requests were targeting progressively more sensitive files:

| Timestamp | Request URI |
|-----------|-------------|
| 23:21:29 | `/admin.php?file=../test` |
| 23:21:38 | `/admin.php?file=../../../../../../../../etc/host` |
| 23:21:40 | `/admin.php?file=../../../../../../../../etc/hosts` |
| 23:21:43 | `/admin.php?file=../../../../../../../../etc/passwd` |
| 23:22:09 | `/admin.php?file=../../../../../../../home/bill/.ssh/id_rsa` |

**Screenshots:**

![LFI detections console](screenshots/05_potential_local_file_inclusion_LFI_I.png)
![LFI Snort log detail](screenshots/06_potential_local_file_inclusion_LFI_II.png)
![LFI Wireshark packets](screenshots/07_potential_local_file_inclusion_LFI_III.png)

---

### Q5 — OpenSSH Private Key Exfiltration via HTTP

**Question:** What was the Content-Length of the HTTP response containing the private SSH key?

**Snort rule:**
```snort
alert tcp any any -> any any (
  msg:"OpenSSH Private Key Leak";
  flow:established;
  content:"-----BEGIN OPENSSH PRIVATE KEY-----";
  sid:1000001; rev:1;
)
```

**Verification commands:**
```bash
# Detect the request
alert tcp any any -> any 80 (
  msg:"LFI - SSH private key access attempt";
  flow:to_server,established;
  content:".ssh/id_rsa";
  http_uri;
  sid:1000001; rev:1;
)

# Extract content lengths from HTTP responses
tcpdump -r snort_challenge.pcap -A \
  'host 192.168.1.6 and host 192.168.1.7 and port 80' \
  | grep "Content-Length" | tail
```

The server responded with HTTP `200 OK` to the `id_rsa` request. The Wireshark HTTP stream confirmed the full OpenSSH private key was returned in plaintext, beginning with `-----BEGIN OPENSSH PRIVATE KEY-----`.

Content-Length values observed across all HTTP responses:

```
10671, 10671, 10671, 10671, 10671, 15, 15, 163, 1081, 2134
```

The SSH key response (`2134` bytes) is the final and smallest distinct response — consistent with the size of an RSA/ED25519 private key block.

**Answer: `2134`**

**Screenshots:**

![SSH key access alert](screenshots/08_tcpdump_ssh_I.png)
![SSH key Snort log](screenshots/09_tcpdump_ssh_II.png)
![Wireshark stream — key request](screenshots/10_tcpdump_ssh_III.png)
![Wireshark HTTP 200 OK response](screenshots/11_tcpdump_ssh_IV.png)
![HTTP stream — BEGIN OPENSSH PRIVATE KEY](screenshots/12_tcpdump_ssh_V.png)

---

### Q6 — Outbound FTP Exfiltration & ASN Lookup

**Question:** What is the ASN of the external FTP server the attacker connected to?

**Snort rule:**
```snort
alert tcp 192.168.1.0/24 any -> !192.168.1.0/24 21 (
  msg:"Outbound FTP to external server";
  flow:to_server,established;
  sid:1000001; rev:1;
)
```

**Commands:**
```bash
sudo snort -r snort_challenge.pcap -A console -c /etc/snort/snort.conf -q -k none

sudo snort -r /var/log/snort/snort.log.1781549836 -q -d

whois 194.108.117.16
```

Multiple outbound FTP connections were detected from the compromised server `192.168.1.6:33720` to external IP `194.108.117.16:21`.

RIPE WHOIS lookup result:

```
inetnum:   194.108.116.0 - 194.108.119.0
netname:   TMCZ-1941081160
descr:     T-Mobile Czech Republic a.s.
country:   CZ
route:     194.108.0.0/16
origin:    AS13036
```

**Answer: `AS13036` (T-Mobile Czech Republic)**

**Screenshots:**

![FTP outbound alerts](screenshots/13_ftp_I.png)
![FTP Snort log detail](screenshots/13_ftp_II.png)
![whois ASN result](screenshots/13_ftp_III.png)

---

## IOC Table

| IOC Type | Value | Context |
|----------|-------|---------|
| Attacker IP | `192.168.1.7` | Source of all attack traffic |
| Victim IP | `192.168.1.6` | Compromised web server |
| External FTP IP | `194.108.117.16` | Data exfiltration destination |
| ASN | `AS13036` | T-Mobile Czech Republic (FTP server host) |
| User-Agent | `Mozilla/4.0 (Hydra)` | Hydra brute force tool identifier |
| URI Pattern | `../` / `|2E 2E 2F|` | LFI directory traversal payload |
| Targeted file | `/home/bill/.ssh/id_rsa` | Stolen OpenSSH private key |
| First successful login | `1717795241.242056` | UNIX epoch timestamp |
| SSH key Content-Length | `2134` | HTTP response size of stolen key |
| HTTP status codes | `401`, `302`, `200` | Brute force, redirect, key delivery |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Credential Access | Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Hydra brute force against `/login.php` — 1091 HTTP 401 responses |
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | LFI vulnerability exploited via `/admin.php?file=` parameter |
| Discovery | File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Traversal of `/etc/passwd`, `/etc/hosts`, `/etc/host` |
| Credential Access | Unsecured Credentials: Private Keys | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | `id_rsa` stolen from `/home/bill/.ssh/` via HTTP |
| Lateral Movement | Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Attacker used stolen SSH key to gain shell access |
| Exfiltration | Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | FTP used to exfiltrate data to external IP `194.108.117.16` |

---

## Snort Rules Summary

```snort
# Q1 — Suspicious User-Agent detection
alert tcp any any -> any 80 (
  msg:"Suspicious User-Agent detected";
  content:"User-Agent";
  http_header; nocase;
  sid:100001; rev:1;
)

# Q2 — HTTP 401 Brute Force Threshold
alert tcp any 80 -> any any (
  msg:"HTTP 401 brute force - 10 attempts in 30s";
  flow:to_client,established;
  content:"401"; http_stat_code;
  threshold:type threshold, track by_src, count 10, seconds 30;
  sid:100001; rev:1;
)

# Q3 — Successful Login via HTTP 302
alert tcp any 80 -> any any (
  msg:"HTTP 302 successful login redirect";
  content:"302"; http_stat_code;
  flow:to_client,established;
  sid:1000001; rev:1;
)

# Q4 — LFI Directory Traversal (hex-encoded)
alert tcp any any -> any 80 (
  msg:"LFI payload - directory traversal in URI";
  flow:to_server,established;
  content:"|2E 2E 2F|"; http_uri;
  sid:1000001; rev:1;
)

# Q5 — OpenSSH Private Key in Traffic
alert tcp any any -> any any (
  msg:"OpenSSH Private Key Leak";
  flow:established;
  content:"-----BEGIN OPENSSH PRIVATE KEY-----";
  sid:1000001; rev:1;
)

# Q5b — SSH Private Key Access via LFI
alert tcp any any -> any 80 (
  msg:"LFI - SSH private key access attempt";
  flow:to_server,established;
  content:".ssh/id_rsa"; http_uri;
  sid:1000001; rev:1;
)

# Q6 — Outbound FTP to External Server
alert tcp 192.168.1.0/24 any -> !192.168.1.0/24 21 (
  msg:"Outbound FTP to external server";
  flow:to_server,established;
  sid:1000001; rev:1;
)
```

---

## Detection Opportunities

| Gap | Recommended Control |
|-----|-------------------|
| Hydra brute force not blocked, only detected | Implement rate limiting / IP-based lockout after N failed logins at WAF or application layer |
| LFI via `file=` parameter not sanitised | Web Application Firewall rule to block `../` patterns; server-side input validation |
| SSH private key served over unencrypted HTTP | Private key files should never be web-accessible; restrict web root permissions; enable file access auditing |
| Outbound FTP to foreign IP unblocked | Egress filtering — block port 21 to non-approved destinations at the perimeter firewall |
| No alerting on `Content-Type: application/x-pem-file` responses | DLP rule to detect PEM/key content in HTTP responses |
| SSH session post-compromise not detected | Enable SSH login monitoring and alert on new authenticated sessions from external IPs |

---

## Key Findings

The attacker executed a complete, multi-stage intrusion within approximately **3 minutes**:

1. **Automated credential attack** using Hydra produced over 1,000 failed logins before finding valid credentials
2. **Two successful logins** via HTTP 302 redirects were recorded, the first at UNIX timestamp `1717795241`
3. **LFI exploitation** through an unsanitised `file=` parameter in `/admin.php` allowed directory traversal across 5 distinct requests
4. The final LFI request successfully **exfiltrated the server's OpenSSH private key** (`id_rsa`) for user `bill` — confirmed by the HTTP 200 OK response with Content-Length `2134` and the `-----BEGIN OPENSSH PRIVATE KEY-----` header visible in the stream
5. The stolen key was used to **establish SSH access**, after which the attacker initiated **outbound FTP connections** to `194.108.117.16` (ASN `AS13036`, T-Mobile Czech Republic) to exfiltrate data

The entire attack — from first brute force packet to FTP exfiltration — represents a textbook LFI-to-RCE-to-exfiltration chain and highlights critical gaps in egress filtering, input validation, and filesystem permission hardening.

