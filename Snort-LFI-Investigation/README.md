# Snort Challenge - LFI, Credential Theft & Data Exfiltration Investigation

> The SOC team at Oinksoft detected anomalous activity on one of their internal web servers. DLP alerts triggered alongside suspicious inbound HTTP traffic, indicating a potential compromise. This investigation reconstructs the full attack chain using custom Snort IDS rules and network forensic analysis of a provided PCAP file.

---

## Table of Contents

- [Environment & Tools](#environment--tools)
- [Attack Timeline](#attack-timeline)
- [Credential Brute Force](#credential-brute-force)
- [Local File Inclusion Exploitation](#local-file-inclusion-exploitation)
- [SSH Private Key Exfiltration](#ssh-private-key-exfiltration)
- [Outbound FTP Data Exfiltration](#outbound-ftp-data-exfiltration)
- [IOC Table](#ioc-table)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Snort Rules](#snort-rules)
- [Detection Opportunities](#detection-opportunities)
- [Key Findings](#key-findings)

---

## Environment & Tools

| Tool | Purpose |
|------|---------|
| Snort 2.x | Custom IDS rule authoring and PCAP replay |
| Wireshark | Packet inspection, HTTP stream analysis |
| tcpdump | Timestamp extraction, content grep, packet verification |
| whois / RIPE | ASN and IP attribution for external server |

**Challenge file:** `snort_challenge.pcap`  
**Internal subnet:** `192.168.1.0/24`  
**Attacker IP:** `192.168.1.7`  
**Victim server:** `192.168.1.6:80`

---

## Attack Timeline

```
23:19:58  First HTTP requests observed - suspicious User-Agent string detected
23:20:00  Automated brute force begins against /login.php (Hydra)
23:20:41  First successful login - HTTP 302 redirect confirmed
23:21:29  LFI exploitation begins - directory traversal via /admin.php?file=
23:21:38  Escalation - /etc/host, /etc/hosts, /etc/passwd targeted
23:22:09  SSH private key stolen - /home/bill/.ssh/id_rsa returned via HTTP 200
23:22:37  Outbound FTP connection initiated to external IP 194.108.117.16:21
```

---

## Credential Brute Force

Initial analysis of HTTP traffic in Wireshark revealed two distinct User-Agent strings. The majority of login requests carried a non-standard User-Agent identifying the tool as **Hydra** - a parallelised network login cracker:

```
User-Agent: Mozilla/4.0 (Hydra)
```

This is a reliable IOC as Hydra embeds its name directly in the User-Agent header by default. The attacker targeted `/login.php` on `192.168.1.6` with rapid successive requests, all resulting in HTTP `401 Unauthorized` responses.

A custom Snort threshold rule was written to detect when 10 failed login attempts occur within a 30-second window from the same source IP. Running this rule against the PCAP produced **1,091 alerts**, confirming a sustained, high-volume brute force campaign.

The attack ultimately succeeded - two HTTP `302 Found` redirects were detected, indicating successful authentication. The first successful login was recorded at UNIX epoch timestamp **`1717795241.242056`**, confirmed using `tcpdump -tt` to extract raw timestamps from the Snort alert log.

![Suspicious User-Agent](screenshots/01_suspicious_user-agent_I.png)
![User-Agent hex dump](screenshots/02_suspicious_user-agent_II.png)
![User-Agent Hydra visible in raw traffic](screenshots/02_suspicious_user-agent_III.png)
![Brute force alerts](screenshots/03_brute_force.png)
![UNIX epoch timestamp](screenshots/04_UNIX_epoch_timestamp.png)

---

## Local File Inclusion Exploitation

Following successful authentication, the attacker abused an unsanitised `file=` parameter in `/admin.php` to perform directory traversal. Requests containing the `../` pattern (`|2E 2E 2F|` in hex) were detected in the HTTP URI using a custom Snort rule - **5 alerts** were logged in total.

The traversal attempts escalated progressively, targeting increasingly sensitive system files:

| Timestamp | Target |
|-----------|--------|
| 23:21:29 | `/admin.php?file=../test` — initial probe |
| 23:21:38 | `../../../../../../../../etc/host` |
| 23:21:40 | `../../../../../../../../etc/hosts` |
| 23:21:43 | `../../../../../../../../etc/passwd` |
| 23:22:09 | `../../../../../../../home/bill/.ssh/id_rsa` |

The final traversal request targeted the SSH private key of user `bill` - the most sensitive file accessible via this vulnerability.

![LFI detections console](screenshots/05_potential_local_file_inclusion_LFI_I.png)
![LFI Snort log detail](screenshots/06_potential_local_file_inclusion_LFI_II.png)
![LFI Wireshark packets](screenshots/07_potential_local_file_inclusion_LFI_III.png)

---

## SSH Private Key Exfiltration

The server responded to the `id_rsa` traversal request with HTTP `200 OK`, returning the full OpenSSH private key in plaintext. This was confirmed both via Wireshark stream analysis and a Snort rule matching the key file signature `-----BEGIN OPENSSH PRIVATE KEY-----`.

The HTTP response carrying the private key had a **Content-Length of `2134` bytes** - consistent with an RSA/ED25519 private key block. Analysis of all Content-Length values in the HTTP session confirmed this was the final, unique response distinct from the standard page responses:

```
10671 × 4  - standard page responses
15 × 2     - error responses
163        - redirect body
1081       - partial response
2134       - OpenSSH private key
```

The stolen key gave the attacker passwordless SSH access to the compromised server.

![SSH key access alert](screenshots/08_tcpdump_ssh_I.png)
![SSH key Snort log](screenshots/09_tcpdump_ssh_II.png)
![Wireshark stream - key request](screenshots/10_tcpdump_ssh_III.png)
![Wireshark HTTP 200 OK response](screenshots/11_tcpdump_ssh_IV.png)
![HTTP stream - BEGIN OPENSSH PRIVATE KEY](screenshots/12_tcpdump_ssh_V.png)

---

## Outbound FTP Data Exfiltration

After gaining shell access via the stolen SSH key, the attacker initiated outbound FTP connections from the compromised server (`192.168.1.6:33720`) to an external IP address outside the internal subnet: **`194.108.117.16:21`**.

A Snort rule alerting on outbound TCP port 21 traffic destined for IPs outside `192.168.1.0/24` detected multiple sustained connections. RIPE WHOIS attribution of the destination IP identified the following:

```
inetnum:   194.108.116.0 - 194.108.119.0
netname:   TMCZ-1941081160
descr:     T-Mobile Czech Republic a.s.
country:   CZ
origin:    AS13036
```

**ASN: `AS13036` - T-Mobile Czech Republic**

The use of FTP (unencrypted, port 21) to an external commercial ISP block is a strong indicator of opportunistic data exfiltration over a pre-staged server.

![FTP outbound alerts](screenshots/13_ftp_I.png)
![FTP Snort log detail](screenshots/13_ftp_II.png)
![whois ASN result](screenshots/13_ftp_III.png)

---

## IOC Table

| Type | Value | Context |
|------|-------|---------|
| Attacker IP | `192.168.1.7` | Source of all attack traffic |
| Victim IP | `192.168.1.6` | Compromised web server |
| External FTP IP | `194.108.117.16` | Data exfiltration destination |
| ASN | `AS13036` | T-Mobile Czech Republic |
| User-Agent | `Mozilla/4.0 (Hydra)` | Brute force tool identifier |
| URI Pattern | `../` / `\|2E 2E 2F\|` | LFI directory traversal payload |
| Targeted file | `/home/bill/.ssh/id_rsa` | Stolen OpenSSH private key |
| First successful login | `1717795241.242056` | UNIX epoch timestamp |
| SSH key Content-Length | `2134` | HTTP response size of stolen key |
| HTTP status codes | `401`, `302`, `200` | Brute force / redirect / key delivery |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Credential Access | Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Hydra against `/login.php` - 1,091 HTTP 401 responses |
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | LFI via unsanitised `file=` parameter in `/admin.php` |
| Discovery | File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Traversal targeting `/etc/passwd`, `/etc/hosts` |
| Credential Access | Unsecured Credentials: Private Keys | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | `id_rsa` stolen from `/home/bill/.ssh/` via HTTP |
| Lateral Movement | Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Stolen SSH key used for server access |
| Exfiltration | Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | FTP to external IP `194.108.117.16` |

---

## Snort Rules

All rules were written and tested iteratively against the PCAP. Commented-out variants represent earlier iterations tested during the investigation process.

```snort
# Suspicious User-Agent
alert tcp any any -> any 80 (msg:"Suspisios User-Agent detected"; content:"User-Agent"; http_header; nocase; sid:100001; rev:1;)

# HTTP 401 Brute Force Threshold
alert tcp any 80 -> any any (msg:"HTTP 401 brute force"; flow:to_client,established; content:"401"; http_stat_code; threshold:type threshold, track by_src, count 10 , seconds 30; sid:100002; rev:1;)

# Successful Login via HTTP 302
alert tcp any 80 -> any any (msg:"HTTP 302 in UNIX epoch timestamp"; content:"302"; http_stat_code; flow:to_client,established; sid:1000003; rev:1;)

# LFI Directory Traversal
alert tcp any any -> any 80 (msg:"LFI Payload"; flow:to_server,established; content:"../"; http_uri; http_uri; sid:1000004; rev:1;)

# OpenSSH Private Key Detection — multiple approaches tested
alert tcp any 80 -> any any (msg:"RSA private key in HTTP response"; flow:to_client,established; content:"BEGIN RSA PRIVATE KEY"; nocase; sid:1000005; rev:1;)

# LFI — SSH Private Key Access Attempt
alert tcp any any -> any 80 (msg:"LFI - SSH private key access attempt"; flow:to_server,established; content:".ssh/id_rsa"; http_uri; sid:1000006; rev:1;)

# Outbound FTP to External Server
alert tcp 192.168.1.0/24 any -> !192.168.1.0/24 21 (msg:"Outbound FTP to external server"; flow:to_server,established; sid:1000007; rev:1;)
```

---

## Detection Opportunities

| Gap | Recommended Control |
|-----|-------------------|
| Brute force not blocked at application layer | Rate limiting and IP lockout after failed login threshold at WAF |
| LFI via unsanitised `file=` parameter | Server-side input validation; WAF rule blocking `../` in URI parameters |
| SSH private key accessible via web root | Restrict web server file permissions; private keys must never be web-accessible |
| Outbound FTP to external IPs unblocked | Egress filtering — deny port 21 to non-approved destinations at perimeter firewall |
| No DLP rule for PEM content in HTTP responses | Inspect HTTP responses for `BEGIN OPENSSH PRIVATE KEY` signatures |
| Post-compromise SSH sessions undetected | Alert on new SSH sessions from previously unseen source IPs |

---

## Key Findings

The investigation confirmed a complete, multi-stage intrusion executed within approximately **3 minutes**:

- The attacker used **Hydra** to brute force the web server login, generating over 1,000 failed attempts before achieving two successful authentications
- An **LFI vulnerability** in `/admin.php` was exploited through directory traversal, systematically targeting `/etc/passwd`, `/etc/hosts`, and ultimately `/home/bill/.ssh/id_rsa`
- The **OpenSSH private key** was successfully exfiltrated via a plaintext HTTP response (Content-Length: 2134), granting the attacker passwordless SSH access
- Post-compromise, the attacker used **FTP** to exfiltrate data to an external server hosted on ASN `AS13036` (T-Mobile Czech Republic, `194.108.117.16`)

The attack demonstrates a textbook **LFI → credential theft → lateral movement → exfiltration** chain, with critical failures in input validation, file permission hardening, and egress filtering.
