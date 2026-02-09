# Case Writeup: Origins — FTP Brute Force and Data Exfiltration

## Summary

An FTP server at Forela was compromised via brute force attack from an IP geolocated to Mumbai, India. The attacker successfully authenticated with credentials `forela-ftp:ftprocks69$`, exfiltrated sensitive files including a maintenance document containing SSH credentials and an S3 bucket listing. This led to a larger breach where approximately 20GB of data was stolen from internal S3 buckets, followed by extortion. Confidence: **High** based on PCAP analysis showing complete attack chain from reconnaissance through exfiltration.

---

## Timeline

| Timestamp (UTC) | Event | Source | Significance |
|-----------------|-------|--------|--------------|
| 2024-05-03 04:12:33 | PCAP capture begins | `ftp.pcap` properties | Start of evidence window |
| 2024-05-03 04:12:54 | TCP SYN scan begins from `15.206.185.207` | PCAP (TCP flags) | Attacker reconnaissance |
| 2024-05-03 04:12:54 | FTP brute force attack begins | PCAP (FTP USER/PASS) | Credential guessing attack |
| 2024-05-03 ~04:13:XX | Successful login: `forela-ftp:ftprocks69$` | PCAP (230 Login successful) | Initial access achieved |
| 2024-05-03 ~04:13:XX | Directory listing (LIST) | PCAP (FTP commands) | Attacker enumerates files |
| 2024-05-03 ~04:14:XX | `Maintenance-Notice.pdf` downloaded (RETR) | PCAP (FTP-DATA) | Sensitive document exfiltrated |
| 2024-05-03 ~04:14:XX | `s3_buckets.txt` downloaded (RETR) | PCAP (FTP-DATA) | S3 bucket URLs exfiltrated |
| 2024-05-03 ~04:14:XX | Upload attempt failed (STOR) — Permission denied | PCAP (FTP response) | Attacker tried to leave marker |
| 2024-05-03 ~04:15:XX | Session terminated (QUIT) | PCAP (FTP commands) | Attacker exits |
| 2024-05-03 04:15:03 | PCAP capture ends | `ftp.pcap` properties | End of evidence window |

---

## Attack Narrative

**Reconnaissance:** The attacker from IP `15.206.185.207` (Mumbai, India) initiated a TCP SYN scan against the FTP server (`172.31.45.144`) on port 21, cycling through source ports 56104–56400. The SYN scan confirmed port 21 was open.

**Brute Force Attack:** The attacker launched a credential brute force attack, attempting multiple username/password combinations including:
- `admin`, `backup`, `svcaccount`, `ftpuser`, `forela-ftp`
- `69696969`, `password`, `password123!`, `ftprocks69$`, `password123`

**Initial Access:** The combination `forela-ftp:ftprocks69$` succeeded, granting the attacker authenticated FTP access.

**Discovery:** The attacker issued FTP commands to enumerate the environment:
- `SYST` — Identify system type
- `FEAT` — List supported features
- `LIST` — Directory listing
- `SIZE` — Check file sizes

**Exfiltration:** Two critical files were downloaded:
1. **`Maintenance-Notice.pdf`** (27,855 bytes) — Contained cleartext backup SSH credentials: `B@ckup2024!`
2. **`s3_buckets.txt`** (268 bytes) — Listed internal S3 bucket URLs for bulk data storage

**Attempted Persistence:** The attacker tried to upload a file (`HACKED.txt`) to `/home/cyberjunkieXOX/` but received "Permission denied."

**Exit:** The attacker cleanly terminated the session with `QUIT`.

**Impact:** The exfiltrated credentials and S3 bucket URLs enabled the attacker to:
- Access the backup SSH server using stolen credentials
- Access S3 buckets (`2023-coldstorage`, `2022-warmstor`) and exfiltrate ~20GB of data
- Conduct social engineering using internal email address `archivebackups@forela.co.uk`
- Extort Forela with the stolen data

---

## Key IOCs

| Type | Value | Context |
|------|-------|---------|
| IP Address | `15.206.185.207` | Attacker IP (Mumbai, India) |
| IP Address | `172.31.45.144` | Compromised FTP server (internal) |
| Username | `forela-ftp` | Compromised FTP account |
| Password | `ftprocks69$` | Compromised FTP password |
| Password | `B@ckup2024!` | SSH backup server password (exfiltrated) |
| Filename | `Maintenance-Notice.pdf` | Exfiltrated document with credentials |
| Filename | `s3_buckets.txt` | Exfiltrated S3 bucket listing |
| S3 Bucket | `https://2023-coldstorage.s3.amazonaws.com` | Targeted data storage |
| S3 Bucket | `https://2022-warmstor.s3.amazonaws.com` | Targeted data storage |
| Email | `archivebackups@forela.co.uk` | Used in social engineering |
| Email | `itsupport@forela.co.uk` | Mentioned in exfiltrated document |
| FTP Software | `vsFTPd 3.0.5` | FTP server software |

---

## Findings & Confidence

| Finding | Evidence | Confidence | Notes |
|---------|----------|------------|-------|
| Brute force attack occurred | Multiple USER/PASS attempts in PCAP | High | Pattern clearly visible |
| Attacker from Mumbai, India | GeoIP lookup of `15.206.185.207` | Medium | GeoIP can be inaccurate/VPN |
| Credentials `forela-ftp:ftprocks69$` compromised | Successful login in PCAP | High | Direct observation |
| SSH credentials exfiltrated | `Maintenance-Notice.pdf` contents | High | Cleartext in document |
| S3 bucket URLs exfiltrated | `s3_buckets.txt` contents | High | Direct observation |
| Attacker failed to upload file | "Permission denied" response | High | FTP response in PCAP |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 | TCP SYN scan on port 21 |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Multiple login attempts observed |
| Initial Access | Valid Accounts: Default Accounts | T1078.001 | Used brute-forced FTP credentials |
| Discovery | File and Directory Discovery | T1083 | FTP LIST, SIZE commands |
| Collection | Data from Local System | T1005 | Downloaded files from FTP |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | Data exfiltrated via FTP |
| Lateral Movement | (Subsequent) | — | SSH credentials enabled further access |

---

## Lessons Learned

**What I did well:**
- Correctly identified the brute force pattern in PCAP
- Traced the complete attack chain from reconnaissance to exfiltration
- Used Wireshark effectively to follow TCP streams and extract data
- Identified the FTP server version and attacker IP

**What I missed initially:**
- Could have correlated timing more precisely with packet numbers
- Should have extracted the actual file contents earlier
- Did not initially recognize the significance of the SSH credentials

**What I'd do differently:**
- Build a reference for FTP command meanings
- Create Wireshark display filters for brute force detection
- Correlate with other log sources (auth logs, AWS CloudTrail) if available

---

## Next Actions (if real incident)

- [ ] **Contain:** Disable FTP service or block attacker IP immediately
- [ ] **Rotate:** Change `forela-ftp` password
- [ ] **Rotate:** Change SSH backup password (`B@ckup2024!`)
- [ ] **Rotate:** Rotate all S3 bucket access credentials
- [ ] **Audit:** Review S3 bucket access logs for unauthorized access
- [ ] **Hunt:** Search for `15.206.185.207` across all network logs
- [ ] **Hunt:** Check for SSH logins using stolen credentials
- [ ] **Harden:** Implement FTP rate limiting / fail2ban
- [ ] **Harden:** Remove cleartext credentials from documents
- [ ] **Detect:** Deploy detection for FTP brute force patterns

---

## References

- [MITRE ATT&CK T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [vsFTPd Documentation](https://security.appspot.com/vsftpd.html)
- [Wireshark FTP Analysis](https://wiki.wireshark.org/FTP)
