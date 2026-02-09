# Evidence Map: Origins — FTP Brute Force and Data Exfiltration

## Hypothesis → Data Source → Query/Check

| # | Hypothesis | Data Source | Query/Check | Result | Confidence |
|---|------------|-------------|-------------|--------|------------|
| 1 | FTP server was scanned before attack | PCAP | Filter for SYN without ACK from single IP | TCP SYN scan from `15.206.185.207` on port 21 | High |
| 2 | Brute force attack occurred | PCAP | Filter for FTP USER/PASS commands | Multiple username/password combinations attempted | High |
| 3 | Specific credentials succeeded | PCAP | Filter for FTP 230 response (login successful) | `forela-ftp:ftprocks69$` worked | High |
| 4 | Files were exfiltrated | PCAP | Filter for FTP RETR commands and follow data streams | Two files downloaded: PDF and TXT | High |
| 5 | Exfiltrated files contain sensitive data | PCAP | Extract and read file contents | SSH creds and S3 URLs found | High |
| 6 | Attacker tried to leave backdoor | PCAP | Filter for FTP STOR commands | Upload attempted, permission denied | High |
| 7 | Attacker is from India | GeoIP lookup | `15.206.185.207` → iplocation.net | Mumbai, Maharashtra, India | Medium |

---

## Key Pivots

```
PCAP file properties
    ↓ [Time range: 04:12:33 - 04:15:03, 547 packets]
IPv4 conversations analysis
    ↓ [172.31.45.144 = FTP server, 15.206.185.207 = top external IP]
TCP SYN scan identification
    ↓ [Reconnaissance confirmed]
FTP USER/PASS brute force
    ↓ [Credential guessing attack]
Successful authentication
    ↓ [forela-ftp:ftprocks69$]
RETR commands issued
    ↓ [Maintenance-Notice.pdf, s3_buckets.txt]
Follow TCP stream on FTP-DATA
    ↓ [Extract file contents]
SSH credentials in PDF
    ↓ [B@ckup2024! discovered]
S3 bucket URLs in TXT
    ↓ [2023-coldstorage, 2022-warmstor]
```

---

## Evidence Sources Used

| Source | Location | What It Told Us |
|--------|----------|-----------------|
| PCAP file | `ftp.pcap` | Complete network capture of attack |
| Wireshark statistics | IPv4 Conversations | Identified key IP addresses and traffic volumes |
| Wireshark filters | TCP/FTP analysis | Extracted commands, responses, timing |
| GeoIP lookup | iplocation.net | Attacker geolocation (Mumbai) |
| Extracted PDF | TCP stream follow | Cleartext SSH credentials |
| Extracted TXT | TCP stream follow | S3 bucket URLs |

---

## Wireshark Analysis Details

### File Properties

| Property | Value |
|----------|-------|
| File hash (SHA256) | `b770184fbc4a68e64d8e28ed9d9cf3e778ca441869736b8b33d13ab69e317c8b` |
| Capture duration | 2 minutes 30 seconds |
| Total packets | 547 |
| Average pps | 3.6 |

### IP Address Analysis

| IP Address | Role | Traffic Volume | Notes |
|------------|------|----------------|-------|
| `172.31.45.144` | FTP Server | All conversations | Private IP, target |
| `15.206.185.207` | Attacker | Highest byte count | Mumbai, India |
| `169.159.200.123` | Unknown | Second highest | Possibly benign |
| `203.101.190.9` | Unknown | Third highest | Possibly benign |
| `144.24.146.96` | Unknown | Highest bits/s | Possibly benign |

### Key Wireshark Filters Used

```
# SYN scan detection
ip.src==15.206.185.207 && tcp.flags.syn==1 && tcp.flags.ack==0

# All traffic from attacker
ip.src==15.206.185.207

# FTP commands only
ftp

# FTP data transfers
ftp-data

# Successful login
ftp.response.code==230

# File retrieval
ftp.request.command=="RETR"
```

### FTP Commands Observed (Chronological)

| Command | Response | Significance |
|---------|----------|--------------|
| USER (multiple) | 331 Password required | Brute force attempts |
| PASS (multiple) | 530 Login incorrect | Failed attempts |
| USER forela-ftp | 331 Password required | Valid username found |
| PASS ftprocks69$ | 230 Login successful | Valid password found |
| SYST | L8 | System identification |
| FEAT | Feature list | Capability enumeration |
| EPSV | Extended Passive Mode | Data transfer setup |
| LIST | Directory listing | File enumeration |
| TYPE I | Binary mode | Prepare for download |
| SIZE Maintenance-Notice.pdf | 27855 | File size check |
| RETR Maintenance-Notice.pdf | Transfer complete | File exfiltration |
| SIZE s3_buckets.txt | 268 | File size check |
| RETR s3_buckets.txt | Transfer complete | File exfiltration |
| STOR HACKED.txt | Permission denied | Upload attempt failed |
| QUIT | Goodbye | Session end |

---

## Exfiltrated File Contents

### Maintenance-Notice.pdf (27,855 bytes)
- Contains: Backup server credentials
- SSH Password: `B@ckup2024!`
- Mentioned emails: `itsupport@forela.co.uk`

### s3_buckets.txt (268 bytes)
```
https://2023-coldstorage.s3.amazonaws.com # bulk data from 2023, contact simon or alonzo
https://2022-warmstor.s3.amazonaws.com # pending audit, email archivebackups@forela.co.uk
```

---

## Gaps / What I Couldn't Confirm

| Gap | Why It Matters | What Would Resolve It |
|-----|----------------|----------------------|
| S3 bucket access not in PCAP | Don't know extent of S3 theft | AWS CloudTrail logs |
| SSH login attempts not visible | Can't confirm lateral movement | Auth logs from backup server |
| Attacker's true identity | GeoIP may be VPN/proxy | Threat intel, further investigation |
| Total data exfiltrated | Only see FTP traffic | S3 access logs, network flow data |
| Social engineering details | Only have email address | Email gateway logs, interview victims |
