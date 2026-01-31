# Evidence Map: Mangobleed — MongoDB Server Compromise

## Hypothesis → Data Source → Query/Check

| # | Hypothesis | Data Source | Query/Check | Result | Confidence |
|---|------------|-------------|-------------|--------|------------|
| 1 | MongoBleed was exploited against this server | `dpkg -l` package list | Check MongoDB version against CVE-2025-14847 affected versions | Vulnerable version confirmed | High |
| 2 | Attacker connected to MongoDB remotely | `/var/log/mongodb/mongod.log` | Filter for `"c":"NETWORK"` entries | IP `65.0.76.43` found with 75,260 connections | High |
| 3 | Attacker obtained credentials via heap leak | Timing correlation | Compare MongoDB exploitation window end with first successful SSH | SSH success at 05:40:03, within minutes of exploitation | High |
| 4 | Attacker gained interactive shell access | `/var/log/auth.log` | Search for `Accepted` from attacker IP | `Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43` | High |
| 5 | Attacker performed privilege escalation | `/home/mongoadmin/.bash_history` | Review command history | LinPEAS executed in-memory | High |
| 6 | Attacker targeted MongoDB data | `.bash_history` | Review navigation commands | `cd /var/lib/mongodb/` observed | High |
| 7 | Attacker staged exfiltration | `.bash_history` | Look for exfil tools | `python3 -m http.server 6969` | High |
| 8 | Exfiltration was successful | Netflow / VPC Flow Logs | Check for outbound connections on 6969 | **Not available in triage image** | Unknown |

---

## Key Pivots

```
MongoBleed exploitation (mongod.log)
    ↓ [Credential leaked]
SSH authentication success (auth.log)
    ↓ [Interactive access]
Reconnaissance commands (.bash_history)
    ↓ [Enumeration]
LinPEAS execution (.bash_history)
    ↓ [Privesc attempt]
Data directory access (.bash_history)
    ↓ [Target identified]
Python HTTP server (.bash_history)
    ↓ [Exfil staged]
```

---

## Evidence Sources Used

| Source | Location | What It Told Us |
|--------|----------|-----------------|
| MongoDB logs | `/var/log/mongodb/mongod.log` | Attacker IP, connection count, timing |
| Auth logs | `/var/log/auth.log` | SSH authentication success, username, source IP |
| Bash history | `/home/mongoadmin/.bash_history` | Full post-exploitation command sequence |
| Package list | `live response/packages/dpkg -l` | MongoDB version (vulnerability confirmation) |

---

## Gaps / What I Couldn't Confirm

| Gap | Why It Matters | What Would Resolve It |
|-----|----------------|----------------------|
| Outbound connection logs unavailable | Cannot confirm if data was exfiltrated | VPC Flow Logs, netstat snapshot, or PCAP |
| No memory dump | Cannot analyze heap contents or LinPEAS output | Memory acquisition at incident time |
| No network capture | Cannot see actual MongoBleed payloads | PCAP of MongoDB traffic |
| Sudo/privilege escalation outcome unknown | Don't know if attacker gained root | `/var/log/auth.log` sudo entries, `/var/log/secure` |

---

## Log Parsing Notes

**MongoDB log format:** JSON lines with fields including:
- `t.$date` — timestamp
- `c` — component (NETWORK, COMMAND, etc.)
- `msg` — message
- `attr.remote` — client IP:port

**Efficient parsing approach (for next time):**
```bash
# Extract all unique remote IPs from NETWORK events
cat mongod.log | jq -r 'select(.c == "NETWORK") | .attr.remote' | cut -d: -f1 | sort | uniq -c | sort -rn

# Count connections from specific IP
grep "65.0.76.43" mongod.log | wc -l
```
