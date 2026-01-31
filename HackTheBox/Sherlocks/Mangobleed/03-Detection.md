# Detection: MongoBleed Exploitation Attempt

## Behavior Targeted

Rapid connection/disconnection pattern to MongoDB consistent with MongoBleed (CVE-2025-14847) heap memory leak exploitation.

---

## MITRE ATT&CK Mapping

- **Tactic:** Initial Access / Credential Access
- **Technique:** T1190 (Exploit Public-Facing Application), T1212 (Exploitation for Credential Access)
- **Sub-technique:** N/A

---

## Data Source

- **Log type:** MongoDB logs (`mongod.log`)
- **Key fields:** `t.$date`, `c` (component), `msg`, `attr.remote`

---

## Logic / Query

### Sigma Rule

```yaml
title: Potential MongoBleed Exploitation - Rapid MongoDB Connections
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects rapid connection/disconnection pattern to MongoDB that may indicate MongoBleed (CVE-2025-14847) exploitation
author: D
date: 2026/01/30
references:
    - https://www.akamai.com/blog/security-research/cve-2025-14847-all-you-need-to-know-about-mongobleed
logsource:
    product: mongodb
    service: mongod
detection:
    selection:
        c: 'NETWORK'
        msg|contains:
            - 'Connection accepted'
            - 'Connection ended'
    timeframe: 15m
    condition: selection | count(attr.remote) by attr.remote > 1000
falsepositives:
    - Legitimate connection pooling from application servers
    - Load testing
    - Misconfigured connection handling
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.credential_access
    - attack.t1212
    - cve.2025.14847
```

### Splunk SPL (if ingesting MongoDB logs)

```spl
index=mongodb sourcetype=mongod
| rex field=_raw "\"remote\":\"(?<remote_ip>[^:]+):"
| bucket _time span=15m
| stats count by _time, remote_ip
| where count > 1000
| table _time, remote_ip, count
```

---

## Test Cases

| Test | Input | Expected Result | Actual Result | Pass? |
|------|-------|-----------------|---------------|-------|
| True positive | Replay 75,260 connections from single IP in 15 min | Alert fires | — | ☐ |
| True negative | Normal app traffic (10 conn/min sustained) | No alert | — | ☐ |
| Threshold test | 999 connections in 15 min | No alert (below threshold) | — | ☐ |
| Threshold test | 1001 connections in 15 min | Alert fires | — | ☐ |

---

## False Positive Notes

- **Expected FP sources:**
  - Application servers with aggressive connection pooling
  - Load testing / stress testing
  - Monitoring tools that probe MongoDB frequently

- **Tuning applied:**
  - Whitelist known application server IPs
  - Adjust threshold based on baseline (1000 is aggressive; tune to environment)
  - Add exclusion for internal/RFC1918 IPs if MongoDB is not internet-facing

---

## Triage Checklist (for analyst)

1. [ ] Verify source IP is not a known application server or monitoring tool
2. [ ] Check MongoDB version — is it vulnerable to CVE-2025-14847?
3. [ ] Look for authentication failures in MongoDB logs around same timeframe
4. [ ] Pivot to auth.log — any SSH/login attempts from same IP?
5. [ ] Check if connections were followed by unusual commands (data access, errors)
6. [ ] If confirmed exploitation, escalate to IR and initiate containment

---

## Related Artifacts

- Case Writeup: [Mangobleed Case Writeup](Cases/Mangobleed/01-Case-Writeup.md)
- Evidence Map: [Mangobleed Evidence Map](Cases/Mangobleed/02-Evidence-Map.md)
- Playbook: [Linux MongoDB Compromise Triage](Cases/Mangobleed/04-Playbook.md)

---

# Detection: LinPEAS Execution via Curl Pipe

## Behavior Targeted

In-memory execution of LinPEAS privilege escalation script via curl piped to shell.

---

## MITRE ATT&CK Mapping

- **Tactic:** Privilege Escalation / Discovery
- **Technique:** T1068 (Exploitation for Privilege Escalation), T1082 (System Information Discovery)

---

## Data Source

- **Log type:** Process execution logs (auditd, sysmon for Linux, EDR)
- **Key fields:** command line, parent process, user

---

## Logic / Query

### Sigma Rule

```yaml
title: LinPEAS Download and Execution
id: b2c3d4e5-f678-9012-bcde-f23456789012
status: experimental
description: Detects download and execution of LinPEAS privilege escalation tool
author: D
date: 2026/01/30
references:
    - https://github.com/carlospolop/PEASS-ng
logsource:
    category: process_creation
    product: linux
detection:
    selection_curl_pipe:
        CommandLine|contains|all:
            - 'curl'
            - 'linpeas'
            - '| sh'
    selection_wget_pipe:
        CommandLine|contains|all:
            - 'wget'
            - 'linpeas'
            - '| sh'
    selection_direct:
        CommandLine|contains: 'linpeas.sh'
    condition: selection_curl_pipe or selection_wget_pipe or selection_direct
falsepositives:
    - Legitimate penetration testing
    - Security assessments
level: high
tags:
    - attack.privilege_escalation
    - attack.t1068
    - attack.discovery
    - attack.t1082
```

---

## Triage Checklist (for analyst)

1. [ ] Identify the user running the command
2. [ ] Determine if this is authorized pentesting activity
3. [ ] Check what other commands the user ran (bash_history, auditd)
4. [ ] Look for follow-up privilege escalation attempts
5. [ ] If unauthorized, escalate immediately — active attacker on host
