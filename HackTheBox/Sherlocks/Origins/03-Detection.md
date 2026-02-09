# Detection: FTP Brute Force Attack

## Behavior Targeted

Multiple failed FTP authentication attempts from a single source IP, indicating credential brute force or password spraying attack.

---

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** T1110.001 (Brute Force: Password Guessing)

---

## Data Source

- **Log type:** FTP server logs (vsftpd, ProFTPd), Network flow data, PCAP
- **Key fields:** source_ip, username, auth_result, timestamp

---

## Logic / Query

### Sigma Rule — FTP Brute Force

```yaml
title: FTP Brute Force Attack
id: a1b2c3d4-5678-9012-abcd-ef1234567890
status: experimental
description: Detects multiple failed FTP login attempts from single source IP
author: D
date: 2026/02/09
references:
    - https://attack.mitre.org/techniques/T1110/001/
logsource:
    category: authentication
    product: ftp
detection:
    selection:
        event_type: 'authentication'
        auth_result: 'failure'
        dest_port: 21
    timeframe: 5m
    condition: selection | count(source_ip) by source_ip > 10
falsepositives:
    - Misconfigured backup scripts
    - Users with forgotten passwords
level: high
tags:
    - attack.credential_access
    - attack.t1110.001
```

### Sigma Rule — FTP Login After Multiple Failures

```yaml
title: FTP Successful Login After Brute Force
id: b2c3d4e5-6789-0123-bcde-f23456789012
status: experimental
description: Detects successful FTP login following multiple failed attempts from same IP
author: D
date: 2026/02/09
logsource:
    category: authentication
    product: ftp
detection:
    failures:
        event_type: 'authentication'
        auth_result: 'failure'
        dest_port: 21
    success:
        event_type: 'authentication'
        auth_result: 'success'
        dest_port: 21
    timeframe: 10m
    condition: failures | count() by source_ip > 5 and success
falsepositives:
    - User remembering password after attempts
level: critical
tags:
    - attack.credential_access
    - attack.t1110.001
    - attack.initial_access
```

### Snort/Suricata Rule

```
# FTP Brute Force Detection
alert tcp any any -> any 21 (msg:"FTP Brute Force - Multiple Login Attempts"; \
    flow:to_server,established; \
    content:"USER "; \
    detection_filter:track by_src, count 10, seconds 60; \
    classtype:attempted-user; \
    sid:1000001; rev:1;)

# FTP Successful Login After Failures
alert tcp any 21 -> any any (msg:"FTP Login Success After Failures"; \
    flow:to_client,established; \
    content:"230 "; \
    classtype:successful-user; \
    sid:1000002; rev:1;)
```

### Splunk SPL

```spl
index=network sourcetype=ftp_logs
| stats count(eval(status="failed")) as failures,
        count(eval(status="success")) as successes,
        values(username) as attempted_users
  by src_ip
| where failures > 10
| sort -failures
| table src_ip, failures, successes, attempted_users
```

### Wireshark Display Filter

```
# View all FTP authentication attempts
ftp.request.command == "USER" || ftp.request.command == "PASS"

# View failed authentications
ftp.response.code == 530

# View successful authentications
ftp.response.code == 230

# View brute force pattern from specific IP
ip.src == 15.206.185.207 && (ftp.request.command == "USER" || ftp.request.command == "PASS")
```

---

## Test Cases

| Test | Input | Expected Result | Actual Result | Pass? |
|------|-------|-----------------|---------------|-------|
| True positive | 15 failed FTP logins in 5 min from single IP | Alert fires | — | ☐ |
| True negative | 3 failed logins (normal typo) | No alert | — | ☐ |
| True positive | Success after 10 failures from same IP | Critical alert fires | — | ☐ |
| True negative | Successful login without prior failures | No alert | — | ☐ |

---

## False Positive Notes

- **Expected FP sources:**
  - Backup scripts with incorrect credentials
  - Monitoring tools that probe FTP
  - Users with caps lock / keyboard issues

- **Tuning applied:**
  - Whitelist known backup server IPs
  - Adjust threshold based on environment baseline
  - Alert on success-after-failure pattern for higher fidelity

---

## Triage Checklist

1. [ ] Identify source IP — is it internal or external?
2. [ ] GeoIP lookup — does location match expected users?
3. [ ] Check what usernames were attempted — targeted or spray?
4. [ ] Verify if any attempt succeeded (230 response)
5. [ ] If success: check what commands were executed (LIST, RETR, STOR)
6. [ ] If success: check for data exfiltration (file downloads)
7. [ ] Block source IP at firewall immediately
8. [ ] Rotate credentials for any successfully accessed accounts

---

# Detection: FTP Data Exfiltration

## Behavior Targeted

Large file downloads via FTP RETR command, especially of sensitive file types.

---

## MITRE ATT&CK Mapping

- **Tactic:** Exfiltration
- **Technique:** T1048 (Exfiltration Over Alternative Protocol)

---

## Logic / Query

### Sigma Rule

```yaml
title: FTP Sensitive File Exfiltration
id: c3d4e5f6-7890-1234-cdef-345678901234
status: experimental
description: Detects FTP download of potentially sensitive files
author: D
date: 2026/02/09
logsource:
    category: network
    product: ftp
detection:
    selection_command:
        ftp_command: 'RETR'
    selection_files:
        filename|endswith:
            - '.pdf'
            - '.doc'
            - '.docx'
            - '.xls'
            - '.xlsx'
            - '.txt'
            - '.csv'
            - '.bak'
            - '.sql'
            - '.key'
            - '.pem'
    condition: selection_command and selection_files
falsepositives:
    - Legitimate file transfers
    - Backup operations
level: medium
tags:
    - attack.exfiltration
    - attack.t1048
```

---

## Related Artifacts

- Case Writeup: [Origins Case Writeup](./01-Case-Writeup.md)
- Evidence Map: [Origins Evidence Map](./02-Evidence-Map.md)
- Playbook: [FTP Compromise Response](./04-Playbook.md)
