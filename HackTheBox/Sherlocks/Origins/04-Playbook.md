# Playbook: FTP Server Compromise Investigation

## Trigger

- Detection alert for FTP brute force
- Anomalous FTP traffic volume
- Suspicious FTP authentication success after failures
- Threat intel on FTP-targeting campaigns

---

## Scope

FTP servers (vsFTPd, ProFTPd, FileZilla Server, etc.) exposed to:
- Internet-facing access
- Internal network segments with sensitive data
- Integration with other systems (backup, storage)

---

## Steps

### Phase 1: Initial Triage (15 min)

1. [ ] **Identify the alert source**
   - Network IDS/IPS
   - FTP server logs
   - SIEM correlation
   - PCAP capture

2. [ ] **Gather basic IOCs**
   - Attacker source IP
   - Target FTP server IP
   - Timestamp range
   - Affected username(s)

3. [ ] **Assess current status**
   - Is the attack ongoing?
   - Was authentication successful?
   - Is the FTP service still running?

**Decision point:**
- Attack ongoing → **immediate containment (Phase 4)**
- Attack completed → proceed to Phase 2

---

### Phase 2: Attack Analysis (30 min)

4. [ ] **Analyze authentication attempts**
   - Source: FTP logs (`/var/log/vsftpd.log` or equivalent)
   - PCAP: Filter for `ftp.request.command == "USER" || ftp.request.command == "PASS"`

   Questions to answer:
   - How many attempts were made?
   - What usernames were targeted?
   - Did any succeed?

5. [ ] **Analyze post-authentication activity (if successful)**
   - Commands executed: `SYST`, `FEAT`, `LIST`, `RETR`, `STOR`
   - Files accessed/downloaded
   - Files uploaded (potential backdoor)

   PCAP filter: `ftp && ip.src == <attacker_ip>`

6. [ ] **Extract exfiltrated data**
   - Follow TCP streams for FTP-DATA
   - Identify file contents
   - Assess sensitivity of stolen data

7. [ ] **Determine attacker reconnaissance**
   - Was there a preceding port scan?
   - PCAP filter: `ip.src == <attacker_ip> && tcp.flags.syn == 1 && tcp.flags.ack == 0`

---

### Phase 3: Impact Assessment (20 min)

8. [ ] **Inventory compromised credentials**
   - Which FTP account(s) were compromised?
   - Were any credentials stored in exfiltrated files?

9. [ ] **Assess data sensitivity**
   - What files were downloaded?
   - Do they contain:
     - Credentials/keys?
     - PII/customer data?
     - Intellectual property?
     - Network diagrams/architecture?

10. [ ] **Map lateral movement potential**
    - Can exfiltrated credentials access other systems?
    - Are there shared credentials?
    - What other systems trust this FTP server?

11. [ ] **Check for secondary compromise**
    - Were any files uploaded (backdoors)?
    - Any suspicious processes on FTP server?
    - Any outbound connections to attacker IP?

---

### Phase 4: Containment (Immediate when confirmed)

12. [ ] **Network containment**
    - Block attacker IP at firewall
    - Consider isolating FTP server

    ```bash
    # iptables example
    iptables -A INPUT -s 15.206.185.207 -j DROP
    ```

13. [ ] **Service containment**
    - If ongoing: stop FTP service temporarily
    - If backdoor suspected: isolate server

14. [ ] **Credential rotation**
    - Reset compromised FTP account password
    - Reset ANY credentials found in exfiltrated files
    - Rotate related system credentials

15. [ ] **Downstream containment**
    - If credentials for other systems were stolen:
      - Rotate those credentials immediately
      - Check for unauthorized access
    - If S3 bucket URLs exposed:
      - Review S3 access logs
      - Rotate IAM credentials
      - Consider bucket policy changes

---

### Phase 5: Eradication & Recovery

16. [ ] **Remove attacker access**
    - Confirm no backdoor files uploaded
    - Check for unauthorized SSH keys
    - Review cron jobs, startup scripts

17. [ ] **Harden FTP service**
    - Implement fail2ban / rate limiting
    - Enforce strong passwords
    - Consider replacing with SFTP
    - Restrict to necessary IPs only

18. [ ] **Restore if needed**
    - If integrity compromised, rebuild from backup
    - Verify backup integrity first

19. [ ] **Enhance monitoring**
    - Deploy FTP-specific detection rules
    - Increase logging verbosity
    - Consider full PCAP for FTP segment

---

## Evidence Sources

| Question | Source | Query/Check |
|----------|--------|-------------|
| Who attacked? | PCAP / FTP logs | Source IP of auth attempts |
| What credentials tried? | PCAP / FTP logs | USER commands |
| Did attack succeed? | PCAP / FTP logs | 230 response code |
| What was downloaded? | PCAP / FTP logs | RETR commands, FTP-DATA |
| What was uploaded? | PCAP / FTP logs | STOR commands |
| Where is attacker from? | GeoIP | Lookup source IP |

---

## Escalation Criteria

- **Escalate immediately if:**
  - Attack succeeded and files were exfiltrated
  - Exfiltrated files contain credentials
  - Evidence of lateral movement
  - Customer data potentially exposed
  - Attack is ongoing
  - Multiple systems affected

---

## FTP Command Reference

| Command | Meaning | Security Relevance |
|---------|---------|-------------------|
| USER | Username | Part of auth attempt |
| PASS | Password | Part of auth attempt |
| LIST | Directory listing | Reconnaissance |
| RETR | Retrieve (download) file | Exfiltration |
| STOR | Store (upload) file | Potential backdoor |
| DELE | Delete file | Evidence destruction |
| MKD | Make directory | Persistence preparation |
| QUIT | End session | Attacker exit |

---

## References

- [Origins Case Writeup](./01-Case-Writeup.md)
- [FTP Brute Force Detection](./03-Detection.md)
- [vsFTPd Log Format](https://security.appspot.com/vsftpd/vsftpd_conf.html)
