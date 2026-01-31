# Playbook: Linux MongoDB Server Compromise Triage

## Trigger

- Alert indicating potential MongoDB exploitation (rapid connections, error responses)
- GuardDuty/EDR alert for suspicious activity on MongoDB host
- Report of MongoBleed vulnerability in environment with unpatched MongoDB

---

## Scope

Linux hosts running MongoDB, particularly:
- Internet-facing or DMZ MongoDB instances
- Hosts with MongoDB version vulnerable to CVE-2025-14847

---

## Steps

### Phase 1: Initial Triage (15 min)

1. [ ] **Confirm MongoDB version**
   - Check: `dpkg -l | grep mongo` or `rpm -qa | grep mongo`
   - If vulnerable version → proceed with high priority
   - If patched → lower confidence, still investigate

2. [ ] **Review MongoDB logs for anomalies**
   - Location: `/var/log/mongodb/mongod.log`
   - Look for:
     - Rapid connection/disconnection from single IP
     - Unusual error responses
     - `"c":"NETWORK"` entries with external IPs
   ```bash
   grep -i "Connection accepted" /var/log/mongodb/mongod.log | cut -d'"' -f12 | sort | uniq -c | sort -rn | head -20
   ```

3. [ ] **Check authentication logs for follow-on access**
   - Location: `/var/log/auth.log` or `/var/log/secure`
   - Look for: SSH success from same IP as MongoDB connections
   ```bash
   grep "Accepted" /var/log/auth.log | grep -E "keyboard-interactive|password"
   ```

**Decision point:**
- If SSH access confirmed from attacker IP → **escalate to full IR, proceed to Phase 2**
- If no SSH access → continue monitoring, patch MongoDB, hunt for other indicators

---

### Phase 2: Post-Exploitation Analysis (30 min)

4. [ ] **Identify compromised user account**
   - From auth.log: which user authenticated from attacker IP?
   - Document: username, authentication method, timestamp

5. [ ] **Review user's command history**
   - Location: `/home/<user>/.bash_history`, `.zsh_history`
   - Look for:
     - Reconnaissance: `whoami`, `id`, `uname -a`, `cat /etc/passwd`
     - Privesc tools: `linpeas`, `linenum`, `pspy`
     - Data access: `cd /var/lib/mongodb`, file operations
     - Exfiltration: `curl`, `wget`, `nc`, `python -m http.server`

6. [ ] **Check for privilege escalation**
   - Review: `/var/log/auth.log` for sudo attempts
   - Check: `/etc/sudoers`, `/etc/sudoers.d/` for modifications
   - Look for: new users in `/etc/passwd`, modified `/etc/shadow`

7. [ ] **Identify persistence mechanisms**
   - Cron jobs: `/var/spool/cron/`, `/etc/cron.*`
   - SSH keys: `/home/*/.ssh/authorized_keys`, `/root/.ssh/authorized_keys`
   - Systemd services: `/etc/systemd/system/`, `~/.config/systemd/user/`
   - Shell profiles: `.bashrc`, `.profile`, `/etc/profile.d/`

---

### Phase 3: Scoping (20 min)

8. [ ] **Determine data at risk**
   - What databases exist? `ls /var/lib/mongodb/`
   - What collections contain sensitive data?
   - Was data accessed or staged for exfil?

9. [ ] **Check for lateral movement indicators**
   - Outbound connections: `netstat -tulpn`, `ss -tulpn`
   - SSH to other hosts: `grep ssh .bash_history`
   - Credential files accessed: `.aws/credentials`, config files

10. [ ] **Hunt across environment**
    - Search all hosts for attacker IP in logs
    - Check cloud logs (CloudTrail, VPC Flow Logs) for same IP
    - Review network logs for connections to attacker infrastructure

---

### Phase 4: Containment (Immediate upon confirmation)

11. [ ] **Network isolation**
    - Isolate host from network (security group change, VLAN move, or pull cable)
    - Block attacker IP at perimeter firewall
    - If cloud: modify security group to deny all inbound except forensics jump box

12. [ ] **Credential rotation**
    - Reset compromised user's password
    - Rotate any credentials that may have been accessed
    - Invalidate active sessions

13. [ ] **Preserve evidence**
    - Snapshot disk and memory before remediation
    - Export relevant logs to secure storage
    - Document chain of custody

---

### Phase 5: Eradication & Recovery

14. [ ] **Patch MongoDB**
    - Update to version patched against CVE-2025-14847
    - Verify patch: `mongod --version`

15. [ ] **Remove persistence**
    - Delete unauthorized SSH keys
    - Remove malicious cron jobs
    - Revert modified configurations

16. [ ] **Harden configuration**
    - Enable MongoDB authentication if disabled
    - Bind MongoDB to localhost or internal network only
    - Review firewall rules

17. [ ] **Restore from known-good if necessary**
    - If integrity uncertain, rebuild from golden image
    - Restore data from verified backup

---

## Evidence Sources

| Question | Source | Query/Check |
|----------|--------|-------------|
| What MongoDB version? | `dpkg -l` / `rpm -qa` | `dpkg -l \| grep mongo` |
| Who connected to MongoDB? | `/var/log/mongodb/mongod.log` | Filter `"c":"NETWORK"` |
| Who logged in via SSH? | `/var/log/auth.log` | `grep "Accepted"` |
| What did attacker do? | `~/.bash_history` | Full review |
| Was there privilege escalation? | `/var/log/auth.log`, `/etc/sudoers` | `grep sudo` |
| Was data staged for exfil? | `.bash_history`, `netstat` | Look for http.server, nc |

---

## Escalation Criteria

- **Escalate to senior IR / management if:**
  - Confirmed credential theft and unauthorized access
  - Evidence of data exfiltration
  - Lateral movement to other systems
  - Privilege escalation to root
  - Persistence mechanisms installed

---

## References

- [Mangobleed Case Writeup](Cases/Mangobleed/01-Case-Writeup.md)
- [MongoBleed Detection](Cases/Mangobleed/03-Detection.md)
- [Linux Log Locations Reference](../../Reference/Linux-Log-Locations.md)
