# Guardrail: FTP Service Hardening

## What It Prevents

- Brute force credential attacks against FTP
- Unauthorized file access and exfiltration
- Cleartext credential exposure
- Lateral movement via stolen credentials

---

## Implementation

### 1. Replace FTP with SFTP/FTPS (Primary Control)

**Service/Tool:** OpenSSH SFTP or FTP over TLS

**Why:** FTP transmits credentials in cleartext. SFTP encrypts the entire session.

**Configuration (SFTP via OpenSSH):**
```bash
# /etc/ssh/sshd_config
Subsystem sftp /usr/lib/openssh/sftp-server

# Restrict to SFTP only for specific group
Match Group sftponly
    ForceCommand internal-sftp
    ChrootDirectory /home/%u
    AllowTcpForwarding no
    X11Forwarding no
```

**Configuration (FTPS - vsFTPd):**
```bash
# /etc/vsftpd.conf
ssl_enable=YES
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.key
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
```

---

### 2. Implement Fail2Ban (Brute Force Protection)

**Service/Tool:** Fail2Ban

**Configuration:**
```ini
# /etc/fail2ban/jail.local
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 5
findtime = 300
bantime = 3600
action = iptables-multiport[name=vsftpd, port="ftp,ftp-data,ftps,ftps-data"]
```

**Filter (if needed):**
```ini
# /etc/fail2ban/filter.d/vsftpd.conf
[Definition]
failregex = vsftpd.*FAIL LOGIN: Client "<HOST>"
ignoreregex =
```

**Effect:** IP banned after 5 failed attempts within 5 minutes.

---

### 3. Network Access Control

**Service/Tool:** Firewall (iptables/firewalld), Security Groups

**Configuration (iptables - restrict to known IPs):**
```bash
# Allow FTP only from specific subnets
iptables -A INPUT -p tcp --dport 21 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -j DROP
```

**Configuration (AWS Security Group):**
```
Inbound Rule:
  Type: Custom TCP
  Port: 21
  Source: 10.0.0.0/8 (internal only)
```

**Effect:** FTP not accessible from internet.

---

### 4. Strong Authentication

**Service/Tool:** FTP server configuration, PAM

**Configuration (vsFTPd):**
```bash
# /etc/vsftpd.conf
# Disable anonymous access
anonymous_enable=NO

# Use local users with strong passwords
local_enable=YES
pam_service_name=vsftpd

# Restrict users to their home directories
chroot_local_user=YES
```

**Password Policy (PAM):**
```bash
# /etc/security/pwquality.conf
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
```

---

### 5. Credential Hygiene (Prevent Stored Credential Exposure)

**Principle:** Never store cleartext credentials in files accessible via FTP

**Controls:**
- Audit FTP-accessible directories for credential files
- Use secret management (HashiCorp Vault, AWS Secrets Manager)
- Encrypt sensitive documents
- Implement DLP scanning

**What to look for:**
```bash
# Find potential credential files
find /ftp-root -name "*.txt" -o -name "*.pdf" -o -name "*password*" -o -name "*credential*"
```

---

### 6. Logging and Monitoring

**Service/Tool:** vsFTPd logging, SIEM integration

**Configuration:**
```bash
# /etc/vsftpd.conf
xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES
vsftpd_log_file=/var/log/vsftpd.log
dual_log_enable=YES
```

**Effect:** All FTP commands logged for forensic analysis.

---

## Validation

**How to verify controls are working:**

1. **SFTP/FTPS test:**
   ```bash
   # Test SFTP connection
   sftp user@ftpserver

   # Test FTPS connection
   lftp -u user ftps://ftpserver
   ```

2. **Fail2Ban test:**
   ```bash
   # Attempt 6 failed logins
   for i in {1..6}; do ftp -n ftpserver <<< "user test wrongpass"; done

   # Check if banned
   fail2ban-client status vsftpd
   ```

3. **Network restriction test:**
   ```bash
   # From unauthorized IP, connection should fail
   nc -zv ftpserver 21
   ```

4. **Log verification:**
   ```bash
   # Check logs are being written
   tail -f /var/log/vsftpd.log
   ```

---

## Gaps / Bypass Scenarios

**This does NOT protect against:**

| Gap | Mitigation |
|-----|------------|
| Insider with valid credentials | Monitor for anomalous access patterns, DLP |
| Credential theft via other means | MFA where supported, session monitoring |
| Zero-day FTP vulnerabilities | Keep software updated, WAF for FTP if available |
| Compromised jump host | Network segmentation, PAM for privileged access |
| Social engineering for credentials | User training, phishing simulations |

---

## Related

- **Detection:** [FTP Brute Force Detection](./03-Detection.md)
- **Playbook:** [FTP Compromise Response](./04-Playbook.md)
- **Case where this would've helped:** [Origins Case](./01-Case-Writeup.md) — Fail2Ban would have blocked the brute force; SFTP would have prevented credential sniffing; not storing creds in documents would have limited lateral movement
