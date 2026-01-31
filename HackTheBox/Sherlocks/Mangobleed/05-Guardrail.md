# Guardrail: MongoDB Network Exposure Controls

## What It Prevents

- Direct exploitation of MongoDB from untrusted networks (including MongoBleed/CVE-2025-14847)
- Unauthorized remote access to database services
- Credential harvesting via network-based attacks

---

## Implementation

### 1. Network Binding (Primary Control)

**Service/Tool:** MongoDB configuration (`mongod.conf`)

**Configuration:**
```yaml
# /etc/mongod.conf
net:
  port: 27017
  bindIp: 127.0.0.1,10.0.1.50  # localhost + specific internal IP only
```

**Effect:** MongoDB only listens on specified interfaces, not 0.0.0.0

---

### 2. Firewall Rules (Defense in Depth)

**Service/Tool:** iptables / security groups / firewalld

**Configuration (iptables):**
```bash
# Allow MongoDB only from application subnet
iptables -A INPUT -p tcp --dport 27017 -s 10.0.2.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -j DROP
```

**Configuration (AWS Security Group):**
```
Inbound Rule:
  Type: Custom TCP
  Port: 27017
  Source: sg-app-servers (security group of app servers)
```

---

### 3. Authentication Enforcement

**Service/Tool:** MongoDB configuration

**Configuration:**
```yaml
# /etc/mongod.conf
security:
  authorization: enabled
```

**Effect:** Requires authentication for all database operations; unauthenticated access denied.

---

### 4. Patch Management

**Service/Tool:** Package management + automation

**Configuration:**
- Subscribe to MongoDB security announcements
- Implement automated patching pipeline with testing
- CVE monitoring for MongoDB (NVD, vendor advisories)

---

## Validation

**How to verify it's working:**

1. **Network binding check:**
   ```bash
   netstat -tlnp | grep 27017
   # Should show 127.0.0.1:27017 or specific internal IP, NOT 0.0.0.0
   ```

2. **External connectivity test:**
   ```bash
   # From external host:
   nc -zv <mongodb-host> 27017
   # Should fail / timeout
   ```

3. **Authentication test:**
   ```bash
   mongosh --host localhost --port 27017
   # Should require authentication, not allow anonymous access
   ```

4. **Vulnerability scan:**
   ```bash
   nmap -sV -p 27017 <mongodb-host>
   # Should not be reachable from untrusted networks
   ```

---

## Gaps / Bypass Scenarios

**This does NOT protect against:**

| Gap | Mitigation |
|-----|------------|
| Attacks from within trusted network | Implement network segmentation, zero-trust |
| Compromised application server | Application-level controls, least privilege DB accounts |
| Insider threat with network access | Database activity monitoring, audit logging |
| Zero-day vulnerabilities | Defense in depth, monitoring, rapid patching |
| Credential stuffing if auth is weak | Strong passwords, certificate auth, IP allowlisting |

---

## Related

- **Detection:** [MongoBleed Detection](Cases/Mangobleed/03-Detection.md)
- **Playbook:** [Linux MongoDB Compromise Triage](Cases/Mangobleed/04-Playbook.md)
- **Case where this would've helped:** [Mangobleed Case Writeup](Cases/Mangobleed/01-Case-Writeup.md) — if MongoDB had been bound to localhost only, external exploitation would not have been possible
