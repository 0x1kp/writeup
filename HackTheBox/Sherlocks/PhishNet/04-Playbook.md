# Playbook: Phishing Email Investigation and Response

## Trigger

- Email gateway alert for suspicious attachment or link
- User-reported phishing email
- Detection rule fires for double extension / urgent payment request
- Threat intel match on sender domain or attachment hash

---

## Scope

All email-related phishing incidents including:
- Spearphishing with attachments
- Spearphishing with links
- Business Email Compromise (BEC)
- Credential harvesting campaigns

---

## Steps

### Phase 1: Initial Triage (10 min)

1. [ ] **Collect the email sample**
   - Obtain .eml or .msg file (not forwarded — need full headers)
   - If user-reported, get original from mailbox or gateway

2. [ ] **Analyze email headers**
   - Extract: `From`, `Reply-To`, `Return-Path`, `X-Originating-IP`
   - Trace `Received` headers (bottom to top = oldest to newest)
   - Check `Authentication-Results`: SPF, DKIM, DMARC

   ```
   If SPF/DKIM/DMARC fail → likely spoofed
   If SPF/DKIM/DMARC pass → attacker controls domain
   ```

3. [ ] **Assess social engineering indicators**
   - Urgency language, threats, deadlines
   - Financial requests, credential requests
   - Impersonation of known entities

**Decision point:**
- High confidence phishing → proceed to Phase 2
- Uncertain → deeper header analysis, check threat intel

---

### Phase 2: Payload Analysis (20 min)

4. [ ] **Analyze attachments (if present)**
   - Extract attachment safely (isolated VM/sandbox)
   - Check file extension — look for double extensions
   - Compute hashes (MD5, SHA-256)
   - Check hash against VirusTotal, MalwareBazaar
   - If unknown, submit to sandbox (Any.Run, Joe Sandbox)

5. [ ] **Analyze URLs (if present)**
   - Extract all URLs from email body (including href vs display text mismatches)
   - Check URL reputation (VirusTotal, URLScan.io)
   - Do NOT click — use sandbox or curl with user-agent spoofing
   - Check for credential harvesting forms

6. [ ] **Document IOCs**
   - Sender addresses (From, Reply-To, Return-Path)
   - Sender IPs (X-Originating-IP, Received headers)
   - Domains (sender domain, link domains)
   - File hashes
   - File names

---

### Phase 3: Scope the Campaign (15 min)

7. [ ] **Search for other recipients**
   - Query email gateway for same:
     - Sender address
     - Subject line (exact or similar)
     - Attachment hash
     - MessageID patterns

   ```
   sender:finance@business-finance.com OR
   attachment_hash:8379c41239e9af845b2ab6c27a7509ae* OR
   subject:"Urgent: Invoice Payment Required"
   ```

8. [ ] **Check for user interaction**
   - Did anyone click the link? (proxy logs, DNS logs)
   - Did anyone download/open attachment? (EDR file events)
   - Did anyone submit credentials? (impossible box check, password reset timing)

9. [ ] **Identify affected users**
   - List all recipients
   - Prioritize: clicked > received > similar targeting

---

### Phase 4: Containment (Immediate)

10. [ ] **Block at email gateway**
    - Sender address
    - Sender domain
    - Attachment hash
    - Subject line pattern (if unique)

11. [ ] **Block at network perimeter**
    - Sender IPs
    - Phishing domain(s)
    - C2 infrastructure (if identified from payload analysis)

12. [ ] **Quarantine/delete from mailboxes**
    - Use email admin tools to purge from all recipients
    - Notify affected users

13. [ ] **If credentials potentially compromised**
    - Force password reset for affected users
    - Revoke active sessions
    - Enable/verify MFA
    - Monitor for suspicious login activity

14. [ ] **If malware potentially executed**
    - Isolate affected endpoints
    - Initiate endpoint investigation
    - Preserve memory and disk for forensics

---

### Phase 5: Eradication & Recovery

15. [ ] **Remove all traces**
    - Confirm email purged from all mailboxes
    - Confirm attachment blocked/deleted from endpoints
    - Remove any browser artifacts (cached phishing pages)

16. [ ] **Credential hygiene**
    - If credential harvesting suspected, rotate passwords
    - Check for OAuth app grants
    - Review recent account activity

17. [ ] **User communication**
    - Notify affected users directly
    - Provide guidance on what to look for
    - Encourage reporting of similar emails

---

### Phase 6: Post-Incident

18. [ ] **Update defenses**
    - Add IOCs to permanent blocklists
    - Update email filtering rules
    - Tune detection rules based on findings

19. [ ] **Threat intel sharing**
    - Submit IOCs to threat intel platforms
    - Share with industry ISACs if applicable

20. [ ] **Lessons learned**
    - Document detection gaps
    - Update playbook if needed
    - Consider additional training if users clicked

---

## Evidence Sources

| Question | Source | Query/Check |
|----------|--------|-------------|
| Who sent the email? | Email headers | From, X-Originating-IP |
| Did email pass auth checks? | Authentication-Results | SPF/DKIM/DMARC |
| What's in the attachment? | Sandbox analysis | Detonate and observe |
| Who else received it? | Email gateway logs | Search by sender/hash/subject |
| Did anyone click? | Proxy/DNS logs | Filter by phishing domain |
| Did anyone execute malware? | EDR logs | File creation, process execution |

---

## Escalation Criteria

- **Escalate to IR lead if:**
  - Multiple users clicked/executed
  - Credential compromise confirmed
  - Malware execution observed
  - Executive or finance team targeted
  - Campaign appears ongoing

---

## References

- [PhishNet Case Writeup](./01-Case-Writeup.md)
- [Phishing Detection Rules](./03-Detection.md)
- [MITRE T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
