# Case Writeup: PhishNet — Phishing Email with Malicious Attachment

## Summary

A phishing email impersonating "Business Finance Ltd." was sent to the accounting department at Global Accounting, containing an urgent fake invoice notice. The email included a malicious ZIP attachment (`Invoice_2025_Payment.zip`) containing a disguised batch file (`invoice_document.pdf.bat`), and a phishing link to a fraudulent domain. Despite passing SPF, DKIM, and DMARC checks (indicating attacker-controlled infrastructure), the email exhibited classic business email compromise (BEC) tactics. Confidence: **High** based on email header analysis and attachment inspection.

---

## Timeline

| Timestamp (UTC) | Event | Source | Significance |
|-----------------|-------|--------|--------------|
| 2025-02-26 10:05:00 | Email originated from `198.51.100.75` | Email headers (Received) | Initial send from attacker infrastructure |
| 2025-02-26 10:10:00 | Email relayed through `198.51.100.45` | Email headers (Received) | First relay hop |
| 2025-02-26 10:15:00 | Email received by `mail.target.com` from `203.0.113.25` | Email headers (Received) | Final delivery to victim mail server |
| 2025-02-26 10:15:00 | Email delivered to `accounts@globalaccounting.com` | Email headers (To) | Victim receives phishing email |
| Unknown | Victim opens attachment / clicks link | Scenario context | Potential malware execution |

---

## Attack Narrative

**Delivery:** The attacker crafted a convincing phishing email impersonating "Business Finance Ltd." using the domain `business-finance.com`. The email was sent from `finance@business-finance.com` to the accounting department, claiming an urgent overdue invoice (#INV-2025-0012) requiring immediate payment of $4,750.00.

**Social Engineering:** The email employed multiple pressure tactics:
- Urgent subject line: "Urgent: Invoice Payment Required - Overdue Notice"
- High priority flags (`X-Priority: 1`, `X-MSMail-Priority: High`)
- Threat of penalties and service suspension
- Specific invoice details to appear legitimate

**Payload Delivery (Two Vectors):**
1. **Phishing Link:** `https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment` — likely leads to credential harvesting or drive-by download
2. **Malicious Attachment:** `Invoice_2025_Payment.zip` containing `invoice_document.pdf.bat` — a batch file disguised as a PDF using double extension

**Infrastructure:** The attacker controlled legitimate-looking infrastructure that passed email authentication:
- SPF: Pass
- DKIM: Pass
- DMARC: Pass

This indicates a sophisticated attacker who either compromised a legitimate domain or set up convincing lookalike infrastructure with proper DNS records.

**Execution:** If the victim extracts and runs `invoice_document.pdf.bat`, the batch file would execute malicious commands on the Windows host.

---

## Key IOCs

| Type | Value | Context |
|------|-------|---------|
| Email Address | `finance@business-finance.com` | Sender (From) |
| Email Address | `support@business-finance.com` | Reply-To address |
| Domain | `business-finance.com` | Attacker-controlled domain |
| Domain | `secure.business-finance.com` | Phishing link domain |
| IP Address | `45.67.89.10` | X-Originating-IP (sender) |
| IP Address | `203.0.113.25` | Mail relay server |
| IP Address | `198.51.100.45` | Internal relay |
| IP Address | `198.51.100.75` | Origin server |
| Filename | `Invoice_2025_Payment.zip` | Malicious attachment |
| Filename | `invoice_document.pdf.bat` | Disguised malware |
| Hash (SHA-256) | `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a` | ZIP attachment hash |
| URL | `https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment` | Phishing URL |

---

## Findings & Confidence

| Finding | Evidence | Confidence | Notes |
|---------|----------|------------|-------|
| Phishing email targeting accounting | Email content, urgency tactics | High | Classic BEC pattern |
| Attacker controls `business-finance.com` | SPF/DKIM/DMARC all pass | High | Legitimate-looking infrastructure |
| Malicious attachment contains disguised executable | `.pdf.bat` double extension | High | Common evasion technique |
| Phishing link leads to attacker domain | URL in email body | High | Same domain as sender |
| High-priority flags used for urgency | X-Priority: 1 | High | Social engineering tactic |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | ZIP attachment with malicious batch file |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Embedded phishing URL |
| Execution | User Execution: Malicious File | T1204.002 | `.pdf.bat` requires user to run |
| Defense Evasion | Masquerading: Double File Extension | T1036.007 | `invoice_document.pdf.bat` |
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | `business-finance.com` with valid email auth |

---

## Lessons Learned

**What I did well:**
- Correctly identified the email structure and extracted key headers
- Recognized the double extension masquerading technique
- Computed SHA-256 hash of attachment in sandbox
- Mapped attack to correct MITRE ATT&CK technique (T1566.001)

**What I missed initially:**
- Could have extracted and analyzed the batch file contents for deeper IOCs
- Did not investigate the phishing URL infrastructure further
- Could have checked domain registration (WHOIS) for `business-finance.com`

**What I'd do differently:**
- Perform full static analysis of the batch file
- Use URL sandbox to analyze the phishing link
- Check domain age and registration details
- Look for similar campaigns using threat intel feeds

---

## Next Actions (if real incident)

- [ ] **Block:** Add `business-finance.com` domain to email gateway blocklist
- [ ] **Block:** Add sender IPs to firewall deny list
- [ ] **Block:** Add file hash to EDR blocklist
- [ ] **Hunt:** Search email logs for other recipients of this campaign
- [ ] **Hunt:** Check if any user clicked the link (proxy/DNS logs)
- [ ] **Hunt:** Check if any user executed the attachment (EDR telemetry)
- [ ] **Analyze:** Submit batch file to sandbox for behavioral analysis
- [ ] **Notify:** Alert all accounting/finance staff about this campaign
- [ ] **Report:** Submit IOCs to threat intel sharing platforms

---

## References

- [MITRE ATT&CK T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1036.007 — Double File Extension](https://attack.mitre.org/techniques/T1036/007/)
- Email Header Analysis Best Practices
