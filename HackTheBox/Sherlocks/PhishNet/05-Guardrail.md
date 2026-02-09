# Guardrail: Email Attachment and Link Protection

## What It Prevents

- Delivery of malicious email attachments (malware, disguised executables)
- Credential harvesting via phishing links
- Business Email Compromise (BEC) success
- User execution of email-borne threats

---

## Implementation

### 1. Attachment Filtering (Primary Control)

**Service/Tool:** Email Gateway (Microsoft Defender for O365, Proofpoint, Mimecast)

**Configuration — Block Dangerous Extensions:**
```
Block attachments with extensions:
.exe, .bat, .cmd, .ps1, .vbs, .js, .hta, .scr, .pif, .com, .msi, .jar, .wsf

Block archives containing:
Any of the above extensions

Block double extensions:
*.pdf.exe, *.doc.bat, *.xlsx.ps1, etc.
```

**Configuration — Microsoft 365 Safe Attachments:**
```powershell
# Enable Safe Attachments policy
New-SafeAttachmentPolicy -Name "Block Malicious Attachments" `
  -Action Block `
  -Enable $true `
  -Redirect $true `
  -RedirectAddress security@company.com
```

---

### 2. Link Protection

**Service/Tool:** Email Gateway URL Rewriting / Safe Links

**Configuration — Microsoft 365 Safe Links:**
```powershell
New-SafeLinksPolicy -Name "Protect All Links" `
  -IsEnabled $true `
  -ScanUrls $true `
  -EnableForInternalSenders $true `
  -DeliverMessageAfterScan $true `
  -DisableUrlRewrite $false `
  -EnableOrganizationBranding $true
```

**Effect:** All URLs are rewritten to pass through Microsoft's scanning before redirect.

---

### 3. External Email Warning Banner

**Service/Tool:** Exchange Transport Rules / Email Gateway

**Configuration (Exchange Online):**
```powershell
New-TransportRule -Name "External Email Warning" `
  -FromScope NotInOrganization `
  -PrependSubject "[EXTERNAL] " `
  -SetHeaderName "X-External-Sender" `
  -SetHeaderValue "true" `
  -ApplyHtmlDisclaimerLocation Prepend `
  -ApplyHtmlDisclaimerText "<div style='background:#ffeb3b;padding:10px;'>⚠️ CAUTION: This email originated from outside the organization. Do not click links or open attachments unless you recognize the sender.</div>"
```

---

### 4. DMARC Enforcement

**Service/Tool:** DNS / Email Authentication

**Configuration (DNS TXT Record):**
```
_dmarc.company.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com; ruf=mailto:dmarc-forensics@company.com; pct=100"
```

**Effect:** Emails failing DMARC are rejected, preventing domain spoofing.

---

### 5. User Training & Phishing Simulation

**Service/Tool:** Security Awareness Platform (KnowBe4, Proofpoint, etc.)

**Configuration:**
- Monthly simulated phishing campaigns
- Immediate training for users who click
- Reporting button in email client
- Recognition for users who report

---

## Validation

**How to verify controls are working:**

1. **Attachment blocking test:**
   - Send test email with `.bat` or `.exe` attachment
   - Verify it's blocked/quarantined
   ```bash
   echo "test" > test.bat
   # Send via external email to internal user
   # Should be blocked
   ```

2. **Double extension test:**
   - Send email with `invoice.pdf.bat` attachment
   - Verify detection and blocking

3. **Safe Links test:**
   - Send email with test URL
   - Verify URL is rewritten to pass through scanner

4. **DMARC test:**
   - Use online DMARC checker (dmarcian, MXToolbox)
   - Verify policy is `p=reject`

5. **External banner test:**
   - Send from external address
   - Verify warning banner appears

---

## Gaps / Bypass Scenarios

**This does NOT protect against:**

| Gap | Mitigation |
|-----|------------|
| Legitimate file-sharing links (OneDrive, Dropbox) containing malware | Cloud app security scanning |
| Compromised trusted sender accounts | Anomaly detection, impossible travel |
| HTML smuggling in email body | Advanced threat protection with sandboxing |
| Zero-day malware in allowed formats (PDF, DOCX) | Sandbox detonation before delivery |
| Social engineering without technical payload | User training, verbal verification policies |
| Phishing via other channels (SMS, voice, social media) | Multi-channel security awareness |

---

## Related

- **Detection:** [Phishing Email Detection](./03-Detection.md)
- **Playbook:** [Phishing Email Response](./04-Playbook.md)
- **Case where this would've helped:** [PhishNet Case](./01-Case-Writeup.md) — double extension blocking would have stopped the `.pdf.bat` attachment
