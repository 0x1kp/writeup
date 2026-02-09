# Detection: Phishing Email with Disguised Executable Attachment

## Behavior Targeted

Email attachments containing files with double extensions (e.g., `.pdf.bat`, `.doc.exe`) that masquerade as documents but are actually executable files.

---

## MITRE ATT&CK Mapping

- **Tactic:** Initial Access, Defense Evasion
- **Technique:** T1566.001 (Phishing: Spearphishing Attachment), T1036.007 (Masquerading: Double File Extension)

---

## Data Source

- **Log type:** Email gateway logs, Endpoint detection (file creation)
- **Key fields:** attachment_name, attachment_extension, file_type, sender_domain

---

## Logic / Query

### Sigma Rule — Email Attachment Double Extension

```yaml
title: Email Attachment with Double Extension
id: f1a2b3c4-d5e6-7890-abcd-123456789012
status: experimental
description: Detects email attachments using double file extensions to disguise executables as documents
author: D
date: 2026/02/09
references:
    - https://attack.mitre.org/techniques/T1036/007/
    - https://attack.mitre.org/techniques/T1566/001/
logsource:
    category: email
    product: email_gateway
detection:
    selection:
        attachment_name|re: '.*\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|png)\.(exe|bat|cmd|ps1|vbs|js|hta|scr|pif|com|msi)$'
    condition: selection
falsepositives:
    - Legitimate files with unusual naming conventions (rare)
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.defense_evasion
    - attack.t1036.007
```

### Sigma Rule — ZIP Containing Executable

```yaml
title: Email ZIP Attachment Containing Executable
id: f2b3c4d5-e6f7-8901-bcde-234567890123
status: experimental
description: Detects ZIP attachments containing executable files
author: D
date: 2026/02/09
logsource:
    category: email
    product: email_gateway
detection:
    selection_zip:
        attachment_name|endswith:
            - '.zip'
            - '.rar'
            - '.7z'
    selection_content:
        archive_contains|endswith:
            - '.exe'
            - '.bat'
            - '.cmd'
            - '.ps1'
            - '.vbs'
            - '.js'
            - '.hta'
    condition: selection_zip and selection_content
falsepositives:
    - Legitimate software distribution
    - IT department sending tools
level: medium
tags:
    - attack.initial_access
    - attack.t1566.001
```

### KQL (Microsoft Defender for Office 365)

```kql
EmailAttachmentInfo
| where FileName matches regex @".*\.(pdf|doc|docx|xls|xlsx)\.(exe|bat|cmd|ps1|vbs|js)$"
    or (FileName endswith ".zip" and FileType has_any ("executable", "script"))
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256
| join EmailEvents on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, FileName, SHA256
```

### Splunk SPL (Email Gateway)

```spl
index=email sourcetype=email_gateway
| regex attachment_name=".*\.(pdf|doc|docx|xls|xlsx)\.(exe|bat|cmd|ps1|vbs|js)$"
| table _time, sender, recipient, subject, attachment_name, attachment_hash
| sort -_time
```

---

## Test Cases

| Test | Input | Expected Result | Actual Result | Pass? |
|------|-------|-----------------|---------------|-------|
| True positive | Email with `invoice.pdf.bat` attachment | Alert fires | — | ☐ |
| True positive | ZIP containing `document.doc.exe` | Alert fires | — | ☐ |
| True negative | Email with `report.pdf` (no double ext) | No alert | — | ☐ |
| True negative | ZIP containing only `data.csv` | No alert | — | ☐ |
| Edge case | File named `v1.0.exe` (version number) | No alert (single ext) | — | ☐ |

---

## False Positive Notes

- **Expected FP sources:**
  - Version-numbered executables (e.g., `app.v2.0.exe`)
  - Legitimate software archives from IT
  - Developer tools shared via email

- **Tuning applied:**
  - Whitelist known IT distribution addresses
  - Focus on document-to-executable patterns specifically
  - Add sender reputation scoring

---

## Triage Checklist

1. [ ] Verify sender address — is it external or spoofed internal?
2. [ ] Check sender domain age and reputation
3. [ ] Extract and sandbox the attachment
4. [ ] Check if recipient opened/executed the file (EDR logs)
5. [ ] Search for other recipients of same MessageID
6. [ ] Review email body for social engineering indicators
7. [ ] If confirmed phishing, block sender domain and hash

---

# Detection: High-Priority External Email with Payment Request

## Behavior Targeted

External emails with high-priority flags and financial/payment keywords targeting finance or accounting teams.

---

## MITRE ATT&CK Mapping

- **Tactic:** Initial Access
- **Technique:** T1566 (Phishing)

---

## Logic / Query

### Sigma Rule

```yaml
title: High Priority External Email with Payment Keywords
id: f3c4d5e6-f789-0123-cdef-345678901234
status: experimental
description: Detects high-priority external emails containing urgent payment requests
author: D
date: 2026/02/09
logsource:
    category: email
    product: email_gateway
detection:
    selection_priority:
        x_priority: '1'
    selection_external:
        sender_domain|not_endswith: '@yourcompany.com'
    selection_keywords:
        subject|contains:
            - 'urgent'
            - 'invoice'
            - 'payment'
            - 'overdue'
            - 'wire transfer'
            - 'immediate action'
    selection_target:
        recipient|contains:
            - 'accounting'
            - 'finance'
            - 'payable'
            - 'accounts'
    condition: selection_priority and selection_external and selection_keywords and selection_target
falsepositives:
    - Legitimate urgent vendor communications
level: medium
tags:
    - attack.initial_access
    - attack.t1566
```

---

## Related Artifacts

- Case Writeup: [PhishNet Case Writeup](./01-Case-Writeup.md)
- Evidence Map: [PhishNet Evidence Map](./02-Evidence-Map.md)
- Playbook: [Phishing Email Triage](./04-Playbook.md)
