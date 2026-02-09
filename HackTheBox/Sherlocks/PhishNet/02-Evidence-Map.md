# Evidence Map: PhishNet — Phishing Email Analysis

## Hypothesis → Data Source → Query/Check

| # | Hypothesis | Data Source | Query/Check | Result | Confidence |
|---|------------|-------------|-------------|--------|------------|
| 1 | Email is phishing attempt | Email content | Review subject, body, urgency tactics | Urgent invoice, payment threats, deadline pressure | High |
| 2 | Sender domain is attacker-controlled | Email headers | Check SPF/DKIM/DMARC results | All pass — attacker owns infrastructure | High |
| 3 | X-Originating-IP reveals attacker | Email headers | Extract X-Originating-IP | `45.67.89.10` identified | High |
| 4 | Attachment contains malware | ZIP file | Extract and inspect contents | `invoice_document.pdf.bat` — disguised batch file | High |
| 5 | Phishing URL leads to malicious site | Email body | Extract and analyze URL | `secure.business-finance.com` — same attacker domain | High |
| 6 | Email passed authentication checks | Authentication-Results header | Review SPF/DKIM/DMARC | All pass, making detection harder | High |
| 7 | Batch file is malicious | Attachment contents | Hash and analyze | SHA-256: `8379c41...` — needs sandbox analysis | Medium |

---

## Key Pivots

```
Email headers analysis
    ↓ [Extracted X-Originating-IP: 45.67.89.10]
Received headers trace
    ↓ [Mail path: 198.51.100.75 → 198.51.100.45 → 203.0.113.25 → target]
Authentication-Results review
    ↓ [SPF/DKIM/DMARC pass — attacker controls domain]
Email body analysis
    ↓ [Phishing URL: secure.business-finance.com]
Attachment extraction
    ↓ [ZIP contains invoice_document.pdf.bat]
Double extension identified
    ↓ [Masquerading technique confirmed]
```

---

## Evidence Sources Used

| Source | Location | What It Told Us |
|--------|----------|-----------------|
| Email headers | `email.eml` raw source | Sender IP, mail path, authentication results |
| Email body (HTML) | `email.eml` content | Phishing URL, social engineering tactics |
| Attachment | `Invoice_2025_Payment.zip` | Contains disguised batch file |
| SHA-256 hash | Computed in sandbox | File fingerprint for blocklisting |

---

## Email Header Analysis Details

### Key Headers Extracted

| Header | Value | Significance |
|--------|-------|--------------|
| `X-Originating-IP` | `45.67.89.10` | True sender IP |
| `Return-Path` | `finance@business-finance.com` | Bounce address |
| `Reply-To` | `support@business-finance.com` | Where replies go |
| `From` | `finance@business-finance.com` | Display sender |
| `X-Priority` | `1 (Highest)` | Urgency flag |
| `Received-SPF` | `Pass` | SPF validation passed |
| `DKIM` | `Pass` | DKIM signature valid |
| `DMARC` | `Pass` | DMARC policy satisfied |

### Mail Relay Path (oldest to newest)

```
1. 198.51.100.75 (origin) → relay.business-finance.com [10:05:00]
2. 198.51.100.45 (relay) → mail.business-finance.com [10:10:00]
3. 203.0.113.25 (sender MTA) → mail.target.com [10:15:00]
```

---

## Gaps / What I Couldn't Confirm

| Gap | Why It Matters | What Would Resolve It |
|-----|----------------|----------------------|
| Batch file behavior unknown | Don't know what malware does if executed | Sandbox dynamic analysis |
| Phishing URL destination | Don't know what page is served | URL sandbox analysis |
| Domain registration details | Could reveal attacker identity/patterns | WHOIS lookup |
| Other campaign recipients | May be broader attack | Email gateway log search |
| Credential harvesting success | Don't know if anyone submitted creds | Web proxy logs |

---

## Social Engineering Analysis

| Tactic | Implementation | Effectiveness |
|--------|----------------|---------------|
| Authority | "Finance Department", "Business Finance Ltd." | Medium — generic company name |
| Urgency | "final notice", "flagged for overdue", "penalties" | High — financial pressure |
| Scarcity | "Due Date: February 28, 2025" | Medium — tight deadline |
| Familiarity | Invoice format, professional layout | High — looks legitimate |
| Multiple vectors | Link AND attachment | High — increases success chance |
