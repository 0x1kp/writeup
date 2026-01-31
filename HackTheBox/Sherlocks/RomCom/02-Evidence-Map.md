# Evidence Map: RomCom — WinRAR Path Traversal Exploitation

## Hypothesis → Data Source → Query/Check

| # | Hypothesis | Data Source | Query/Check | Result | Confidence |
|---|------------|-------------|-------------|--------|------------|
| 1 | CVE-2025-8088 was exploited | Vulnerability research | Cross-reference RomCom TTPs with CVE database | CVE-2025-8088 confirmed as WinRAR path traversal | High |
| 2 | Malicious archive was delivered to Susan | `$MFT` | Navigate to `C:\Users\Susan\Documents` | `Pathology-Department-Research-Records.rar` found | High |
| 3 | Archive was opened by user | `$J` (USN Journal) | Filter for ObjectIdChange on RAR file | Opened at 2025-09-02 08:14:04 | High |
| 4 | Backdoor was dropped via path traversal | `$MFT` + `$J` | Search for EXE/DLL files created same time as archive open | `ApbxHelper.exe` in AppData\Local | High |
| 5 | Persistence was established | `$MFT` | Check Startup folder for new files | `Display Settings.lnk` found | High |
| 6 | Decoy document was used | `$J` | Filter for PDF files extracted from archive | `Genotyping_Results_B57_Positive.pdf` | High |
| 7 | User opened decoy document | `$J` | Look for LNK creation indicating file open | LNK created at 2025-09-02 08:15:05 | High |

---

## Key Pivots

```
Malicious RAR in Documents ($MFT)
    ↓ [User opened archive]
USN Journal shows archive access ($J)
    ↓ [Path traversal exploit triggers]
Backdoor EXE dropped to AppData\Local ($MFT/$J)
    ↓ [Persistence mechanism deployed]
LNK dropped to Startup folder ($MFT/$J)
    ↓ [User distracted]
Decoy PDF extracted and opened ($J)
```

---

## Evidence Sources Used

| Source | Location | What It Told Us |
|--------|----------|-----------------|
| $MFT | `C:\$MFT` | File paths, creation timestamps, directory structure |
| $J (USN Journal) | `C:\$Extend\$UsnJrnl:$J` | File operations with timestamps, update reasons |
| VHDX Image | Provided triage image | Container for all evidence |

---

## Artifact Analysis Details

### $MFT Analysis (MFTExplorer)

**Key entries found:**

| File | Path | Created | Modified |
|------|------|---------|----------|
| `Pathology-Department-Research-Records.rar` | `C:\Users\Susan\Documents\` | 2025-09-02 08:13:50 | 2025-09-02 08:13:50 |
| `ApbxHelper.exe` | `C:\Users\Susan\AppData\Local\` | 2025-09-02 08:14:04 | 2025-09-02 08:14:04 |
| `Display Settings.lnk` | `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | 2025-09-02 08:14:04 | 2025-09-02 08:14:04 |

### USN Journal Analysis

**Key operations:**

| Timestamp | File | Update Reason | Interpretation |
|-----------|------|---------------|----------------|
| 08:14:04 | `Pathology-Department-Research-Records.rar` | ObjectIdChange | File opened/accessed |
| 08:14:04 | `ApbxHelper.exe` | FileCreate | Backdoor dropped |
| 08:14:04 | `Display Settings.lnk` | FileCreate | Persistence created |
| 08:14:04 | `Genotyping_Results_B57_Positive.pdf` | FileCreate | Decoy extracted |
| 08:15:05 | `Genotyping_Results_B57_Positive.pdf.lnk` | FileCreate | User opened PDF |

---

## Gaps / What I Couldn't Confirm

| Gap | Why It Matters | What Would Resolve It |
|-----|----------------|----------------------|
| Delivery vector not confirmed | Don't know how RAR reached Susan | Email logs, browser history, download folder analysis |
| Backdoor functionality unknown | Don't know attacker's capabilities | Malware reverse engineering, sandbox analysis |
| C2 communication not observed | Don't know if backdoor phoned home | Network logs, PCAP, proxy logs |
| Other affected users unknown | May be broader campaign | Enterprise-wide hunt for IOCs |
| Sender/attacker identity | Attribution incomplete | Email headers, threat intel correlation |

---

## Forensic Tool Notes

**Setup required:**
1. Download and mount VHDX: `Mount-DiskImage -ImagePath "path\to\file.vhdx"`
2. Install Zimmerman tools: `.\Get-ZimmermanTools.ps1`
3. May need: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

**MFTExplorer usage:**
- Load $MFT file from mounted drive
- Navigate directory tree to find files of interest
- Export timeline for external analysis

**USN Journal parsing:**
- Use MFTECmd.exe or similar to parse $J
- Filter by timestamp range around incident
- Look for FileCreate, Rename, Delete operations
