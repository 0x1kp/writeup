# Case Writeup: RomCom — WinRAR Path Traversal Exploitation

## Summary

A hospital research lab workstation (user: Susan) was compromised via CVE-2025-8088, a WinRAR path traversal vulnerability exploited by the RomCom threat group. The attacker delivered a malicious RAR archive (`Pathology-Department-Research-Records.rar`) that, when opened, dropped a backdoor executable (`ApbxHelper.exe`) and established persistence via a startup folder shortcut. A decoy PDF distracted the user while the malware executed. Confidence: **High** based on MFT and USN Journal forensic analysis.

---

## Timeline

| Timestamp (UTC) | Event | Source | Significance |
|-----------------|-------|--------|--------------|
| 2025-09-02 08:13:50 | Malicious RAR archive created on disk | `$MFT` (Susan\Documents) | Archive delivered to victim (likely via email/download) |
| 2025-09-02 08:14:04 | RAR archive opened by user | `$J` (USN Journal) | User interaction triggers exploit |
| 2025-09-02 08:14:04 | `ApbxHelper.exe` dropped to `AppData\Local` | `$J` / `$MFT` | Backdoor payload written via path traversal |
| 2025-09-02 08:14:04 | `Display Settings.lnk` dropped to Startup folder | `$J` / `$MFT` | Persistence mechanism established |
| 2025-09-02 08:14:04 | `Genotyping_Results_B57_Positive.pdf` extracted | `$J` | Decoy document extracted to distract user |
| 2025-09-02 08:15:05 | Decoy PDF opened by user | `$J` (LNK file creation) | User believes extraction was legitimate |

---

## Attack Narrative

**Delivery:** The RomCom threat group delivered a weaponized RAR archive named `Pathology-Department-Research-Records.rar` to Susan in the hospital's pathology department. The archive was crafted to exploit CVE-2025-8088, a path traversal vulnerability in WinRAR.

**Exploitation:** When Susan opened the archive using WinRAR, the vulnerability allowed files to be written outside the intended extraction directory. Despite receiving "tons of errors," the decoy document appeared to extract normally, leading Susan to believe nothing was wrong.

**Payload Deployment:** The exploit dropped two malicious files:
1. **`ApbxHelper.exe`** — A backdoor executable placed in `C:\Users\Susan\AppData\Local\`
2. **`Display Settings.lnk`** — A shortcut placed in the Startup folder (`...\Start Menu\Programs\Startup\`) that points to the backdoor, ensuring persistence across reboots

**User Deception:** A legitimate-looking decoy PDF (`Genotyping_Results_B57_Positive.pdf`) was extracted to distract Susan. She opened this document at 08:15:05, unaware that the backdoor had already been deployed.

**Result:** The attacker achieved persistent access to Susan's workstation via the startup shortcut executing the backdoor on every login.

---

## Key IOCs

| Type | Value | Context |
|------|-------|---------|
| CVE | CVE-2025-8088 | WinRAR path traversal vulnerability |
| Archive | `Pathology-Department-Research-Records.rar` | Malicious RAR file |
| Backdoor | `C:\Users\Susan\AppData\Local\ApbxHelper.exe` | Primary payload |
| Persistence | `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk` | Startup folder shortcut |
| Decoy | `Genotyping_Results_B57_Positive.pdf` | Social engineering lure |
| Threat Actor | RomCom | Attribution based on TTP and vulnerability usage |

---

## Findings & Confidence

| Finding | Evidence | Confidence | Notes |
|---------|----------|------------|-------|
| CVE-2025-8088 exploitation | Files written outside extraction path (AppData, Startup) | High | Path traversal behavior confirmed |
| RomCom attribution | Known TTP match (WinRAR exploit + healthcare targeting) | Medium-High | Based on threat intel correlation |
| Backdoor dropped | `ApbxHelper.exe` in AppData\Local | High | MFT entry confirms |
| Persistence established | LNK in Startup folder | High | MFT/USN Journal confirms |
| User opened decoy | LNK prefetch/creation timestamp | High | Timeline correlation |
| User received warnings | Scenario context ("tons of errors") | Medium | User-reported |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Malicious RAR delivered (presumed via email) |
| Execution | User Execution: Malicious File | T1204.002 | User opened RAR archive |
| Defense Evasion | Masquerading | T1036 | Decoy PDF, LNK named "Display Settings" |
| Persistence | Boot or Logon Autostart: Registry Run Keys / Startup Folder | T1547.009 | LNK in Startup folder |
| Initial Access | Exploit Public-Facing Application | T1190 | CVE-2025-8088 (WinRAR vulnerability) |

---

## Lessons Learned

**What I did well:**
- Successfully mounted and navigated VHDX forensic image
- Used Zimmerman tools (MFTExplorer) effectively to analyze filesystem artifacts
- Correlated USN Journal entries with MFT to build accurate timeline
- Identified persistence mechanism and mapped to MITRE ATT&CK

**What I missed initially:**
- Had to research VHDX forensics workflow (new to Windows forensics tooling)
- Needed to learn PowerShell execution policy to run Zimmerman tools
- Initially unfamiliar with USN Journal analysis

**What I'd do differently:**
- Pre-stage Windows forensics VM with tools installed
- Build reference for common MFT/USN Journal analysis queries
- Document KAPE artifact locations for faster triage

---

## Next Actions (if real incident)

- [ ] **Isolate:** Remove Susan's workstation from network immediately
- [ ] **Preserve:** Image disk and memory before remediation
- [ ] **Analyze backdoor:** Submit `ApbxHelper.exe` to sandbox and reverse engineering
- [ ] **Hunt:** Search for `ApbxHelper.exe` hash and `Display Settings.lnk` across all endpoints
- [ ] **Block:** Add file hashes to EDR blocklist
- [ ] **Patch:** Update WinRAR to version patched against CVE-2025-8088 across enterprise
- [ ] **Alert:** Notify other potential targets (pathology department, similar roles)
- [ ] **Email search:** Identify delivery vector and other recipients

---

## References

- [NVD — CVE-2025-8088](https://nvd.nist.gov/vuln/detail/CVE-2025-8088)
- [ESET: RomCom exploiting WinRAR zero-day](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [Malpedia: RomCom Threat Actor](https://malpedia.caad.fkie.fraunhofer.de/actor/romcom)
- [MITRE ATT&CK: T1547.009 — Startup Folder](https://attack.mitre.org/techniques/T1547/009/)
