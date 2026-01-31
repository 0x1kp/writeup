# Playbook: Windows Archive Exploitation Triage (WinRAR/7-Zip Path Traversal)

## Trigger

- EDR/AV alert for suspicious file in Startup folder or AppData
- Detection rule fires for archive utility writing to sensitive path
- User reports "errors" when extracting archive but document opened fine
- Threat intel on active exploitation of archive tool vulnerabilities

---

## Scope

Windows endpoints with WinRAR, 7-Zip, or similar archive utilities installed, particularly:
- Unpatched versions vulnerable to path traversal (e.g., CVE-2025-8088)
- Users who receive external files (email, downloads)

---

## Steps

### Phase 1: Initial Triage (15 min)

1. [ ] **Identify the archive**
   - Check user's Downloads, Documents, Desktop, email attachments
   - Look for recently accessed RAR, ZIP, 7Z files
   - Note filename — often uses social engineering (invoices, reports, records)

2. [ ] **Check archive utility version**
   - WinRAR: Help → About (or registry `HKLM\SOFTWARE\WinRAR`)
   - 7-Zip: Help → About
   - Compare against CVE-affected versions

3. [ ] **Review Startup folder**
   - Path: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
   - Look for: unexpected LNK files, EXE files, scripts
   - Note creation timestamps

4. [ ] **Check AppData for dropped files**
   - Paths: `%LOCALAPPDATA%`, `%APPDATA%`
   - Look for: recently created EXE, DLL, scripts
   - Compare timestamps with archive access time

**Decision point:**
- If suspicious files found in Startup/AppData with matching timestamps → **escalate to full IR**
- If nothing found → may be false positive, but continue basic validation

---

### Phase 2: Forensic Analysis (30 min)

5. [ ] **Acquire forensic artifacts**
   - $MFT: `C:\$MFT`
   - USN Journal: `C:\$Extend\$UsnJrnl:$J`
   - Prefetch: `C:\Windows\Prefetch\`
   - Recent files: `%APPDATA%\Microsoft\Windows\Recent\`

6. [ ] **Analyze $MFT for file creation timeline**
   - Tool: MFTExplorer, MFTECmd
   - Look for files created within seconds of archive access
   - Focus on: EXE, DLL, LNK, BAT, PS1, VBS

7. [ ] **Parse USN Journal for operations**
   - Filter by timestamp (around archive open time)
   - Look for: FileCreate operations in Startup, AppData, System folders
   - Note: ObjectIdChange on archive = user opened it

8. [ ] **Analyze LNK files**
   - Tool: LECmd (Zimmerman), LNK Parser
   - Extract target path, arguments, working directory
   - If target is in AppData/Temp → highly suspicious

9. [ ] **Check for decoy documents**
   - Look for PDF, DOCX, XLSX extracted from archive
   - These distract user while malware executes
   - Check if user opened decoy (Recent files, Prefetch)

---

### Phase 3: Malware Analysis (if file recovered)

10. [ ] **Collect the dropped executable**
    - Hash it (MD5, SHA256)
    - Check against VirusTotal, MalwareBazaar
    - Note: May be zero-day, low VT detection initially

11. [ ] **Static analysis (quick)**
    - Strings: look for C2 domains, suspicious imports
    - PE headers: compilation timestamp, packer detection
    - Signed? Check certificate validity

12. [ ] **Dynamic analysis (sandbox)**
    - Submit to sandbox (Any.Run, Joe Sandbox, Cuckoo)
    - Monitor: network connections, file operations, registry changes
    - Document C2 infrastructure if observed

---

### Phase 4: Scoping

13. [ ] **Enterprise-wide hunt**
    - Search for dropped file hash across all endpoints
    - Search for archive filename in email logs
    - Look for same LNK name in other Startup folders

14. [ ] **Check for execution**
    - Prefetch for dropped EXE
    - Process creation logs (Sysmon Event ID 1)
    - Network connections from dropped file

15. [ ] **Identify delivery vector**
    - Email: search for archive as attachment
    - Web: check browser history, download logs
    - USB: check for removable media events

---

### Phase 5: Containment

16. [ ] **Isolate affected host**
    - Network isolation (EDR, switch port, firewall)
    - Do NOT power off (preserve memory evidence)

17. [ ] **Block IOCs**
    - Add file hashes to EDR blocklist
    - Block C2 domains/IPs at perimeter
    - Email filter for archive filename

18. [ ] **Disable persistence**
    - Delete malicious LNK from Startup folder
    - Remove dropped EXE (after acquisition)
    - Check scheduled tasks, registry Run keys

---

### Phase 6: Eradication & Recovery

19. [ ] **Patch archive utilities**
    - Update WinRAR/7-Zip to latest version
    - Deploy via SCCM/Intune/GPO

20. [ ] **Reimage if needed**
    - If backdoor executed, consider full reimage
    - Restore from known-good backup

21. [ ] **User notification**
    - Inform user of compromise
    - Remind to report suspicious archives/errors

---

## Evidence Sources

| Question | Source | Tool/Query |
|----------|--------|------------|
| What archive was opened? | $MFT, Recent files | MFTExplorer, dir /a |
| When was it opened? | $J (USN Journal) | MFTECmd |
| What files were created? | $MFT, $J, Sysmon | Timeline analysis |
| Where does LNK point? | LNK file | LECmd |
| Did malware execute? | Prefetch, Sysmon | PECmd, Event logs |
| What's the file hash? | Dropped file | Get-FileHash, sha256sum |

---

## Escalation Criteria

- **Escalate immediately if:**
  - Confirmed file drop to Startup folder or System directories
  - Malware executed (Prefetch, process logs)
  - C2 communication observed
  - Multiple users affected
  - Threat actor attribution (known APT group)

---

## References

- [RomCom Case Writeup](Cases/RomCom/01-Case-Writeup.md)
- [WinRAR Path Traversal Detection](Cases/RomCom/03-Detection.md)
- [Zimmerman Tools](https://ericzimmerman.github.io/)
- [MITRE T1547.009 — Startup Folder](https://attack.mitre.org/techniques/T1547/009/)
