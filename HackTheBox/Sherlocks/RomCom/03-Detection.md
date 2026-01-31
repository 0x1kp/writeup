# Detection: WinRAR Path Traversal Exploitation (CVE-2025-8088)

## Behavior Targeted

File creation in sensitive directories (AppData, Startup, System32) immediately following WinRAR archive extraction, indicating path traversal exploitation.

---

## MITRE ATT&CK Mapping

- **Tactic:** Initial Access / Persistence
- **Technique:** T1190 (Exploit Public-Facing Application), T1547.009 (Boot or Logon Autostart: Startup Folder)

---

## Data Source

- **Log type:** Sysmon (Event ID 11 - FileCreate), EDR file creation events
- **Key fields:** TargetFilename, Image (process creating file), CreationUtcTime

---

## Logic / Query

### Sigma Rule

```yaml
title: WinRAR Path Traversal - File Written to Startup Folder
id: c3d4e5f6-7890-1234-cdef-345678901234
status: experimental
description: Detects WinRAR writing files directly to Startup folder, indicating potential CVE-2025-8088 exploitation
author: D
date: 2026/01/30
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-8088
    - https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/
logsource:
    category: file_event
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\WinRAR.exe'
            - '\unrar.exe'
            - '\7zFM.exe'
            - '\7z.exe'
    selection_path:
        TargetFilename|contains:
            - '\Start Menu\Programs\Startup\'
            - '\AppData\Local\'
            - '\AppData\Roaming\'
            - '\Windows\System32\'
            - '\Windows\SysWOW64\'
    filter_legitimate:
        TargetFilename|endswith:
            - '.txt'
            - '.log'
    condition: selection_process and selection_path and not filter_legitimate
falsepositives:
    - Legitimate software installers distributed as archives
    - Self-extracting archives with intended installation paths
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.persistence
    - attack.t1547.009
    - cve.2025.8088
```

### KQL (Microsoft Defender / Sentinel)

```kql
DeviceFileEvents
| where InitiatingProcessFileName in~ ("WinRAR.exe", "unrar.exe", "7z.exe", "7zFM.exe")
| where FolderPath has_any ("Start Menu\\Programs\\Startup", "AppData\\Local", "AppData\\Roaming")
| where FileName !endswith ".txt" and FileName !endswith ".log"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, InitiatingProcessAccountName
| sort by Timestamp desc
```

### Splunk SPL

```spl
index=sysmon EventCode=11
| where match(Image, "(?i)(WinRAR|unrar|7z)")
| where match(TargetFilename, "(?i)(Start Menu.*Startup|AppData\\\\Local|AppData\\\\Roaming)")
| where NOT match(TargetFilename, "(?i)\\.(txt|log)$")
| table _time, Computer, User, Image, TargetFilename
```

---

## Test Cases

| Test | Input | Expected Result | Actual Result | Pass? |
|------|-------|-----------------|---------------|-------|
| True positive | Extract malicious RAR that writes to Startup | Alert fires | — | ☐ |
| True negative | Extract normal RAR to Documents folder | No alert | — | ☐ |
| True positive | WinRAR writes EXE to AppData\Local | Alert fires | — | ☐ |
| False positive test | Self-extracting installer to AppData | May alert — tune if needed | — | ☐ |

---

## False Positive Notes

- **Expected FP sources:**
  - Self-extracting software installers
  - Portable applications extracted to AppData
  - Legitimate archives containing configuration files

- **Tuning applied:**
  - Exclude .txt and .log files
  - Consider excluding known software installer hashes
  - May need to whitelist specific legitimate archives

---

## Triage Checklist (for analyst)

1. [ ] Verify the archive name and source — was it expected/requested by user?
2. [ ] Check file hash of created file against known malware databases
3. [ ] Review what other files were created in the same timeframe
4. [ ] Look for decoy documents (PDF, DOCX) extracted alongside
5. [ ] Check if persistence mechanism (LNK, EXE in Startup) was created
6. [ ] Verify WinRAR version — is it vulnerable to CVE-2025-8088?
7. [ ] If confirmed malicious, isolate host and escalate to IR

---

# Detection: Suspicious LNK in Startup Folder

## Behavior Targeted

Creation of LNK (shortcut) files in the Startup folder pointing to executables in non-standard locations.

---

## Logic / Query

### Sigma Rule

```yaml
title: Suspicious LNK Created in Startup Folder
id: d4e5f678-9012-3456-def0-456789012345
status: experimental
description: Detects LNK file creation in Startup folder, potential persistence mechanism
author: D
date: 2026/01/30
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Start Menu\Programs\Startup\'
        TargetFilename|endswith: '.lnk'
    condition: selection
falsepositives:
    - Legitimate software installation
    - User-created shortcuts for startup applications
level: medium
tags:
    - attack.persistence
    - attack.t1547.009
```

---

## Triage Checklist

1. [ ] Parse the LNK file to identify target executable path
2. [ ] Verify target executable is legitimate (signed, known location)
3. [ ] Check if LNK was created by user interaction or automated process
4. [ ] Correlate with recent archive extractions or downloads
5. [ ] If target is in AppData or Temp, treat as suspicious

---

## Related Artifacts

- Case Writeup: [RomCom Case Writeup](Cases/RomCom/01-Case-Writeup.md)
- Evidence Map: [RomCom Evidence Map](Cases/RomCom/02-Evidence-Map.md)
- Playbook: [Windows Archive Exploitation Triage](Cases/RomCom/04-Playbook.md)
