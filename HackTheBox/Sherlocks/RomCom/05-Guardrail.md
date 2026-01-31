# Guardrail: Archive Utility Hardening & Path Traversal Prevention

## What It Prevents

- Exploitation of archive tool path traversal vulnerabilities (CVE-2025-8088, etc.)
- Malware deployment via weaponized archives
- Persistence establishment through archive extraction

---

## Implementation

### 1. Patch Management (Primary Control)

**Service/Tool:** SCCM, Intune, PDQ Deploy, or manual update

**Configuration:**
- Maintain inventory of archive utilities (WinRAR, 7-Zip, PeaZip)
- Subscribe to vendor security advisories
- Deploy patches within 72 hours of critical CVE disclosure

**Verification:**
```powershell
# Check WinRAR version
(Get-ItemProperty "HKLM:\SOFTWARE\WinRAR").exe | Split-Path -Leaf
# Or check file version
(Get-Item "C:\Program Files\WinRAR\WinRAR.exe").VersionInfo.FileVersion
```

---

### 2. Application Whitelisting / Control

**Service/Tool:** Windows Defender Application Control (WDAC), AppLocker

**Configuration (AppLocker - block unsigned from user-writable locations):**
```xml
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePathRule Id="..." Name="Block AppData executables"
                Description="Block unsigned EXE from AppData"
                UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
      <FilePathCondition Path="%LOCALAPPDATA%\*"/>
    </Conditions>
  </FilePathRule>
</RuleCollection>
```

**Effect:** Executables dropped to AppData via path traversal cannot execute.

---

### 3. Startup Folder Monitoring

**Service/Tool:** Sysmon, EDR, or GPO folder auditing

**Configuration (Sysmon):**
```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
</FileCreate>
```

**Configuration (GPO Auditing):**
- Enable Object Access auditing
- Apply SACL to Startup folder for Create/Write operations

**Effect:** Immediate alert when any file is written to Startup folder.

---

### 4. Email/Web Gateway Filtering

**Service/Tool:** Email security gateway, web proxy

**Configuration:**
- Block or quarantine RAR, 7Z, ACE files from external senders
- Require password-protected archives to be submitted for analysis
- Strip Mark-of-the-Web (MOTW) checking for downloaded archives

**Considerations:**
- May impact legitimate business workflows
- Consider quarantine + release workflow vs. outright block

---

### 5. User Training

**Service/Tool:** Security awareness program

**Content:**
- Warn about archive files from unknown sources
- Teach recognition of "errors but it worked" exploitation pattern
- Encourage reporting of suspicious archives

---

## Validation

**How to verify controls are working:**

1. **Patch verification:**
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\WinRAR" | Select-Object exe, version
   ```

2. **AppLocker test:**
   - Drop test EXE to `%LOCALAPPDATA%\test.exe`
   - Attempt to execute — should be blocked

3. **Startup monitoring test:**
   - Create benign file in Startup folder
   - Verify Sysmon event or alert generated

4. **Gateway test:**
   - Send test RAR with benign payload from external address
   - Verify quarantine or block action

---

## Gaps / Bypass Scenarios

**This does NOT protect against:**

| Gap | Mitigation |
|-----|------------|
| Zero-day vulnerabilities before patch | Defense in depth (AppLocker, monitoring) |
| Signed malware | Behavioral detection, EDR |
| User manually moves file to trusted location | Endpoint detection, user training |
| Alternative archive formats not filtered | Expand gateway rules |
| Attackers using legitimate archive locations | Anomaly-based detection |

---

## Related

- **Detection:** [WinRAR Path Traversal Detection](Cases/RomCom/03-Detection.md)
- **Playbook:** [Archive Exploitation Triage](Cases/RomCom/04-Playbook.md)
- **Case where this would've helped:** [RomCom Case Writeup](Cases/RomCom/01-Case-Writeup.md) — patching WinRAR would have prevented exploitation; AppLocker would have blocked dropped EXE execution
