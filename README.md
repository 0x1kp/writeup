# Cybersecurity Writeups and Lab Notes: Detection and Response

This repository is a structured ledger of defensive repetitions. Each entry documents the detection, investigation, and remediation of a specific threat scenario across home lab, cloud, and professional lab platforms.

Instead of simple walkthroughs, these writeups follow a rigorous Incident Response life cycle, focusing on telemetry analysis, containment strategy, and control improvement.

---

## Repository Structure

The repository is organized by platform and environment type to ensure quick navigation:

- **Home-Lab/**: Documentation of local virtualization environments, including network topology, AD forest builds, and defensive tool integration.

- **HackTheBox/**: Walkthroughs for Blue Team labs and Sherlocks, focusing on retired content and detection engineering.

- **Blue-Team-Labs/**: Incident response and SOC-related investigations from Blue Team Labs Online (BTLO).

- **Cyber-Defenders/**: Deep-dive forensics, memory analysis, and network traffic investigations.


---

## Methodology

Every investigation in this repository adheres to a strict 10-point template. This ensures that every lab session results in actionable defensive data and repeatable detection logic.

### Core Workflow

1. Preparation: Defining the scenario, threat story, and expected telemetry.
    
2. Execution: Documenting specific attack tools and operator identities.
    
3. Analysis: Deep-diving into evidence artifacts and building a high-fidelity timeline.
    
4. Response: Documenting containment, eradication, and recovery steps.
    
5. Hardening: Identifying root causes and implementing prevention (SCPs, IAM hardening) and detections (Athena/KQL queries).
    

---

## Rep Template (Copy/Paste)

Create a new file per rep at: `reps/YYYY-MM-DD_<tenant>_<scenario-slug>/README.md`.

### 1) Scenario

**Tenant:** **Date:** **Scenario name:** **Threat story / objective:** **Assumptions:** **Expected telemetry:** (CloudTrail, S3 data events, Flow logs, GuardDuty, etc.)

### 2) Execution

**Technique / tool used:** (e.g., Stratus Red Team technique name)

**Operator identity:** (attack runner principal/role)

**Steps executed:** (high-level, not sensitive)

**Scope of changes introduced:** ### 3) Evidence

#### Key pivots

- Account ID(s):
    
- Principal / role ARN(s):
    
- Source IP(s):
    
- Bucket/object key(s):
    
- Resource ID(s): (instance ID, role name, SG ID)
    

#### Evidence artifacts

- Links to saved Athena query outputs (or exported results)
    
- Screenshots (if used)
    
- Log snippets (minimal, relevant)
    
- Event IDs / timestamps
    

### 4) Timeline

|**Time (UTC)**|**Source**|**Event**|**Notes**|
|---|---|---|---|
|||||

### 5) Investigation Notes

**Initial alert / trigger:** **Working theory:** **What was confirmed:** **What was ruled out:** **Impact assessment:** (what data/resources were accessed/modified)

**Scope:** (how far it spread; other accounts/resources checked)

### 6) Containment

**Containment objective:** **Actions taken (ordered):**

1.

2.

3.

**Artifacts / commands / changes:**

- Security group changes:
    
- IAM changes:
    
- Bucket policy changes:
    
- Instance isolation steps:
    

**Immediate validation:** (how you confirmed containment worked)

### 7) Eradication / Recovery (if applicable)

**Remediation actions:** **Recovery actions:** **Post-recovery validation:** ### 8) Prevention (Required)

**Root cause:** **Control improvement(s):**

- (e.g., tighten trust policy, require ExternalId, restrict principal conditions)
    

**Detection improvement(s):**

- (e.g., alert on AssumeRole + GetObject chain, new ASN/IP, unusual user-agent)
    

**Guardrail/SCP changes (if applicable):**

**How to prove it is fixed:**

- Rerun the scenario OR run a targeted test
    

### 9) Queries (Required)

#### Athena (Log-Archive)

- Query 1: Purpose + SQL
    
- Query 2: Purpose + SQL
    
- Query 3: Purpose + SQL
    

#### CloudWatch Logs Insights (if used)

- Query 1: Purpose + query
    
- Query 2: Purpose + query
    

#### Service console pivots (GuardDuty/SecHub/Detective)

- What you clicked/pivoted to and what you looked for
    

### 10) Lessons Learned

- What worked
    
- What broke / was missing
    
- What to change in the range before the next rep
    

---

## Disclaimer

All activities are performed in isolated lab environments. Detections and remediations are documented for educational purposes. Always test IAM and SCP changes in a sandbox before applying to production-adjacent environments.
