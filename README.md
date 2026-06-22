<div align="center">

# Threat Hunting & Security Operations

**Environment:** LOG(N) Pacific Cyber Range · Azure Lab  
**Tools:** `Microsoft Sentinel` `Defender for Endpoint` `KQL` `Log Analytics Workspaces` `Azure VMs`

[← Back to Portfolio](../README.md)

</div>

---

## Overview

Threat hunting is the practice of proactively looking for evidence of compromise that automated detection missed. It requires knowing what normal looks like well enough to recognize what doesn't belong — and being willing to follow that thread wherever it leads.

This page documents the threat hunting engagements and security operations work I completed through the LOG(N) Pacific Cyber Range. Each case presented a different challenge: different attacker techniques, different tooling, different investigation paths.

---

## Case Studies

---

### 🔴 [Threat Hunt: Sudden Network Slowdowns — PowerShell LOLBin Investigation](./cases/network-slowdown-powershell.md)

**Type:** Threat Hunt → Incident Response
**Environment:** Cyber Range Lab — Windows Azure VM
**Tools:** KQL Microsoft Defender for Endpoint Log Analytics Workspaces

A Windows VM exposed to the internet began showing unusual network behavior — high volumes of failed outbound connections with no obvious cause. What started as a network slowdown investigation uncovered suspicious PowerShell execution chains consistent with Living-off-the-Land (LOLBin) attacker tradecraft.

**Key findings:**


182+ failed outbound connections from a single host, mostly on TCP 80/443 — not scanning behavior, but unusual volume
Pivoted to process telemetry and found cmd.exe → powershell.exe chains with ExecutionPolicy Bypass flags
Scripts including portscan.ps1 and staged payloads pulled from external URLs via Invoke-WebRequest
Mapped to MITRE ATT&CK: T1059.001, T1562.001, T1105, T1046


Outcome: No confirmed malware found on scan. Device isolated and flagged for reimaging. NSG rules hardened and detection rules created for PowerShell execution policy bypass patterns.

---
### 🟠 [Threat Hunt: Suspected Data Exfiltration from PIP'd Employee](./cases/data-exfiltration-piped-employee.md)

**Type:** Threat Hunt → Incident Response
**Environment:** Cyber Range Lab — Windows Azure VM
**Tools:** KQL Microsoft Defender for Endpoint Log Analytics Workspaces

An employee placed on a Performance Improvement Plan (PIP) was flagged by management as a potential insider threat. The investigation focused on detecting data archiving, staging, and exfiltration activity on the employee's corporate device using MDE telemetry across file, process, and network logs.

**Key findings:**


Discovered repeated .zip archive creation and file renaming activity in C:\ProgramData\backup\ consistent with data staging
Identified exfiltratedata.ps1 script created on the device — a PowerShell script used to archive and exfiltrate employee data
No confirmed network exfiltration detected across a 40-minute window around the suspicious activity
Mapped to MITRE ATT&CK: T1059.001, T1560, T1074, T1041 (suspected), T1048 (suspected)


**Outcome:** Findings reported to employee's manager. Device isolated pending further instructions. PowerShell hardening and DLP rules recommended.

---

### 🔵 [Threat Hunt: Devices Accidentally Exposed to the Internet — Brute Force Investigation](./cases/devices-exposed-internet.md)

**Type:** Threat Hunt → Incident Response  
**Environment:** Cyber Range Lab — Windows Azure VM  
**Tools:** `KQL` `Microsoft Defender for Endpoint` `Log Analytics Workspaces`

During routine maintenance, a Windows VM in the shared services cluster was discovered to have been internet-facing for several days without authorization. The investigation focused on identifying brute force login attempts from external IPs and determining whether any unauthorized access had occurred.

**Key findings:**
- Device was internet-facing from `2026-02-01` through `2026-02-03` — over 48 hours of exposure
- Multiple external IPs attempted failed network logons, with the top offender making 25 attempts
- None of the attacking IPs achieved a successful logon
- Only the `labuser0` account had successful logins — all from expected internal IPs with zero failed attempts, ruling out brute force
- Mapped to MITRE ATT&CK: T1133, T1110, T1078, T1021

**Outcome:** No unauthorized access confirmed. NSG hardened to restrict RDP to specific endpoints only. Account lockout policy implemented.

---

### 🔵 [Threat Hunt Lab: Tor Browser Usage](./cases/tor-browser-detection.md)

**Type:** Threat Hunt  
**Environment:** Cyber Range Simulation  
**Tools:** `KQL` `MDE` `Microsoft Azure` `Log Analytics Workspaces`

**Hypothesis:** A user on the corporate network is using Tor Browser to bypass monitoring and access the internet anonymously.

Used KQL queries across Defender for Endpoint telemetry to identify process execution patterns consistent with Tor Browser usage. Confirmed unauthorized installation and usage, and documented the detection logic for use as a reusable hunt playbook.

```kql
// Sample detection logic — process name and known Tor browser path
DeviceProcessEvents
| where FileName =~ "firefox.exe"
| where FolderPath contains "Tor Browser"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine
```

---

### 🟣 [Threat Hunt Lab: "IT Support" Recon Simulation](./cases/it-support-recon.md)

**Type:** Threat Hunt — Social Engineering TTPs  
**Environment:** Cyber Range Simulation  
**Tools:** `Microsoft Azure` `Log Analytics Workspaces` `KQL`

**Scenario:** An attacker poses as IT support to gain initial access, then performs staged reconnaissance before attempting exfiltration.

Investigated a simulated social engineering attack chain. Used Azure telemetry to surface reconnaissance activity, egress testing, deception techniques, and persistence attempts that followed the initial access event.

**What made this interesting:** The attacker's tradecraft was deliberate — slow, methodical, designed to blend in. Detecting it required correlating low-signal events across multiple log sources rather than relying on single high-fidelity alerts.

---

## Detection Engineering

Beyond hunting, I built detection rules in Microsoft Defender for Endpoint to automate investigation and response for confirmed threat patterns:

- **Automated isolation rule** — triggered on confirmed cryptominer IoCs, isolating the host and initiating investigation workflow
- **Brute force threshold alert** — custom Sentinel rule firing after N failed logon attempts from a single IP within a rolling window
- **Tor browser execution alert** — process-based detection for known Tor browser file paths and execution patterns

---

## KQL Reference Queries

A selection of queries used across these engagements:

```kql
// Failed logon activity — brute force detection
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 50
| order by FailedAttempts desc

// Process execution from suspicious path
DeviceProcessEvents
| where FolderPath has_any ("Temp", "AppData", "Downloads")
| where FileName endswith ".ps1" or FileName endswith ".exe"
| where InitiatingProcessFileName =~ "cmd.exe" or InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc

// Network connections to known cryptomining pools
DeviceNetworkEvents
| where RemotePort in (3333, 4444, 5555, 7777, 9999, 14444, 45560)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## Lessons Learned

**Alerts tell you something happened. Hunting tells you what it means.** Several of these cases started as noisy alert queues that required context and correlation to make sense of.

**Document as you go.** Every hunt was written up in real time. A finding you can't explain clearly to someone else isn't a finding — it's a hunch.

**False positives are part of the job.** The PowerShell crash case looked suspicious on the surface. Working through it thoroughly and ruling out malicious activity is just as valuable as confirming a compromise.

---

## Related Projects

- [Vulnerability Management Program →](../vulnerability-management/README.md)
- [Log Visualization Maps →](../log-visualization/README.md)

---

<div align="center">

[← Back to Portfolio](../README.md)

*Michael Edwards · Houston, TX · [maedwards880@gmail.com](mailto:maedwards880@gmail.com)*

</div>
