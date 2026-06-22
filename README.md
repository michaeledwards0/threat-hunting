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

### 🔴 [Case Study: Diicot (aka Mexals) Cryptominer Worm — Full-System Linux Compromise](./cases/diicot-cryptominer.md)

**Type:** Forensic Investigation + Incident Response  
**Environment:** Cyber Range Lab — Linux VM  
**Tools:** `KQL` `Microsoft Defender for Endpoint` `Log Analytics Workspaces`

A root-level compromise of a Linux VM via SSH brute force, followed by installation of the Diicot cryptominer worm. This was a full end-to-end forensic investigation covering initial access, persistence mechanisms, payload staging, and cryptomining infrastructure.

**Key findings:**
- Attacker established immutable SSH key persistence to survive reboots and remediation attempts
- Script-based payload staging was used to download and execute the miner without leaving obvious binaries
- Network connections revealed active cryptomining pool infrastructure

**What I did:** Traced the full attack chain from initial brute force event through payload execution, documented indicators of compromise, and built a detection rule in Defender for Endpoint to catch this TTPs pattern going forward.

---

### 🟠 [Case Study: Brute Force Attack — NSG Hardening & Elimination](./cases/brute-force-nsg.md)

**Type:** Detection + Remediation  
**Environment:** Cyber Range Lab — Azure Windows VM  
**Tools:** `Microsoft Sentinel` `KQL` `Azure NSG` `Defender for Endpoint`

An Azure-hosted Windows VM was being hit with sustained brute force attacks over exposed RDP/SSH ports. Rather than just alerting on the activity, I eliminated the attack surface entirely.

**Key findings:**
- Direct internet exposure of management ports was the root cause
- Sentinel logs showed hundreds of failed logon attempts from distributed IP ranges
- After NSG rule changes blocking inbound internet traffic to management ports, brute force incidents dropped to zero

**What I did:** Identified the exposure, implemented targeted inbound NSG rules, verified elimination of the attack vector through post-remediation log review.

---

### 🟡 [Case Study: Unhandled PowerShell Script Crash (Azure Guest Agent Degradation)](./cases/powershell-crash-azure-agent.md)

**Type:** Incident Response — False Positive Investigation  
**Environment:** Cyber Range Incident Response  
**Tools:** `KQL` `MDE` `Microsoft Azure` `Log Analytics Workspaces`

A SYSTEM-level PowerShell script crash triggered a cascade of Azure Guest Agent failures — heartbeat degradation, extension timeouts, and Azure losing trust in the VM. The initial alert looked like a potential malicious script execution.

**Key findings:**
- The crash originated from `pwncrypt.ps1` — a name that immediately flags as suspicious
- Investigation revealed the exception was unhandled but non-malicious, triggering WERFault.exe
- Azure Management Plane responded by restricting VM access and switching to health validation mode
- No indicators of compromise found — this was platform behavior, not an attack

**What I did:** Traced the full event chain across Management Plane and Data Plane logs, ruled out malicious activity, documented the Azure Guest Agent recovery behavior, and published the findings as a reference for future incident response tabletop exercises.

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
