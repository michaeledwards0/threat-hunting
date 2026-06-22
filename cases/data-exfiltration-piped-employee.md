<div align="center">

# Threat Hunt: Suspected Data Exfiltration from PIP'd Employee

**Type:** Threat Hunt → Incident Response  
**Environment:** LOG(N) Pacific Cyber Range — Windows Azure VM  
**Tools:** `KQL` `Microsoft Defender for Endpoint` `Log Analytics Workspaces` `Microsoft Azure`

[← Back to Threat Hunting Overview](../README.md)

</div>

---

## Background

An employee named John Doe, working in a sensitive department, was recently placed on a Performance Improvement Plan (PIP). After an escalated reaction to the news, management raised concerns that John may be planning to steal proprietary information before leaving the company. My task was to investigate John's activity on his corporate device using Microsoft Defender for Endpoint and determine whether anything suspicious was taking place.

---

## Hypothesis

> John is an administrator on his device with no application restrictions. If he intends to exfiltrate data, he may attempt to archive or compress sensitive files and transfer them to a personal or external destination. Evidence would appear as archiving tool usage, suspicious file creation, and outbound network connections to non-corporate destinations.

---

## Investigation

### Step 1 — Search for Archive Activity in DeviceFileEvents

Started by looking for `.zip` file activity on the device to identify any archiving or data staging behavior.

```kql
DeviceFileEvents
| where DeviceName == "ironman2"
| where FileName endswith ".zip"
| order by Timestamp desc
```

**Finding:** 22 results returned. Observed repeated archiving and file movement to a `backup` folder under `C:\ProgramData\`. Two entries stood out immediately:

- `employee-data-20260208` — **FileRenamed** → `C:\ProgramData\backup\`
- `employee-data-20260208` — **FileCreated** → `C:\ProgramData\employee`

The naming convention and destination folder were consistent with an employee staging company data for later retrieval or transfer.

---

### Step 2 — Search for Process Activity Around the Suspicious Timestamp

Took the timestamp from the suspicious file creation (`2026-02-08T18:38:09Z`) and searched for process activity within a 4-minute window to identify what triggered the file event.

```kql
let VMName = "ironman2";
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Finding:** No results in the process table for this time window. This suggested the archiving was either script-driven or occurred outside the queried window.

---

### Step 3 — Expand File Event Search Around the Suspicious Timestamp

Searched DeviceFileEvents for all activity in a 2-minute window around the suspicious file creation to get a fuller picture of what was happening on the device at that moment.

```kql
let specificTime = datetime(2026-02-08T18:38:09.6516844Z);
let VMName = "ironman2";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Finding:** 110 file events returned within a 1-minute window — a high volume that immediately indicated automated or scripted activity. Among the results:

- `employee-data-temp2026` created in `C:\ProgramData\employee\`
- `exfiltratedata.ps1` **FileCreated** in `C:\ProgramData\exfiltrate\` — a PowerShell script responsible for archiving and staging the data
- Multiple `__PSScriptPolicyTest` files created in `C:\Users\ironman2\AppData\` — consistent with PowerShell execution policy testing prior to script execution
- `VMAgentLogs.zip` created repeatedly in `D:\CollectGuestLogsTemp\`

The presence of `exfiltratedata.ps1` confirmed the archiving was script-driven, not manual.

---

### Step 4 — Check for Network Exfiltration

Searched DeviceNetworkEvents across a 40-minute window centered on the suspicious activity to determine whether any data was actually sent out of the network.

```kql
let VMName = "ironman2-";
let specificTime = datetime(2026-02-08T18:38:09.6516844Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 20m) .. (specificTime + 20m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Finding:** 0 results. No network activity detected for this device in the specified window. **Exfiltration over the network was not confirmed.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Status |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | **T1059.001** | Confirmed |
| Archive Collected Data | **T1560** | Confirmed |
| Data Staged | **T1074** | Confirmed |
| Exfiltration Over C2 Channel | **T1041** | Suspected — not confirmed |
| Exfiltration Over Alternative Protocol | **T1048** | Suspected — not confirmed |

---

## Response

Findings were reported to the employee's manager. Summary of what was confirmed:

- A PowerShell script (`exfiltratedata.ps1`) was present on the device and executed
- Employee data was archived and renamed into a staging folder (`C:\ProgramData\backup\`)
- No outbound network exfiltration was detected within the monitored window

The absence of network exfiltration does not rule out data theft — files could have been transferred via physical media, personal cloud sync applications outside the monitored window, or other channels not captured in DeviceNetworkEvents.

**Standing by for further instructions from management.**

---

## Remediation

- **Device isolated** during investigation to prevent any further potential exfiltration
- **PowerShell hardening** recommended:
  - Block `ExecutionPolicy Bypass` via Group Policy
  - Enable Constrained Language Mode for non-administrative users
- **Data Loss Prevention (DLP) rules** implemented to alert on bulk file archiving and movement to non-standard directories
- Review and restrict admin rights for employees in sensitive departments

---

## Key KQL Queries Used

```kql
// 1. Search for zip archive activity on the device
DeviceFileEvents
| where DeviceName == "ironman2"
| where FileName endswith ".zip"
| order by Timestamp desc

// 2. Search for process activity around suspicious file creation
let VMName = "ironman2";
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc

// 3. Expand file event search around suspicious timestamp
let specificTime = datetime(2026-02-08T18:38:09.6516844Z);
let VMName = "ironman2";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc

// 4. Check for network exfiltration in 40-minute window
let VMName = "ironman2-";
let specificTime = datetime(2026-02-08T18:38:09.6516844Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 20m) .. (specificTime + 20m))
| where DeviceName == VMName
| order by Timestamp desc
```

---

## Lessons Learned

**Absence of network exfiltration doesn't mean absence of a threat.** The data was staged and archived — whether it left the network through a channel we weren't monitoring is still an open question. DLP controls and endpoint monitoring need to cover more than just outbound TCP connections.

**Script artifacts tell the story.** The discovery of `exfiltratedata.ps1` in the file events was the key pivot point. Without that filename surfacing in the log, the investigation might have stalled at "unusual archiving activity." Logging file creation events with full paths is non-negotiable for insider threat scenarios.

**Insider threat hunts require broader time windows.** A 2-minute process event window returned nothing. Widening the file event search to ±1 minute around the right timestamp returned 110 events. Knowing when to widen vs. narrow your time window is a skill that only develops through repetition.

---

<div align="center">

[← Back to Threat Hunting Overview](../README.md) · [← Back to Portfolio](../../README.md)

*Michael Edwards · Houston, TX · [maedwards880@gmail.com](mailto:maedwards880@gmail.com)*

</div>
