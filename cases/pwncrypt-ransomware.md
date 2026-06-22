<div align="center">

# Threat Hunt: Zero-Day Ransomware (PwnCrypt) Outbreak
## Ransomware Detection & Incident Response on Corporate Endpoint

**Type:** Threat Hunt → Incident Response  
**Environment:** LOG(N) Pacific Cyber Range — Windows Azure VM  
**Tools:** `KQL` `Microsoft Defender for Endpoint` `Log Analytics Workspaces` `Microsoft Azure`

[← Back to Threat Hunting Overview](../README.md)

</div>

---

## Background

A new ransomware strain named **PwnCrypt** was reported in the news, leveraging a PowerShell-based payload to encrypt files using AES-256 encryption. The ransomware targets specific directories and renames encrypted files by prepending a `.pwncrypt` extension — for example, `EmployeeRecords.csv` becomes `3257_EmployeeRecords_pwncrypt.csv`.

The CISO flagged the threat and tasked the security team with determining whether PwnCrypt had made its way onto the corporate network. Given that the organization's security program was still maturing — lacking user awareness training and consistent endpoint hardening — the risk of infection was considered credible.

---

## Hypothesis

> The newly reported PwnCrypt ransomware may have infected one or more devices on the corporate network. If present, it would manifest as file rename and creation events matching the known IoC pattern `*.pwncrypt.*` across targeted directories. Lateral movement to other systems is also possible given the immature security posture.

---

## Investigation

### Step 1 — Hunt for Known IoCs in DeviceFileEvents

Started the hunt using the known PwnCrypt file naming pattern as the primary IoC — any file containing `.pwncrypt` in the name is a confirmed indicator of ransomware activity.

```kql
let VName = "windows-target-";
DeviceFileEvents
| where DeviceName == VName
| where FileName contains "pwncrypt"
| order by Timestamp desc
```

**Finding:** 18 results returned. Files showed both `FileRenamed` and `FileCreated` action types, consistent with the ransomware's encryption behavior — renaming the original file and creating the encrypted version side by side.

Encrypted files identified included:

| File Name | Action Type | Timestamp |
|---|---|---|
| 3257_EmployeeRecords_pwncrypt.csv | FileRenamed | Jun 22, 2026 11:13:03 AM |
| 3257_EmployeeRecords_pwncrypt.csv | FileCreated | Jun 22, 2026 11:13:03 AM |
| 7890_ProjectList_pwncrypt.csv | FileRenamed | Jun 22, 2026 11:13:03 AM |
| 7890_ProjectList_pwncrypt.csv | FileCreated | Jun 22, 2026 11:13:03 AM |
| 5387_CompanyFinancials_pwncrypt.csv | FileRenamed | Jun 22, 2026 11:13:03 AM |
| 5387_CompanyFinancials_pwncrypt.csv | FileCreated | Jun 22, 2026 11:13:02 AM |
| 3671_EmployeeRecords_pwncrypt.csv | FileRenamed | Jun 22, 2026 7:12:59 AM |
| 3671_EmployeeRecords_pwncrypt.csv | FileCreated | Jun 22, 2026 7:12:59 AM |

The file naming pattern — numerical prefix, original filename, `.pwncrypt` extension — is a clear signature of this ransomware strain. Critically, files targeted included **EmployeeRecords**, **CompanyFinancials**, and **ProjectList** — all high-sensitivity data categories.

---

### Step 2 — Quantify the Scope of Encryption

Ran a summary query to establish the total number of affected files and the full time window of ransomware activity.

```kql
let VName = "windows-target-";
DeviceFileEvents
| where DeviceName == VName
| where FileName contains "pwncrypt"
| summarize EncryptedFiles = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
```

**Finding:**

| Encrypted Files | First Seen | Last Seen |
|---|---|---|
| 18 | Jun 22, 2026 3:13:03 AM | Jun 22, 2026 11:13:03 AM |

The ransomware was active across an **8-hour window**, indicating either multiple execution cycles or a persistent encryption process running in the background across the morning.

---

### Step 3 — Attempt to Identify the Process Chain

Attempted to pivot into DeviceProcessEvents using the earliest file event timestamp to identify the delivery mechanism and execution chain behind the encryption activity.

```kql
let VMName = "windows-target-";
let specificTime = datetime(2026-06-22T11:13:03);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| order by Timestamp desc
```

**Finding:** No results returned. Process telemetry for this device was not available in MDE at the time of the investigation — likely due to a sensor ingestion lag on the newly onboarded VM. While process-level visibility was limited, the file event evidence alone was sufficient to confirm active ransomware infection.

Based on the known PwnCrypt delivery method, the execution chain was:

```
Invoke-WebRequest (download pwncrypt.ps1 from GitHub)
  → cmd.exe /c powershell.exe -ExecutionPolicy Bypass
    → pwncrypt.ps1 (AES-256 file encryption)
      → FileRenamed + FileCreated events in DeviceFileEvents
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | **T1059.001** | PowerShell used as primary execution mechanism for ransomware payload |
| Data Encrypted for Impact | **T1486** | AES-256 encryption applied to files, prepending `.pwncrypt` extension |
| Ingress Tool Transfer | **T1105** | `Invoke-WebRequest` used to pull `pwncrypt.ps1` from external GitHub URL |
| Impair Defenses: Execution Policy Bypass | **T1562.001** | `-ExecutionPolicy Bypass` flag used to circumvent PowerShell script restrictions |

---

## Response

**Confirmed:** PwnCrypt ransomware was present and active on `windows-target-`. 18 files were encrypted across an 8-hour window, targeting high-sensitivity data including employee records and company financials.

### Immediate Containment
- **Isolate the device** immediately to prevent lateral movement to other systems on the network
- **Identify the full scope** of encrypted files across all targeted directories
- **Restore from clean backup** — encrypted files cannot be recovered without the decryption key

---

## Remediation

### Endpoint Hardening
- **Block ExecutionPolicy Bypass** via Group Policy — prevent scripts from disabling PowerShell safety controls
- **Enable PowerShell Constrained Language Mode** for non-administrative users — limits what PowerShell can execute
- **Application allowlisting** — restrict which scripts and executables can run on endpoints

### Detection Engineering
- **Create a Sentinel detection rule** alerting on any file creation or rename event containing `.pwncrypt` in the filename — this provides near real-time alerting for future infections
- **Alert on PowerShell downloading from external URLs** — flag `Invoke-WebRequest` calls to non-corporate domains from endpoints

```kql
// Detection rule — PwnCrypt file encryption activity
DeviceFileEvents
| where FileName contains ".pwncrypt"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc
```

### Process & People
- **User awareness training** — the scenario assumed an immature security program with no training. Ransomware frequently enters via phishing or social engineering before executing a payload
- **Patch management** — ensure endpoints are current; ransomware often exploits known vulnerabilities as an alternative delivery mechanism
- **Backup verification** — confirm backups are clean, isolated from the network, and tested regularly

---

## Key KQL Queries Used

```kql
// 1. Hunt for PwnCrypt IoCs in file events
let VName = "windows-target-";
DeviceFileEvents
| where DeviceName == VName
| where FileName contains "pwncrypt"
| order by Timestamp desc

// 2. Quantify scope of encryption
let VName = "windows-target-";
DeviceFileEvents
| where DeviceName == VName
| where FileName contains "pwncrypt"
| summarize EncryptedFiles = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)

// 3. Attempt to identify process chain (no results due to sensor lag)
let VMName = "windows-target-";
let specificTime = datetime(2026-06-22T11:13:03);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| order by Timestamp desc

// 4. Detection rule — alert on future PwnCrypt activity
DeviceFileEvents
| where FileName contains ".pwncrypt"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc
```

---

## Lessons Learned

**IoC-based hunting works — when you know what to look for.** The `.pwncrypt` file naming pattern was a strong, unambiguous signal. A single query confirmed active infection within seconds of starting the hunt. This is why threat intelligence sharing and rapid IoC publication after a zero-day announcement matters.

**File events can confirm an attack even when process telemetry is unavailable.** The sensor lag on the newly onboarded VM meant process-level visibility wasn't there. But the file event data alone was enough to confirm infection, scope the damage, and drive a response. Know which log sources cover which gaps.

**An 8-hour encryption window means detection failed well before this hunt started.** The ransomware ran from 3 AM to 11 AM before being caught. A real-time detection rule on `.pwncrypt` file creation would have triggered an alert within seconds of the first encrypted file — not hours later. Detection rules aren't optional; they're the difference between catching ransomware at file one versus file eighteen.

**Immature security programs need layered controls, not just one fix.** No user training, no execution policy enforcement, no file integrity monitoring — any one of these gaps alone might be survivable. All of them together created the conditions for this infection to run undetected for hours.

---

<div align="center">

[← Back to Threat Hunting Overview](../README.md) · [← Back to Portfolio](../../README.md)

*Michael Edwards · Houston, TX · [maedwards880@gmail.com](mailto:maedwards880@gmail.com)*

</div>
