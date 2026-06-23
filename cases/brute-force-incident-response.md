<div align="center">

# Incident Response: Brute Force Attack Detection & Containment

**Type:** Incident Response  
**Environment:** LOG(N) Pacific Cyber Range — Azure Windows VMs  
**Tools:** `Microsoft Sentinel` `KQL` `Microsoft Defender for Endpoint` `Azure NSG`

[← Back to Threat Hunting Overview](../README.md)

</div>

---

## Background

A custom Sentinel analytics rule was created to detect brute force activity across the Cyber Range environment. The rule monitored for repeated failed logon attempts from the same remote IP address against the same Azure VM — triggering an incident when the threshold of 10 or more failures was reached within a 5-hour window.

The rule fired, generating an active incident. My role was to investigate the incident, determine whether any unauthorized access had occurred, and contain the threat.

---

## Detection Rule

**Rule type:** Scheduled Query Rule (Microsoft Sentinel — Log Analytics)  
**Logic:** Alert when the same remote IP produces 10+ failed logon attempts against the same local host within 5 hours

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedAttempts = count() by RemoteIP, DeviceName, bin(Timestamp, 5h)
| where FailedAttempts >= 10
```

> 📸 *[Screenshot: Sentinel analytics rule configuration]*

---

## Phase 1 — Preparation

**Goal:** Establish scope and assign roles before beginning the investigation.

| Role | Assigned To |
|---|---|
| Cybersecurity Specialist (Investigator) | Michael Edwards |

**Tools staged:**
- Microsoft Sentinel — incident triage and alert review
- Microsoft Defender for Endpoint (MDE) — endpoint telemetry and device isolation
- KQL — log querying across DeviceLogonEvents
- Azure NSG — network-level containment

---

## Phase 2 — Detection & Analysis

### Incident Triage

The Sentinel rule generated an active incident flagged as **Medium severity**. The incident graph revealed connections from multiple external IPs to the affected VM (`ironman12`), along with several other VMs in the shared environment being targeted simultaneously.

> 📸 *[Screenshot: Sentinel incident graph — ironman12 Brute Force Attempt Detection]*

**Attacking IP addresses identified:**

| IP Address | Failed Attempts | Notes |
|---|---|---|
| 45.142.193.166 | Multiple | External — confirmed attacker |
| 14.136.73.18 | 40 | External — hitting multiple VMs simultaneously |
| 91.238.181.8 | 51 | External — confirmed attacker |
| 148.251.140.16 | 31 | External — confirmed attacker |
| 119.139.34.42 | 100 | External — most aggressive single source |

> 📸 *[Screenshot: DeviceLogonEvents results showing failed attempts by RemoteIP]*

**Notable finding:** `14.136.73.18` appeared against multiple VMs in the environment with exactly 40 failed attempts each — a pattern consistent with **automated scanning tools** methodically targeting every internet-exposed host rather than a targeted human-driven attack.

---

### Investigation — Check for Successful Logons

The critical question in any brute force investigation is whether the attacker eventually succeeded. Queried all 5 attacking IPs against `LogonSuccess` events:

```kql
let AttackerIPs = dynamic(["45.142.193.166", "14.136.73.18", "91.238.181.8", 
                            "148.251.140.16", "119.139.34.42"]);
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(AttackerIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| order by Timestamp desc
```

**Finding:** No results. **None of the attacking IPs achieved a successful logon.**

> 📸 *[Screenshot: Query returning zero results for successful logons from attacking IPs]*

---

## Phase 3 — Containment & Eradication

With brute force confirmed but no successful access detected, the priority shifted to stopping the attack and hardening the environment.

### Immediate Containment

**Antivirus scan** — ran a full AV scan on the affected device to rule out any malware that may have been installed through a vector not captured in logon telemetry. No threats detected.

**Device isolation in MDE** — isolated `ironman12` in Microsoft Defender for Endpoint to prevent any potential lateral movement while the investigation was completed and hardening was applied.

> 📸 *[Screenshot: MDE device isolation confirmation]*

### Network Hardening

**NSG lockdown** — updated the Network Security Group attached to the affected VM to block all inbound RDP traffic from the public internet. Access restricted to specific known IP ranges only.

> 📸 *[Screenshot: NSG inbound rule — deny RDP from internet]*

**Corporate policy proposal** — documented a recommendation to enforce this NSG configuration across all VMs in the environment going forward using **Azure Policy**. Azure Policy can automatically audit and remediate VMs that allow public RDP exposure, preventing this scenario from recurring as new VMs are deployed.

---

## Phase 4 — Post-Incident Activity

### Lessons Learned

**The detection rule worked — but the exposure should never have existed.** The NSG should have been locked down before the VM was internet-facing. Detection caught the brute force, but prevention would have stopped it from ever starting. The Azure Policy proposal addresses this gap at the infrastructure level.

**Automated scanning is relentless.** The pattern of `14.136.73.18` hitting every VM with exactly 40 attempts is characteristic of botnet-driven credential stuffing — not a targeted human attacker. These scans happen continuously against any internet-exposed RDP port. The only reliable defense is not having RDP exposed in the first place.

**No successful logon doesn't mean no risk.** The absence of a brute force success is good news, but it doesn't rule out other attack vectors. A comprehensive post-incident review should also check `DeviceFileEvents` and `DeviceProcessEvents` for any anomalous activity that may have occurred through means other than direct RDP logon.

### Recommended Follow-On Actions

- Implement **Azure Bastion** as the standard RDP access method — eliminates the need to expose RDP ports publicly entirely
- Enable **account lockout policy** on all VMs — automatically locks accounts after N failed attempts, making brute force mathematically impractical
- Create a **Sentinel watchlist** of known malicious IPs from this incident for automated blocking on future detections
- Schedule a **quarterly NSG audit** using Azure Policy compliance reports to catch misconfigurations before attackers do

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Password Guessing | **T1110.001** | Repeated failed logon attempts from external IPs |
| External Remote Services | **T1133** | RDP exposed directly to the public internet |
| Valid Accounts | **T1078** | Evaluated — no abuse of legitimate accounts confirmed |

---

## Key KQL Queries Used

```kql
// 1. Identify failed logon attempts by remote IP
DeviceLogonEvents
| where DeviceName == "ironman12"
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP, DeviceName
| order by Attempts desc

// 2. Check if any attacking IPs achieved successful logon
let AttackerIPs = dynamic(["45.142.193.166", "14.136.73.18", "91.238.181.8",
                            "148.251.140.16", "119.139.34.42"]);
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(AttackerIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| order by Timestamp desc

// 3. Confirm all successful logons came from expected internal IPs
DeviceLogonEvents
| where DeviceName == "ironman12"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

---

<div align="center">

[← Back to Threat Hunting Overview](../README.md) · [← Back to Portfolio](../../README.md)

*Michael Edwards · Houston, TX · [maedwards880@gmail.com](mailto:maedwards880@gmail.com)*

</div>
