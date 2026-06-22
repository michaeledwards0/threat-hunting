<div align="center">

# Threat Hunt: Devices Accidentally Exposed to the Internet
## Brute Force Investigation on Internet-Facing Windows VM

**Type:** Threat Hunt → Incident Response  
**Environment:** LOG(N) Pacific Cyber Range — Windows Azure VM  
**Tools:** `KQL` `Microsoft Defender for Endpoint` `Log Analytics Workspaces` `Microsoft Azure`

[← Back to Threat Hunting Overview](../README.md)

</div>

---

## Background

During routine maintenance, the security team identified a Windows VM in the shared services cluster that had been mistakenly exposed to the public internet. The device had no account lockout policy configured, meaning it was vulnerable to sustained brute force attempts without any built-in throttling. The goal was to determine how long the device had been exposed, identify any external actors who had attempted to log in, and confirm whether any unauthorized access had succeeded.

---

## Hypothesis

> During the time the device was unknowingly exposed to the internet, external threat actors may have attempted brute force login attempts. Without an account lockout policy in place, a sustained attack could have eventually succeeded. Evidence would appear as repeated failed logon events from external IPs, potentially followed by a successful logon from the same source.

---

## Investigation

### Step 1 — Confirm Internet Exposure Window

Started by confirming how long the device had actually been internet-facing using DeviceInfo.

```kql
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == true
| order by Timestamp desc
```

**Finding:**
- **First internet-facing timestamp:** `2026-02-01T19:52:34Z`
- **Last internet-facing timestamp:** `2026-02-03T19:07:17Z`

The device was publicly exposed for approximately **48 hours** before being caught.

---

### Step 2 — Identify External Brute Force Attempts

Queried DeviceLogonEvents for all failed network logon attempts with a remote IP to surface which external actors were targeting the device.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName, LogonType
| order by Attempts
```

**Finding:** Multiple external IPs had attempted failed logons. Top offenders:

| Remote IP | Failed Attempts |
|---|---|
| 217.154.98.229 | 25 |
| 94.26.88.47 | 17 |
| 109.205.211.14 | 12 |
| 213.55.95.235 | 10 |
| 201.150.150.54 | 9 |
| 102.88.21.214 | 9 |
| 72.167.225.241 | 8 |
| 163.223.99.217 | 6 |
| 192.169.88.9 | 5 |
| 178.57.110.29 | 5 |

---

### Step 3 — Check Whether Any Attacking IPs Succeeded

Took the top offending IPs and checked whether any of them had a corresponding successful logon on the device.

```kql
let RemoteIPsInQuestion = dynamic(["171.237.177.172","84.8.107.159",
"217.154.98.229", "94.26.88.47", "109.205.211.14", "213.55.95.235",
"201.150.150.54"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**Finding:** No results. None of the attacking IPs achieved a successful logon.

---

### Step 4 — Identify All Successful Logons on the Device

Shifted focus to understand what legitimate access looked like on this machine during the exposure window.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| distinct AccountName
```

**Finding:** Only one account had successful network logons — `labuser0`.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where AccountName == "labuser0"
| summarize count()
```

`labuser0` had **19 successful logons** during the period.

---

### Step 5 — Rule Out Brute Force on the Legitimate Account

Checked whether `labuser0` had any failed logon attempts to determine if the successful logins were the result of a brute force attack.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonFailed"
| where LogonType == "Network"
| where AccountName == "labuser0"
| summarize count()
```

**Finding:** 0 failed logon attempts for `labuser0`. No brute force pattern present — a successful login with zero preceding failures rules out both brute force and a lucky one-time password guess.

---

### Step 6 — Verify Successful Login Source IPs

Confirmed that all successful `labuser0` logins came from expected internal IP addresses and not from any external or suspicious source.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where AccountName == "labuser0"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

**Finding:** All 19 successful logins originated from internal IPs in the `10.0.8.x` range — consistent with legitimate administrative access. No anomalous source IPs detected.

| Account | Remote IP | Login Count |
|---|---|---|
| labuser0 | *(local/null)* | 7 |
| labuser0 | 10.0.8.5 | 1 |
| labuser0 | 10.0.8.9 | 2 |
| labuser0 | 10.0.8.6 | 4 |
| labuser0 | 10.0.8.8 | 5 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Status |
|---|---|---|
| External Remote Services | **T1133** | Confirmed — internet-facing Windows host exposed |
| Brute Force | **T1110** | Confirmed — multiple failed logon attempts from external IPs |
| Valid Accounts | **T1078** | Evaluated — legitimate account usage observed, no abuse confirmed |
| Remote Services | **T1021** | Observed — network and remote interactive logon attempts detected |

---

## Response

**Conclusion:** Though the device was exposed to the internet for 48 hours and sustained brute force attempts from multiple external IPs, **no unauthorized access was confirmed**. All successful logons were from the `labuser0` account using internal IPs with no preceding failures.

### Hardening Applied
- **NSG updated** — RDP traffic restricted to specific known endpoints only; public internet access removed
- **Account lockout policy implemented** — excessive failed logon attempts now trigger automatic lockout, eliminating the risk of sustained brute force succeeding on future exposure

### Additional Remediation Options
- **Brute force mitigation** — Fail2Ban or Defender Attack Surface Reduction rules to block IPs after threshold failures
- **Alerting** — Create Sentinel alert for excessive failed logons from a single external IP within a rolling time window
- **Detection rule** — Flag any `LogonSuccess` event from a `RemoteIP` that previously appeared in `LogonFailed` events on the same device

---

## Key KQL Queries Used

```kql
// 1. Confirm internet exposure window
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == true
| order by Timestamp desc

// 2. Failed logon attempts by remote IP
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName, LogonType
| order by Attempts

// 3. Check if attacking IPs ever succeeded
let RemoteIPsInQuestion = dynamic(["171.237.177.172","84.8.107.159",
"217.154.98.229", "94.26.88.47", "109.205.211.14", "213.55.95.235", "201.150.150.54"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)

// 4. Identify all successful network logon accounts
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| distinct AccountName

// 5. Count successful logins for labuser0
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where AccountName == "labuser0"
| summarize count()

// 6. Confirm zero failed logons for labuser0
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonFailed"
| where LogonType == "Network"
| where AccountName == "labuser0"
| summarize count()

// 7. Verify source IPs for all successful labuser0 logins
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where AccountName == "labuser0"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

---

## Lessons Learned

**Exposure window matters as much as the attack.** 48 hours is a long time for an internet-facing host with no lockout policy. The fact that no brute force succeeded doesn't mean the risk wasn't real — it means the attacker either didn't persist long enough or the password was strong enough to hold.

**Absence of brute force success doesn't mean absence of risk.** Confirming that `labuser0` had zero failed attempts before its successful logins was the key step that closed the loop. Without that check, the successful logins could have looked suspicious in isolation.

**Lockout policies are non-negotiable on internet-exposed hosts.** This device had none configured. Had an attacker been more persistent or used a credential stuffing list, the outcome could have been very different. Hardening after the fact is better than not hardening at all — but the policy should have been in place before the device went live.

---

<div align="center">

[← Back to Threat Hunting Overview](../README.md) · [← Back to Portfolio](../../README.md)

*Michael Edwards · Houston, TX · [maedwards880@gmail.com](mailto:maedwards880@gmail.com)*

</div>
