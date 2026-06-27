# Threat Hunt: Unauthorized TOR Browser Installation & Usage

![Tools](https://img.shields.io/badge/Microsoft_Defender_for_Endpoint-00B294?style=flat&logo=microsoft&logoColor=white)
![Tools](https://img.shields.io/badge/KQL-F2C811?style=flat&logo=azuredataexplorer&logoColor=black)
![Tools](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Tools](https://img.shields.io/badge/Azure-0089D6?style=flat&logo=microsoftazure&logoColor=white)

---

## Scenario

Management flagged unusual encrypted traffic patterns in recent network logs, including connections to known TOR entry nodes. Anonymous internal reports also surfaced indicating employees were discussing methods to bypass network security controls and access restricted sites during work hours. A proactive threat hunt was initiated to detect any TOR browser installation or active usage across endpoints and assess the scope of the security risk.

**Hypothesis:** One or more endpoints have TOR Browser installed and are actively routing traffic through the TOR network to bypass security controls.

---

## Incident Details

| Field | Detail |
|---|---|
| **Hunt Type** | Proactive Threat Hunt |
| **Affected Endpoint** | `bashphishing-vm` |
| **Affected User** | `bashphishing` |
| **Confirmed Activity** | TOR Browser silent install + active TOR network usage + suspicious file creation |
| **Tools Used** | Microsoft Defender for Endpoint, KQL, Azure |

---

## IoC Discovery Plan

Before querying, a structured hypothesis-driven hunt plan was established targeting three data sources:

- **DeviceFileEvents** — detect `tor.exe`, `firefox.exe`, or TOR-related file creation events
- **DeviceProcessEvents** — identify installer execution or TOR process launches
- **DeviceNetworkEvents** — confirm outbound connections over known TOR ports (9001, 9050, 9150)

---

## Investigation & KQL Queries

### Step 1 — DeviceFileEvents: TOR File Activity

```kql
DeviceFileEvents
| where DeviceName == "bashphishing-vm"
| where FileName has_any ("tor", "firefox", "torbrowser")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath
| order by Timestamp asc
```

**Findings:** The employee downloaded the TOR Browser portable installer (`tor-browser-windows-x86_64-portable-15.0.16.exe`) via Microsoft Edge to the Downloads folder. Multiple TOR-related files were subsequently extracted to `C:\Users\bashphishing\Desktop\Tor Browser\`, including `tor.exe`, `firefox.exe`, and pluggable transport tools `conjure-client.exe` and `lyrebird.exe` — tools specifically used to obfuscate TOR traffic from network inspection.

At **1:44 PM**, a file named `tor-shopping-list.txt` was created in `C:\Users\bashphishing\Documents\` via Notepad, with a corresponding shortcut appearing in the user's Recent files directory.

---

### Step 2 — DeviceProcessEvents: Silent Installer Execution

```kql
DeviceProcessEvents
| where DeviceName == "bashphishing-vm"
| where FileName has_any ("tor-browser", "tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Findings:** At **12:45 PM**, the installer was executed with the `/S` silent flag:

```
tor-browser-windows-x86_64-portable-15.0.16.exe /S
```

The `/S` flag suppresses all installation prompts, indicating the user was deliberately concealing the installation from casual observation. At **12:46 PM**, `firefox.exe` launched and initialized a TOR Browser profile, creating SQLite database files including `places.sqlite`, `cookies.sqlite`, and `favicons.sqlite`.

---

### Step 3 — DeviceNetworkEvents: TOR Network Connections

```kql
DeviceNetworkEvents
| where DeviceName == "bashphishing-vm"
| where RemotePort in (9001, 9050, 9150)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, ActionType
| order by Timestamp asc
```

**Findings:** At **12:47 PM**, `tor.exe` established successful outbound connections to known TOR entry nodes:

| Timestamp | Remote IP | Port | Process |
|---|---|---|---|
| 12:47 PM | 45.90.135.141 | 9001 | tor.exe |
| 12:47 PM | 88.151.194.12 | 9001 | tor.exe |
| 1:18 PM | Multiple | 9001 | tor.exe |
| 1:39 PM | 45.90.135.141 | 9001 | tor.exe |

Simultaneously, `firefox.exe` connected to the local TOR SOCKS proxy at `127.0.0.1:9150`, confirming active browsing through the TOR network. Additional circuit connections at 1:18 PM and 1:39 PM indicate sustained TOR usage over approximately **one hour**.

---

## Chronological Attack Timeline

| Time | Event |
|---|---|
| 12:41 PM | TOR Browser portable installer downloaded via Microsoft Edge |
| 12:45 PM | Installer executed silently with `/S` flag — full TOR suite deployed to Desktop |
| 12:46 PM | `firefox.exe` launched, TOR Browser profile initialized, SQLite databases created |
| 12:47 PM | `tor.exe` established outbound connections to TOR entry nodes over port 9001 |
| 12:47 PM | `firefox.exe` connected to local SOCKS proxy at `127.0.0.1:9150` — active TOR browsing confirmed |
| 1:18 PM | Additional TOR circuit connections observed |
| 1:39 PM | Continued outbound TOR connections confirmed |
| 1:44 PM | `tor-shopping-list.txt` created in Documents folder via Notepad |

---

## Summary

On June 26, 2026, unauthorized TOR Browser installation and active usage was confirmed on endpoint `bashphishing-vm` under user account `bashphishing`. The threat hunt was initiated based on management concerns about unusual encrypted traffic and anonymous internal reports.

The use of the `/S` silent install flag and the subsequent creation of `tor-shopping-list.txt` are the two most significant indicators of **deliberate and intentional misuse** rather than casual curiosity. The silent flag demonstrates awareness that the installation would be flagged, and the shopping list suggests the user was actively planning or documenting activity conducted over the TOR network.

TOR usage was sustained for approximately one hour across multiple confirmed circuit connections to known entry nodes.

---

## Response Taken

- **Isolated** endpoint `bashphishing-vm` via Microsoft Defender for Endpoint
- **Notified** the user's direct manager of confirmed unauthorized TOR usage
- Incident escalated for HR and policy review

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | Proxy: Multi-hop Proxy (TOR) | T1090.003 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Command & Control | Proxy | T1090 |

---

## Key Takeaways

- Silent installer flags (`/S`) are a reliable behavioral indicator of deliberate evasion — standard user installs don't require suppressing prompts
- Cross-table KQL correlation across FileEvents, ProcessEvents, and NetworkEvents is essential for building a complete attack timeline — no single table alone would have confirmed this
- Port 9001 is the primary TOR OR port for entry node connections; port 9150 confirms local SOCKS proxy usage and active browser routing through TOR
- Pluggable transports (`lyrebird.exe`, `conjure-client.exe`) signal an advanced user attempting to disguise TOR traffic as normal HTTPS — a significant escalation indicator
