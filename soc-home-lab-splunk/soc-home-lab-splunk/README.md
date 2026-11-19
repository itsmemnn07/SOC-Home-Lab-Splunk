# SOC Home Lab — Centralized Log Collection & Threat Detection with Splunk

A self-contained Security Operations Center (SOC) lab built in VirtualBox to simulate an enterprise monitoring environment — covering the full pipeline from endpoint telemetry collection to centralized log analysis and detection engineering.

## Table of Contents

- [Architecture](#architecture)
- [Lab Environment](#lab-environment)
- [Implementation](#implementation)
- [Configuration Files](#configuration-files)
- [Detection Engineering](#detection-engineering)
- [Adversary Simulation](#adversary-simulation)
- [Skills Demonstrated](#skills-demonstrated)
- [Future Work](#future-work)

## Architecture

```
┌─────────────────┐         ┌──────────────────────┐         ┌───────────────────────┐
│   Kali Linux     │         │     Windows 11        │   TCP   │   Ubuntu Server        │
│   (Attacker)     │────────▶│  (Victim + Splunk UF)  │──9997──▶│  (Splunk Indexer /     │
│                  │         │                        │         │   Search Head)         │
└─────────────────┘         └──────────────────────┘         └───────────────────────┘
```

All VMs are isolated on a VirtualBox **Internal Network** to replicate a segmented enterprise environment with no external exposure — static IP addressing used throughout (no DHCP/internet egress on the internal segment).

## Lab Environment

| Component | Role | Details |
|---|---|---|
| Kali Linux | Attacker | Nmap, Hydra, Mimikatz testing |
| Windows 11 | Victim / Endpoint | Splunk Universal Forwarder + Sysmon |
| Ubuntu Server | SIEM | Splunk Indexer / Search Head |

## Implementation

- Installed and configured **Splunk Universal Forwarder** on the Windows 11 endpoint to collect Windows Event Logs (Security, System, Application)
- Authored `inputs.conf` to define log sources and route them to dedicated Splunk indexes
- Authored `outputs.conf` to establish a forwarding pipeline to the Splunk indexer over TCP (port 9997)
- Enabled receiving on the Splunk server and validated forwarder connectivity via Forwarder Management
- Deployed **Sysmon** (SwiftOnSecurity config) to extend visibility into process creation, network connections, and process access events beyond native Windows auditing
- Ingested Sysmon telemetry into Splunk alongside native Windows Event Logs for enriched endpoint visibility

## Configuration Files

### `inputs.conf` (Windows 11 — Splunk Universal Forwarder)

```ini
[WinEventLog://Security]
disabled = false
index = endpoint
renderXml = true

[WinEventLog://System]
disabled = false
index = endpoint

[WinEventLog://Application]
disabled = false
index = endpoint

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = endpoint
renderXml = true
```

### `outputs.conf` (Windows 11 — Splunk Universal Forwarder)

```ini
[tcpout]
defaultGroup = my_indexers

[tcpout:my_indexers]
server = <ubuntu-server-ip>:9997
```

> Replace `<ubuntu-server-ip>` with your Splunk indexer's actual IP address.

## Detection Engineering

SPL (Search Processing Language) queries built and validated against simulated attack traffic.

### 1. RDP Brute Force Detection (Event ID 4625)

```spl
index=endpoint EventCode=4625
| bucket _time span=1m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 5
```

### 2. Privilege Escalation Indicators (Event ID 4672)

```spl
index=endpoint EventCode=4672
| search NOT Account_Name IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| search Privileges="*SeDebugPrivilege*" OR Privileges="*SeImpersonatePrivilege*" OR Privileges="*SeTcbPrivilege*"
| table _time, Account_Name, Source_Network_Address, Privileges
```

### 3. Network Reconnaissance Detection (Sysmon Event ID 3)

```spl
index=endpoint source="*Sysmon*" EventCode=3
| stats dc(DestinationPort) as unique_ports count by SourceIp, DestinationIp
| where unique_ports > 20
```

### 4. Credential Access Detection — LSASS Access (Sysmon Event ID 10)

```spl
index=endpoint source="*Sysmon*" EventCode=10
| search TargetImage="*lsass.exe*"
| table _time, SourceImage, TargetImage, GrantedAccess, SourceProcessId
| where GrantedAccess="0x1010" OR GrantedAccess="0x1410"
```

## Adversary Simulation

Attack activity generated from the Kali VM to validate each detection:

| Technique | Tool | MITRE ATT&CK |
|---|---|---|
| RDP Brute Force | Hydra | T1110 — Brute Force |
| Network Scanning | Nmap | T1046 — Network Service Discovery |
| Credential Dumping | Mimikatz | T1003 — OS Credential Dumping |

## Skills Demonstrated

`Splunk Administration` · `SIEM Configuration` · `Log Forwarding` · `Windows Event Log Analysis` · `Sysmon Deployment` · `SPL Query Development` · `Detection Engineering` · `Network Segmentation` · `Adversary Simulation` · `Blue Team Fundamentals`

## Future Work

- [ ] Build Splunk dashboards for real-time visualization of detection results
- [ ] Add correlation search chaining 4672 → Sysmon EID 10 → EID 1 for full attack-chain storytelling
- [ ] Integrate Windows Firewall logging for additional network visibility
- [ ] Explore Splunk alerting/notable events for automated response triggers

