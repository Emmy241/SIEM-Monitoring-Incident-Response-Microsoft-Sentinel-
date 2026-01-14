# SIEM Monitoring & Incident Response with Microsoft Sentinel

## Project Overview

This project demonstrates the design and operation of a Tier 1 Security Operations Center (SOC) using Microsoft Sentinel. It covers end-to-end SOC activities including log ingestion, detection engineering, alert investigation, and incident response, aligned with real-world SOC workflows and the MITRE ATT&CK framework.

The environment simulates common attack scenarios such as brute-force authentication attempts, privilege escalation, and network reconnaissance, with detections and incident handling fully documented.

---

## Project Objectives

- Deploy and configure Microsoft Sentinel
- Ingest Windows and Azure network security logs
- Build and tune custom analytics rules
- Investigate alerts using KQL and entity correlation
- Perform Tier 1 incident response actions
- Produce structured incident documentation

---

## Architecture

### SIEM Platform

- Microsoft Sentinel
- Azure Log Analytics Workspace

### Data Sources

- Windows Security Event Logs (Azure Virtual Machine)
- Azure Network Security Group (NSG) Flow Logs

### Frameworks and Standards

- MITRE ATT&CK
- SOC Tier 1 Incident Response Lifecycle

### Data Flow
```
Log Sources
→ Log Analytics Workspace
→ Sentinel Analytics Rules
→ Sentinel Incidents
→ Investigation, Response, Documentation
```

---

## Log Ingestion

### Windows Security Events

- Source: Azure Virtual Machine
- Key Event IDs:
  - 4624 – Successful logon
  - 4625 – Failed logon
  - 4672 – Special privileges assigned to new logon

### Azure Network Logs

- NSG Flow Logs enabled using Azure Network Watcher
- Traffic Analytics configured
- Logs sent to Log Analytics Workspace
- Used for detecting network reconnaissance activity

---

## Detection Engineering

### Brute-Force Login Detection

Detects multiple failed authentication attempts from the same source within a short time window.

- Event ID: 4625
- MITRE ATT&CK: T1110 – Brute Force
- Severity: Medium
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

### Privilege Escalation Detection

Detects logon events where special administrative privileges are assigned to a user account.

- Event ID: 4672
- MITRE ATT&CK: T1068 – Exploitation for Privilege Escalation
- Severity: High
```kql
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Account, Computer
```

### Network Scanning Detection (Azure-Native)

Detects reconnaissance activity based on repeated network connection attempts targeting an Azure Virtual Machine.

- Data Source: Azure NSG Flow Logs
- MITRE ATT&CK: T1046 – Network Service Scanning
- Severity: Medium
```kql
AzureNetworkAnalytics_CL
| summarize Attempts = count() by SrcIP_s, DestIP_s, bin(TimeGenerated, 5m)
| where Attempts > 50
```

---

## Incident Response Workflow

For each triggered alert, the following SOC Tier 1 workflow is executed:

1. Alert triage and validation
2. Severity classification
3. Log correlation and timeline analysis
4. Entity identification (user account, host, IP address)
5. MITRE ATT&CK technique mapping
6. Response and mitigation recommendations
7. Incident closure with documentation

---

## Incident Reports

### IR-001 – Brute Force Login Attempt

**Description:** Multiple failed authentication attempts detected from a single source IP

**Findings:** Repeated Event ID 4625, no successful authentication observed

**Impact:** No confirmed account compromise

**Response Actions:**
- Block source IP
- Enforce account lockout policy
- Continue monitoring

### IR-002 – Privilege Escalation Event

**Description:** Administrative privileges assigned during user logon

**Findings:** Event ID 4672 detected

**Impact:** Potential unauthorized privilege use

**Response Actions:**
- Validate legitimacy of admin access
- Review group membership
- Monitor for follow-on activity

### IR-003 – Network Reconnaissance Activity

**Description:** High-volume network connection attempts consistent with scanning behavior

**Findings:** Azure NSG Flow Logs show repeated connections from a single source

**Impact:** Pre-attack discovery activity identified

**Response Actions:**
- Block source IP at NSG level
- Review exposed services
- Increase monitoring sensitivity

---

## Key Learnings

- Hands-on deployment and operation of Microsoft Sentinel
- Practical detection engineering using KQL
- Understanding host-based versus network-based detections in Azure
- Application of MITRE ATT&CK to real incidents
- Execution of Tier 1 SOC investigation and response workflows

---

## Future Enhancements

- Integrate Sysmon for enhanced endpoint telemetry
- Implement Sentinel playbooks for automated response
- Perform proactive threat hunting activities
- Expand detections to lateral movement and persistence techniques

---

## Tools and Technologies

- Microsoft Sentinel
- Azure Log Analytics
- Azure Virtual Machines
- Azure Network Security Groups
- Kusto Query Language (KQL)
- MITRE ATT&CK

---

## 📄 Incident Reports | 📸 Evidence & Screenshots

Detailed incident documentation is available below:

- [SOC Incident Reports (PDF)](doc/SOC_Incident_Reports.pdf)

- Supporting evidence and screenshots are maintained in the [`/screenshots`](screenshots) directory.

  

