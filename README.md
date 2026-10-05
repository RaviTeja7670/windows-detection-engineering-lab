# Windows SIEM Detection Engineering Lab

A practical Windows SIEM and detection engineering lab built with **Splunk Enterprise, Windows Security Logs, Microsoft Sysmon, and Splunk Universal Forwarder**.

The project demonstrates end-to-end SOC detection engineering: telemetry collection, field extraction, SPL detection logic, alerting, MITRE ATT&CK mapping, investigation workflows, and SOC dashboarding.

---

## Architecture

```text
                    Windows Endpoint / VM
                           |
              +------------+------------+
              |                         |
       Windows Security             Microsoft Sysmon
          Event Logs                 Event IDs
              |                         |
              +------------+------------+
                           |
                  Splunk Universal
                     Forwarder
                           |
                       TCP 9997
                           |
                           v
                   Splunk Enterprise
                           |
              +------------+------------+
              |            |            |
         SPL Detection   Alerting    Dashboard
             Rules
              |
              v
       MITRE ATT&CK Mapping
              |
              v
        SOC Investigation
Detection Coverage

The lab contains 15 Windows security detections covering authentication, execution, persistence, credential access, defense evasion, and correlation. 
| #  | Detection                             | Primary Telemetry              |
| -- | ------------------------------------- | ------------------------------ |
| 01 | Windows Failed Logon / Brute Force    | Security 4625                  |
| 02 | Successful Logon After Failed Logons  | Security 4624 / 4625           |
| 03 | Privileged Logon                      | Security authentication events |
| 04 | Suspicious Process Creation           | Sysmon 1                       |
| 05 | Suspicious PowerShell Execution       | Sysmon 1                       |
| 06 | Suspicious Network Connection         | Sysmon 3                       |
| 07 | Suspicious LSASS Process Access       | Sysmon 10                      |
| 08 | Suspicious File Creation in User Temp | Sysmon 11                      |
| 09 | Registry Run Key Modification         | Sysmon 13                      |
| 10 | Windows Account Creation              | Security 4720                  |
| 11 | Privileged Group Modification         | Windows Security               |
| 12 | Windows Service Creation              | Windows Security / System      |
| 13 | Scheduled Task Creation               | Security 4698                  |
| 14 | Security Log Clearing                 | Security 1102                  |
| 15 | Authentication Correlation            | Security 4624 / 4625           |

Telemetry
   |
   v
Field Extraction
   |
   v
SPL Detection Logic
   |
   v
Threshold / Correlation
   |
   v
Alert
   |
   v
SOC Investigation
   |
   v
MITRE ATT&CK Mapping
   |
   v
Documentation
Data Sources
Windows Security Event Log

Used for authentication, account management, privilege, scheduled task, and security audit detections.

Examples:

Event ID 4624 — Successful Logon
Event ID 4625 — Failed Logon
Event ID 4698 — Scheduled Task Created
Event ID 4720 — User Account Created
Event ID 1102 — Security Audit Log Cleared
Microsoft Sysmon

Used for endpoint telemetry including:

Process creation
Network connections
Process access
File creation
Registry modification

Key Sysmon events used in this project:

Event ID 1 — Process Creation
Event ID 3 — Network Connection
Event ID 10 — Process Access
Event ID 11 — File Creation
Event ID 13 — Registry Value Set
Splunk Components

The project uses:

Splunk Enterprise
Splunk Universal Forwarder
Splunk Search Processing Language (SPL)
Saved Searches / Scheduled Alerts
Simple XML Dashboard
Field Extractor
Sysmon
Windows Event Logging

Custom Splunk app:
splunk_app/
└── windows_detection_lab/
    ├── default/
    ├── local/
    └── metadata/
Repository Structure
windows-detection-engineering-lab/
│
├── detections/
│   ├── 01_windows_failed_logon_bruteforce.md
│   ├── 02_successful_logon_after_failures.md
│   ├── 03_privileged_logon.md
│   ├── 04_suspicious_process_creation.md
│   ├── 05_powershell_execution.md
│   ├── 06_network_connection_monitoring.md
│   ├── 07_process_injection.md
│   ├── 08_suspicious_file_creation.md
│   ├── 09_registry_modification.md
│   ├── 10_account_creation.md
│   ├── 11_privileged_group_modification.md
│   ├── 12_windows_service_creation.md
│   ├── 13_scheduled_task_creation.md
│   ├── 14_security_log_clearing.md
│   └── 15_authentication_correlation.md
│
├── docs/
│   ├── architecture.md
│   └── detection-status.md
│
├── mitre/
│   ├── 01_authentication_and_execution.md
│   ├── 02_endpoint_and_persistence.md
│   └── 03_persistence_and_defense_evasion.md
│
├── splunk_app/
│   └── windows_detection_lab/
│       ├── default/
│       ├── local/
│       └── metadata/
│
├── .gitignore
└── README.md

Detection Examples
Failed Logon Brute Force
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time host src_ip
| where failed_attempts >= 3
| sort - failed_attempts
Detects repeated Windows authentication failures from the same source within a five-minute window.

Suspicious PowerShell Execution
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*FromBase64String*" OR CommandLine="*ExecutionPolicy Bypass*"
Suspicious LSASS Access
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search TargetImage="*\\lsass.exe"
| table _time host SourceImage TargetImage GrantedAccess CallTrace SourceUser TargetUser
| sort 0 - _time
Alerting

Detection rules are implemented as scheduled Splunk alerts with:

Five-minute detection windows where appropriate
Trigger conditions
Alert throttling
Email notifications
Result fields included in alert messages
SOC-oriented alert descriptions

Example alert naming convention:
WDL - Windows Failed Logon Brute Force Detection
WDL - Suspicious Process Execution
WDL - Suspicious PowerShell Execution
WDL - Suspicious Network Connection
WDL - Suspicious LSASS Process Access
WDL - Suspicious File Creation in User Temp
WDL - Registry Run Key Modification
MITRE ATT&CK

Detections are mapped to relevant MITRE ATT&CK techniques to demonstrate how individual telemetry sources and detection rules correspond to adversary behavior.

The mitre/ directory contains the ATT&CK mapping documentation used by the project.
Investigation Focus

The project is designed around practical SOC investigation questions:

Which host generated the event?
Which user account was involved?
What process generated the activity?
What source IP initiated the activity?
What target was accessed?
What command line was executed?
What registry key or file was modified?
Is the behavior expected or anomalous?
Which MITRE ATT&CK technique does the activity represent?
What additional telemetry should be investigated?
Purpose

This repository is intended as a practical cybersecurity portfolio project demonstrating hands-on experience with:

SIEM engineering
Splunk administration
SPL development
Windows security monitoring
Sysmon
Detection engineering
Alert engineering
MITRE ATT&CK
SOC investigation
Security event correlation
Author

Ravi Teja

Windows SIEM Detection Engineering Lab
Splunk Enterprise + Windows Security Logs + Sysmon
