# Detection 09 - Suspicious Registry Modification

Status: DETECTION LIBRARY

## Objective
Monitor registry modifications that may indicate persistence, defense evasion
or system configuration changes.

## Data Source
Microsoft Sysmon

## Events
Sysmon Event IDs 12, 13 and 14

- 12 = Registry object created/deleted
- 13 = Registry value set
- 14 = Registry object renamed

## SPL
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=12 OR EventCode=13 OR EventCode=14)
| stats count by host EventCode Image TargetObject Details
| sort - count

## Focused Persistence Hunt
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*"
| table _time host Image TargetObject Details
| sort - _time

## MITRE ATT&CK
T1112 - Modify Registry

## Investigation
Prioritize:
- Run / RunOnce keys
- Security-related registry changes
- Unexpected modifying processes
- Changes immediately following suspicious process execution
