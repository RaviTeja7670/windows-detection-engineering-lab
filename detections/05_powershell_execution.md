# Detection 05 - PowerShell Execution

Status: DETECTION LIBRARY

## Objective
Identify PowerShell process execution and provide command-line context for investigation.

## Data Source
Microsoft Sysmon

## Event
Sysmon Event ID 1 - Process Creation

## SPL
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe" OR CommandLine="*powershell*"
| table _time host User Image ParentImage CommandLine ProcessId
| sort - _time

## MITRE ATT&CK
T1059.001 - PowerShell

## Investigation
Review PowerShell command line, parent process, user, execution time and associated network/file activity.
