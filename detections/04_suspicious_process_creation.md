# Detection 04 - Suspicious Process Creation

Status: DETECTION LIBRARY

## Objective
Monitor Windows process creation events for suspicious or unusual process execution.

## Data Source
Microsoft Sysmon

## Event
Sysmon Event ID 1 - Process Creation

## SPL
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by Image ParentImage CommandLine host
| sort - count

## Investigation
Review the executable, parent process and command line for abnormal process chains.

## MITRE ATT&CK
T1059 - Command and Scripting Interpreter
