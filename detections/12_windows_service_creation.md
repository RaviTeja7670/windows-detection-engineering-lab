# Detection 12 - Windows Service Creation

Status: DETECTION LIBRARY

## Objective
Detect creation of new Windows services that could establish persistence or
execute code with elevated privileges.

## Data Source
Windows Security Event Log

## Event
4697 - A service was installed in the system

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4697
| stats count by host ServiceName ServiceFileName SubjectUserName
| sort - count

## Investigation
Review:
- ServiceName
- ServiceFileName
- SubjectUserName
- Host
- Creation time

Pay particular attention to services whose binaries execute from unusual
directories such as user-writable locations.

## MITRE ATT&CK
T1543.003 - Windows Service

## Security Relevance
Attackers can create Windows services to establish persistence or execute
commands with elevated privileges.

## Tuning
Exclude known enterprise software deployment and management systems.
