# Detection 07 - Process Injection Indicators

Status: DETECTION LIBRARY

## Objective
Identify CreateRemoteThread activity that may indicate process injection.

## Data Source
Microsoft Sysmon

## Event
Sysmon Event ID 8 - CreateRemoteThread

## SPL
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| stats count by host SourceImage TargetImage StartAddress StartModule StartFunction
| sort - count

## Detection Logic
CreateRemoteThread records a thread created in another process. This can be
associated with process injection and should be investigated in context.

## MITRE ATT&CK
T1055.001 - Dynamic-link Library Injection

## Investigation
Review:
- SourceImage
- TargetImage
- StartAddress
- StartModule
- StartFunction

Pay particular attention to unexpected source-to-target process relationships.

## Tuning
Do not automatically treat every Event ID 8 event as malicious. Security software
and legitimate applications may also generate remote threads.
