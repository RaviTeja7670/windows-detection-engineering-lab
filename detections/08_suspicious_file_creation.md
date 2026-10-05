# Detection 08 - Suspicious File Creation

Status: DETECTION LIBRARY

## Objective
Monitor files created or overwritten on the Windows endpoint and provide a basis
for detecting payload staging and persistence activity.

## Data Source
Microsoft Sysmon

## Event
Sysmon Event ID 11 - FileCreate

## SPL
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| stats count by host Image TargetFilename
| sort - count

## Focused Hunting Example
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search TargetFilename="*.exe" OR TargetFilename="*.dll" OR TargetFilename="*.ps1"
| stats count by host Image TargetFilename
| sort - count

## Detection Logic
File creation by itself is not malicious. The useful detection signal comes from
the combination of file type, destination path, creating process and surrounding
process/network activity.

## MITRE ATT&CK
Context dependent.

File creation telemetry can support investigation of:
- T1105 - Ingress Tool Transfer
- T1547.001 - Registry Run Keys / Startup Folder
- Malware staging

## Tuning
FileCreate can be noisy. Production implementations should focus on high-value
paths, executable/script extensions and suspicious creating processes.
