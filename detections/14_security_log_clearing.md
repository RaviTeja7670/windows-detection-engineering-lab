
Detection 14 - Windows Security Log Clearing

Status: VALIDATED

Objective

Detect attempts to clear the Windows Security event log.

Data Source
Index: windows_security
Sourcetype: XmlWinEventLog:Security
Event ID: 1102 - The audit log was cleared
SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=1102
| table _time host SubjectUserName SubjectDomainName
| sort 0 - _time
Investigation

Identify the account that cleared the log, the host, timing, and surrounding activity immediately before and after the event.

Validation

The Security log was cleared on the monitored Windows VM using wevtutil cl Security, generating Event ID 1102.

False Positives

Authorized maintenance, testing, forensic procedures, or administrative activity may clear logs.

MITRE ATT&CK

T1070.001 - Clear Windows Event Logs

Response

Treat unexpected log clearing as a high-priority defense-evasion signal. Preserve available telemetry and investigate preceding activity.
