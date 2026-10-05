# Detection 14 - Windows Security Log Clearing

Status: DETECTION LIBRARY

## Objective
Detect attempts to clear the Windows Security event log.

## Data Source
Windows Security Event Log

## Event
1102 - The audit log was cleared

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=1102
| stats count by host SubjectUserName
| sort - count

## MITRE ATT&CK
T1070.001 - Clear Windows Event Logs

## Security Relevance
Clearing security logs can remove evidence and impair incident investigation.

## Investigation
Review:
- Account that cleared the log
- Host
- Time
- Events immediately before and after the clearing event

## False Positives
Legitimate administrative log-management activity may generate this event.

## Response
Correlate the event with other detections before determining whether the activity
is malicious.
