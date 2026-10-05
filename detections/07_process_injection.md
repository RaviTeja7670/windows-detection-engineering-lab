
Detection 07 - Suspicious LSASS Process Access

Status: VALIDATED

Objective

Detect Sysmon Process Access events targeting LSASS that may indicate credential-access activity.

Data Source
Index: sysmon
Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Event ID: 10 - Process Access
SPL
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search TargetImage="*\\lsass.exe"
| table _time host SourceImage TargetImage GrantedAccess CallTrace SourceUser TargetUser
| sort 0 - _time
Investigation

Review the source process, target process, granted access mask, source user, target user, and call trace.

Known baseline activity should be considered before escalation.

False Positives

Security software, Windows services, endpoint management, and legitimate diagnostic tools can access LSASS.

MITRE ATT&CK

T1003.001 - LSASS Memory

Validation

Validated against Sysmon Event ID 10 telemetry targeting lsass.exe.

Alerting

Implemented as WDL - Suspicious LSASS Process Access.

Response

Investigate the source process and access rights and correlate with credential, process, and network activity.
