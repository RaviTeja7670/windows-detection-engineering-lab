
Detection 09 - Registry Run Key Modification

Status: VALIDATED

Objective

Detect modifications to Windows Registry Run and RunOnce keys that may establish persistence.

Data Source
Index: sysmon
Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Event ID: 13 - Registry Value Set
SPL
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
    OR TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"
| table _time host Image TargetObject Details User
| sort 0 - _time
Investigation

Review the modifying process, registry path, value details, user, and whether the configured executable or script is legitimate.

Validation

A test Run key named Detection9-Test was created and observed in Splunk.

MITRE ATT&CK

T1547.001 - Registry Run Keys / Startup Folder

Alerting

Implemented as WDL - Registry Run Key Modification.

False Positives

Legitimate applications commonly use Run keys for startup behavior.

Response

Identify the process making the change and investigate the referenced executable or script.
