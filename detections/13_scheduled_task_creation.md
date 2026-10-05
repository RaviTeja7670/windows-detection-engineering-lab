
Detection 13 - Scheduled Task Creation

Status: VALIDATED

Objective

Detect creation of Windows scheduled tasks that may be used for persistence or execution.

Data Source
Index: windows_security
Sourcetype: XmlWinEventLog:Security
Event ID: 4698 - A scheduled task was created
SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4698
| table _time host TaskName SubjectUserName SubjectDomainName TaskContent
| sort 0 - _time
Investigation

Review the task name, creator, task content, executable or command, trigger, and run context.

Validation

Audit policy for scheduled-task creation was enabled and a test scheduled task was created on the monitored Windows VM. Event ID 4698 was observed.

False Positives

Legitimate software installation, maintenance, updates, and administrative automation create scheduled tasks.

MITRE ATT&CK

T1053.005 - Scheduled Task/Job: Scheduled Task

Response

Validate the task owner and command. Investigate the referenced executable or script and related process activity.
