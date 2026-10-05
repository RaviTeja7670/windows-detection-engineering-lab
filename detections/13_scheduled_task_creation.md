# Detection 13 - Scheduled Task Creation

Status: DETECTION LIBRARY

## Objective
Detect creation or modification of Windows scheduled tasks that may provide
persistence or recurring execution.

## Data Source
Windows Security Event Log

## Events
4698 - Scheduled task created
4700 - Scheduled task enabled
4702 - Scheduled task updated

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode IN (4698,4700,4702)
| stats count by host EventCode SubjectUserName TaskName
| sort - count

## Focused Hunt
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4698
| search TaskName="*"
| table _time host SubjectUserName TaskName
| sort - _time

## MITRE ATT&CK
T1053.005 - Scheduled Task/Job: Scheduled Task

## Investigation
Review the task name, creating user, command/action and execution path.

High-value cases include tasks executing PowerShell, cmd.exe, scripts or binaries
from user-writable directories.

## Tuning
Scheduled tasks are common on Windows. High-confidence detection requires
command/path context and allowlisting of known enterprise tasks.
