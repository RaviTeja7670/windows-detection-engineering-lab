# Detection 03 - Privileged Logon

Status: DETECTION LIBRARY

## Objective
Identify Windows logon activity associated with special privileges.

## Data Source
Windows Security Event Log

## Event
4672 - Special privileges assigned to new logon

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4672
| stats count values(host) as hosts by SubjectUserName
| sort - count

## MITRE ATT&CK
T1078 - Valid Accounts

## Investigation
Determine whether the privileged logon corresponds to an expected administrative activity.
