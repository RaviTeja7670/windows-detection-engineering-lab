# Detection 11 - Privileged Group Modification

Status: DETECTION LIBRARY

## Objective
Detect users being added to security-sensitive local or domain groups.

## Data Source
Windows Security Event Log

## Events
4728 - Member added to security-enabled global group
4732 - Member added to security-enabled local group
4756 - Member added to security-enabled universal group

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode IN (4728,4732,4756)
| stats count by host EventCode SubjectUserName TargetUserName
| sort - count

## Investigation
Review:
- SubjectUserName - account performing the modification
- TargetUserName - account being added
- Group name
- Host
- Event time

## MITRE ATT&CK
T1098 - Account Manipulation

## Security Relevance
Unexpected group membership changes can provide privilege escalation or persistence.

## Tuning
Production implementations should identify privileged groups and approved
administrative accounts before creating high-confidence alerts.
