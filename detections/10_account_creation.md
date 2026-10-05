# Detection 10 - Windows Account Creation

Status: DETECTION LIBRARY

## Objective
Detect creation of new Windows user accounts.

## Data Source
Windows Security Event Log

## Event
EventCode 4720 - A user account was created

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4720
| stats count by host SubjectUserName TargetUserName
| sort - count

## Investigation
Review:
- SubjectUserName - account performing the creation
- TargetUserName - newly created account
- Host
- Time of creation

Determine whether the account creation corresponds to an approved
administrative action.

## MITRE ATT&CK
T1136.001 - Create Account: Local Account

## Security Relevance
Unauthorized account creation can provide persistence or additional access
to a compromised Windows system.

## Tuning
Exclude known administrative/service-account provisioning processes where
appropriate.
