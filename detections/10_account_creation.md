
Detection 10 - Windows Account Creation

Status: VALIDATED

Objective

Detect creation of new Windows user accounts.

Data Source
Index: windows_security
Sourcetype: XmlWinEventLog:Security
Event ID: 4720 - A user account was created
SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4720
| table _time host SubjectUserName SubjectDomainName TargetUserName TargetDomainName
| sort 0 - _time
Investigation

Determine who created the account, which account was created, when it was created, and whether the action was authorized.

Validation

A test account named Detection10-Test was created on the monitored Windows VM and Event ID 4720 was observed.

False Positives

Legitimate administrative provisioning and software deployment may create accounts.

MITRE ATT&CK

T1136.001 - Create Account: Local Account

Response

Validate the account owner and business purpose. Investigate subsequent logons, group membership, and process activity.
