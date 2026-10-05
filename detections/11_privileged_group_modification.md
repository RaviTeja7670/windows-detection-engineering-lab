
Detection 11 - Privileged Group Modification

Status: IMPLEMENTED

Objective

Detect additions of accounts to Windows security-enabled groups that can increase privileges.

Data Source

Windows Security Event Log.

Relevant Windows Security events include group-membership modification events such as Event IDs 4728, 4732, and 4756.

Detection Logic

Monitor security-enabled group membership changes and identify additions that may grant administrative or elevated privileges.

SPL
index=windows_security sourcetype="XmlWinEventLog:Security"
(EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time host EventCode SubjectUserName MemberName TargetUserName
| sort 0 - _time
Investigation

Determine which account was added, which group was modified, who performed the change, and whether the change was authorized.

False Positives

Legitimate onboarding, administration, application deployment, and access-management workflows may modify group membership.

MITRE ATT&CK

T1098 - Account Manipulation

Response

Validate the change against approved access requests. If unauthorized, remove the membership and investigate related account activity.

Note

This detection should be tuned to the organization's privileged groups to reduce normal administrative noise.
