
Detection 15 - Authentication Correlation

Status: VALIDATED

Objective

Correlate Windows failed and successful authentication events to identify a successful logon occurring shortly after a failed logon.

Data Source
Index: windows_security
Sourcetype: XmlWinEventLog:Security
Event IDs: 4624 and 4625
SPL
index=windows_security sourcetype="XmlWinEventLog:Security"
(EventCode=4624 OR EventCode=4625)
| sort 0 host _time
| streamstats window=10 current=f
    last(EventCode) as PreviousEventCode
    last(_time) as PreviousEventTime
    by host
| where EventCode=4624 AND PreviousEventCode=4625
| eval TimeBetween=round(_time-PreviousEventTime,2)
| where TimeBetween <= 300
| table _time host PreviousEventCode PreviousEventTime TimeBetween EventCode
| sort 0 - _time
Detection Logic

The correlation identifies Event ID 4624 occurring after Event ID 4625 on the same host within five minutes.

Investigation

Review source IP, account, logon type, number of preceding failures, authentication timing, and related endpoint activity.

Validation

The detection returned multiple qualifying authentication sequences. Observed successful-logon intervals included approximately 3, 9, 11, and 12 seconds after a failed authentication event.

False Positives

Users can legitimately enter an incorrect password and then authenticate successfully. Automated services may also retry authentication.

MITRE ATT&CK

Potential mapping includes T1078 - Valid Accounts when successful authentication follows credential-guessing activity.

Response

Investigate the authentication sequence and correlate it with failed-logon, process, network, and account activity.
