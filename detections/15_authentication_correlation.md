# Detection 15 - Authentication Attack Correlation

Status: DETECTION LIBRARY

## Objective
Correlate repeated failed authentication attempts with a subsequent successful
authentication from the same source and host.

## Data Source
Windows Security Event Log

## Events
4625 - Failed Logon
4624 - Successful Logon

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| bin _time span=10m
| stats
    count(eval(EventCode=4625)) as failed_logons
    count(eval(EventCode=4624)) as successful_logons
    values(EventCode) as event_codes
    by _time host src_ip
| where failed_logons >= 3 AND successful_logons >= 1
| eval risk_score = 70
| eval detection="Authentication Attack Correlation"
| sort - risk_score - failed_logons

## Correlation Logic

Multiple failed logons
        +
Successful logon
        +
Same host/source/time window
        =
Higher-priority investigation

## MITRE ATT&CK

T1110 - Brute Force
T1078 - Valid Accounts

## Risk Concept

This is a correlation/risk-oriented use case rather than a single-event detector.
The risk score is a lab demonstration value and is not intended to represent a
universal production risk score.

## Investigation

Review:
- Source IP
- Host
- Number of failed logons
- Successful logon timing
- Target account
- Other activity from the same source
