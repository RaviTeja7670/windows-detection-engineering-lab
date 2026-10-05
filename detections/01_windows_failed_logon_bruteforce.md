# Detection 01 - Windows Failed Logon / Brute Force

Status: VALIDATED

## Objective
Detect multiple Windows failed authentication attempts within a five-minute window.

## Data Source
Windows Security Event Log

## Event
EventCode 4625

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time host src_ip
| where failed_attempts >= 3
| sort - failed_attempts

## Threshold
3 or more failures within 5 minutes.

## MITRE ATT&CK
T1110 - Brute Force

## Response
Investigate source IP, targeted host, targeted account and subsequent successful authentication.
