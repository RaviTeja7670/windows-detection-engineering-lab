# Detection 02 - Successful Logon After Multiple Failures

Status: DETECTION LIBRARY

## Objective
Identify a successful Windows logon occurring after multiple failed logon attempts.

## Data Source
Windows Security Event Log

## Events
4625 - Failed Logon
4624 - Successful Logon

## SPL
index=windows_security sourcetype="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| bin _time span=10m
| stats count(eval(EventCode=4625)) as failed_logons
        count(eval(EventCode=4624)) as successful_logons
        values(EventCode) as event_codes
        by _time host src_ip
| where failed_logons >= 3 AND successful_logons >= 1

## MITRE ATT&CK
T1078 - Valid Accounts

## Investigation
Review the source IP, target host, account and timing relationship between failed and successful authentication.
