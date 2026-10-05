# Detection 02 - Successful Logon After Failed Logons

**Status:** VALIDATED

## Objective

Identify a successful Windows authentication occurring shortly after a failed authentication attempt from the same host.

The detection is designed to identify authentication sequences where repeated failures are followed by a successful logon.

## Why It Matters

A successful logon following failed authentication attempts can indicate:

- Credential guessing followed by successful access
- Password spraying
- Compromised credentials
- An attacker obtaining valid credentials
- Legitimate users eventually entering the correct password

The event sequence requires investigation rather than being treated as confirmed malicious activity.

## Data Source

**Windows Security Event Log**

| Field | Value |
|---|---|
| Index | `windows_security` |
| Sourcetype | `XmlWinEventLog:Security` |
| Failed Logon | Event ID `4625` |
| Successful Logon | Event ID `4624` |

## Detection Logic

The detection:

1. Searches for Windows Security Event IDs 4624 and 4625.
2. Orders the events by host and event time.
3. Uses `streamstats` to examine the previous authentication event.
4. Identifies a successful logon whose immediately preceding authentication event was a failed logon.
5. Calculates the time between the failed and successful events.
6. Keeps correlations occurring within 300 seconds.

## SPL

```spl
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
Correlation Window

Maximum time between failed and successful authentication: 300 seconds (5 minutes).

The detection also requires the previous authentication event for the host to be Event ID 4625.

Investigation

When the detection triggers, investigate:

Source IP associated with the authentication
Target host
Target account
Logon type
Number of preceding failures
Time between failed and successful authentication
Whether the successful authentication is expected
Other activity from the same account or host
Related endpoint and network telemetry

The key question is whether the successful authentication represents legitimate user activity or successful access after credential-guessing activity.

False Positives

Potential legitimate causes include:

Users entering an incorrect password before correcting it
Forgotten or expired credentials
Automated services retrying authentication
Administrative troubleshooting
Authentication synchronization issues

Context from the source IP, account, logon type, and surrounding events is required.

MITRE ATT&CK

Technique: T1078 - Valid Accounts

A successful authentication after failed attempts may indicate that valid credentials were eventually obtained or successfully used.

This mapping represents the potential adversary behavior and does not by itself establish malicious use of valid credentials.

Alerting

The detection is implemented as a scheduled Splunk alert with email notification.

Alert name:

WDL - Successful Logon After Failed Logons

The alert searches for qualifying authentication correlations and notifies the SOC when the detection condition is met.

Validation

The detection was validated using Windows Security authentication events generated on the monitored Windows endpoint.

The completed correlation search returned multiple qualifying events where Event ID 4624 followed Event ID 4625 within the five-minute correlation window.

Observed examples included successful authentication occurring approximately:

3 seconds after a failed logon
9 seconds after a failed logon
11 seconds after a failed logon
12 seconds after a failed logon
Response

If the authentication sequence appears suspicious:

Identify the source system and IP.
Identify the account that successfully authenticated.
Review the authentication method and logon type.
Examine the preceding failed attempts.
Search for additional activity from the account and host.
Investigate endpoint and network telemetry.
Consider account protection or host containment if malicious activity is confirmed.
Related Detection

Detection 01 - Windows Failed Logon / Brute Force

Detection 01 identifies repeated failed authentication attempts, while this detection adds temporal correlation with a subsequent successful authentication.
