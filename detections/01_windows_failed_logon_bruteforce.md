# Detection 01 - Windows Failed Logon / Brute Force

**Status:** VALIDATED

## Objective

Detect repeated Windows authentication failures from the same source IP against the same host within a five-minute window.

## Why It Matters

Repeated failed logons can indicate:

- Brute-force authentication attempts
- Password spraying activity
- Credential guessing
- Misconfigured applications repeatedly attempting authentication

The detection provides an initial signal for investigating suspicious authentication activity.

## Data Source

**Windows Security Event Log**

| Field | Value |
|---|---|
| Index | `windows_security` |
| Sourcetype | `XmlWinEventLog:Security` |
| Event Code | `4625` |
| Event | An account failed to log on |

## Detection Logic

The detection:

1. Searches Windows Security Event ID 4625.
2. Groups events into five-minute time buckets.
3. Groups activity by time, host, and source IP.
4. Counts failed authentication attempts.
5. Generates a detection when the count reaches three or more failures.

## SPL

```spl
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time host src_ip
| where failed_attempts >= 3
| sort - failed_attempts
Threshold

3 or more failed logons within 5 minutes from the same source IP against the same host.

The threshold is intended as an initial detection signal rather than proof of malicious activity.

Investigation

When the detection triggers, investigate:

Source IP
Target host
Failed authentication count
Targeted account
Authentication timing
Whether successful authentication followed the failures
Other activity from the same source IP
Related endpoint or network telemetry

A particularly important follow-up is checking for a successful logon after repeated failures.

False Positives

Potential legitimate causes include:

Incorrectly configured services
Stored credentials that are no longer valid
User repeatedly entering an incorrect password
Automated applications using outdated credentials
Administrative or testing activity

The alert should therefore be treated as a suspicious authentication signal requiring investigation.

MITRE ATT&CK

Technique: T1110 - Brute Force

The detection identifies repeated authentication failures that may be associated with credential-guessing activity.

Alerting

The detection is implemented as a scheduled Splunk alert.

Alert configuration:

Schedule: Every 5 minutes
Detection window: Previous 5 minutes
Trigger condition: At least one qualifying result
Alert throttling: 10 minutes
Email notification: Enabled

Alert name:

WDL - Windows Failed Logon Brute Force Detection

Validation

The detection was validated using Windows Security Event ID 4625 events generated on the monitored Windows endpoint.

A qualifying test produced multiple failed authentication events from the same source within the five-minute detection window.

The resulting SPL aggregation identified the host, source IP, and failed-attempt count.

Response

If the activity appears malicious:

Identify the source system.
Determine which accounts were targeted.
Check for successful authentication after the failures.
Investigate related endpoint and network activity.
Determine whether the source should be contained or blocked.
Escalate according to the SOC incident-response process.
Related Detection

Detection 02 - Successful Logon After Failed Logons

This detection can be investigated together with the authentication-correlation rule to identify potentially successful access following failed authentication attempts.
