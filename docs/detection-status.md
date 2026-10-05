# Detection Engineering Project Status

## Detection Library

| # | Detection | Status |
|---|---|---|
| 01 | Windows Failed Logon / Brute Force | VALIDATED |
| 02 | Successful Logon After Failures | LIBRARY |
| 03 | Privileged Logon | LIBRARY |
| 04 | Suspicious Process Creation | LIBRARY |
| 05 | PowerShell Execution | LIBRARY |
| 06 | Network Connection Monitoring | LIBRARY |
| 07 | Process Injection Indicators | LIBRARY |
| 08 | Suspicious File Creation | LIBRARY |
| 09 | Registry Modification | LIBRARY |
| 10 | Account Creation | LIBRARY |
| 11 | Privileged Group Modification | LIBRARY |
| 12 | Windows Service Creation | LIBRARY |
| 13 | Scheduled Task Creation | LIBRARY |
| 14 | Security Log Clearing | LIBRARY |
| 15 | Authentication Attack Correlation | LIBRARY |

## Validation Policy

A detection is marked VALIDATED only after its SPL has been executed against
the lab telemetry and the expected behavior has been confirmed.

A detection marked LIBRARY is a documented detection candidate and has not yet
been represented as production-validated.

## Current Validated Detection

Detection 01 - Windows Failed Logon / Brute Force

EventCode 4625
Threshold: 3 or more events within 5 minutes
