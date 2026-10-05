# Windows SIEM Detection Engineering Lab

A Splunk Enterprise detection engineering lab using Windows Security Event Logs and Sysmon.

## Architecture

Windows Endpoint
    |
    | Security Logs + Sysmon
    v
Splunk Universal Forwarder
    |
    | TCP 9997
    v
Splunk Enterprise
    |
    +-- Detection Rules
    +-- MITRE ATT&CK Mapping
    +-- Alerting
    +-- SOC Dashboard
    |
    v
GitHub Detection Engineering Project

## Detection Coverage

1. Windows Failed Logon / Brute Force
2. Successful Logon After Multiple Failures
3. Privileged Logon
4. Suspicious Process Creation
5. PowerShell Execution
6. Network Connection Monitoring
7. Process Injection Indicators
8. File Creation Monitoring
9. Registry Modification
10. Account Creation
11. Privileged Group Modification
12. Windows Service Creation
13. Scheduled Task Creation
14. Security Log Clearing
15. Multi-event Correlation / Risk

## Data Sources

- Windows Security Event Log
- Microsoft Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise

## Project Status

Detection 1 is currently implemented and tested.

Additional detections are being developed and documented as part of the detection engineering library.
