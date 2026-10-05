# Detection 04 - Suspicious Process Creation

**Status:** VALIDATED

## Objective
Detect potentially suspicious Windows process execution using Sysmon Event ID 1.

## Data Source
- Index: `sysmon`
- Sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Event ID: `1 - Process Creation`

## Detection Logic
Monitor process creation involving commonly abused Windows utilities such as PowerShell, CMD, rundll32, mshta, regsvr32, and certutil.

## SPL
```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\powershell.exe"
    OR Image="*\\cmd.exe"
    OR Image="*\\rundll32.exe"
    OR Image="*\\mshta.exe"
    OR Image="*\\regsvr32.exe"
    OR Image="*\\certutil.exe"
| table _time host Image CommandLine User
| sort 0 - _time
Investigation

Review the process image, command line, user, parent process, execution time, and related network activity.

False Positives

Administrative tools, software installation, automation, and legitimate scripting may generate these events.

MITRE ATT&CK

Potential mappings include Command and Scripting Interpreter (T1059) and Signed Binary Proxy Execution (T1218), depending on the executable involved.

Validation

Validated using Sysmon process creation telemetry from the monitored Windows endpoint.

Response

Investigate the process chain and command line. Correlate with PowerShell, network, file, and authentication activity.
