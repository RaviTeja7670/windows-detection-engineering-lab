
Detection 05 - Suspicious PowerShell Execution

Status: VALIDATED

Objective

Detect potentially suspicious PowerShell execution and command-line indicators associated with script-based execution or evasion.

Data Source
Index: sysmon
Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Event ID: 1 - Process Creation
Detection Logic

Identify PowerShell or pwsh processes and prioritize command lines containing encoded commands, IEX, download activity, Base64 decoding, execution-policy bypass, and hidden/non-interactive execution options.

SPL
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| search CommandLine="*-enc*"
    OR CommandLine="*-encodedcommand*"
    OR CommandLine="*IEX*"
    OR CommandLine="*Invoke-Expression*"
    OR CommandLine="*DownloadString*"
    OR CommandLine="*Invoke-WebRequest*"
    OR CommandLine="*FromBase64String*"
    OR CommandLine="*ExecutionPolicy Bypass*"
    OR CommandLine="* -nop*"
    OR CommandLine="* -noprofile*"
| table _time host Image CommandLine User
| sort 0 - _time
Investigation

Review the full command line, user, parent process, destination network connections, downloaded files, and subsequent process creation.

False Positives

Legitimate administration, automation, software deployment, and security tooling can use PowerShell.

MITRE ATT&CK

T1059.001 - PowerShell

Alerting

Implemented as WDL - Suspicious PowerShell Execution.

Validation

Validated with PowerShell process creation telemetry and a suspicious command-line test event.

Response

Investigate the script execution chain and correlate with network, file creation, and authentication telemetry.
