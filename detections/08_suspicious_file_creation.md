
Detection 08 - Suspicious File Creation in User Temp

Status: VALIDATED

Objective

Detect executable and script files created in user AppData Local Temp directories.

Data Source
Index: sysmon
Sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Event ID: 11 - File Creation
SPL
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search (TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.exe"
    OR TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.dll"
    OR TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.ps1"
    OR TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.bat"
    OR TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.cmd"
    OR TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.vbs"
    OR TargetFilename="*\\Users\\*\\AppData\\Local\\Temp\\*.js")
| table _time host Image TargetFilename User
| sort 0 - _time
Investigation

Review the creating process, file path, user, file extension, and subsequent process execution.

Validation

Validated by creating Detection8-Test.exe in the monitored VM's user Temp directory.

False Positives

Software installers, browsers, Windows diagnostics, updates, and security tools may legitimately create temporary files.

MITRE ATT&CK

Potential mapping: T1204/T1105, depending on the surrounding execution or download behavior.

Alerting

Implemented as WDL - Suspicious File Creation in User Temp.

Response

Investigate the creating process and determine whether the file was subsequently executed or downloaded.
