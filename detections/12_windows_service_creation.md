
Detection 12 - Windows Service Creation

Status: VALIDATED

Objective

Detect creation of Windows services that may provide persistence or execute code with elevated privileges.

Data Source

Windows event telemetry associated with Windows Service Control Manager activity.

Detection Logic

Identify service-creation events and investigate the service name, executable path, account, and creating activity.

SPL
index=windows_security sourcetype="XmlWinEventLog:Security" EventCode=7045
| table _time host ServiceName ImagePath ServiceType StartType AccountName
| sort 0 - _time
Investigation

Review the service executable path, service account, start type, creator context, and whether the binary is trusted.

False Positives

Software installation, Windows updates, endpoint management, and legitimate administration can create services.

MITRE ATT&CK

T1543.003 - Windows Service

Response

Investigate the service binary and determine whether it is expected. Correlate with process creation and file creation telemetry.
