# Detection 06 - Network Connection Monitoring

Status: DETECTION LIBRARY

## Objective
Monitor network connections initiated by Windows processes and identify unusual
destination addresses or ports for investigation.

## Data Source
Microsoft Sysmon

## Event
Sysmon Event ID 3 - Network Connection

## SPL
index=windows_security sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by host Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - count

## Investigation Fields
- Image
- SourceIp
- SourcePort
- DestinationIp
- DestinationPort
- Protocol

## Detection Logic
This is a network telemetry/hunting rule rather than a universal maliciousness rule.
Production implementations should baseline normal destinations and filter expected
system/application traffic.

## MITRE ATT&CK
Telemetry only / contextual mapping.

Network connection telemetry can support investigation of command-and-control,
lateral movement and other network-related techniques depending on the destination,
process and protocol.

## Tuning
Sysmon Event ID 3 can be high-volume and should be selectively collected/tuned.
