# Lab Architecture

Windows Endpoint
- Windows Security Event Logs
- Sysmon
- Splunk Universal Forwarder

        |
        | TCP 9997
        v

Splunk Enterprise
- Windows event ingestion
- SPL detection rules
- Scheduled alerts
- MITRE ATT&CK mapping
- SOC investigation dashboard

        |
        v

GitHub
- Splunk app configuration
- Detection SPL
- PowerShell test scripts
- MITRE mappings
- Documentation
- Screenshots
