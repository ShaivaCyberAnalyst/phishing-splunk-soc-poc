Phishing Attack Detection & Incident Investigation (SOC Lab)
📌 Overview

This project demonstrates an end-to-end phishing attack simulation and SOC investigation performed in a controlled lab environment using Splunk SIEM.

A phishing email was delivered to a user, leading to suspicious PowerShell execution with encoded commands. The activity was detected, alerted, and investigated using SPL queries, replicating a real-world SOC L1 workflow.

🎯 Objective

Simulate a real phishing attack scenario

Detect malicious PowerShell activity

Perform SOC-style alert triage and investigation

Validate attacker behavior using log correlation

Document findings as a professional incident report

🛠 Tools & Technologies

GoPhish – Phishing campaign simulation

MailHog – SMTP capture and email testing

Windows 10 Endpoint – Victim machine

PowerShell Script Block Logging (Event ID 4104)

Windows Security Logs (Event ID 4688)

Splunk Enterprise SIEM – Detection and investigation

🧪 Attack Scenario

Phishing email crafted and sent using GoPhish

User receives phishing email

User clicks the malicious link

PowerShell executes an encoded command

Endpoint logs generated (PowerShell + Process Creation)

Logs forwarded to Splunk SIEM

Alert triggered and investigation initiated

🚨 Detection & Investigation
Suspicious Behavior Observed

PowerShell executed using Base64 encoded command

Use of ExecutionPolicy Bypass

Script execution via IEX

Repeated encoded PowerShell activity

🔍 Key SPL Queries Used
Detect Encoded PowerShell Execution
index=powershell EventCode=4104
| search ScriptBlockText="*EncodedCommand*"


Why this matters:
Attackers commonly use encoded PowerShell commands to evade detection.

Detect PowerShell Process Creation
index=wineventlog EventCode=4688
| search NewProcessName="*powershell.exe*"


Why this matters:
Identifies suspicious PowerShell execution at the process level.

Identify Execution Policy Bypass
index=powershell EventCode=4104
| search ScriptBlockText="*ExecutionPolicy Bypass*"

🧠 Payload Analysis

Extracted Base64 encoded payload from logs

Decoded payload using PowerShell

Verified malicious execution intent

Confirmed use of IEX for script execution

🧩 MITRE ATT&CK Mapping
Technique ID	Technique Name
T1566	Phishing
T1059.001	Command and Scripting Interpreter – PowerShell
👨‍💻 SOC Analyst (L1) Responsibilities Performed

Monitored Splunk SIEM for endpoint alerts

Identified suspicious PowerShell activity

Analyzed Script Block Logs (Event ID 4104)

Correlated process creation logs (Event ID 4688)

Decoded encoded PowerShell payloads

Assessed attack impact and behavior

Documented findings and incident timeline

📂 Evidence & Documentation

A detailed incident report with screenshots is included, covering:

GoPhish campaign configuration

Phishing email delivery

User interaction evidence

PowerShell execution logs

Splunk alerts and investigation queries

📎 Full Incident Report (PDF):
👉 (Attach Google Drive link here)

✅ Outcome

Successfully simulated a phishing attack

Detected malicious PowerShell execution

Performed SOC-style investigation

Validated attacker techniques

Gained hands-on experience with Splunk SIEM detection workflows

📌 Key Takeaways

Phishing remains a primary initial access vector

PowerShell encoded commands are strong malicious indicators

Proper logging enables effective SOC investigations

SIEM correlation is critical for incident validation

🔐 Disclaimer

This project was performed strictly in a controlled lab environment for educational purposes only.
