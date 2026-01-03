# Phishing Attack Detection & Incident Investigation (SOC Lab)

## 📌 Overview
This project demonstrates an end-to-end phishing attack simulation and incident investigation performed in a SOC lab environment using Splunk SIEM.

A phishing email was delivered to a user, leading to suspicious PowerShell execution. The activity was detected, alerted, and investigated using SPL queries similar to a real SOC L1 workflow.

---

## 🛠 Tools Used
- GoPhish (Phishing Simulation)
- MailHog (SMTP Capture)
- Windows 10 Endpoint
- PowerShell Script Block Logging (Event ID 4104)
- Windows Security Logs (Event ID 4688)
- Splunk Enterprise SIEM

---

## 🧪 Attack Scenario
1. Phishing email sent using GoPhish
2. User clicks malicious link
3. PowerShell executed with encoded command
4. Suspicious activity logged on endpoint
5. Splunk SIEM detects and triggers alert
6. SOC investigation performed using SPL

---

## 🚨 Detection & Investigation
- Detected encoded PowerShell execution
- Correlated process creation and script block logs
- Extracted and decoded Base64 payload
- Mapped behavior to MITRE ATT&CK

**MITRE Techniques:**
- T1566 – Phishing
- T1059.001 – PowerShell

---

## 🔍 Sample SPL Queries
```spl
index=powershell EventCode=4104
| search ScriptBlockText="*EncodedCommand*"

index=wineventlog EventCode=4688
| search NewProcessName="*powershell.exe*"
