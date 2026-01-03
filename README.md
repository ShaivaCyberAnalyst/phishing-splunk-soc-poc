# Phishing Attack Detection & Incident Investigation (SOC Lab)

## Overview
This project demonstrates an end-to-end **phishing attack simulation and SOC investigation** performed in a controlled lab environment using **Splunk SIEM**.

A phishing email was delivered to a user, leading to **suspicious PowerShell execution with encoded commands**. The activity was detected, alerted, and investigated using SPL queries, simulating a **real-world SOC L1 workflow**.

---

## Objective
- Simulate a real phishing attack scenario  
- Detect malicious PowerShell execution  
- Perform SOC-style alert triage and investigation  
- Correlate endpoint logs using SIEM  
- Document findings as a professional incident report  

---

## Tools & Technologies
- GoPhish – Phishing campaign simulation  
- MailHog – SMTP email capture  
- Windows 10 – Victim endpoint  
- PowerShell Script Block Logging (Event ID 4104)  
- Windows Security Logs (Event ID 4688)  
- Splunk Enterprise SIEM  

---

## Attack Flow
1. Phishing email created and sent using GoPhish  
2. User receives phishing email  
3. User clicks the malicious link  
4. PowerShell executes an encoded command  
5. Endpoint generates security and PowerShell logs  
6. Logs are forwarded to Splunk SIEM  
7. Alert is triggered and investigation begins  

---

## Detection & Investigation

### Indicators Observed
- PowerShell executed with **EncodedCommand**
- Use of **ExecutionPolicy Bypass**
- Script execution using **IEX**
- Multiple suspicious PowerShell executions

---

## SPL Queries Used

### Detect Encoded PowerShell Execution
```spl
index=powershell EventCode=4104
| search ScriptBlockText="*EncodedCommand*"

Detect PowerShell Process Creation
index=wineventlog EventCode=4688
| search NewProcessName="*powershell.exe*"

Identify Execution Policy Bypass
index=powershell EventCode=4104
| search ScriptBlockText="*ExecutionPolicy Bypass*"
