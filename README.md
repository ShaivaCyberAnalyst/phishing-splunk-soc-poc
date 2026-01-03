# Phishing Attack Detection & Incident Investigation (SOC Lab)

## 📌 Overview

This project demonstrates an end-to-end phishing attack simulation and SOC investigation performed in a controlled lab environment using Splunk SIEM.

A phishing email was delivered to a user, leading to suspicious PowerShell execution with encoded commands. The activity was detected, alerted, and investigated using SPL queries, replicating a real-world SOC Level 1 workflow.

---

## 🎯 Objectives

- Simulate a realistic phishing attack scenario  
- Detect malicious PowerShell activity  
- Perform SOC-style alert triage and investigation  
- Correlate endpoint logs to validate attacker behavior  
- Document findings as a professional incident report  

---

## 🛠 Tools & Technologies

- GoPhish – Phishing campaign simulation  
- MailHog – SMTP capture and email testing  
- Windows 10 Endpoint  
- PowerShell Script Block Logging (Event ID 4104)  
- Windows Security Logs (Event ID 4688)  
- Splunk Enterprise SIEM  

---

## 🧪 Attack Scenario

1. Phishing email created and sent using GoPhish  
2. Email delivered to the user via MailHog  
3. User clicked the phishing link  
4. PowerShell executed with EncodedCommand  
5. Endpoint logs generated  
6. Logs forwarded to Splunk SIEM  
7. Suspicious activity detected and investigated  

---

## 🚨 Detection & Investigation

### Indicators Observed

- PowerShell executed with EncodedCommand  
- Use of ExecutionPolicy Bypass  
- Script execution using IEX  
- Multiple suspicious PowerShell executions  

---

## 🔍 SPL Queries Used

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

🧬 Payload Analysis

During the investigation, encoded PowerShell commands were extracted and analyzed to validate malicious intent.
Steps Performed

    Identified Base64-encoded payload from PowerShell Script Block Logging (Event ID 4104)

    Extracted the EncodedCommand value from Splunk logs

    Decoded the payload using PowerShell

    Reviewed decoded content for suspicious behavior

Decoding Command Used

$enc="<Base64_String>"
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String($enc)
)

Analysis Outcome

    Obfuscated PowerShell execution confirmed

    Behavior consistent with phishing-based initial access

    No legitimate administrative activity identified

🧠 MITRE ATT&CK Mapping
Technique ID	Technique Name
T1566	Phishing
T1059.001	PowerShell
📄 Incident Summary (SOC View)

    Initial Vector: Phishing Email

    Execution Method: Encoded PowerShell Command

    Detection Source: Splunk SIEM

    Severity: Medium

    Impact: Suspicious command execution

✅ Conclusion

This Proof of Concept demonstrates a complete SOC Level 1 investigation lifecycle, including phishing simulation, endpoint detection, SPL-based investigation, payload decoding, MITRE mapping, and professional incident documentation.
📂 Notes

    Conducted in a controlled lab environment

    No production systems or real users involved

👤 Author

Shaiva Kumar
SOC Analyst (L1) | SIEM | Incident Response | Blue Team
