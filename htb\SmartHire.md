# SmartHire Walkthrough

## Overview
SmartHire is a web application that integrates with MLflow for model training and prediction. The intended path is:

1. Register a normal user account
2. Log in and access the dashboard
3. Train a model through the CSV upload feature
4. Abuse MLflow model artifact handling to achieve remote code execution
5. Use the obtained shell to perform local privilege escalation

This write-up omits the target IP, attack IP, `user.txt`, and `root.txt` values as requested.

---

## Enumeration

Initial port scan showed only two interesting services:

- SSH on port 22
- HTTP on port 80

The web server redirected to `smarthire.htb`, so the first step was to add the proper hosts entry for the application and its MLflow subdomain.

The main page exposed:

- `/login`
- `/register`
- `/dashboard`
- `/predict`
- `/upload_hiring_data`
- `/model_info`

The dashboard source code revealed that the app uses:

- Flask sessions
- a per-user model name based on the company name
- MLflow for model storage and loading

---

## User Access

### 1. Register a user
The `/register` endpoint allowed account creation with:

- username
- company
- password

After registration, the app redirected to `/login`.

### 2. Log in
Logging in created a valid session and redirected to `/dashboard`.

### 3. Review the dashboard
The dashboard exposed the training workflow and the CSV format required for model training.

The page source also showed that `/upload_hiring_data` could be reached in two ways:

- multipart CSV upload
- JSON training payload

The model status endpoint returned the current user model name, but initially `model_info` was `null`.

### 4. Train a model
Create a CSV file with the required columns:

```csv
name,skills,experience,education,position_applied,previous_company
Alice,"Python, Machine Learning, SQL",48,Masters,Engineer,Corp
Bob,"Java, Spring, PostgreSQL",72,Bachelors,Developer,Inc
Carol,"JavaScript, React, Node.js",36,Bachelors,Full Stack Dev,StartupXYZ
```

Upload it using the session cookie:

```bash
curl -i -b cookies.txt -X POST http://smarthire.htb/upload_hiring_data \
  -F "file=@train.csv"
```

After this, the app registered a model version and exposed a model name like:

- `testco-XXXXXXXXXXXX-model`

### 5. Extract MLflow information
The model registry status showed that MLflow already had a run and artifact path. Querying MLflow returned the active run ID and confirmed the model artifact path:

- experiment ID `0`
- run ID `...`
- artifact path `model/python_model.pkl`

This is the key point for the code execution step.

---

## Remote Code Execution

The MLflow artifact path was writable through the MLflow artifacts API. The exploit abused pickle deserialization by replacing `python_model.pkl` with a malicious pickle payload.

### Exploit flow

1. Log in to SmartHire
2. Train a model so the MLflow artifact exists
3. Query MLflow for the latest run ID
4. Overwrite `python_model.pkl` with a malicious pickle
5. Trigger `/predict` so the model loads the payload

The reverse shell callback connected back successfully.

---

## Shell Access

After triggering prediction, a shell was obtained as the low-privileged web user.

From there, the following were observed:

- user home directory contained `user.txt`
- the account belonged to the `devs` group
- the MLflow service and tooling were installed locally

The `user.txt` flag was captured at this stage.

---

## Privilege Escalation

### 1. Check sudo permissions
The key sudo rule was:

```text
(root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

This meant the user could run the MLflow control script as root with arbitrary arguments.

### 2. Inspect the script
The script imported plugin modules dynamically from:

- `/opt/tools/mlflow_ctl/plugins/core`
- `/opt/tools/mlflow_ctl/plugins/dev`

The `dev` plugin directory was group-writable by `devs`, and the current user was part of that group.

### 3. Abuse Python module loading
Because the root-run script adds plugin directories to Python’s module search path, a malicious module placed in the writable `dev` plugin directory could be loaded by root.

### 4. Plant a SUID bash
A malicious `evil.pth` file was enough to execute code during Python startup/import handling. The payload copied `/bin/bash` to `/tmp/rootbash` and set the SUID bit:

```python
import os; os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
```

After running the root-owned MLflow control command, `/tmp/rootbash` existed with the SUID bit set.

### 5. Become root
Run the binary with `-p` to preserve privileges:

```bash
/tmp/rootbash -p
```

This yielded a root shell and allowed reading `root.txt`.

---

## Key Takeaways

- A normal user registration path was enough to reach the dashboard
- MLflow artifact management exposed a pickle deserialization vector
- The application’s model registry logic enabled RCE through a malicious model payload
- Sudo misconfiguration on the MLflow control utility enabled privilege escalation to root
- A writable plugin directory under a root-run Python script was the final escalation path

---

## Flags

- `user.txt` was obtained after the initial shell as the web user
- `root.txt` was obtained after privilege escalation to root
