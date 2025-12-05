# Understanding Core Security

> **Keywords** are **bolded** for quick review.

## 1. CIA Triad – The Foundation

| Goal            | Purpose                                                                 |
|-----------------|-------------------------------------------------------------------------|
| **Confidentiality** | Prevent **unauthorized disclosure** – keep secrets secret. |
| **Integrity**       | Prevent **unauthorized alteration** – detect & stop tampering. |
| **Availability**    | Ensure **authorized access** when needed – systems stay up. |

## 2. Security Scenarios – Spot the Goal

Exam tip: every story-based question is testing **which CIA goal** is at risk or must be protected.

| Scenario Driver | Quick Clue | Typical Controls |
|-----------------|------------|------------------|
| **Confidentiality** | “Stop **leaks** / **eavesdropping**” | **Encryption**, **Access Controls** |
| **Integrity** | “Stop **changes** / **tampering**” | **Hashing** (SHA, MD5) |
| **Availability** | “Keep **online** / **recover fast**” | **Redundancy**, **Patching**, **Backups** |

## 3. How to Enforce Each Element

### 3.1 Ensure **Confidentiality**
- **Encryption** – scrambles data in transit & at rest (AES, TLS).  
- **Access Controls** trilogy:
  1. **Identification** – unique username.  
  2. **Authentication** – password, MFA.  
  3. **Authorization** – permissions, ACLs.

> **Remember**: encrypt **PII**, **email**, **DBs**, **mobile**.

### 3.2 Provide **Integrity**
- **Hashing** – fixed-length, one-way fingerprint.  
  - Sender creates **hash** ➜ Receiver re-hashes ➜ **Match = intact**.  
  - Common algos: **SHA-256**, **SHA-3**.  
- Use on **downloads**, **emails**, **files**, **logs**.

> **Remember**: different hash ➜ data **changed**.

### 3.3 Increase **Availability**
- **Redundancy / Fault-tolerance** – remove **Single Point of Failure (SPOF)**.
  - **RAID** (1, 5, 10) – disk redundancy.  
  - **Failover clusters** – redundant servers.  
  - **Load-balancers / NIC teaming** – network redundancy.  
  - **UPS & generators** – power redundancy.
- **Scalability** – manual add: **horizontal** (more nodes) vs **vertical** (bigger box).
- **Elasticity** – **auto**-scale cloud resources in/out.
- **Patching** – kill bugs before they crash the box.
- **Resiliency** – **self-heal** & **retry** vs 99.999 % uptime (costly).

## 4. Resource Availability vs. Security Constraints

- **Encryption** costs:
  - ↑ **60 % storage** overhead (example: 265 → 430 chars).  
  - ↑ **CPU / RAM** for encrypt/decrypt cycles.  
- **Business balance**: execs minimize **TCO** while meeting **security reqs**.

> **Takeaway**: apply **strongest** controls **only** where **risk** justifies **cost**.

---

# Introducing Basic Risk Concepts

> **Keywords** are **bolded** for quick review.

## 1. Risk Defined
- **Risk** = **likelihood** that a **threat** exploits a **vulnerability** ➜ **loss**  
- **Threat** = any event that can harm **CIA** (natural, human, insider, accidental).  
- **Vulnerability** = **weakness** (tech, config, human).  
- **Security Incident** = adverse event that negatively affects **CIA**.

## 2. Risk Mitigation
- **Risk Mitigation** = reduce **probability** or **impact** of risk.  
- Achieved via **controls / countermeasures / safeguards**.

| Threat Example | Mitigation Control |
|----------------|--------------------|
| **Disgruntled employee** | **Access controls** ➜ limit reach. |
| **Tornado / flood** | **BC/DR plans**, **geo-redundancy**. |
| **Malware** | **AV/EDR**, **patching**, **least privilege**. |

> **Remember**: you **can’t stop** most threats, but you **can shrink** vulnerabilities or blast radius

---

# Selecting Effective Security Controls

> **Keywords** are **bolded** for quick review.

Security controls reduce **risk** by protecting the **CIA triad**. Each control fits into:
- A **category** → *how* the control works  
- A **type** → *what goal* the control achieves  

Every control belongs to **at least one category** and **at least one type**.

## 1. Control Categories – *How the Control Works*

| Category | What It Means | Examples |
|----------|----------------|----------|
| **Technical** | Uses **technology** (hardware/software/firmware) to protect systems automatically | **Encryption**, **Antivirus**, **IDS/IPS**, **Firewalls**, **Least Privilege** |
| **Managerial** | **Administrative** controls defined in policy; manage & assess risk | **Risk assessments**, **Vulnerability assessments**, **Policies** |
| **Operational** | **People-driven** controls executed in daily operations | **Training**, **Config/Change mgmt**, **Media protection** |
| **Physical** | Controls you can **touch**; protect physical spaces | **Locks**, **Fences**, **Bollards**, **Mantraps**, **Lighting** |

> **Remember**: Technical = tech; Managerial = policy/admin; Operational = people; Physical = real-world barriers.

## 2. Technical Controls – *Tech that Reduces Risk*

- **Encryption** – protects confidentiality in transit & at rest.  
- **Antivirus / EDR** – detects & blocks malware.  
- **IDS / IPS** – monitor or block malicious activity.  
- **Firewalls** – restrict inbound/outbound traffic.  
- **Least Privilege** – users only get the access they need.

## 3. Managerial Controls – *Policy & Risk Management*

- **Risk assessments**  
  - **Quantitative** → $$$ values  
  - **Qualitative** → likelihood + impact  
- **Vulnerability assessments** – discover weaknesses & guide mitigation.

> **Remember**: Managerial controls are **documented** in written policies.

## 4. Operational Controls – *People Implement Them Daily*

- **Awareness & training** – stop phishing, maintain password hygiene, follow clean desk.  
- **Configuration management** – baselines, hardening, change management.  
- **Media protection** – secure backups, encrypt USB drives, control storage devices.

## 5. Physical Controls – *Real-World Barriers*

- **Locks**, **Fences**, **Mantraps**, **Guards**, **Lighting**, **Sensors**  
> Physical controls can also be **preventive** and **deterrent** (e.g., a locked door).

## 6. NIST SP 800 Series – *Control Frameworks*

- Published by **NIST** (U.S. Dept. of Commerce).  
- **SP 800-53** = the key reference for security + privacy controls.  
- Includes **20 control families** with hundreds of controls.  
- Earlier versions labeled controls as technical/managerial/operational — removed due to overlap.

> Interested in a career? SP 800-53 is worth reading.

## 7. Control Types – *What the Control Achieves*

| Type | Purpose | Examples |
|------|---------|----------|
| **Preventive** | Stop incidents before they occur | **Hardening**, **IPS**, **Account disablement**, **Guards**, **Training** |
| **Deterrent** | Discourage attacks or policy violations | **Warning signs**, **Login banners**, **Security guard presence** |
| **Detective** | Discover incidents **after** they occur | **Logs**, **SIEM**, **Audits**, **CCTV**, **Motion detection**, **IDS** |
| **Corrective** | Fix issues **after** an incident; restore CIA | **Backups**, **System recovery**, **Incident handling** |
| **Compensating** | Alternative control when primary isn’t available | **TOTP** instead of smart card |
| **Directive** | Provide **instructions** for expected behavior | **Policies**, **Standards**, **Procedures**, **Guidelines**, **Change mgmt** |

## 8. Examples of Each Type

### 8.1 **Preventive Controls**
- **Hardening** – remove defaults, patch, disable services.  
- **Training** – prevent social engineering success.  
- **Security guards** – block unauthorized entry.  
- **Account disablement** – kill accounts when employees leave.  
- **IPS** – blocks malicious traffic automatically.

### 8.2 **Deterrent Controls**
- **Warning signs** – “CCTV in use,” “Restricted area.”  
- **Login banners** – legal notice discouraging misuse.

### 8.3 **Detective Controls**
- **Log monitoring** – firewall, system, auth logs.  
- **SIEM** – correlation, alerts, trend analysis.  
- **Security audits** – permissions, configs, accounts.  
- **CCTV & motion detection** – record & detect events.  
- **IDS** – flags malicious traffic after it enters.

### 8.4 **Corrective Controls**
- **Backups & restore procedures**  
- **Incident response plans**

### 8.5 **Compensating Controls**
- Temporary **TOTP** when **smart cards** are not yet issued.

### 8.6 **Directive Controls**
- Written guidance: **policies**, **standards**, **procedures**, **guidelines**.  
- **Change management** – prevents accidental outages.

## 9. Combining Categories + Types

Controls almost always fit **multiple** labels.

| Example | Category | Type |
|---------|----------|------|
| **Firewall** | Technical | Preventive |
| **Encryption** | Technical | Preventive |
| **Fire suppression system** | Physical + Technical | Corrective / Preventive (depends on purpose) |
| **Change management** | Operational + Directive | Preventive |

> **Takeaway**: A control’s **category** describes *how* it works; its **type** describes *why* it exists.

---

# Logging and Monitoring

> **Keywords** are **bolded** for quick review.

Logging and monitoring provide visibility into **what happened**, **when**, **where**, and **by whom**. Logs create an **audit trail** that supports security investigations, detects incidents, and maintains compliance.

## 1. OS / Endpoint Logs – *Local System Activity*

Operating systems generate logs showing system activity, user actions, errors, and security events.

### 1.1 Windows Logs (Event Viewer)
Windows stores several types of logs under **Event Viewer**:

| Log | What It Records | Examples |
|------|-----------------|----------|
| **Security log** | Authentication, access attempts, and audited actions | Successful login, failed login, permission errors |
| **System log** | OS-level events | Startup/shutdown, driver failures, services starting/stopping |
| **Application log** | Events from installed apps | App warnings/errors, software failures |

> **Remember**: Security log = auth/activity; System log = OS health; Application log = app events.

### 1.2 Linux Logs
Linux stores logs in **/var/log/** and can be viewed using `cat`, `less`, or log viewers.

Common Linux logs:

| Path | Purpose |
|------|---------|
| **/var/log/syslog** or **/var/log/messages** | General system messages, mail, kernel, startup events |
| **/var/log/secure** | Authentication/authorization, SSH login attempts |

Example:  
```bash
cat /var/log/auth.log
```

## 2. Network Logs – Traffic & Security Events

Network devices generate logs that help detect intrusions, traffic anomalies, and connectivity issues.

### 2.1 Firewall Logs
- Track allowed and blocked traffic  
- Show source IP, destination IP, protocol, and action  
- Useful for identifying scans, intrusion attempts, and misconfigurations  

### 2.2 IDS/IPS Logs
- IDS: alerts on suspicious activity  
- IPS: alerts and blocks suspicious activity  
- Critical for identifying attacks such as scans, brute force, exploitation attempts.  

### 2.3 Packet Captures
- Protocol analyzers (Wireshark) capture raw network packets  
- Used during active investigations to reconstruct events  
- Provide deep visibility into protocols, payloads, and suspicious behavior  

## 3. Application Logs – Software-Level Activity

Many applications create their own logs outside the OS logs.

### 3.1 Web Server Logs (W3C Common Log Format)

Common fields include:
- **host** – IP or hostname of client  
- **user-identifier** – identity of requester  
- **authuser** – authenticated username  
- **date** – timestamp  
- **request** – actual HTTP request  
- **status** – HTTP response code  
- **bytes** – size of server response  

Useful for spotting attacks like directory traversal, brute forcing, or abnormal request patterns.

## 4. Metadata – Data About Data

Metadata describes how, when, and by whom data was created or modified.

Examples:
- **Email metadata** → routing path, mail servers, timestamps  
- **Image metadata (EXIF)** → GPS location, camera type, date/time  

Metadata is valuable during forensic investigations but often hidden from end users.

## 5. Centralized Logging & Monitoring

Reviewing logs on every device is impractical. Organizations centralize log collection for visibility, efficiency, and correlation.

## 6. SIEM Systems – Centralized Log Intelligence

A Security Information and Event Management (SIEM) tool centralizes:
- Collection  
- Aggregation  
- Analysis  
- Alerting  
- Reporting  

### 6.1 SEM vs. SIM

| Component | Role |
|----------|------|
| **SEM** | Real-time monitoring, alerting, response |
| **SIM** | Long-term storage, reporting, trend analysis |

### 6.2 Core SIEM Capabilities
- **Log collectors** – ingest logs from systems, apps, and devices  
- **Data inputs** – firewalls, routers, servers, proxies, IDS/IPS  
- **Log aggregation** – standardizes formats for analysis  
- **Correlation engine** – identifies patterns & suspicious activities  
- **Automated reports** – compliance and event reports  
- **User Behavior Analysis (UBA)** – detects unusual user activity  
- **Security alerts** – predefined and custom alert rules  
- **Automated triggers** – automatic actions (e.g., block IP after 5 failed logins)  
- **Time synchronization** – uses NTP to align timestamps across all systems  
- **Archiving** – moves older logs to offline storage  

## 7. Alert Tuning – Balance False Positives & False Negatives

Alerts must be tuned to avoid:

- **False positives** → harmless activity triggers an alert  
- **False negatives** → real attack not detected  

Example: Failed login threshold  
- Too low → every mistake triggers an alert  
- Too high → attackers may brute force undetected  

Goal: Find a threshold that maintains accuracy without alert fatigue.

## 8. SIEM Dashboards – Real-Time Visualization

Dashboards display meaningful real-time insights such as:
- Sensors feeding data to SIEM  
- Alerts from triggers  
- Correlation views showing linked events  
- Trends (e.g., login failures, traffic spikes)  

Large organizations show dashboards on big screens (NOCs).

## 9. Syslog – Standard Log Format

Syslog provides:
- Standard message format  
- Standard transport mechanism  

Used by most network devices and SIEMs.

Components:
- **Originators** – devices sending logs  
- **Collector** – server storing received logs  

Syslog defines how logs are sent, not how the collector stores or manages them.
