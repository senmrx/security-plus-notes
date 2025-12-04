# Exploring Authentication Management

## Identification & Authentication Basics

**Identification:** Claiming an identity (username, email, ID number).

**Authentication:** Proving the claimed identity (password, PIN, fingerprint, certificate).

**Credentials = identification + authentication method.**

**Real-world analogy:**  
Saying “I’m Darril Gibson” (identification) → showing driver’s license (authentication).

Authentication applies not only to humans but also:
- services  
- servers  
- devices  
- websites (e.g., digital certificates used by web servers)

## AAA – Authentication, Authorization, Accounting

AAA works with identification to manage access:
- **Authentication** – Prove identity (password/PIN/biometric).
- **Authorization** – What you’re allowed to access after authentication.
- **Accounting** – Logging of what you did (audit trails).

**Key Reminder:**  
If attackers bypass authentication, authorization & accounting become useless.

## Authentication Factors

CompTIA recognizes four factors:
- **Something You Know** – password, PIN  
- **Something You Have** – smart card, token, phone  
- **Something You Are** – biometrics  
- **Somewhere You Are** – geolocation/IP  

**Note:** Most security pros consider only the first three as true strong factors. Location is a weak factor unless combined with others.

## Something You Know (Passwords & PINs)

### Best Practices (NIST SP 800-63B)
- Hash all passwords.
- Require MFA.
- Don't force frequent password resets (unless compromise suspected).
- Minimum 8 characters.
- Check against known weak/common passwords.
- Allow all special characters (even spaces).
- Discourage reuse across multiple sites.

### Password Length & Complexity
Longer = stronger.

Complexity often requires at least 3–4 character sets:
- Uppercase  
- Lowercase  
- Numbers  
- Special characters  

### Password Expiration
- Older policy: change every 60–90 days.
- **Modern best practice:** NO expiration unless MFA is used AND no breach detected.

### Password History & Reuse
- Prevents users from reusing old passwords.
- Often stores last 24 passwords.
- Usually paired with minimum password age (e.g., 1 day).

### Password Managers
- Store credentials in encrypted vaults.
- Reduce password fatigue and encourage strong, unique passwords.
- Examples: Chrome Password Manager, standalone vault apps.

### Knowledge-Based Authentication (KBA)
Two types:

**Static KBA**  
- Pre-set security questions (weak security).  
- Used for account recovery.

**Dynamic KBA**  
- Questions generated from external data (credit report, property records).  
- Used for high-risk transactions.

**Identity Proofing** – verifying a real person before issuing an account (used during onboarding).

### Account Lockout Policies
Protect against brute-force attacks.

Key settings:
- **Lockout threshold** – # of incorrect attempts allowed.  
- **Lockout duration** – how long lockout lasts (0 = admin must unlock).

### Changing Default Passwords
- Always change default vendor passwords (common in routers, IoT, apps).
- Also change default **Administrator** account name to reduce attacks.

### User Training
Users must be trained to:
- Create strong passwords.
- Never reuse the same password across systems.
- Never share passwords.
- Understand risk of common passwords (“123456”).

## Something You Have (Physical Items)

### Smart Cards
Contain:
- Embedded certificate  
- Private key  
- Public Key Infrastructure (PKI) support  

Used for:
- Digital signatures  
- Encryption  
- System login  
- Physical access  

Often paired with a PIN → **two-factor authentication**.

### Security Keys
- Physical key-fob devices (e.g., YubiKey) with cryptographic functions.

### Hardware Tokens (Hard Tokens)
- Small device with LCD screen showing OTP (one-time password).
- Usually a new number appears when the user presses a button.

### Software Tokens (Soft Tokens)
- App on phone generating OTPs (e.g., Google Authenticator).

## HOTP vs. TOTP

| Feature       | HOTP        | TOTP                |
|---------------|-------------|---------------------|
| Based on      | Counter     | Time                |
| Expires?      | Only after use | Yes (30–60 seconds) |
| How triggered?| Button press | Automatic refresh   |

Both are open-source standards.

### SMS / Push Notifications
- **SMS:** sends a code to user’s phone (**NOT recommended by NIST** due to SIM hijacking & message preview on lock screen).
- **Push Notifications:** user approves login request via app.

## Something You Are (Biometrics)

Biometric authentication = **strongest single-factor option.**

### Biometric Types
- Fingerprint  
- Vein pattern recognition  
- Retina scan (intrusive, may reveal medical info)  
- Iris scan (preferred)  
- Facial Recognition  
- Voice Recognition  
- Gait Analysis (used for identification, can be passive)

> **Remember This:**
> - **Iris & retina scans = strongest biometric methods.**
> - Iris preferred for privacy and non-intrusiveness.
> - Facial + gait = useful for passive identification (casinos, border crossings).

## Biometric Efficacy Terms

Possible outcomes:
- **True Accept**  
- **True Reject**  
- **False Accept** (security risk)  
- **False Reject** (usability issue)

Key Metrics:
- **FAR (False Acceptance Rate)**
- **FRR (False Rejection Rate)**
- **CER (Crossover Error Rate)** – where FAR = FRR; **lower CER = better system**.

## Somewhere You Are (Geolocation Factor)

The **somewhere you are** authentication factor identifies a user’s **location**.

**Geolocation** is the most common method, typically determined by an IP address. An IP address can reveal:
- Country  
- Region  
- State  
- City  
- Sometimes ZIP code  

**Example:**  
A virtual assistant in India attempted to log in to an account created for them in Hootsuite. Hootsuite detected the login attempt from India, blocked the login, and emailed the account owner for verification. This shows automated geolocation-based protection.

### Impossible Travel Time / Risky Logins
Systems can detect suspicious activity based on unrealistic travel speed.

**Example:**  
Lisa logs in from Springfield, and one minute later someone logs in to her account from another country. This is impossible without teleportation → flagged as suspicious.

### Limitations (VPNs)
Geolocation via IP is **not foolproof**.

VPNs can mask a user’s real location.  
Example: A user in Russia can route traffic through a U.S. VPN server, so the website only sees a U.S. IP.

### Internal Network Location Controls
Organizations can restrict logins using:
- **Computer name**
- **MAC address**

Example:  
Active Directory can restrict a user account so they can only log in from a specific workstation. If they try from another system → access is blocked.

## Two-Factor and Multifactor Authentication

**Two-factor authentication (2FA)** uses **two different authentication factors**, such as:
- Soft token (**something you have**) + password (**something you know**)  
- Fingerprint (**something you are**) + PIN (**something you know**)  
- Security key (**something you have**) + retinal scan (**something you are**)  

### Important Clarification
Using two methods from the **same factor** is **not** two-factor authentication.

Examples:
- Password + reusable PIN → both are **something you know** → **single-factor**
- Thumbprint + retina scan → both are **something you are** → **single-factor**

> **Remember This:**
> - Using two or more methods **in the same factor** = **single-factor authentication**  
> - **Two-factor authentication** = two **different** factors  
> - **Multifactor authentication (MFA)** = two or more factors  
> - MFA ⊃ 2FA (MFA includes 2FA but can go beyond it)

## Passwordless Authentication

Organizations are moving toward passwordless authentication because:
- Users dislike passwords  
- Passwords are often insecure  
- Password reuse is widespread  

**Passwordless authentication** removes passwords entirely and replaces them with:
- **Something you have**  
- **Something you are**  

Examples include:
- Security keys  
- Biometrics  

> **Remember This:**
> Passwordless ≠ MFA  
> Passwordless can still be single-factor (e.g., a fingerprint alone).

## Authentication Log Files

Authentication logs track:
- **Successful login attempts**
- **Unsuccessful login attempts**

Most important to monitor:
- **Privileged accounts** (administrators)

### Integration With SIEM
Logs are typically sent to a SIEM for:
- Alerting  
- Correlation  
- Threat detection  

### Log Entry Data
Authentication logs help determine:
- **What happened:** login success or failure  
- **When it happened:** timestamp  
- **Where it happened:** IP address or computer name  
- **Who or what did it:** user account involved  

# Managing Accounts

Account management is concerned with creating, managing, disabling, and terminating accounts. When the account is active, access control methods are used to control what the user can do. Additionally, administrators use access controls to control when, where, and how users can log on. The following sections cover common account management practices and some basic principles used with account management.

An important concept to remember when creating accounts is to give users only the account permissions they need to perform their job, and no more. Chapter 11, “Implementing Policies to Mitigate Risks,” covers the principle of least privilege, emphasizing this in more depth.

## Credential Policies and Account Types

Credential policies define login policies for different personnel, devices, and accounts. This includes items in the something you know factor (such as passwords) or any other factor or combination of factors. It’s common for an organization to apply credential policies differently to different types of accounts. The following list identifies different account types and credential policies associated with each:

- **Personnel or end-user accounts.** Most accounts are for regular users or the personnel working in the organizations. Administrators create these accounts and then assign appropriate privileges based on the user’s job responsibilities. It’s common to assign a basic credential policy that applies to all personnel. This could be a password policy defining things like the minimum password length, password history, and account lockout policies.

- **Administrator and root accounts.** Administrator and root accounts are privileged accounts that have additional rights and privileges beyond what a regular user has. Strong authentication methods, such as multifactor authentication, are required. Privileged access management (PAM) applies additional controls to protect these accounts.

- **Service accounts.** Applications and services sometimes need to run under the context of an account, and a service account fills this need. Credential policies may require long, complex passwords for these accounts, but they should not expire.

- **Device accounts.** Computers and devices have accounts, though it isn’t always apparent. Active Directory manages these automatically.

- **Third-party accounts.** These are accounts from external entities with access to a network. Strong credential policies should be enforced.

- **Guest accounts.** These allow temporary or very limited access. They are commonly disabled unless needed for special cases.

- **Shared and generic account/credentials.** Temporary workers may use shared accounts, though they are discouraged for normal work. Basic credential policies apply.

## Privileged Access Management

Privileged access management (PAM) allows an organization to apply strict controls over accounts with elevated privileges such as administrator or root accounts. PAM implements **just-in-time permissions**, meaning administrators only receive elevated privileges when needed and only for a limited time.

> **Remember This:**
> Privileged access management (PAM) systems implement stringent security controls over accounts with elevated privileges such as administrator or root-level accounts. Some capabilities include allowing authorized users to access the administrator account without knowing the password, logging all elevated privilege usage, and automatically changing the administrator account password.

PAM systems also store administrative account passwords in a vault, often without any human ever seeing the password. PAM systems can also issue **temporal accounts**, temporary admin-level accounts that are destroyed when no longer needed.

**Some capabilities of PAM include:**

- Allow privileged access without knowing the password  
- Automatically rotate privileged account passwords  
- Limit the time privileged accounts can be used  
- Allow users to check out credentials  
- Log all credential access  

If an attacker gains admin access, they can do almost anything. PAM reduces the opportunities for attackers and increases monitoring and visibility.

## Requiring Administrators to Use Two Accounts

Administrators are commonly required to have two accounts:

1. A **standard user account** for daily tasks  
2. An **elevated privileged account** only for administrative actions  

This reduces the attack surface and the chance of privilege escalation. Malware running on a system with an admin logged in inherits elevated rights. Using a standard account for normal activity prevents this risk.

> **Remember This:**
> Requiring administrators to use two accounts—one with administrator privileges and one with regular user privileges—helps prevent privilege escalation attacks. Users should not use shared accounts.

## Prohibiting Shared and Generic Accounts

Policies often prohibit shared accounts. When several users share one account, you lose:

- **Identification**  
- **Authentication**  
- **Authorization**  
- **Accounting**  

For example, if multiple users log in using the same Guest account, you cannot track who performed which actions.

> **Remember This:**
> Shared accounts break identification, authentication, authorization, and accounting. Unique accounts maintain proper audit trails.

## Deprovisioning

Deprovisioning is the process of disabling an account when an employee leaves the organization. Accounts are typically **disabled immediately**, often automatically when HR updates their status.

Disabling accounts is preferred over deleting them at first, because deleting an account deletes associated encryption keys, which may be needed.

**Account disablement policies commonly include:**

- **Terminated employee:** Disable account ASAP  
- **Leave of absence:** Disable account during the leave  
- **Account deletion:** Delete after a defined inactive period (e.g., 60–90 days)

> **Remember This:**
> Disable accounts rather than delete them to retain access to encrypted data and associated security keys. Deleting an account permanently removes keys.

## Time-Based Logins

Time-based logins (time-of-day restrictions) restrict when users can log on. For example, a company may allow logins only between 6:00 a.m. and 8:00 p.m., Monday through Friday.

If users are logged in when the restriction begins, they are not forced off the system, but new connections are blocked.

## Account Audits

An **account audit** evaluates user permissions to enforce least privilege and detect **privilege creep**—when users accumulate unnecessary permissions over time.

Organizations using role-based access control rely on group membership changes when employees change roles. Permission audits verify these changes are correctly applied.

Audits are typically performed at least annually.

**Attestation** is a formal process where managers certify that permissions are correct.

> **Remember This:**
> Usage auditing records user activity in logs and can re-create audit trails. Permission auditing ensures least privilege is followed and detects privilege creep.

# **Comparing Authentication Services**

## **Single Sign-On (SSO)**  
Single sign-on allows users to authenticate **once** and then access multiple systems without re-authenticating.  
- Reduces password fatigue (one set of credentials).  
- Reduces likelihood of users writing passwords down.  
- Uses a **secure token** created during login, reused for authentication across sessions.  
- Requires **strong authentication** — if an attacker compromises a single SSO account, they gain access to multiple systems.  
- SSO is powerful because it integrates with many OSs, apps, and services for identity, authentication, authorization, and accounting.

## **LDAP**  
**Lightweight Directory Access Protocol (LDAP)** is heavily used in SSO environments.  
- Allows systems to query directory services (e.g., Active Directory) for user and device information.  
- Acts as a central repository of user accounts and organizational objects.  
- Windows domains rely on LDAP for directory queries.  

## **SSO and Federation**  
Some SSO systems allow authentication to span **different organizations or different operating systems**. This is done using **federated identity management**.

A **federation**:  
- Links identity management of separate organizations without merging networks.  
- Uses a **federated database** to coordinate shared authentication information.  
- Treats a user’s credentials from multiple networks as **one unified identity**.

**Example:**  
Springfield Nuclear Power Plant employees can access Springfield School System resources without creating school accounts or logging in twice — the networks are separate but federated.

A federation requires:  
- A federated identity management system  
- Agreement on identity standards  
- A method to exchange identity information securely  

## **SAML (Security Assertion Markup Language)**  
SAML is an **XML-based standard** used for **web-based SSO**.  
- Commonly used with web portals where one login grants access to multiple partner sites.  
- Allows authentication to be passed from one trusted organization to another.

### **SAML Roles**
1. **Principal**  
   - The user (e.g., Homer).  
   - Logs in once and requests access to services.

2. **Identity Provider (IdP)**  
   - Authenticates the user and manages identity data.  
   - Could be an employer, school system, or third party.

3. **Service Provider (SP)**  
   - The system providing the service or web application.  
   - Trusts the IdP and checks with it before granting access.

The XML messages used between IdP and SP are not visible to the user.

> **Remember This:**  
> **SAML** is an **XML-based** standard used to exchange authentication and authorization data between organizations. It provides **web-based SSO**.

## **SAML and Authorization**  
SSO deals with **identification and authentication**, not authorization.  
- SSO does **not** automatically give users access to everything once logged in.  
- Authorization must still be configured separately.  

However, many SSO federation systems (including SAML) **can pass authorization data** between systems.

## **OAuth**  
OAuth is an **open standard for authorization** — NOT authentication.  
- Allows a user to let one service access protected data on another service **without sharing their login credentials**.  
- Commonly used by Google, Facebook, Microsoft, etc.

**Example:**  
Doodle wants access to your Google Calendar.  
- You do not give Doodle your Google password.  
- Instead, Google shows a popup asking whether you want to grant Doodle access.  
- OAuth issues a token that grants only the specified permissions.

> **Remember This:**  
> **OAuth = authorization**, not authentication. The “Auth” stands for **authorization**.

# Authorization Models

Access control ensures that only authenticated and authorized entities can access resources. This starts by ensuring that users are accurately identified and authenticated, then granting access using one of several authorization models:

- Role-based access control (RBAC)
- Rule-based access control
- Discretionary access control (DAC)
- Mandatory access control (MAC)
- Attribute-based access control (ABAC)

Understanding these models helps explain why access policies work the way they do.

## Key Terms

- **Subjects:** Users, groups, or services that request access to objects.
- **Objects:** Resources such as files, folders, shares, printers.

## Role-Based Access Control (RBAC)

RBAC uses roles to manage permissions. Administrators assign rights to roles, and users inherit those rights when added to the role.

### Using Roles Based on Jobs and Functions

Organizations often create roles mapped to departments (e.g., Accounting, Sales, IT). Assigning users to these roles grants them appropriate access.

Example: Microsoft Project Server roles:

- Administrators
- Executives
- Project Managers
- Team Members

### Documenting Roles with a Matrix

RBAC implementations often use a permissions matrix that maps roles to privileges.

RBAC may be:

- **Hierarchy-based**
- **Job-, task-, or function-based**

> **Remember This:**  
> A role-based access control scheme uses roles based on jobs and functions. A roles and permissions matrix is a planning document that matches the roles with the required privileges.

### Establishing Access with Group-Based Privileges

Administrators commonly implement RBAC using security groups. Permissions are assigned to groups, and users inherit group privileges.

> **Remember This:**  
> Group-based privileges reduce the administrative workload of access management. Administrators put user accounts into security groups and assign privileges to the groups. Users automatically inherit the group's privileges.

## Rule-Based Access Control

Rule-BAC uses rules defined in ACLs or application logic.

- Routers and firewalls use static ACL rules.
- Some systems use dynamic rules (e.g., IPS blocking an attacker).
- Applications may trigger rules based on events (e.g., granting extra permissions when someone is absent).

> **Remember This:**  
> Rule-based access control is based on a set of approved instructions, such as an access control list. Some rule-BAC systems use rules that trigger in response to an event.

## Discretionary Access Control (DAC)

In DAC, **objects have owners**, and owners determine access.

### Filesystem Permissions

NTFS permissions include:

- Write  
- Read  
- Read & execute  
- Modify  
- Full control  

If a permission is not explicitly allowed, access is denied (implicit deny).

### SIDs and DACLs

Objects contain a **DACL** listing ACEs. Each ACE includes a SID and granted permissions.

> **Remember This:**  
> The DAC scheme specifies that every object has an owner, and the owner has full, explicit control of the object. Microsoft NTFS uses the DAC scheme.

## Mandatory Access Control (MAC)

MAC uses **security labels** assigned to subjects and objects. Access is granted only if labels match.

Used heavily in government/military.

### SELinux Modes

- **Enforcing:** Enforces MAC policy  
- **Permissive:** Logs what would be denied  
- **Disabled:** Ignores MAC policy  

Multiple meanings of MAC:

- Media access control (MAC) address  
- Mandatory access control  
- Message authentication code  

### Labels and Lattices

A lattice defines clearance levels (Top Secret, Secret, Confidential). Access requires appropriate clearance + need to know.

> **Remember This:**  
> The MAC scheme uses sensitivity labels for users and data. It is commonly used when access needs to be restricted based on a need to know. Multiple approval levels are usually involved in determining access.

## Attribute-Based Access Control (ABAC)

ABAC evaluates **attributes** (user, resource, environment) to grant access based on policies.

Example attributes: employee, inspector, nuclear aware.

Common in Software-Defined Networks (SDNs).

ABAC policies use four elements:

- **Subject**
- **Object**
- **Action**
- **Environment**

> **Remember This:**  
> The ABAC scheme uses attributes defined in policies to grant access to resources. It’s commonly used in software-defined networks (SDNs).

# Analyzing Authentication Indicators

Authentication systems provide a rich source of information for cybersecurity analysts looking for signs of potentially malicious activity. Sometimes the signs of this activity are buried in otherwise innocent-looking log entries. Some of the key things to look for when reviewing authentication logs include:

- **Account lockouts.** Watch for user accounts that have been locked out due to repeated failed login attempts, as those failed logins may be a sign of malicious activity.

- **Concurrent session usage.** If the same user is logged in to the same (or different) systems from different locations at the same time, that may indicate that more than one person is using the account.

- **Impossible travel time.** If a user completes a login from one location and then logs in from another geographic location without sufficient time to travel between those locations, this may indicate two users sharing the same account.

- **Blocked content.** If content filters begin screening out unusual levels of malicious code, that’s worthy of further investigation.

- **Resource consumption.** Excessive processor time, memory, storage, or other resource use without explanation may indicate malicious code running on the system.

- **Resource inaccessibility.** If services suddenly become unavailable, malicious activity may be interfering with them. For example, a website may go down because of malicious code running on the web server.

- **Log anomalies.** If logging levels are abnormal — such as log entries appearing at strange times or log files going missing — this may be an indicator of malicious activity.

Cybersecurity analysts should always watch for emerging indicators of compromise by monitoring cybersecurity news sources and staying aware of new malicious techniques.

> **Remember This:**  
> Authentication logs can reveal indicators of malicious activity, such as account lockouts, concurrent sessions, impossible travel, blocked content, resource issues, or log anomalies. Analysts should stay alert to new indicators of compromise.
