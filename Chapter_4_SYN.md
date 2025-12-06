## Advanced Security Devices

### Intrusion Detection Systems (IDS)

IDSs are **detective security controls** that monitor systems or network traffic and send **alerts** upon detecting suspicious events. They do *not* prevent attacks.

| Type | Acronym | Location / Scope | Key Limitations |
| :--- | :--- | :--- | :--- |
| **Host-based** | **HIDS** | Installed directly on a **single system** (server/workstation). | Can't monitor network traffic beyond its own NIC. |
| **Network-based** | **NIDS** | Sensors placed on network devices (switches, routers, firewalls). Reports to a central console. | Cannot decrypt and monitor **encrypted traffic**. Cannot monitor activity on **individual hosts** unless it causes network traffic. |
| **Placement** | N/A | Sensors can be placed before or after firewalls, or using **port mirroring (port spanning)** or **network taps** on switches/routers to capture all traffic.  | Where placed determines what traffic is seen (e.g., placing after a firewall only sees what the firewall permits). |

### Detection Methods (IDS & IPS)

Both IDSs and IPSs use the same two primary methods for identifying malicious activity:

1.  **Signature-Based Detection (Definition-based):**
    * Uses a database of **known vulnerabilities** or attack patterns (e.g., specific packet sequences).
    * Effective against **known attack types** (like a specific SYN flood pattern).
    * Requires **regular updates** from the vendor to protect against current threats.
2.  **Trend-Based Detection (Anomaly-based or Heuristic-based):**
    * Identifies the network's **normal behavior** by creating a **performance baseline**.
    * Compares current traffic against the baseline and alerts when activity **deviates significantly**.
    * Effective at discovering **zero-day exploits** (vulnerabilities unknown to the vendor, thus lacking a signature).

| Term | Description |
| :--- | :--- |
| **SYN Flood Attack** | DoS attack where the attacker sends many **SYN** packets but never completes the **TCP three-way handshake** (by sending the final ACK), consuming server resources. |

### Alert Validation and Error Types

Security professionals must **validate** IDS/IPS alerts, looking for four possible outcomes: 

| Response | Condition | Description | Desirability |
| :--- | :--- | :--- | :--- |
| **False Positive** | Alert triggers, but **no actual attack** exists. | Increases administrator workload ("cries wolf"). | Undesirable. |
| **False Negative** | Attack exists, but the system **fails to alert**. | Attack gets through undetected. | Highly Undesirable. |
| **True Positive** | Alert triggers, and an **attack exists**. | Correctly identified threat. | Desirable. |
| **True Negative** | No alert triggers, and **no attack exists**. | Correctly determined clean traffic. | Desirable. |
| **Thresholds** | Settings are adjusted to minimize **false positives** while reducing the risk of **false negatives**. | | |

### Intrusion Prevention Systems (IPS)

An **IPS** is an extension of an IDS that performs the same detection but adds the capability to **react to and prevent attacks**.

| Feature | IPS (Intrusion Prevention System) | IDS (Intrusion Detection System) |
| :--- | :--- | :--- |
| **Primary Role** | **Preventive Control**. Detects, reacts, and **stops** attacks. | **Detective Control**. Monitors and sends **alerts** (does not prevent). |
| **Deployment** | **In-line** (or **Active**). All traffic passes through the IPS. | **Out-of-band** (or **Passive**). Monitors traffic via a tap/mirror. |
| **Components** | **HIPS** (Host-based) and **NIPS** (Network-based, most common). | **HIDS** (Host-based) and **NIDS** (Network-based). |
| **Key Capability** | Inspects packets and **blocks malicious packets** before they reach the network.  | Can sometimes modify ACLs or divert traffic, but only *after* the attack has begun. |

### Honeypots and Deception

These tools are designed to **deceive attackers**, divert them from live networks, and allow security personnel to gather intelligence on attacker methodologies (including **zero-day exploits**).

| Tool | Purpose | Example |
| :--- | :--- | :--- |
| **Honeypot** | A single server designed to look like an easy, sweet target (sloppily secured) with bogus data. | A fake web server with fabricated credit card files. |
| **Honeynet** | A **group of honeypots** within a separate network or zone (often virtual servers) that mimics a live network. | A virtualized subnet containing a web server, email server, and database server. |
| **Honeyfile** | A file designed to attract attention by its name (e.g., `passwords.txt`) to lure the attacker. | |
| **Honeytoken** | A fake, easily detectable record (e.g., a unique email address or customer ID) inserted into a **production database** to detect if data theft has occurred. | If the fake email receives spam, the database was stolen. |

## Securing Wireless Networks

### Wireless Access Points (AP) and Routers

* A **Wireless Access Point (AP)** connects wireless clients to a wired network.
* A **Wireless Router** is an AP with additional capabilities, specifically **routing** (and often NAT, PAT, and DHCP).
    * **All wireless routers are APs, but not all APs are wireless routers.**
* Most wireless routers include **physical ports** (RJ-45) for wired clients and a **wireless transceiver** for wireless clients. 

### Wireless Basics and Signals

* Wireless networks operate on two primary radio bands: **2.4 GHz** and **5 GHz**.
    * **2.4 GHz:** Signals travel the **farthest** but offer less bandwidth.
    * **5 GHz:** Offers the **widest bandwidth** (highest data transfer) but the shortest distance.
* **Channel Overlap:** Within both bands, channels overlap. Using an overlapping channel can **impact network efficiency**.

### Basic Wireless Security Measures (Weak Controls)

These practices are generally recommended but can be easily defeated by a determined attacker.

| Measure | Description | Security Context |
| :--- | :--- | :--- |
| **SSID** (Service Set Identifier) | The wireless network name. | Change the default SSID name (e.g., "Linksys") to deny attackers clues about the AP vendor and potential specific vulnerabilities. |
| **MAC Filtering** | Allows or blocks wireless access based on the client's **48-bit MAC address**. | **Insecure.** An attacker can use a **wireless sniffer** to discover an allowed MAC address and then **spoof (clone)** that MAC address to bypass the filter. |
| **MAC Cloning Attack** | An attacker changes their system's MAC address to impersonate an authorized client's MAC address, bypassing MAC filtering. | |

### Wireless Survey and Mapping

| Tool / Process | Description | Purpose |
| :--- | :--- | :--- |
| **Site Survey** | A process performed during planning and periodically repeats to examine the wireless environment. | Identifies potential issues, noise, channel conflicts, and security problems. |
| **Wi-Fi Analyzer** | A tool used to identify and analyze activity levels on channels within the wireless spectrum. | Helps troubleshoot interference and select optimal channels. |
| **Heat Map** | A color-coded graphical representation of wireless signal strength and coverage. | Shows where signals are the strongest (hotspots) and weakest (**dead spots**). |
| **Wireless Footprinting** | Creating a detailed diagram by overlaying the heat map onto an architectural drawing. | Gives a visual layout of AP locations, hotspots, and dead spots. |

### Access Point Antennas

* **Omnidirectional Antenna:** The most common antenna type. Transmits and receives signals **in all directions** simultaneously.
* **Directional Antenna:** Transmits and receives signals in a **single direction**. Has **greater gain** and can transmit over longer distances due to focused power.

## Wireless Cryptographic Protocols

### The Evolution of Wireless Security

The early protocols **WEP** and **WPA** are **deprecated (obsolete)** due to known vulnerabilities and should **not be used**. Current security relies on WPA2 and WPA3.

| Protocol | Standard | Encryption Protocol | Security Status |
| :--- | :--- | :--- | :--- |
| **WPA2** | IEEE 802.11i | **AES** and **CCMP** (Counter-mode/CBC-MAC Protocol) | **Strong** and currently widely used. |
| **WPA3** | Latest Generation | Uses enhanced encryption and **SAE** | **Strongest** and replacing WPA2. |

### WPA2 Operating Modes

WPA2 is configured to run in one of three modes, which dictate the level of authentication required:

| Mode | Authentication Requirement | Key Management | Security Context |
| :--- | :--- | :--- | :--- |
| **Open** | None | No encryption (cleartext). | **Insecure.** Turns off all WPA2 security features. |
| **PSK (Pre-Shared Key)** | Anonymous (No individual user authentication). | Users share a single, static passphrase. | Used in most **home networks**. Provides authorization but lacks strong authentication. |
| **Enterprise** | Individual user authentication is **required**. | Uses the **802.1X standard** (often implemented with a **RADIUS server**). | Used by larger organizations for strong, centralized authentication. |

### WPA2 Enterprise (802.1X / RADIUS)

The Enterprise mode provides strong authentication by integrating with a centralized server.

* **Process:** The Access Point (AP) forwards connection attempts to the **802.1X server** (usually a **RADIUS server**).
* **Authentication:** The user must provide **unique credentials** (username/password) to the RADIUS server. If successful, the server tells the AP to grant access.
* **Configuration:** Requires the AP to be configured with the **RADIUS server IP address**, **RADIUS port** (default 1812), and a **shared secret** (separate from the user's password).

### WPA3 Operating Modes

**WPA3** is the newest and most secure wireless protocol, replacing WPA2 with three enhanced modes:

1.  **Enhanced Open Mode:** Replaces the insecure WPA2 Open mode with **strong encryption** for unauthenticated users, allowing secure guest networks.
2.  **SAE (Simultaneous Authentication of Equals) Mode:** Replaces WPA2-PSK. It still uses a passphrase but adds **stronger security defenses** against password guessing and cracking attempts.
3.  **Enterprise Mode:** Also supported, using 802.1X/RADIUS for centralized, individual user authentication.

## Wireless Authentication Protocols

These protocols, often built on the **Extensible Authentication Protocol (EAP)** framework, are used by the **802.1X server (RADIUS)** to provide strong authentication in Enterprise wireless networks.

### EAP and Key Generation

* **EAP (Extensible Authentication Protocol):** An authentication **framework** providing general guidance for authentication methods.
* **Key Function:** EAP creates a **Pairwise Master Key (PMK)**, which is then used to generate a **Pairwise Transient Key (PTK)**. The PTK is the key used by the **AES-based CCMP** to encrypt all data transmitted between the devices.

### EAP Authentication Methods (Focus on Certificates)

The primary difference between the methods below is the requirement for **certificates** to establish the secure connection.

| Protocol | Certificate Requirement | Key Features | Security Context |
| :--- | :--- | :--- | :--- |
| **PEAP** (Protected EAP) | **Server Certificate Required.** (Client certificate is *not* required.) | Encapsulates and encrypts the EAP conversation within a **TLS tunnel**. Often implemented with **MS-CHAPv2**. | Adds security where physical security is weak. |
| **EAP-FAST** (Flexible Authentication via Secure Tunneling) | **No Certificates.** | Uses **PAC** (Protected Access Credential) instead of certificates. | Cisco-designed, secure replacement for LEAP. |
| **EAP-TLS** (Transport Layer Security) | **Server AND Client Certificates Required.** | One of the **most secure** EAP standards. | Requires a Public Key Infrastructure (PKI) to issue certificates. |
| **EAP-TTLS** (Tunneled TLS) | **Server Certificate Required.** (Client certificate is *not* required.) | Allows older, less-secure protocols (like **PAP**) to be used securely within a **TLS tunnel**. | Similar certificate requirement to PEAP. |

### RADIUS Federation

* **Concept:** Allows two or more entities (companies) to share the same identity management system using their **802.1X and RADIUS servers**.
* **Benefit:** Enables **Single Sign-On (SSO)** access to shared network resources for users of the federated organizations without needing to log on again.

## IEEE 802.1X Security

### Core Function of 802.1X

* **Definition:** **IEEE 802.1X** is a **port-based authentication protocol**.
* **Primary Role:** Requires users or devices to **authenticate** before they can gain access to a specific network port (physical RJ-45 jack) or a wireless Access Point (AP).
* **Security Control:** It acts as a gatekeeper, securing the authentication process and **blocking or restricting network access** if the client cannot authenticate. This is key to preventing **rogue devices** from connecting.
* **Usage:** Implemented in both **wired** and **wireless** networks (required for **WPA2/WPA3 Enterprise** mode).

### Implementation Details

| Component | Role | Function in 802.1X |
| :--- | :--- | :--- |
| **Authentication Protocol** | The set of rules used for ID checking. | Can use simple usernames/passwords or stronger **certificates** (e.g., EAP-TLS). |
| **Authentication Server** | The backend that verifies credentials. | Implemented as a **RADIUS** or **Diameter** server. |

### Advanced Use Cases

* **Wired Port Security:** Used to require authentication on **open RJ-45 wall jacks**, preventing any device from plugging in and gaining unauthorized access.
* **VLAN Integration:** The 802.1X server can direct unauthorized clients to a **restricted network segment** (e.g., a guest **VLAN**) while granting full access to authorized clients.
* **VPN Clients:** Can be used to authenticate **Virtual Private Network (VPN)** clients before they connect to the corporate network.

## AP Security & Captive Portals

### Controller and Access Point (AP) Security

| Security Measure | Description | Risk Mitigation |
| :--- | :--- | :--- |
| **Physical Security** | Placing APs in secure, inaccessible locations. | Prevents attackers from connecting unauthorized devices, collecting traffic, or physically **resetting the AP** to factory settings (removing all security). |
| **Cryptographic Protocols** | Using modern, strong encryption standards. | Always use **WPA2** or **WPA3**. **WEP** and **WPA** are **deprecated** and should not be used. |

### Captive Portals

A **captive portal** is a technical solution that forces clients using web browsers to complete a specific process—like agreeing to terms or logging in—before gaining access to the network.

| Use Case | Requirement / Action | Primary Goal |
| :--- | :--- | :--- |
| **Free Internet Access** | Requires users to agree to an **Acceptable Use Policy (AUP)**. | Provides legal coverage and ensures users understand usage rules. |
| **Paid Internet Access** | Requires users to log on with a paid account or enter credit card information. | Enables pay-as-you-go service and access control. |
| **Alternative to 802.1X** | Requires users to authenticate (username/password) before network access is granted. | A less expensive alternative to implementing a full **802.1X Enterprise** solution. |

## Wireless Attacks

Most Wi-Fi attacks can be mitigated by using strong protocols like **WPA2 (CCMP)** or **WPA3 (SAE)**. Using older protocols like WEP and WPA (especially using TKIP) leaves networks vulnerable.

### Wi-Fi Access & DoS Attacks

| Attack Type | Mechanism | Goal / Outcome | Defense Strategy |
| :--- | :--- | :--- | :--- |
| **Disassociation Attack** | Attacker sends a **spoofed disassociation frame** to the AP, forcing a client to disconnect and constantly re-authenticate. | **Denial of Service (DoS)** against a specific client. | Use strong WPA2/WPA3 protocols. |
| **WPS Attack** | **Brute-force attack** against the weak **eight-digit PIN** of **Wi-Fi Protected Setup (WPS)**. | Discovers the PIN quickly (hours) and uses it to obtain the WPA2 passphrase. | **Disable WPS** entirely. WPA3 is resistant to this attack. |
| **Rogue Access Point (Rogue AP)** | An **unauthorized AP** connected inside the network, often via an unsecured physical port (a **Shadow IT** issue). | **Sniffing:** Captures network traffic from the wired network and exfiltrates it wirelessly. | **Physical security** of wiring closets; **802.1X port authentication**; regular **wireless audits**. |
| **Evil Twin** | A **rogue AP** broadcasting the **same SSID** as a legitimate network (e.g., "Free Airport Wi-Fi"). | Tricks users into connecting to capture **credentials** (via bogus login pages) and session traffic. | Educate users; administrators use **site surveys** to locate rogue signals. |
| **Jamming Attack** | Attacker transmits **noise** or another radio signal on the same wireless frequency. | **Denial of Service (DoS):** Interferes with transmissions, degrading performance or preventing connection. | Change wireless channel; increase AP power (limited effectiveness). |
| **IV Attack** | Attacker exploits the reuse of the small **Initialization Vector (IV)** in **WEP** (24-bit). | **Key Cracking:** Uses **packet injection** to force IV reuse, rapidly cracking the WEP pre-shared key. | **Do not use WEP.** Use WPA2/WPA3. |
| **Wireless Replay Attack** | Attacker **captures** data (like an authentication handshake), **modifies** it, and **replays** it later to impersonate a party. | Bypassing authentication or re-sending malicious commands. | **WPA2 and WPA3 are resistant** due to security measures (like nonces) that prevent replay. |

### Reconnaissance and Auditing

| Activity | Platform | Purpose | Security Context |
| :--- | :--- | :--- | :--- |
| **War Driving** | Car, walking. | Looking for vulnerable wireless networks using a laptop and an antenna. | Used by **administrators** as part of a **wireless audit** to map the signal footprint and detect **rogue APs** or signals extending too far outside the building. |
| **War Flying** | Private plane or **drone**. | Similar to war driving but conducted from the air to scan for wireless networks over a larger area. | Drones are also used for **reconnaissance** (collecting pictures and network information). |

### Proximity & Bluetooth Attacks

| Attack Type | Technology | Mechanism | Outcome | Defense Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **NFC Eavesdropping** | **Near Field Communication (NFC)** (short-range payments/data sharing). | Attacker uses an enhanced NFC reader to capture data from another device's transaction. | **Unauthorized charges** or data theft. | Only share data in secure, controlled settings. |
| **RFID Sniffing/Cloning** | **Radio-Frequency Identification (RFID)** (asset tracking). | Sniffing captures data over the air; Cloning uses that data to create a **bogus tag**. | Stealing assets or bypassing inventory/access controls. | Use encryption on RFID systems where possible. |
| **Bluejacking** | **Bluetooth** (PANs). | Sending **unsolicited messages** (text, images, sound) to a nearby Bluetooth device. | Harmless annoyance/confusion. | Disable Discovery mode. |
| **Bluesnarfing** | **Bluetooth** | **Unauthorized access and theft** of information (contacts, email, calendar) from a Bluetooth device. | Data theft. | Ensure devices are **not in Discovery mode**; require **manual pairing acknowledgement**. |
| **Bluebugging** | **Bluetooth** | Gains full control over a phone, installs a **backdoor**, and allows the attacker to place calls, listen to conversations, and forward messages. | Full device compromise. | Require **manual pairing**; use **Faraday cages** (conductive metal lockboxes) to block signals. |

## Using VPNs for Remote Access

A **Virtual Private Network (VPN)** provides remote access to a **private network** over a **public network** (most commonly the Internet). This access is secured by **tunneling protocols** that **encapsulate and encrypt** the traffic. VPNs are a common target for attackers because they provide a direct access vector into the internal network.

### VPN Components

| Component | Description | Deployment Location |
| :--- | :--- | :--- |
| **VPN Server** | A server role on a standard server, suitable for supporting a few clients. | Often placed in the Screened Subnet (DMZ). |
| **VPN Concentrator** | A **dedicated, specialized device** for creating and managing VPNs. Supports **many clients** and offers high-performance encryption/authentication. | Placed in the **Screened Subnet** (DMZ). |
| **VPN Client** | Software on the user's remote device (e.g., laptop, phone) that initiates the secure tunnel. | End-user device. |

### Authentication (Remote Access VPN)

When a remote user initiates a connection (referred to as a **remote access VPN** or **direct access VPN**):

1.  The VPN server receives the user's credentials.
2.  The VPN server commonly forwards the credentials to a **RADIUS server** for primary authentication.
3.  The RADIUS server often passes the credentials to a directory service, such as an **LDAP server** (e.g., a Microsoft Domain Controller), for final validation.

### Tunneling Protocols

VPNs use different protocols to create the secure tunnel:

| Protocol | Protocol ID / Port | Key Features |
| :--- | :--- | :--- |
| **IPsec** (Internet Protocol Security) | **ESP (Protocol ID 50)**; **IKE (Port 500)** | Provides **authentication (AH)** and **encryption/confidentiality (ESP)**. Uses **Tunnel mode** to encrypt the entire IP packet, hiding internal network addresses. |
| **SSL/TLS** (Secure Socket/Transport Layer Security) | **Port 443** (e.g., SSTP) | Encrypts VPN traffic using the same port as web traffic, offering flexibility and easy firewall traversal (especially useful with NAT). **TLS** is the secure replacement for SSL. |
| **L2TP** (Layer 2 Tunneling Protocol) | N/A | Provides tunneling but **no encryption**. Must be paired with a protocol like **IPsec** to secure VPN traffic. |

### Tunnel Configuration

The configuration determines which traffic uses the encrypted tunnel:

| Tunnel Type | Traffic Encrypted | Security/Performance Trade-off |
| :--- | :--- | :--- |
| **Full Tunnel** | **All traffic** (Internet and private network) goes through the VPN tunnel. | **Higher Security:** Allows all traffic to be inspected by internal security devices (**UTM**) before reaching the Internet. **Slower** due to encryption overhead and indirect routing. |
| **Split Tunnel** | **Only traffic destined for the private network** is encrypted and tunneled. | **Faster Performance:** Internet traffic goes directly to the ISP. **Lower Security:** Leaves non-VPN traffic unprotected and bypasses corporate inspection. |

### VPN Deployment Models

| Model | Description | User Involvement |
| :--- | :--- | :--- |
| **Remote Access VPN** (Host-to-Gateway) | A single remote user establishes a secure connection to a VPN server on the corporate network. | **User-initiated** connection. |
| **Site-to-Site VPN** (Gateway-to-Gateway) | Connects two geographically separated corporate networks (e.g., HQ and remote office) using dedicated VPN servers as network gateways. | **Transparent** to end-users in both locations. |
| **Always-On VPN** | Automatically attempts to establish and maintain a VPN connection whenever the user's device or the site gateway is connected to the Internet. | **No user action** required after initial setup. |
| **HTML5 VPN Portal** | Allows users to connect to the VPN using their **web browser** (via TLS). Typically used for a small number of users accessing **limited resources** (e.g., a consultant accessing a VoIP PBX). | Very simple for the user but **resource intensive** for the server. |

## Network Access Control (NAC)

**Network Access Control (NAC)** is a security method that **inspects** computers and devices (**clients**) attempting to access a network and grants access only if they meet predetermined "health" conditions. This prevents vulnerable or infected clients from introducing risks to the private network.

### Host Health Checks

NAC ensures clients meet specific conditions before connecting. Common conditions checked include:

* **Client Firewall:** Must be enabled.
* **Operating System:** Must be up-to-date with all current patches and fixes.
* **Antivirus Software:** Must be installed, enabled, and have up-to-date signature definitions.

### NAC Process and Remediation

1.  **Inspection:** An **authentication agent** (or **health agent**) inspects the client and reports its status in a **Statement of Health**.
2.  **Access Decision:** If the client meets all health requirements, the NAC system grants it **full access** to the network.
3.  **Quarantine (Remediation):** If the client fails the health check (is "unhealthy"), the NAC system redirects it to a **remediation network** (or **quarantine network**).
4.  **Remediation:** The client uses resources on the remediation network (e.g., patch downloads, antivirus updates) to meet the health requirements and can then attempt to access the network again.

NAC can be used to inspect **VPN clients** and **internal clients** (e.g., mobile computers plugging into live wall jacks).

### NAC Agent Types

NAC systems use different methods to inspect clients:

| Agent Type | Description | Key Feature |
| :--- | :--- | :--- |
| **Permanent Agent** (Persistent) | Software that is **permanently installed** on the client device. | Used every time the client connects remotely. |
| **Dissolvable Agent** | Software that is **downloaded and runs temporarily** during the connection attempt. | Collects information, reports health status, and then **removes itself** (or is removed after the session ends). |
| **Agentless NAC** | Inspects the client **remotely** without installing any code (permanent or temporary). | Similar to a vulnerability scanner; useful for devices that cannot host an agent. |

## Authentication and Authorization Methods

**Authentication** verifies a user's identity, and **Authorization** determines the resources they can access. These methods are critical for securing VPNs and centralized network access.

### Legacy and Challenge/Response Protocols

| Protocol | Used With | Key Security Feature | Weakness / Notes |
| :--- | :--- | :--- | :--- |
| **PAP** (Password Authentication Protocol) | PPP (Point-to-Point Protocol) | Simple password authentication. | **Sends passwords in CLEARTEXT** across the network, making it highly susceptible to sniffing attacks. Used only as a last resort. |
| **CHAP** (Challenge Handshake Authentication Protocol) | PPP | **More secure than PAP.** Uses a **shared secret** and a **nonce** (number used once) from the server. | The client hashes the secret + nonce and sends the hash, **never sending the actual password** in plaintext. |

### Centralized AAA Protocols

**AAA Protocols** provide **Authentication** (identity verification), **Authorization** (access rights), and **Accounting** (tracking user activity). RADIUS, TACACS+, and Diameter are considered AAA protocols.

#### RADIUS vs. TACACS+

RADIUS and TACACS+ are the primary centralized services used by VPN concentrators and 802.1X systems to authenticate users by forwarding requests to a central server (often an LDAP server/Domain Controller).

| Feature | RADIUS (Remote Authentication Dial-In User Service) | TACACS+ (Terminal Access Controller Access-Control System Plus) |
| :--- | :--- | :--- |
| **Transport Protocol** | **UDP** (User Datagram Protocol - best-effort delivery) | **TCP** (Transmission Control Protocol - guaranteed delivery) |
| **Encryption** (Default) | Only the **password** is encrypted by default. | The **entire authentication process** is encrypted by default. |
| **Multi-Factor Support** | Can be used with **EAP** (RFC 3579) to encrypt entire sessions. | Uses **multiple challenges and responses** (suited for more robust authentication). |
| **Primary Use** | VPN and **802.1X/Wireless** authentication. | Network device access (routers/switches) and VPNs. Can interface with **Kerberos** (Microsoft AD). |

### Kerberos and AAA

* **Kerberos:** An authentication protocol used by Microsoft Active Directory. It provides strong **Authentication**, but does **not** provide Accounting services on its own, meaning it is **not** strictly an AAA protocol.
* **TACACS+ and Kerberos:** TACACS+ can interact with Kerberos, allowing a Cisco device (or other network device) to authenticate users within a Microsoft Active Directory environment.
