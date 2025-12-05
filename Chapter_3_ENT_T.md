# Reviewing Basic Networking Concepts

Networks carry data using a series of **protocols** that define how to encode data (**bits and bytes**) into physical signals (electrical, radio waves, light pulses).

## OSI Model – The Theoretical Foundation

The **Open Systems Interconnection (OSI) model** is a theoretical framework describing all activities on a network, organized into **seven layers**. The lower the layer number, the closer to the physical hardware; the higher the number, the closer to the end-user software.

> **Memory Trick:** Use a mnemonic like "**P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way" to remember the order (Physical to Application). 

| Layer # | Name | Primary Function & Components | Security+ Focus |
| :---: | :--- | :--- | :--- |
| **L7** | **Application** | Provides network services directly to **applications**. | End-user interface. |
| **L6** | **Presentation** | Handles **data translation** into a standard format; includes **encryption** and compression. | Data transformation. |
| **L5** | **Session** | **Establishes, manages, and terminates sessions** between communicating applications. | Communication management. |
| **L4** | **Transport** | Provides **end-to-end communication** services. Primary protocols: **TCP** and **UDP**. | Reliable/unreliable transmission. |
| **L3** | **Network** | Handles routing between different local networks (**inter-network**) using **IP addresses**. Primary device: **Router**. | Routing/IP addressing. |
| **L2** | **Data Link** | Handles routing on the **local network** using **MAC addresses**. Primary device: **Switch**. Formats data into **frames**. | Local addressing/Switches. |
| **L1** | **Physical** | Basic network equipment: wires, cables, radio waves. | Physical media. |

> **Key takeaway**: Security and network professionals use layer numbers (e.g., "**Layer 3 problem**") to describe where an issue exists (e.g., routing, switching, or application).

## Basic Networking Protocols

**Networking protocols** provide the rules for communication over a network. The **TCP/IP** suite is a collection of protocols, with some (like TCP and IP) providing basic connectivity and others (like HTTP, SMTP) supporting specific traffic types.

> **Note**: While CompTIA has deemphasized specific port numbers, you still need to know them for implementing **ACLs** in **stateless firewalls** and **routers**.

| Protocol | Layer | Function/Description | Security Relevance |
| :--- | :--- | :--- | :--- |
| **TCP** (Transmission Control Protocol) | L4 (Transport) | **Connection-oriented traffic** (guaranteed delivery). Uses a **three-way handshake** (SYN, SYN/ACK, ACK). | Ensures reliable data transfer. |
| **UDP** (User Datagram Protocol) | L4 (Transport) | **Connectionless sessions** (no handshake). Provides **best effort delivery** without guaranteed delivery. | Used by many **DoS attacks** because of its connectionless nature. |
| **IP** (Internet Protocol) | L3 (Network) | Identifies hosts using **IP addresses** and handles traffic delivery between hosts. **IPv4** (32-bit, dotted decimal) and **IPv6** (128-bit, hexadecimal). | The foundation for network addressing and routing. |
| **ICMP** (Internet Control Message Protocol) | L3 (Network) | Tests basic connectivity using tools like **ping** and **tracert**. | Often blocked at firewalls/routers because it is heavily used in **DoS attacks** and for network device discovery (**scanning**). |
| **ARP** (Address Resolution Protocol) | L2 (Data Link) | Resolves **IPv4 addresses to MAC addresses** (physical/hardware addresses). Required once a packet reaches its destination subnet. | Prone to **ARP poisoning attacks** (gives clients false MAC updates to redirect traffic). |

### TCP Three-Way Handshake
To establish a **TCP** session (connection-oriented):
1. Client sends **SYN** (synchronize).
2. Server responds with **SYN/ACK** (synchronize/acknowledge).
3. Client completes with **ACK** (acknowledge) to establish the connection.

> **Remember**: IP addresses handle routing *between* networks; **MAC addresses** handle delivery *to the correct host* on the local subnet, via **ARP**.

## Implementing Protocols for Use Cases

IT professionals enable specific **protocols** to meet organizational goals and security needs.

### Data in Transit Use Cases

**Data in transit** is traffic sent over a network. **Confidentiality** is protected by **encryption**. Data sent in **cleartext** (unencrypted) can be easily read by an attacker using a **packet capture** tool.

| Protocol | Purpose | Port(s) | Status | Secure Alternative |
| :--- | :--- | :--- | :--- | :--- |
| **FTP** (File Transfer Protocol) | Uploads/downloads files. | 21 (Control) | **Insecure**: Transmits data in **cleartext**. | **SFTP** or **FTPS** |
| **TFTP** (Trivial FTP) | Transfers small data amounts, often with network devices. | 69 (UDP) | **Insecure**: Commonly disabled due to security risks. | **SFTP** or **SCP** |
| **SSL** (Secure Sockets Layer) | Secured HTTP (HTTPS) and other traffic. | Various | **Compromised**: Vulnerable to **POODLE attack**. **Prohibited** by many organizations. | **TLS** |

#### Secure Alternatives for Data in Transit
* **TLS** (Transport Layer Security): The designated, recommended **replacement for SSL**. Used to encrypt various protocols, including HTTPS.
* **IPsec** (Internet Protocol Security): Used to **encrypt IP traffic** (covered in Chapter 4).
* **SSH** (Secure Shell): Encrypts traffic in transit; can secure other protocols. Uses **TCP port 22**.
* **SCP** (Secure Copy): Based on **SSH**; copies **encrypted files** over a network. Uses **TCP port 22**.
* **SFTP** (Secure FTP): Secure implementation of FTP; an **extension of SSH** that encrypts file transfers. Uses **TCP port 22**.
* **FTPS** (FTP Secure): Secure implementation of FTP; uses **TLS** to encrypt FTP traffic.

### Email and Web Use Cases

Originally built without security, these services now have secure alternatives that provide **encryption**.

| Protocol | Purpose | Unencrypted Port | Secure Protocol/Port |
| :--- | :--- | :--- | :--- |
| **SMTP** (Simple Mail Transfer Protocol) | Transfers email **between servers and clients**. | 25 (TCP) | **SMTPS** (TLS encryption): **587 (TCP)** |
| **POP3** (Post Office Protocol v3) | Transfers email **from server to end user** (downloads email). | 110 (TCP) | **POP3** (TLS encryption): **995 (TCP)** |
| **IMAP** (Internet Message Access Protocol) | **Stores email on server**; allows organization/management. | 143 (TCP) | **IMAP** (TLS encryption): **993 (TCP)** |
| **HTTP** (Hypertext Transfer Protocol) | Transmits **web traffic** between servers and browsers. | 80 (TCP) | **HTTPS** (TLS encryption): **443 (TCP)** |

#### Enhancing Email Security (Authentication)
These methods verify sender authenticity and prevent fraud:
* **SPF** (Sender Policy Framework): Uses **DNS records** to define which **IP addresses** are authorized to send email for a domain.
* **DKIM** (DomainKeys Identified Mail): Uses **public key cryptography** to digitally **sign** and verify an email's domain and content.
* **DMARC** (Domain-based Message Authentication, Reporting, and Conformance): Builds on SPF and DKIM, allowing domain owners to set **policies** for emails that fail authentication and provides **reporting**.
* **Email Gateways**: Network devices or software that **filter** incoming/outgoing emails for **spam** and **malware**.

### Directory Use Cases

**Directory services** (like Microsoft **Active Directory Domain Services** - AD DS) streamline management and provide **authentication** and **authorization**.

* **LDAP** (Lightweight Directory Access Protocol): Specifies the formats and methods to **query directories** (e.g., AD DS). Uses **TCP port 389**.
* **LDAPS** (LDAP Secure): Encrypts data with **TLS** when querying the directory. Uses **TCP port 636**.
* Windows domains and Unix realms rely on **LDAP** for directory queries.

### Voice and Video Use Cases

Live voice and video streaming commonly use **UDP** instead of TCP due to its connectionless (faster) nature.

* **RTP** (Real-time Transport Protocol): Delivers **audio and video over IP networks** (e.g., **VoIP**, streaming media).
* **SRTP** (Secure Real-time Transport Protocol): Provides **encryption**, **message authentication**, and **integrity** for RTP transmissions.
* **SIP** (Session Initiation Protocol): Used to **initiate, maintain, and terminate** voice, video, and messaging sessions. Uses **text-based messages** (metadata) that are readable if captured.
    * **SIP Logging**: Records metadata (**equipment, IP addresses, timestamps**) useful for detecting SIP-based attacks and forensics.

### Remote Access Use Case

Personnel often access systems remotely for administration.

* **Telnet**: **Insecure** protocol historically used for remote administration; sends data and credentials in **cleartext**. **Not recommended**.
* **SSH** (Secure Shell): The **recommended replacement for Telnet**; encrypts traffic. (Uses **TCP port 22**).
* **RDP** (Remote Desktop Protocol): Used to connect to other systems (e.g., Windows servers/desktops) from remote locations. Uses **TCP port 3389**.
* **Virtual Private Network (VPN)**: Another method for supporting secure remote access (covered in Chapter 4).

#### OpenSSH
**OpenSSH** is a suite of tools simplifying the use of **SSH**, **SCP**, and **SFTP**.
* Supports **passwordless SSH login** using a **public/private key pair**.
* **ssh-keygen -t rsa**: Command used to create the **key pair** (e.g., `id_rsa.pub` is public key, `id_rsa` is private key).
* **ssh-copy-id**: Command used to copy the **public key** to the remote server for authentication.
* The **private key** must remain secret.

### Time Synchronization Use Case

Systems require close time synchronization (e.g., **Kerberos** authentication requires systems to be within five minutes of each other).

* **NTP** (Network Time Protocol): Most commonly used protocol for **time synchronization**, often synchronizing time to within milliseconds.
* Within a domain (like Microsoft), a reliable Internet server running **NTP** is used as the primary source.

### Network Address Allocation Use Case

Refers to allocating **IP addresses** to hosts.

* **DHCP** (Dynamic Host Configuration Protocol): Dynamically assigns **IP addresses**, **subnet masks**, **default gateways**, **DNS server addresses**, etc., to hosts.

#### IPv4
* Uses **32-bit IP addresses** (dotted decimal format).
* **Public IP addresses** are controlled (purchased/rented).
* **Private IP addresses** (defined by **RFC 1918**) are reserved for internal networks; routers on the Internet drop traffic from these ranges:
    * `10.0.0.0` through `10.255.255.255`
    * `172.16.0.0` through `172.31.255.255`
    * `192.168.0.0` through `192.168.255.255`

#### IPv6
* Uses **128-bit IP addresses** (hexadecimal format). Created by IETF to solve IPv4 address exhaustion.
* Uses **unique local addresses** (starting with `fc00`) instead of private IP addresses for internal networks.

### Domain Name Resolution Use Case

The primary purpose of **DNS** is **domain name resolution** (resolving **hostnames to IP addresses**).

* DNS servers host data in **zones** (databases), containing various **records**.

| Record Type | Purpose | Lookup Type |
| :--- | :--- | :--- |
| **A** | Hostname to **IPv4 address**. Most common record (**forward lookup**). | Forward |
| **AAAA** | Hostname to **IPv6 address**. | Forward |
| **PTR** | **IP address to hostname** (**pointer record**). Used for **reverse lookups**. | Reverse |
| **MX** | **Mail exchange**; identifies a mail server for email. Lowest preference number is primary. | Forward |
| **CNAME** | **Canonical name** or **alias**; allows a single system to have multiple names. | Forward |
| **SOA** | **Start of Authority**; includes zone settings, such as **TTL** (Time to Live). | N/A |

#### DNSSEC
* **DNS poisoning** (or **DNS cache poisoning**) is a risk where an attacker modifies the DNS cache with a bogus IP address to redirect users to a malicious site.
* **DNSSEC** (Domain Name System Security Extensions): A suite of extensions that prevents DNS cache poisoning by providing **validation** for DNS responses.
* DNSSEC adds a **Resource Record Signature (RRSIG)** (a **digital signature**) to each record, providing **data integrity and authentication** for DNS replies.

# Understanding Basic Network Infrastructure

Any device with an **IP address** is a **host**, often referred to as a **client** or **node**.

| Addressing Type | Description | Use Case |
| :--- | :--- | :--- |
| **Unicast** | **One-to-one** traffic. One host sends traffic to a specific destination IP address. | Standard client-server communication. |
| **Broadcast** | **One-to-all** traffic on the subnet (using address like `255.255.255.255`). Every host processes the packet. | **Switches** pass broadcasts; **routers** do **not** pass broadcasts. |

## Switches

A **switch** connects hosts on a **local network** using their **MAC addresses**. It learns which MAC address is on which physical port and creates **internal switched connections** (unicast traffic).

### Security Relevance of Switches
* **Reduced Risk**: Unlike a **hub** (which sends traffic to all ports), a switch only forwards **unicast traffic** to the correct destination port.
* **Defense**: This prevents an attacker on a different port from capturing targeted unicast traffic with a **protocol analyzer**.

### Hardening Switches

**Hardening** a device means configuring it in a secure manner.

| Hardening Technique | Description | Security Goal |
| :--- | :--- | :--- |
| **Port Security** | Limits connections to physical ports. **Disable unused ports** to prevent unauthorized connection. | Blocks rogue devices from accessing the network. |
| **MAC Filtering** | Switch remembers/allows only specific **MAC addresses** per port. Advanced: Restrict a port to a **single, specific MAC address**. | Ensures only authorized devices can connect. |
| **Broadcast Storm & Loop Prevention** | Prevents **switching loop** or **bridge loop** problems (e.g., two switch ports connected). Loops flood the network and disable the switch. | Prevents DoS/disruption. Achieved using **STP** (Spanning Tree Protocol) or **RSTP** (Rapid STP). |
| **BPDU Guard** | Monitors **edge ports** (connected to hosts/printers) for unwanted **BPDU** messages (used by STP). If received, the port is **disabled**. | Blocks attacks attempting to disrupt STP (BPDU attack). |

> **Remember**: A physical port is where you plug in a cable; a **logical port** is a number (e.g., 80, 443) embedded in a packet identifying a service or process.

## Routers

A **router** connects multiple **network segments** and routes traffic between them using **IP addresses**. Routers separate **broadcast domains**, reducing traffic on individual segments.

### Hardening Routers

#### Router Access Control Lists (ACLs)
**ACLs** are rules implemented on routers and firewalls to perform **rule-based management**, identifying what traffic is **allowed** and what is **denied**.

ACLs filter traffic based on:
* **IP addresses/Networks**: Block traffic from single IPs or entire subnets.
* **Ports**: Filter traffic based on **logical ports** (e.g., blocking TCP port 443 for HTTPS).
* **Protocols**: Filter traffic based on the protocol (e.g., ICMP).

#### Implicit Deny
* The essential security principle that states: all traffic that is **not explicitly allowed is implicitly denied**.
* It is the **last rule** in an ACL (e.g., `DENY ANY ANY`).
* It provides a **secure starting point** or **default deny** posture.

> **Remember**: **Routers** and **stateless firewalls** perform basic filtering using **ACLs**. **Implicit deny** is the final rule to block all ungranted access.

#### Route Security
* The `route` command is used to display or modify a system’s **routing table**.
* Verifying the routing table prevents **on-path attacks** where an attacker modifies the table to reroute traffic through a malicious router (**default gateway**).

#### Simple Network Management Protocol (SNMP)
* **SNMP** monitors and manages network devices (routers, switches).
* **SNMP agents** send status information (**SNMP traps**) to an **SNMP manager**.
* **SNMPv1** and **SNMPv2** send credentials in **cleartext**.
* **SNMPv3** **encrypts credentials** and provides **secure management** of network devices. Uses **UDP ports 161** and **162**.

## Firewalls

A **firewall** filters incoming and outgoing traffic for a single host or between networks. It acts as a barrier, using **implicit deny** as a starting point.

| Type | Protection Scope | Implementation | Layer Focus |
| :--- | :--- | :--- | :--- |
| **Host-Based Firewall** | Protects a **single host** (server or workstation). | Software-based (e.g., Microsoft Defender Firewall). | L7-L1 |
| **Network-Based Firewall** | Protects an **entire network**. | Dedicated **network appliance** (hardware or virtual). Controls traffic at the network border. | L7-L1 (depending on type) |

> **Defense-in-Depth**: Use **host-based** and **network-based** firewalls together.

### Firewall Types by Function

| Type | Description | Layer Focus | Security Features |
| :--- | :--- | :--- | :--- |
| **Stateless Firewall** | Uses **ACLs** only; treats each packet as a **new event**; does **not** track session context (**state**). | L3/L4 | Basic packet filtering (IP, Port, Protocol). |
| **Stateful Firewall** | Inspects traffic based on its **state** (context) within an established session. Blocks traffic without a proper session (e.g., without a TCP handshake). | **Layer 4** (Transport) | Tracks session status, blocks suspicious session-level traffic. |
| **WAF** (Web Application Firewall) | Specifically protects a **web application** (placed between client and web server). | **Layer 7** (Application) | Blocks web attacks (e.g., **XSS attacks**). Provides protection *in addition* to network firewalls. |
| **NGFW** (Next-Generation Firewall) | Advanced firewall that adds **deep-packet inspection** and **application-level inspection** (Layer 7). | **Layer 7** (Application) | Detects application commands, content filtering, URL filtering, intrusion detection features. |

### Failure Modes

Security systems designers must choose how a system behaves when it fails:

* **Fail-Open System**: Allows **everything to pass through** when it fails. Network activity is uninterrupted, but **security controls are not enforced** (High risk).
* **Fail-Closed System**: Allows **nothing to pass through** when it fails. Security policies are not violated, but there is a **significant disruption to network activity** (Preferred by security professionals).

# Implementing Network Designs

Creating a secure network involves using various **topologies** and **network appliances** to achieve **segmentation** and **isolation**. This limits connectivity and reduces the **attack surface**.

## Security Zones

Networks are often divided into **security zones** with defined boundaries and access rules.

| Zone Term | Description | Purpose |
| :--- | :--- | :--- |
| **Intranet** | The **internal network**. Used for communication and resource sharing among internal users. | Internal communication and data sharing. |
| **Extranet** | Part of the network accessible by **authorized external entities** (e.g., business partners, vendors). | Limited, controlled access for approved outsiders. |
| **Perimeter** | The boundary between the intranet and the Internet; protected by **boundary protection** methods. | Delineates the secure internal space from the public Internet. |

### Screened Subnet (Demilitarized Zone - DMZ)

A **screened subnet**, or **demilitarized zone (DMZ)**, is a **buffer zone** between the **Internet** and the **internal network (Intranet)**.

* **Configuration**: Often uses **two firewalls (FW1 and FW2)**.
    * **FW1** separates the **DMZ from the Internet**.
    * **FW2** separates the **DMZ from the Intranet**.
* **Purpose**: Hosts **Internet-facing servers** (web, mail, CA, VPN servers) with high risk, while providing a layer of protection (**segmentation**) for the internal network.
* **Security Principle**: Internet clients can access services in the DMZ, but the DMZ provides a controlled choke point to protect the internal network resources (like a database server).

> **Example**: FW2 allows traffic only from the web server in the DMZ to the internal database server (e.g., on port 1433) while blocking all other Internet traffic.

## Network Address Translation Gateway

**Network Address Translation (NAT)** translates public IP addresses to private IP addresses and vice versa. A **NAT gateway** (often a router or firewall) provides internal clients using private IPs a path to the Internet.

* **Common Form**: **Port Address Translation (PAT)**, which is a form of NAT that also uses port numbers.

| NAT Benefit | Description |
| :--- | :--- |
| **IP Conservation** | Fewer **public IP addresses** need to be purchased, as many internal clients share one or a few public IPs. |
| **Security/Hiding** | **Hides internal computers** with **private IP addresses** from direct access/attack from the Internet. |

> **Drawback**: NAT is generally **incompatible with IPsec** (VPN encryption).

| NAT Type | Mapping | Public IP Usage |
| :--- | :--- | :--- |
| **Static NAT** | **One-to-one mapping**. A single private IP is permanently mapped to a single public IP. | Single public IP used for one internal host. |
| **Dynamic NAT** | **One-to-many mapping**. Uses multiple public IP addresses and assigns one based on **load**. | Multiple public IPs used for many internal hosts. |

## Physical Isolation and Air Gaps

**Physical isolation** ensures one network is **not connected** to another network, significantly reducing risk.

* **SCADA Systems**: **Supervisory Control and Data Acquisition** systems (industrial control systems) are often **physically isolated** from all other networks.
* **Air Gap**: Provides the highest level of physical isolation by ensuring there is a **physical gap of air** (no cables) between the isolated system and other systems.
    * **Use Case**: Highly sensitive environments (e.g., classified networks) use air gaps.

## Logical Separation and Segmentation

Segmentation divides traffic based on logical (rather than physical) groups.

* **Traditional Segmentation**: **Routers** (using subnets and ACLs) and **Firewalls** segment traffic.

### Isolating Traffic with a VLAN

A **Virtual Local Area Network (VLAN)** uses switches to group computers into a **virtual network** based on **logical needs** (department, project, function) instead of physical location.

* **Benefit**: Provides **logical separation** and isolates traffic between different groups.
    * Example: Separating HR traffic and IT traffic on the same physical switch using two different VLANs.
* **Traffic Segmentation**: Used to separate different types of traffic (e.g., **VoIP traffic** on one dedicated VLAN and **data traffic** on a separate VLAN) to increase **availability and reliability**.

#### Traffic Direction Terminology
* **East-West Traffic**: Traffic that flows **between servers** (horizontally) within a data center or network segment.
* **North-South Traffic**: Traffic that flows **between clients** (above/below) **and servers**.

## Network Appliances

**Network appliances** are dedicated systems or services designed to fulfill a specific network need with simplicity (like a toaster). They are often vendors' dedicated hardware devices.

### Proxy Servers (Forward Proxy)

A **proxy server** (or **forward proxy**) is positioned at the network edge (between the intranet and the Internet) to forward requests from internal clients. 

| Function | Description | Security/Performance Benefit |
| :--- | :--- | :--- |
| **Caching Content** | Stores (caches) results from the Internet (e.g., webpages) in **temporary storage** (RAM/disk). | Improves **performance** and reduces **Internet bandwidth** usage. |
| **Content Filtering** | Examines user requests against security/content policies (e.g., **URL filtering** using subscription lists). | **Restricts access** to malicious or inappropriate websites using **block rules**. |
| **Logging** | Records each site visited by users. | Monitors user web browsing activities and aids in security investigations. |

#### Proxy Server Types

| Type | Description |
| :--- | :--- |
| **Transparent Proxy** | Accepts and forwards requests **without modifying** them. |
| **Non-transparent Proxy** | **Filters content** and applies policies, often presenting a warning page to the user if access is restricted. |

> **Centralized vs. Agent-Based**: Most proxying is **centralized** on a strategic network appliance, but content filtering can also be done via a local **agent** on the user's computer.

### Reverse Proxy

A **reverse proxy** accepts requests from the **Internet** on behalf of internal servers, shielding the servers from direct external access. 

* **Location**: Placed on the network edge, often in the **DMZ** or behind the first firewall, protecting the web server which can then be located deeper in the private network.
* **Mechanism**: It appears to the client as the web server, retrieves content from the real web server (or a **web farm**), and forwards the response back to the client.
* **Benefits**:
    * **Security**: Hides the real web server's IP address and protects it from direct attacks.
    * **Performance**: Caches content just like a forward proxy.
    * **Load Balancing**: Can distribute incoming Internet requests to a farm of multiple web servers (acting as a **load balancer**).
 
## Unified Threat Management (UTM)

**Unified Threat Management (UTM)** is a single security appliance that **combines multiple security controls** to simplify management while providing comprehensive protection. This makes it particularly popular for smaller organizations with limited IT staff and budgets.

### Core Concept: Feature Consolidation

UTMs address the complexity of managing many separate security solutions (firewalls, anti-virus, proxies) by merging them into one device.

### Integrated Security Capabilities

A typical UTM appliance includes the functionality of several dedicated systems:

| UTM Component | Function | Security Goal |
| :--- | :--- | :--- |
| **Firewall** | Provides basic packet filtering and stateful inspection. | Controls network flow. |
| **URL Filtering** | Blocks access to malicious or undesirable websites based on the URL (same job as a **proxy server**). | Enforces content policies and prevents access to known bad sites. |
| **Malware Inspection** | Scans incoming data streams (web, email) for known **malware** and blocks the infection payload. | Protects systems from infection. |
| **Content Inspection** | Monitors data streams using filters (like **spam filters**) to block specific content (e.g., streaming media, certain file types like zip files). | Controls data flow and blocks unwanted transmissions. |
| **DDoS Mitigator** | Detects and attempts to block **Distributed Denial of Service (DDoS)** attacks. | Ensures **availability** of network services. |

### Placement

A UTM is commonly placed at the **network border** (between the Internet and the intranet) to analyze all incoming and outgoing traffic. If used as a proxy, clients are configured to direct their traffic to the UTM's proxy service.

## Jump Server (Jump Box)

A **jump server** (or **jump box**) is a **hardened server** used as an intermediary device to access and manage systems located in a different **security zone**.

### Function and Security Role

* **Access Control:** It acts as a controlled gateway, providing the **only authorized path** for administrators to access a high-security or isolated zone (e.g., a **screened subnet/DMZ** or a network with a **SCADA system**).
* **Isolation:** The jump server sits between the two zones. Administrators connect to the jump server first, and then, from the jump server, they connect to the target server (e.g., a database or CA server).

### Hardening Requirements

Because the jump server is the critical link between security zones, it must be highly secured:

* **Dedicated Use:** Ideally, it should be dedicated to management access only and **not used for anything else** (i.e., minimal services running) to reduce the attack surface.
* **Target Restrictions:** The target systems (e.g., servers in the DMZ) should be configured to **only accept connections** from the **jump server's IP address**, restricting all other connections from the internal network.
* **Connection Method:** Connections often use secure protocols like **SSH** (Secure Shell), sometimes leveraging passwordless login and the `-J` switch for TCP forwarding.

> **Remember:** A **jump server** provides secure, controlled access from devices in one zone (e.g., the intranet) to manage devices in another zone (e.g., the DMZ).

## Zero Trust Network Access (ZTNA)

The **Zero Trust Network Access (ZTNA)** philosophy replaces the old model of **implicit trust** (trusting devices inside the network perimeter). ZTNA is necessary because remote work and cloud services have blurred the lines between "inside" and "outside."

* **Core Principle**: **Do not trust based on network location.** Access decisions are based on the **user's identity** and **policy-driven access controls**, regardless of where the system is located.
* **Goal**: **Threat scope reduction** (decreasing risk).
* **Trust Decisions**: Based on **adaptive identity authentication**, where the required authentication level (e.g., MFA) changes based on the context (location, device, etc.).

### Zero Trust Architecture Components

Zero Trust environments logically separate network communications into two distinct planes: the **Control Plane** and the **Data Plane**. 

#### 1. Control Plane (Decision Making)

This network handles communications used to control and configure the network. Together, the PE and PA form the **Policy Decision Point (PDP)**.

| Component | Role | Function |
| :--- | :--- | :--- |
| **Policy Engine (PE)** | **The Decision Maker** | Decides whether to **grant, deny, or revoke access** to a resource based on enterprise policy. |
| **Policy Administrator (PA)** | **The Communicator** | Communicates the PE's decision to the enforcement tool on the network. |

#### 2. Data Plane (Work Execution)

This network contains the systems that carry out the work of the organization and enforces the policy.

| Component | Role | Description |
| :--- | :--- | :--- |
| **Subject** | User/System | The entity requesting access to a resource. |
| **Enterprise Resource** | Target | The file, server, or service the subject wishes to access. |
| **Policy Enforcement Point (PEP)** | **The Enforcer** | The system (e.g., gateway) that **enforces** the PE's decision on the traffic. It sits at the boundary between the Control Plane and the Data Plane. |

## Secure Access Service Edge (SASE)

**Secure Access Service Edge (SASE)** is a broader **design philosophy** that builds upon ZTNA. It brings together networking and security functions and delivers them as an integrated **cloud service**.

SASE is an integrated approach that adds several additional cloud-delivered security services, including:

* Firewall services
* Secure web gateway services
* Intrusion prevention services
* Cloud access service broker (CASB) services
* Data loss prevention (DLP) services
