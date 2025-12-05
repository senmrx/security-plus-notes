# Protocol and Port List Grouped by Function

| Category | Protocol | Port(s) | Type | Security Status / Context |
| :--- | :--- | :--- | :--- | :--- |
| **Web Traffic** | **HTTP** | 80 | TCP | **Insecure** (Cleartext) |
| | **HTTPS** | **443** | TCP | **Secure** (Uses **TLS**) |
| **Email Services** | **SMTP** | 25 | TCP | Insecure (Mail Transfer) |
| | **POP3** | 110 | TCP | Insecure (Download) |
| | **IMAP** | 143 | TCP | Insecure (Management) |
| | **SMTPS** | 587 | TCP | **Secure** (Submission via **TLS**) |
| | **POP3S** | 995 | TCP | **Secure** (Download via **TLS**) |
| | **IMAPS** | 993 | TCP | **Secure** (Management via **TLS**) |
| **Remote Access & Shell** | **Telnet** | 23 | TCP | **Insecure** (Cleartext) |
| | **SSH** | **22** | TCP | **Secure** (Encrypted Shell) |
| | **RDP** | 3389 | TCP | **Secure** (Encrypted Graphical Access) |
| **File Transfer** | **FTP** | 20/21 | TCP | Insecure (Cleartext) |
| | **SFTP/SCP** | **22** | TCP | **Secure** (Uses **SSH**) |
| | **FTPS** | 989/990 | TCP | **Secure** (Uses **TLS**) |
| **Directory Services** | **LDAP** | 389 | TCP | Insecure (Cleartext Queries) |
| | **LDAPS** | **636** | TCP | **Secure** (Uses **TLS**) |
| **Network Management** | **SNMP** (v1/v2) | 161/162 | UDP | Insecure (Cleartext Credentials) |
| | **TACACS+** | 49 | TCP | **AAA** for Cisco devices. |
| | **RADIUS** | 1812/1813 | UDP | **AAA** for network access. |
| | **Diameter** | 3868 | TCP | **AAA** (Upgrade to RADIUS). |
| **Core Infrastructure** | **DNS** | **53** | **UDP**/TCP | Query (UDP) / Zone Transfer (TCP) |
| | **DHCP** | 67/68 | UDP | IP Address Assignment |
| | **NTP** | 123 | UDP | Time Synchronization |
| | **Kerberos** | 88 | UDP/TCP | Network Authentication |
| | **SMB** | 139, **445** | TCP/UDP | Windows File Sharing |
| **VPN & Tunneling** | **IPsec ISAKMP** | 500 | UDP | Key Exchange for IPsec Tunnels |
| | **L2TP** | 1701 | UDP | Needs **IPsec** for security. |
| | **PPTP** | 1723 | TCP | **Deprecated** (Insecure VPN) |
| | **SSTP** | 443 | TCP | VPN over **HTTPS/TLS**. |
| **Real-Time/Voice** | **SRTP** | 5004+ | UDP | **Secure** Voice/Video (VoIP) |
