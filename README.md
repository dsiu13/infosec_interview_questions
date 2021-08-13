## Interview questions for SOC Analyst, Sec Engineering, etc

# Table of Contents
- [Tools/Frameworks](#Tools/Frameworks)
- [DLP](#DLP)
- [Attacks/Vulnerabilities](#Attacks/Vulnerabilities)
- [DNS](#DNS)
- [Networking](#Networking)
- [Encryption/Hashing](#Encryption/Hashing)
- [Ports](#Ports)
- [Firewalls/IDS/IPS](#Firewalls/IDS/IPS)
- [Malware](#Malware)

## Non-technical Questions

### Tell me about yourself tips
1. Explain your skills and abilities that will help you excel in the role.
2. Added value to the company. What would you bring to the company?

### What are some of the biggest security vulnerabilities of 2019?
- Dominant category was Injection. A large percentage was related to Remote Code/Command Execution (RCE). Followed by Cross-Site Scripting (XSS) mainly Reflected.
- Vulnerabilities in API (App Programming Interface) continues to grow.
- Increase in third-party components (Word Press Plugins, Jenkins Plugins, and NodeJS packages.
- DoS (Denial of Service) and CSRF (Cross-Site request forgery) fell out of the OWASP Top 10, but are still common.

### What are some of the biggest security vulnerabilities of 2020?

### How do you keep up with cyber security?
- Reddit RSS
- darkreading
- krebs on security
- Security Weekly
- CISO - Cyber Security Headlines

## Tools/Frameworks:

### Password Crackers: Hydra, John the Ripper
### Exploit Frameworks: Metasploit, Burp Suite
### Port Scanners: nmap

## DLP:

### Explain in your own words what data leakage is.
- Data leakage is the unauthorized transmission of data from within an organization to an external destination or recipient.
- Can mean both physically and electronically. Emails, Web, or USB, or laptops. etc..
- Also known as low or slow data theft. Major problem in data security.
- "Unauthorized" Data Leakage is not always malicious. A User may send an email to the wrong user.
- Data Exfiltration - Vast majority occurs over physically media rather than electronically. USBs, Printers, Cameras, and improperly disposed of documents are all sources of data leaks. Disgruntled employees selling or leaking info.
- Malware or Phishing attacks are ways data leaks happen electronically
- Data Loss Prevention (DLP) is a set of tools and processes that are used to ensure sensitive data is not lost, misused, or accessed by unauthorized. DLP enforces remediation with alerts, encryption, and other measures to prevent accidental and malicious data leaks.
- DLP can id, classify, and tag sensitive info. Provide reporting data for audits
- Protect Personal Information / Compliance - Personally Identifiable Information (PII), Protected Health Information (PHI), or Payment Card Information (PCI). Follow guidelines set by HIPPA (Health) and EDPR(EU)
- Protect Intellectual Property (IP)
- Track data movement on your own endpoints, network, and the cloud.

### List out the high level steps involved in a successful data loss prevention project.
1. Prioritize Data: Not all data is equally critical. Determine which data would cause the biggest problem is stolen.
2. Categorize (Classify) the Data. Simple way to scale is by using context. Source app, data store, user who created. Persistent class tags allow for data tracking
3. Understand what data is at risk. When is it at it's most vulnerable
4. Monitor all data movement. Understand how the data is being used and identify any existing behavior that puts data at risk. Not all movement represents loss
5. Communicate and create controls. Teach why loss may happen and any risks, then help create controls to reduce those risks
6. Employee Training
7. Repeat with an expanded data set or data id and classification to enable more fine-tuned data controls.

## Attacks/Vulnerabilities:

#### SQL Injection
- Structured Query Language (SQL) is used to query, operate, and administer database systems such as Microsoft SQL server, oracle, or mySQL
- A SQL injection attack involves the alteration of SQL statements that are used within a web application through the use of attacker-supplied data. Insufficient input validation and improper construction of SQL statements in web applications can expose them to SQL injection attacks.
- **Blind SQL Injection**: When no info is returned directly to the user or attacker. The attacker determines if an SQL statement was executed.
- **Second Order SQL Injection**: Involves user-submitted data that is first stored in the database, then retrieved and used as port of a vulnerable SQL statement. More difficult to locate and exploit.
- Successful SQL Injections can lead to:
1. Authentication Bypass - An attacker to log on to an application, potentially with admin privileges without the need for a valid username or pw.
2. Info Disclosure - Attacker gets sensitive info from the db either directly or indirectly
3. Compromised Data Integrity - Attacker may alter the contents of the database. Either to deface it or more likely to insert malicious content.
4. Compromised Availability of Data - Delete info with the intent to cause harm or delete log or audit info in the database.
5. Remote Command Execution - Command Execution through a db can allow the attacker to compromise the host OS. Exploit predefined stored procedure for host OS command execution.
- **Defending vs SQL Injects**: SQL Injections can be detected and potentially block at two locations in the app traffic flow: In the application and in the network
- Defenses in Application: validation of user submitted data, whitelisting or blacklisting, SQL statements that user-supplied data cannot influence the logic of the statement.
- **Whitelisting**: Examines each piece of user input against a list of permitted characters.
- **Blacklisting**: Known malicious characters are removed from or replace in user input. Not as effective as Whitelisting.
- The application must act deterministically when it receives invalid characters from a user. Different levels of response may be appropriate based on the circumstances in which the unexpected data is being processed and the effect it could have.
- Input validation and sanitization should contain alerting functionality.
- **Fortifying SQL Statements**: Each of these techniques performs all required escaping of dangerous characters before the SQL statement is passed to the underlying database system.
- **Defense in Network**: Intrusion Prevention System.

#### Cross-Site Scripting (XSS)
- Type of injection attack, where malicious scripts are injected into otherwise benign and trust websites.
- Attack occurs when an attacker uses a web app to send malicious code. Usually in the form of a browser side script, to a different end user.
- This script runs because the client believes it comes from a trust source. It can gain access to cookies, session tokens, or any sensitive info
- Separated into two categories: Stored and Reflected.
- **Stored attacks** - The attacker injects the website with a malicious script. Each time the website is visited the scripted is executed because the user's browser recognizes it as a trusted source
- **Reflected** aka Non-persistent attacks occur when when malicious script is reflected off a web app to the victim's browser. Reflect works when incoming requests are not being sufficiently sanitized. This allows for manipulation of a web application's functions and the activation of malicious script. Unlike stored attacks which need a website vulnerability that allows for permanent injections of malicious scripts. Reflected attacks only require the malicious script to be embedded
- **Web Application Firewall (WAF)** is the most common solution for XSS and web application attacks. WAF employ different methods to counter attack vectors. In XSS, that would be signature based filtering to identify and block malicious requests.
- Reflected attacks are more common, reflected attacks do not have the same reach as stored, and reflected attacks can be avoided by vigilant users
- Reflected attacks are best avoided by vigilant users. The user's request is block in reflected where as in stored it's the websites request.

#### Distributed Denial of Service / Denial of Service (DDoS/DoS)
- DDoS is distributed denial of service is an attack that involves a series of connected online devices that are used to overwhelm a target website, server or other network with fake traffic.
- DoS attack does that same thing, but from only one machine.
- DDoS attacks don't just aim at bypassing the security layer, DDoS main focus is to make your servers and sites unavailable to legitimate users. They can also be used as a "smokescreen" to cover other harmful acts or destroy systems.
- DDoS is one of the most common forms of attacks.
- Application layer attack: Exhausts targets resources and disrupts access to the targets service or site. HttP Flood is an example
- Protocol attack: Aimed at the networking layer to overwhelm the tablespace of the firewall, core networking services, or load balancer that sends requests to the target.
- Volumetric attack: Uses a botnet to generate huge traffic and jams up the work on the target. DNS amplification is an example of volumetric
- Their are hosting services who will monitor your VPN, proxies, dns, and data to see any potential DDoS attack.
- You can also send traffic into the abyss with **Black Hole Routing**

#### Cross-Site Request Forgery (CSRF)
- Attack that forces an end user to execute unwanted actions on a web app in which they are currently authenticated. An attacker may trick the user of the web app into executing malicious actions of the attacker's choosing.
- CSRF attacks target functionality that causes a state change on the server, such as changing the victim’s email address or password, or purchasing something. Forcing the victim to retrieve data doesn’t benefit an attacker because the attacker doesn’t receive the response, the victim does.
- **Stored CSRF Flaws**: When the CSRF attack is stored on the vulnerable site itself. This can be accomplished by simply storing an IMG or IFRAME tag in a field that accepts HTML, or by a more complex cross-site scripting attack
- CSRF are also known as XSRF, "Sea Surf", Session Riding, Cross-Site Reference Forgery and Hostile Linking.
- Prevention measures against CSRF that do NOT work: Secret Cookie, Only accepting POST requests, Multi-step transactions, URL rewriting, HTTPS
- Secret Cookies: All cookies are submitted regardless of whether or not the end-user submits a request. Session Identifiers are simply used by the application, they do not verify if the end-user meant to send the request
- POST reqs only: There are numerous methods in which an attacker can trick a victim into submitting a forged POST request, such as a simple form hosted in an attacker’s Website with hidden values. This form can be triggered automatically by JavaScript or can be triggered by the victim who thinks the form will do something else.
- Multi-Step Transactions: As long as the attacker can predict or deduce each step of the completed transaction CSRF is possible.
- URL Rewriting: Since the attacker cannot guess the session ID. However, the user's session ID is exposed in the URL
- HTTPS: does nothing itself to defend against CSRF, but it is a prerequisite measure.

### What is a Cross Site Scripting (XSS) attack? Reflected XSS? Stored XSS?
- XSS is a type of injection. An attacker must find a vulnerability in a web app and then inject malicious script into it's server via a comment field, etc...
- Malicious script is injected into trust sites and an attack occurs when an attacker uses a web app to send that malicious code to an end user. This injected browser site script is accepted because it comes from a trust source.
- Reflected XSS: Reflects malicious script off a web app onto a user's browser.
- Stored / Persistent: Occurs when malicious script is directly injected into a vulnerable web application.

## Give examples of an Active Directory Attack
- Active Directory: A hierarchical structure to store objects, so they can access and manage resources of an enterprise. Resources like users, groups, computers, policies. AD is widely in use.
- Active Directories rely on different technologies to provide features, LDAP and DNS.
- The global catalog provides a central repository of domain info, and provides a resource for searching an active directory forest.
- LDAP queries use the global catalog to search for info.
- Domains-Users have read access to the global catalog.

#### Pass-the-Hash (PtH) - mimikatz
- An attacker obtains the password hashes of one or more users on a computer network. The attacker then leverages the compromised user's username and password hash to authenticate to other systems or resources that account has access to.
- **NTLM**: Suite of Microsoft security protocols intended to provide authentication, integrity, and confidentiality to users.

#### Plaintext Password Extraction - PowerSloit
- Attacker locates group policy XML files containing AES encrpyted local account passwords on a Domain Controller's SYSVOL share.
- **SYSVOL Share**: Shared directory that stores the server copy of the domain's public files that must be shared for common access and replication throughout the domain.
- In conjunction with the Microsoft-published AES key, the attacker decrypts the passwords, exposing Admin account passwords in clear text.

#### AdminSDHolder Modification
- Attacker compromises privileged credentials
- The attacker modified AdminSHHolder permissions container by adding a new user to its Access Control List (ACL)
- Via SDProp, the AdminSHHolder permissions are pushed down to all protected objects every 60 minutes (default) including privileged groups such as Admins, Administrators, Enterprise Admins, and Schema Admins

#### Ntds.dit File Password Extraction
- **Ntds.dit**: Database that stores Active Directory data, including info about user objects, groups, and group membership.
- VSSAdmin method via the DC's Volume Shadow Copy.
- Attacker obtains access to an Active Directory Domain Controller, then creates a Volume Shadow Copy from the system cmd prompt.
- Attacker retrieves the Ntds.dit file from the Volume Shadow Copy.
- Attacker copies the SYSTEM file from the registry or Volume Shadow Copy as it contains the **Boot Key** needed to decrypt the Ntds.dit file. Then the attacker deletes the Volume Shadow Copy.
- Once offline the attacker can extract the password hashes from the Ntds.dit file, after extraction the attacker can use tools to obtain clear text values.

#### LDAP Recon
- Attacker obtains access to any domain-joined system (by phishing, social engineering, etc..)
- By using powershell the attacker crafts and executes queries against the AD objects, search for various conditions such as: User objs containing service principal names(SPN) indicating which the accounts are used to run services to support apps. Membership of sensitive security groups like domain, enterprise, and schema admins, listing the user acct containing the highest level of privilege in the domain
Location of high profile assets such as file servers, sql dbs, Active Directory Domain Controllers

#### DC Sync
- Attacker compromises an account with the rights to perform domain replication. Once proper privileges are obtained, the attacker DCSync command to retrieve account password hashes from Active Direct. The attacker can now create a forged Kerberos tickets and access any linked resources.

#### Kerberos Golden Ticket
- Golden Ticket is the kerberos auth token for the KRBTGT account, a special hidden account responsible for encryption all the auth tokens for the Domain Controller
- The ticket is used for a pass the hash attack allowing the attacker to move through the network
- Least Privilege Model, User Training, Endpoint Blocking of mimikatz, etc...
- Choke point for Domain Controller access, terminal server can only talk to DCs, DCs only accept admin connections from that terminal.

### Social Engineering Attacks
- Phishing: A technique used to obtain personal information, such as a username or password. It collects log in info by creating a fake looking login page for a company.
- This can be done using phones, texts, robocalls, etc...
- Target Phishing is called Spear Phishing
- Prevention by checking URLs, don't click links it email, filters for inbox, and employee training.

### Two types of sniffing attacks?
- Active Sniffing: Sniffing in the switch is active sniffing. Looks at the switch and injects traffic into the LAN
- Passive Sniffing: Sniffing through the hub, it waits for data to be sent and captures it.
- Active attacks: MAC-Flooding, ARP Spoofing, ARP Poisoning, Man-in-the-Middle

### What is MAC Spoofing?
- Technique of changing your factory assigned MAC address of a network interface on a networked device.
- The MAC address on the Network Interface Controller cannot be changed.
- Drivers allow for MAC address changing.
- Spoofing allows you to bypass Access Control Lists on servers or routers. Impersonates a MAC address on the whitelist or that is not black listed.

### What is ARP Poisoning? (ARP Flooding)
- ARP only works with 32-bit IP addresses in the older IPv4 standard. The newer IPv6 protocol uses a different protocol, Neighbor Discovery Protocol (NDP).
- Man in the Middle attack (MitM)
1. The attacker must have access to the network. They scan the network to determine the IP addresses of at least two devices⁠.
2. The attacker uses a spoofing tool(Arpspoof or Driftnet), to send out forged ARP responses.
3. The forged responses advertise that the correct MAC address for both IP addresses, belonging to the the devices, but is the attacker’s MAC address. This fools both router and workstation to connect to the attacker’s machine instead.
4. The two devices update their ARP cache entries and from that point onwards, communicate with the attacker instead of directly with each other.
5. The attacker is now secretly in the middle of all communications.
- The attacker can now continue routing the communications to steal unencrypted data.
- Perform session hijacking (Session ID required), allowing access to accounts the user is logged in to.
- Alter communication and send the User to a malicious site or file
- Attacker can give the MAC address of a server they wish to attack with a DDoS. Target server gets flooded with traffic.
- You can detect ARP Cache Poisoning Attack using Windows/Linux Command "arp - a". If two address have the same MAC Address then a poisoning attack is happening.
- Preventions Methods: VPN, Static ARP, Packet Filtering, and run tests to detect any vulnerabilities.

## DNS:

### Explain how DNS works.
- Translates domain names into IP address. Each device has a unique which other machines use to the device.
- **DNS Recursor**: Server designed to receive queries from client machines through an app. The recursor is then responsible for making additional request for the client's query
- **Root nameserver**: Root server is the 1st step in translating a human reable host name in an IP address. Serves as a reference to more specific locations.
- **TLD nameserver**: Top Level Domain Server (TLD), contains the last part of a hostname (.com, .net, etc..)
- **Authoritative nameserver**: Final nameserver, last stop on the nameserver query. If it has the requested hostname, it will return the IP address to the DNS recursor

#### DNS Server vs recursive DNS resolver
- Recursive resolver is at the beginning of the DNS query and Authoritative is at the end.
- The recursive resolve responds to recursive request from the client and tracks down the DNS record. It makes a series of request until it reaches the authoratative nameserver with the requested record or timesout.
- **Caching** is a data persistence process that helps serve the request resource earlier in the DNS lookup.
- Authoritative DNS server: holds and is responsible for DNS resource records. Last server of the DNS lookup chain, and provides the IP for requested domain name.
- An additional nameserver is added to the sequence if there is CNAME record.

#### DNS Lookup
1. domain name is requested and is received by a DNS recursive resolver.
2. Resolver queries DNS root nameserver
3. Root server responds with the Top Level Domain (TLD) DNS server, .com -> .com TLD, etc..
4. Resolver makes a request to that TLD
5. TLD responds with the IP address of the domain's nameserver
6. Recursive resolver then sends a query to the domain's nameserver
7. IP address returns to the resolver from nameserver
8. DNS resolver provides the requested IP address of the domain name
9. Browser sends HTTP request to the returned IP
10. IP server returns the webpage for render.

#### DNS Resolver
- First step in the DNS lookup and is responsible for dealing with the client who made the request. It starts the series of queries that lead to a URL being translated into the necessary IP address
- Uncached DNS lookup will involve both recursive and iterative queries.
- The query refers to the request made to a DNS resolver requiring the resolution of the query.
- A DNS recursive resolver is the computer that accepts a recursive query and processes the response by making the necessary requests.

#### DNS Queries
1. **Recursive**: a DNS client requires a DNS server (DNS recursive resolver) that will respond to the client with either the requested resource record or error if it cannot be found.
2. **Iterative**: The DNS is allowed to return the best answer it can. If the queried DNS server does not have match for the query name, it will return a referral DNS server authoratative for a lower level of domain name space.
3. **Non-Recursive**: Will occur when a DNS resolver client queries a DNS server for a record that it has access to because it's the authoritative for the record or the record is cached.

#### DNS Caching
- **Browser DNS Cache**: Records are cached for a set amount of time. The browser cache is the first place searched for the requested record.
- **OS level Cache (Stub Resolver/DNS Client)**: 2nd and last local stop before a DNS query leaves your machine. When a request is received, it checks it's own cache for the record, if it is not found a DNS query(Recursive Flag) it sent outside the local network to a DNS recursive resolver inside the ISP
- **Recursive resolver DNS cache**: Will also check to see if host-to-IP address translation is already in the location persistence layer.
- If there is no A record, but a NS record for the authoritative server it will query the name server directly, bypassing steps in the query. Allows for DNS queries to occur faster.
- If there is no NS record, a query is sent to TLD, skipping the root server
- If there a no records pointing to a TLD server, it will then query the root servers. Typically occurs after DNS cache purge

## Encryption/Hashing

### What is the difference between hashing and encryption?
- Encryption is a two way function, what is encrypted can be decrypted with the proper key. Either Symmetric and Asymmetric. Email, Data Storage, web traffic most common uses.
- Hashing is a one way function that scrambles plain text to produce a unique message digest. With a proper algorithm there is no way to reverse the hash. If a hashed password is taken, the password must be guessed. Hashing provides integrity. If the hashes don't match when checked the file has been modified.

### Common Encryption and Hashing Algorithms
- Sym Encryption: DES/3DES, AES, RC4, RC5
- Asym Encryption: RSA, ECC
- Hashing: MD5, SHA-1/2, NTLM, LANMAN

## Ports:

### Explain what each of these ports are used for; 80, 22, 443, 53 etc
- Port Range: 0-65535, Well Known: 0-1023, Registered: 1024 to 49151, Dynamic: 49152-65535
- **20 & 21**: file transfer proto. one is data transfer. the other is control channel
- **22**: SSH, SFTP, SCP - Secure Shell, Secure File Transfer, Secure Copy Protocol. Remote access terminal program
- **23**: telnet - txt based terminal program remote access - unencrypted
- **25**: simple mail transfer protocol (smtp) (default port non encrpyted)
- **53**: Domain Name System
- **80**: http - computer sends and receives web client-based info. no encryption. No sensitive info should be sent over HTTP
- **110**: pop3 (Post office protocol) (Email Protocol to receive email from a remote server to a local email client) Downloaded then deleted from server
- **111**: rpcbind
- **135**: msrpc
- **139**: netbios-ssn. ports 137-139.
- **143**: imap4 - synchronized local copy with whats on server.
- **161**: SNMP - setting and getting info. Manage network.
- **443**: https
- **445**: microsoft-ds
- **993**: imaps
- **995**: pop3s
- **1433**: MS SQL. Database platform for data storage and retrieval
- **1723**: pptp
- **3306**: mysql
- **3389**: Remote Desktop Protocol. Allows remote access to a machine.
- **5900**: vnc
- **8080**: http-proxy

## Firewalls/IDS/IPS:

### Whats Intrusion Detection System (IDS) and Intrusion Prevention System (IPS)?
- **IDS**: Monitors a network or system for malicious activity or policy violations. Reports to a Security and Event Management System (SIEM).
- Two common classifications of IDS: **Network Intrusion Detection Systems (NIDS) and Host Based Intrusion Detection Systems (HIDS).**
- **IPS**: An IDS system that has the ability to respond to detected intrusions.
- **NIDS**: Placed at a strategic point or points within the network to monitor network traffic to and from all devices on the network. Performs analysis of passing traffic on the entire subnet, and matches the traffic that is passed on subnets to a library of known attacks.
- **HIDS**: Run on individual hosts or devices on a network. Monitors inbound and outbound packets from the device and will alert user or admin if any suspicious activity is detected. Takes snapshots of existing system files and matches to the previous snapshot. If any changes are detected an alert is sent.

### What is a Firewall, IPS, IDS, and where are they placed on a network?
#### Firewall
- Network Security System that monitors and controls incoming and outgoing network traffic based on predetermined security roles.
- Firewalls: Categorized as network-based or a host-based system. Network-based firewalls can be positioned anywhere within a LAN or WAN.
- Software app on general-purpose hardware, hardware app running on special purpose hardware, or a virtual appliance running on a virtual host controlled by a hypervisor.
- Firewall apps may offer non firewall functionality, such as DHCP or VPN services.

#### Intrusion Prevention System - IPS
- Commonly located behind a firewall to function as another filter for malicious activity. IPS is capable of analyzing and taking automated actions on all network traffic flows.
- Commonly uses of Signature-based detection and statistical anomaly-based detection.
- IPS can take actions against threats.

#### Intrusion Detection System - IDS
- Monitors network for possible dangerous activity, including malicious acts and security protocol violations. IDS alerts admin, but no further action is taken.
- Common placement being behind the firewall on the edge of a network. Allows IDS with high visibility of traffic entering your network and will not receive any traffic between users on the network. If resources are available you can place your first IDS at the point of highest visibility of traffic and if able place another at the next highest visibility, this repeats if possible until all network points are covered.
- An IDS place outside a firewall is to defend against noise from the internet, common attacks: Port scans, Network mappers, etc.
- IDS advanced features would be integrated with a firewall, allowing for interception of more sophisticated attacks entering the network.
- IDS placement within actual network. These will reveal attacks or suspicious activity within the network. Makes it more difficult to move around within the network.

#### Two intrusion detection methods?
- Intrusion Detection System (IDS) and Intrusion Prevention System (IPS).

## Networking:

#### What's the difference between (Transfer Control Protocol) TCP and (User Datagram Protocol) UDP?
- **TCP**: Connection Based. Connection established with a three way handshake. Has QA, can determine if all packets arrived.
**Three Way Shake**: Client sends a SYN to server. Server sends a SYN/ACK to client. Client responds with an ACK.
- Step 1 (SYN) : In the first step, client wants to establish a connection with server, so it sends a segment with SYN(Synchronize Sequence Number) which informs server that client is likely to start communication and with what sequence number it starts segments with
- Step 2 (SYN + ACK): Server responds to the client request with SYN-ACK signal bits set. Acknowledgement(ACK) signifies the response of segment it received and SYN signifies with what sequence number it is likely to start the segments with
- Step 3 (ACK) : In the final part client acknowledges the response of server and they both establish a reliable connection with which they will start the actual data transfer.
- **UDP**: No connection needed/connectionless protocol. UDP does not have a mechanism to check for payload corruption. Common uses are for VoIP, Streaming, Online Gaming

### What is TCP?
- Transmission Control Protocol: Standard that defines how to establish and maintain a network convo through which an app can exchange data.
- Connection Oriented Protocol, the connection once established is maintained until ended.
- Helps organizing data allowing for a secure transmission. SSH, FTP, Telnet, SMTP, POP, IMAP, HTTP make use of TCP.
- Exists in the transport layer. Ensures error free transmission of data.

### TCP Header Flags?
- Flags are used to indicate a particular state of connection or to provide some additional useful info like troubleshooting purposes, or to handle a control of a particular connection.
- Common flags are, SYN, ACK, and FIN
- SYN: Synchronization - 1st step of a connection establishment (3 Way Handshake). Only 1st packet from sender and receiver should have this flag set. Used to synchronize sequence number, telling the other end which sequence number they should expect.
- ACK: Acknowledgement is used to acknowledge packets which are successful received by the host. The flag is set if the acknowledgement number field contains a valid acknowledgement number.
- FIN: Finish is used to request for connection termination. Last packet sent by sender, and this frees the reserved resources and ends the connection.

### UDP Header Fields?
1. Source Port Number - Port of the sending device
2. Destination Port Number - Port of receiving device
3. Data Field Length - Number of bytes comprising the UDP header. Limit is determined by the underlying IP protocol used.
4. Checksum Field - Allows receiving device to verify integrity of the packet header and payload. Optional in IPv4. Required in IPv6.

### TCP Three Way Handshake
1. TCP Client sends SYN to TCP Server (SYN)
2. TCP Server receives SYN and sends SYN to Client (SYN/ACK)
3. Client sends ACK, Server receives (ACK)

#### OSI Model "Theory" - "Please do not throw sausage pizza away"
- Going from Layer 1 to Layer 7 is Encapsulation. Returning from Layer 7 to Layer 1.
- Layer 7: Application
- Layer 6 - Presentation (Syntax)
- Layer 5 - Session
- Layer 4 - Transport
- Layer 3 - Network
- Layer 2 - Data Link
- Layer 1 - Physical

#### TCP/IP Model "Practical/Reality" - Internet Suite
- 4. Application - Data
- 3. Transport - Segments
- 2. Network / Internet - Packets or Datagrams
- 1. Network Access / Link Layer (Data Link + Physical) - Bits & Frames

#### OSI + TCP/IP Devices
- Layers 5 to 7: Layer 7 Firewall - Can see packets
- 4. Layer 4 Firewall
- 3. Router, Multilayer Switch, Wireless Router
- 2. Switch, Bridge, NIC, Wireless Access Point
- 1. Hub, NIC, Wireless Access Point

#### OSI + TCP/IP Protocols
- Layers 5 to 7: HTTP, DNS, DHCP, FTP, Telnet, SSH, SMTP, POP, IMAP, NTP, SNMP, TLS/SSL. BGP, RIP, SIP
- Layer 4: TCP, UDP
- Layer 3: IPv4, IPv6, ICMP, ICMPv6, IPSec, OSPF, EIGRP
- Layer 1 to 2: MAC, ARP, Ethernet 802.3(Wired), CDP, LLDP. HDLC, PPP, DSL, L2TP, 802.11(Wireless), SONET/SDH (Fiber Optic)

### What are the three main transmission modes?
- Simple, Half Duplex, and Full Duplex

### What are some communication networks?
- Local Area Network, Metropolitan Area Network, Wide Area Network, and Personal Area Network

### What is Simple Service Discovery Protocol (SSDP)?
- Network Protocol, does not need assistance of server-based configuration mechanisms - Dynamic Host Configuration Protocol (DHCP), or Domain Name Service (DNS), and does not need a special static configuration of a network host.
- Text-based protocol based on Universal Plug and Play (HTTPU)
- Uses UDP as the transport protocol. **Services are announced by the hosting system with a multicast address at UDP port number 1900**
- IPv4 Multicast Address: 239.255.255.250
- IPv6 Multicast Address: ff0X::c for all scope ranges indicated by X

#### Well Known Practical Multicasts addresses for SSDP.
- 239.255.255.250 (IPv4 site-local address)
- [FF02::C] (IPv6 link-local)
- [FF05::C] (IPv6 site-local)
- [FF08::C] (IPv6 organization-local)
- [FF0E::C] (IPv6 global)

#### What is Simple Network Management Protocol (SNMP)?
- Collects and organizes info about managed devices on IP networks and modifies that info to change device behavior
- Used in network management for network monitoring
- SNMP exposes management data in the form of variables on managed systems organized in a management information base (MIB) which describe the system status and configuration.
- These variables can then be remotely queried (and, in some circumstances, manipulated) by managing applications.
- In typical uses of SNMP, one or more administrative computers called managers have the task of monitoring or managing a group of hosts or devices on a computer network.
- Consists of three key components: Managed devices, Agent(Software which runs on the managed device), and Network management station(NMS software which runs the management station)
- Works in the Application Layer. All SNMP are transported via UDP. SNMP agent receives request on UDP port 161.
- Manager may send requests from any available source port to port 161.
- When Agents send back the Manager receives it on port 162
- Port 10161 is used when Transport Layer Security or Datagram Transport Layer Security.

#### Three Main Data transmission methods in Layer 2 (Data Link)
- Logical Link Control (LLC)
1. Connection Services: Provides acknowledgement of receipt of a message, limits amount of data sender can send at one time, preventing overwhelming of receiver, and receiver can notify sender when an error occurs (Checksum, Frame Loss)
2. Synchronizing Transmissions: **Isochronous**: Network devices use a common reference clock and create time slots for transmission. **Asynchronous**: Network devices reference their own internal clocks and use start/stop bits. **Synchronous**: Network devices agree on clocking method to indicate start and end. Can use Control Characters or separate timing channel.

### What is DHCP?
- Dynamic Host Configuration Protocol: Network management protocol used on IP networks, DHCP dynamically assigns IP address and other network configurations to each device on network.
- DHCP servers enable computers to request IP addresses and networking parameters from the ISP. Reducing need for manually IP assignment.

### What is a Virtual Local Area Network (VLAN)? Types of VLANs?
- Logically connected devices regardless of their physical locations. Connected by a switch based on their functionalities. Behave as if they are connected to a single network segment.
- VLAN enhances security between departments and for easy reconfiguration

### Tools used to secure a common network?
- Access Control List (ACL)
- Firewall
- Intrusion Detection Systems, NIDS, NIPS
- Network Segmentation
- Security Information and Event Management (SIEM)
- Data Loss Prevention (DLP)
- Virtual Private Network (VPN)
- Web/Wireless Security
- Endpoint Security
- Email Security
- Anomaly Detection
- Anti-Malware Software
- Application Security

### What is a SIEM?
- System Info Event Manager: An approach to security management that combines Security Information Management (SIM) and Security Event Management Function (SEM).
- Goal of SIEM system is to aggregate relevant data from multiple sources
- SIEM can be rules-based or employ a statistical correlation engine to establish relationship between event log entries.
- Advanced SIEM systems include user and entity behavior (UEBA), security orchestration, automation and response SOAR

### Explain SSL Handshake
1. Client Hello: Client sends info that will be required by the server started an HTTPS connection.
2. Server Hello: Server responds back with the configuration it selected from the Client Hello with info to proceed with the handshake.
3. Server Key Exchange Message: Message sent by the server to the client carrying the required details for client to generate the pre-secret. Only used if the premaster secret is needed.
4. Certificate Request: Server will send a certificate request from the client with the certificate type, cert signature algos and cert authorities list can be empty. Server then sends Server Hello Done message.
5. Client Certificate: Client presents its cert chain to the server. Cert needs to be appropriate for the negotiated cipher suite's key exchange algo and any negotiated extensions.
6. Client Key Exchange Message: Message needs to be sent by the client following the client cert message. Data between server and client HTTPS connection will be encrypted. Symmetric is used due to lower overhead

#### SSH
1. Secure Shell: Provides strong authentication and secure communication over insecure channels.
2. Runs on port 22, but can be changed.
3. Uses public key for authentication of users accessing a server and provides great security.
4. Used on most popular OS (Unix, Solaris, Red-Hat Linux, CentOS, Ubuntu). Protects
5. Protects network from attacks such as IP spoofing, DNS spoofing, and IP source routing. Attacker can only force a disconnect, and is unable to replay traffic or highjack the connection.
6. Entire session is encrypted.

#### Telnet
1. Not a secure communication protocol because it does not use any security mechanism and transfer data in plain text allowing for sniffing to occur.
2. No authentication policies and data encryption tech used in telnet/

### HTTP vs HTTPS
- HTTP runs on port 80, insecure connection. Layer 7 Protocol. Transfers data over the internet (API, web content)
- HTTPS uses TLS/SSL to encrypt HTTP. Public key encryption(Asymmetric). Public key shared via SSL Cert. Once connection is established two devices agree on new keys(Session Keys). Everything is encrypted, attacker would only see Cipher Text. Runs on port 443.

### Explain HTTPS and SSL
- **Hypertext Transfer Protocol** (HTTP): used for viewing web pages. All info is sent in clear text
- **Secure Hypertext Transfer Protocol**: Encrypts the data is being retrieved by HTTP
- **SSL**: Protocol that's used to ensure security on the internet. Uses a public key encryption. SSL Cert is used to authenticate the ID of a website

### Subnetting and Classless Inter-domain Routing/CIDR Notation


## Malware:
- Virus, Keyloggers, Worms, Trojans, Ransomware / Cryptomalware, Logic Bombs, bot/botnets, adware, spyware, and root kits.
- ### How to defend against ransomware?
- Anti Virus and Segmented VLANs


### What would you do if you had a bot net? How to make money with it?

### What is a DMZ and what would likely be in it?
- Demilitarized zone


### Basic Linux commands

### Powershell

### Bash

### Risk vs Vuln vs Threat
- Balance Risk and needs of the business

### Preventative vs Detective
- IPS in line - capacity issues - single failure point.
- Detective allows analysis without letting an attacker know you're watching.

### Encryption and Compression 1st?
- Compress first then encrypt.

### Rest API
- How two servers talk to each other using Get, Post, Del, Put.

## Misc:

### How does an antivirus program work?
- Checks a file, program, or an app and compares a specific set of code with info stored in it's database. If that code is found in the anti viruses library that is similar or identical, the program knows it is malicious.

### What is a Zero Day?
- An exploit that exposes a vulnerability in software or hardware before the developer can patch it.
- The attacker uses the vulnerability and exploits the flaw, after the exploit is released and noticed a patch is applied to address the flaw.

### What is a MAC Address?
- Media Access Control is a unique identifier assigned to a Network Interface Controller (NIC) for use as a network address for communication.

### What is Data Center Multi-Tier Model Design?
- Levels of reliability of data centers
- Tier 1: Lacks redundant IT equipment, 99.671% Avail, 1729 min annual downtime max. If the power goes, it all goes.
- Tier 2: Adds redundant infrastructure, 99.741% Avail, 1361 min annual downtime max. Does have a backup gen
- Tier 3: Has concurrent availability means one can go down and still function. One Adds more data paths. Duplicate equipment, dual powered. 95 mins annual downtime. Lower redundancy level while components are out.
- Tier 4: Dual-powered cooling, fault tolerance, 99.995%, 26 min of annual downtime. You can lose any component and still have fault resilience. Essentially two Tier 3s

### Where do you find logs (Linux/Windows)
- Windows: C: WINDOWS system32
- Linux: Var Log sub directory

### If you went into a room and there were two computers there and one was infected with malware, how would you find out which one it was?
