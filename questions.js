export const questionSets = {

  "Fundamentals & Terminology": [
    {
      question: "What principle ensures that information is accessible only to those authorized to have access?",
      answers: [
        { text: "Integrity", correct: false },
        { text: "Confidentiality", correct: true },
        { text: "Availability", correct: false },
        { text: "Non-repudiation", correct: false }
      ],
      explanation: "Confidentiality, part of the CIA Triad, is the principle that protects information from unauthorized access or disclosure."
    },
    {
      question: "What is a 'zero-day' vulnerability?",
      answers: [
        { text: "A flaw patched on the day it's disclosed.", correct: false },
        { text: "A vulnerability that is already known and has a patch available.", correct: false },
        { text: "A flaw exploited before the developer is aware of it or has a patch ready.", correct: true },
        { text: "A vulnerability that is over a year old.", correct: false }
      ],
      explanation: "A zero-day is a vulnerability that is unknown to the vendor, meaning they have zero days to fix it before it is exploited in the wild."
    },
    {
      question: "The process of verifying a user's identity is called:",
      answers: [
        { text: "Authorization", correct: false },
        { text: "Accounting", correct: false },
        { text: "Authentication", correct: true },
        { text: "Auditing", correct: false }
      ],
      explanation: "Authentication is the act of confirming the truth of an attribute of a single piece of data or entity. Authorization is granting access to resources after identity is confirmed."
    },
    // New questions start here
    {
      question: "Which principle of the CIA Triad ensures that systems and data are accessible when needed?",
      answers: [
        { text: "Confidentiality", correct: false },
        { text: "Integrity", correct: false },
        { text: "Availability", correct: true },
        { text: "Authentication", correct: false }
      ],
      explanation: "Availability ensures that information and systems are operational and accessible to authorized users in a timely and reliable manner."
    },
    {
      question: "What is the primary goal of an 'Integrity' control?",
      answers: [
        { text: "To prevent data theft.", correct: false },
        { text: "To ensure data is accurate and unaltered.", correct: true },
        { text: "To keep systems running 24/7.", correct: false },
        { text: "To verify user identity.", correct: false }
      ],
      explanation: "Integrity involves maintaining the consistency, accuracy, and trustworthiness of data over its entire lifecycle, preventing unauthorized modification."
    },
    {
      question: "The principle that prevents an individual from denying having performed an action is known as:",
      answers: [
        { text: "Confidentiality", correct: false },
        { text: "Authentication", correct: false },
        { text: "Non-repudiation", correct: true },
        { text: "Accountability", correct: false }
      ],
      explanation: "Non-repudiation provides undeniable proof that a specific user took a specific action, such as sending a message or approving a transaction."
    },
    {
      question: "What does the 'AAA' framework in security stand for?",
      answers: [
        { text: "Authentication, Authorization, and Accounting", correct: true },
        { text: "Assessment, Analysis, and Action", correct: false },
        { text: "Availability, Authentication, and Authorization", correct: false },
        { text: "Attack, Audit, and Alert", correct: false }
      ],
      explanation: "The AAA framework is a core concept: Authentication (who are you?), Authorization (what are you allowed to do?), and Accounting (logging what you did)."
    },
    {
      question: "A security event that constitutes a breach of policy or law is called a(n):",
      answers: [
        { text: "Incident", correct: true },
        { text: "Exploit", correct: false },
        { text: "Vulnerability", correct: false },
        { text: "Threat", correct: false }
      ],
      explanation: "A security incident is an event that violates an organization's security policies, potentially compromising its systems or data."
    },
    {
      question: "A weakness in a system that could be exploited is known as a:",
      answers: [
        { text: "Threat", correct: false },
        { text: "Risk", correct: false },
        { text: "Vulnerability", correct: true },
        { text: "Attack", correct: false }
      ],
      explanation: "A vulnerability is a flaw or weakness in a system's design, implementation, or operation that could be exploited by a threat actor."
    },
    {
      question: "A potential cause of an unwanted incident, which may result in harm to a system or organization, is a:",
      answers: [
        { text: "Vulnerability", correct: false },
        { text: "Threat", correct: true },
        { text: "Exploit", correct: false },
        { text: "Control", correct: false }
      ],
      explanation: "A threat is any potential danger that can exploit a vulnerability to breach security and cause harm (e.g., a hacker, a natural disaster, or malware)."
    },
    {
      question: "What is the relationship between a 'vulnerability,' a 'threat,' and a 'risk'?",
      answers: [
        { text: "A threat exploits a vulnerability to create a risk.", correct: true },
        { text: "A vulnerability exploits a risk to create a threat.", correct: false },
        { text: "A risk exploits a threat to create a vulnerability.", correct: false },
        { text: "They are all synonymous terms.", correct: false }
      ],
      explanation: "Risk is the potential for loss or damage when a threat actor exploits a vulnerability. The formula is often expressed as: Risk = Threat x Vulnerability."
    },
    {
      question: "What is the process of converting plaintext into ciphertext?",
      answers: [
        { text: "Decryption", correct: false },
        { text: "Hashing", correct: false },
        { text: "Encoding", correct: false },
        { text: "Encryption", correct: true }
      ],
      explanation: "Encryption is the process of using an algorithm to transform readable data (plaintext) into an unreadable format (ciphertext) to protect its confidentiality."
    },
    {
      question: "A one-way mathematical function that maps data of any size to a fixed-length output is a:",
      answers: [
        { text: "Symmetric Key", correct: false },
        { text: "Hash", correct: true },
        { text: "Cipher", correct: false },
        { text: "Nonce", correct: false }
      ],
      explanation: "A hash function produces a unique, fixed-size string (hash value/digest) from input data. It is one-way, meaning it should be infeasible to reverse."
    },
    {
      question: "What type of attack involves tricking a user into sending sensitive information to a malicious actor by posing as a trustworthy entity?",
      answers: [
        { text: "Phishing", correct: true },
        { text: "Spoofing", correct: false },
        { text: "Sniffing", correct: false },
        { text: "Brute-Force", correct: false }
      ],
      explanation: "Phishing is a social engineering attack where attackers use fraudulent communications (like email) to deceive victims into revealing sensitive information."
    },
    {
      question: "'Pseudo-random' numbers generated by a computer are:",
      answers: [
        { text: "Truly random and unpredictable.", correct: false },
        { text: "Deterministic and appear random, but are reproducible.", correct: true },
        { text: "Only used for gaming.", correct: false },
        { text: "A type of encryption cipher.", correct: false }
      ],
      explanation: "Pseudo-random numbers are generated by an algorithm and a seed value. While they appear random, they are deterministic and can be reproduced if the seed is known."
    },
    {
      question: "What is the primary purpose of a 'nonce' in cryptography?",
      answers: [
        { text: "To encrypt large amounts of data.", correct: false },
        { text: "To ensure data integrity.", correct: false },
        { text: "To add randomness and prevent replay attacks.", correct: true },
        { text: "To act as a permanent encryption key.", correct: false }
      ],
      explanation: "A nonce (number used once) is a random or semi-random number that is issued once per session to ensure that old communications cannot be reused in replay attacks."
    },
    {
      question: "What term describes the process of hiding a message within another file, image, or video?",
      answers: [
        { text: "Encryption", correct: false },
        { text: "Obfuscation", correct: false },
        { text: "Steganography", correct: true },
        { text: "Tokenization", correct: false }
      ],
      explanation: "Steganography is the practice of concealing a file, message, image, or video within another file, message, image, or video."
    },
    {
      question: "Which term best describes the practice of making data unintelligible without the use of a secret key?",
      answers: [
        { text: "Encoding", correct: false },
        { text: "Hashing", correct: false },
        { text: "Encryption", correct: true },
        { text: "Tokenization", correct: false }
      ],
      explanation: "While encoding (like Base64) is for data representation, encryption specifically uses an algorithm and a key to protect the confidentiality of data."
    },
    {
      question: "A security control that uses two or more types of credentials for authentication is called:",
      answers: [
        { text: "Single Sign-On (SSO)", correct: false },
        { text: "Multi-Factor Authentication (MFA)", correct: true },
        { text: "Privileged Access Management (PAM)", correct: false },
        { text: "Biometric Verification", correct: false }
      ],
      explanation: "MFA requires a user to provide two or more verification factors from different categories (something you know, have, or are) to gain access."
    },
    {
      question: "What is the difference between a 'symmetric' and an 'asymmetric' encryption algorithm?",
      answers: [
        { text: "Symmetric is faster for large data, while asymmetric uses a public/private key pair.", correct: true },
        { text: "Asymmetric is faster for large data, while symmetric uses a public/private key pair.", correct: false },
        { text: "They are identical in function and speed.", correct: false },
        { text: "Symmetric is only used for digital signatures.", correct: false }
      ],
      explanation: "Symmetric encryption uses a single shared key for both encryption and decryption. Asymmetric encryption uses a mathematically linked public and private key pair."
    },
    {
      question: "What does the term 'Attack Surface' refer to?",
      answers: [
        { text: "The total number of vulnerabilities in a system.", correct: false },
        { text: "The sum of all points where an attacker can try to enter or extract data.", correct: true },
        { text: "The geographic location of a cyber attack.", correct: false },
        { text: "The type of malware used in an attack.", correct: false }
      ],
      explanation: "The attack surface encompasses all the potential vulnerabilities and entry points (software, hardware, network, human) that an attacker can exploit."
    },
    {
      question: "A formal statement that defines the set of rules for granting access to a system is a(n):",
      answers: [
        { text: "Access Control List (ACL)", correct: true },
        { text: "Security Policy", correct: false },
        { "text": "Service Level Agreement (SLA)", correct: false },
        { text: "Incident Response Plan", correct: false }
      ],
      explanation: "An Access Control List (ACL) is a list of permissions attached to an object, specifying which users or systems are granted access and what operations they can perform."
    },
    {
      question: "The practice of designing systems to be secure from the ground up is called:",
      answers: [
        { text: "Security by Obscurity", correct: false },
        { text: "Penetration Testing", correct: false },
        { text: "Security by Design", correct: true },
        { text: "Vulnerability Assessment", correct: false }
      ],
      explanation: "Security by Design means integrating security considerations into every phase of the system development lifecycle, rather than adding it as an afterthought."
    },
    {
      question: "What is 'Defense in Depth'?",
      answers: [
        { text: "Using a single, powerful firewall.", correct: false },
        { text: "A strategy that employs multiple, layered security controls.", correct: true },
        { text: "Hiding the source code of an application.", correct: false },
        { text: "Only defending the most critical servers.", correct: false }
      ],
      explanation: "Defense in Depth (or layered defense) uses a variety of security controls (physical, network, host, application) so that if one fails, others are in place."
    },
    {
      question: "What is a 'False Positive' in the context of an Intrusion Detection System (IDS)?",
      answers: [
        { text: "A legitimate threat that was correctly detected.", correct: false },
        { text: "A threat that was missed by the system.", correct: false },
        { text: "An alert that was triggered by benign activity.", correct: true },
        { text: "A test used to validate the IDS.", correct: false }
      ],
      explanation: "A false positive occurs when a security system incorrectly flags legitimate activity as malicious, generating an unnecessary alert."
    },
    {
      question: "What is a 'False Negative'?",
      answers: [
        { text: "A legitimate threat that was correctly detected.", correct: false },
        { text: "A threat that was missed by the system.", correct: true },
        { text: "An alert that was triggered by benign activity.", correct: false },
        { text: "A test used to validate the IDS.", correct: false }
      ],
      explanation: "A false negative is a dangerous situation where a real attack or malicious activity is not detected by the security system."
    },
    {
      question: "Which term describes the act of gathering information about a target network without actively engaging it?",
      answers: [
        { text: "Port Scanning", correct: false },
        { text: "Penetration Testing", correct: false },
        { text: "Passive Reconnaissance", correct: true },
        { text: "Active Scanning", correct: false }
      ],
      explanation: "Passive reconnaissance involves collecting information about a target without directly interacting with it (e.g., searching public DNS records or social media)."
    },
    {
      question: "What is the primary goal of 'Risk Management'?",
      answers: [
        { text: "To eliminate all risk.", correct: false },
        { text: "To identify, assess, and prioritize risks to minimize their impact.", correct: true },
        { text: "To transfer all risk to an insurance company.", correct: false },
        { text: "To ignore low-probability risks.", correct: false }
      ],
      explanation: "Risk management is the ongoing process of identifying, analyzing, evaluating, and treating risks to an acceptable level, as it is impossible to eliminate all risk."
    },
    {
      question: "What does the term 'Attack Vector' mean?",
      answers: [
        { text: "The specific vulnerability being exploited.", correct: false },
        { text: "The path or method a threat actor uses to breach a system.", correct: true },
        { text: "The tool used to launch an attack.", correct: false },
        { text: "The target of the attack.", correct: false }
      ],
      explanation: "An attack vector is the specific path, means, or technique (e.g., phishing email, unpatched software, weak password) that an attacker uses to gain unauthorized access."
    },
    {
      question: "The practice of adding extra data to input fields to crash a program is a basic form of:",
      answers: [
        { text: "SQL Injection", correct: false },
        { text: "Cross-Site Scripting (XSS)", correct: false },
        { text: "Buffer Overflow", correct: true },
        { text: "Man-in-the-Middle (MitM)", correct: false }
      ],
      explanation: "A buffer overflow attack occurs when a program writes more data to a block of memory (a buffer) than it was allocated to hold, potentially allowing execution of malicious code."
    }
  ],
  "Network Security": [
    {
      question: "Which of the following devices operates primarily at Layer 3 (Network Layer) of the OSI model?",
      answers: [
        { text: "Switch", correct: false },
        { text: "Router", correct: true },
        { text: "Hub", correct: false },
        { text: "Bridge", correct: false }
      ],
      explanation: "A Router uses IP addresses to determine the path for data packets, operating at the Network Layer (Layer 3). Switches operate at the Data Link Layer (Layer 2)."
    },
    {
      question: "A firewall that filters traffic based on established connections is known as a:",
      answers: [
        { text: "Packet-filtering firewall", correct: false },
        { text: "Application-layer firewall", correct: false },
        { text: "Stateful firewall", correct: true },
        { text: "Proxy firewall", correct: false }
      ],
      explanation: "A stateful firewall monitors the state of active connections, remembering the context of a session to make filtering decisions, which is more secure than simple packet filtering."
    },
    {
      question: "Which network attack involves the attacker flooding a target with service requests to prevent legitimate users from accessing the service?",
      answers: [
        { text: "Phishing", correct: false },
        { text: "Man-in-the-Middle (MITM)", correct: false },
        { text: "Denial of Service (DoS)", correct: true },
        { text: "SQL Injection", correct: false }
      ],
      explanation: "A Denial of Service (DoS) attack aims to make a machine or network resource unavailable to its intended users by temporarily or indefinitely disrupting the host's services."
    },
    // New questions start here
    {
      question: "What is the primary purpose of a Network Intrusion Detection System (NIDS)?",
      answers: [
        { text: "To block malicious traffic automatically.", correct: false },
        { text: "To encrypt all network traffic.", correct: false },
        { text: "To monitor network traffic for suspicious activity and generate alerts.", correct: true },
        { text: "To filter spam emails.", correct: false }
      ],
      explanation: "A NIDS passively analyzes network traffic to identify potential attacks or policy violations and alerts an administrator. It does not typically block traffic itself."
    },
    {
      question: "Which protocol is used to securely transmit data over a VPN by providing encryption and authentication?",
      answers: [
        { text: "HTTP", correct: false },
        { text: "FTP", correct: false },
        { text: "IPsec", correct: true },
        { text: "SNMP", correct: false }
      ],
      explanation: "IPsec (Internet Protocol Security) is a suite of protocols used to secure Internet Protocol (IP) communications by authenticating and encrypting each IP packet in a data stream."
    },
    {
      question: "What is ARP Spoofing (or ARP Poisoning)?",
      answers: [
        { text: "Flooding a network with ARP requests.", correct: false },
        { text: "Sending falsified ARP messages to link an attacker's MAC address with a legitimate IP address.", correct: true },
        { text: "Intercepting DNS queries.", correct: false },
        { text: "Exploiting a buffer overflow in the ARP protocol.", correct: false }
      ],
      explanation: "ARP Spoofing allows an attacker to associate their MAC address with the IP address of another host (like the default gateway), causing traffic to be sent to the attacker instead."
    },
    {
      question: "A distributed denial-of-service (DDoS) attack differs from a standard DoS attack in that it:",
      answers: [
        { text: "Uses only one powerful machine.", correct: false },
        { text: "Originates from a large number of compromised systems (a botnet).", correct: true },
        { text: "Is easier to stop.", correct: false },
        { text: "Targets only application servers.", correct: false }
      ],
      explanation: "A DDoS attack uses multiple distributed sources (often a botnet of zombies) to launch a coordinated attack, making it much harder to mitigate than a single-source DoS attack."
    },
    {
      question: "What is the main security function of a switch's port security feature?",
      answers: [
        { text: "To encrypt data between switches.", correct: false },
        { text: "To prevent MAC address flooding and spoofing.", correct: true },
        { text: "To block IP-based attacks.", correct: false },
        { text: "To filter web content.", correct: false }
      ],
      explanation: "Port security restricts the MAC addresses that can send traffic on a physical switch port, mitigating attacks like MAC flooding which aim to turn the switch into a 'hub'."
    },
    {
      question: "Which port is commonly associated with the Secure Shell (SSH) protocol?",
      answers: [
        { text: "TCP Port 21", correct: false },
        { text: "TCP Port 22", correct: true },
        { text: "TCP Port 23", correct: false },
        { text: "TCP Port 25", correct: false }
      ],
      explanation: "TCP Port 22 is the standard port for SSH, which provides a secure encrypted channel for remote device administration, replacing the insecure Telnet (Port 23)."
    },
    {
      question: "What does a 'DMZ' (Demilitarized Zone) represent in network architecture?",
      answers: [
        { text: "A highly secure, isolated network for internal servers.", correct: false },
        { text: "A segmented, semi-trusted network that hosts public-facing services.", correct: true },
        { text: "The core internal network where workstations reside.", correct: false },
        { text: "The wireless network for guests.", correct: false }
      ],
      explanation: "A DMZ is a physical or logical subnetwork that contains an organization's external-facing services (e.g., web, email servers), providing an additional layer of security from the internal network."
    },
    {
      question: "The practice of labeling packets with a specific priority or class of service is called:",
      answers: [
        { text: "VLAN Tagging", correct: false },
        { text: "Quality of Service (QoS)", correct: true },
        { text: "Port Mirroring", correct: false },
        { text: "Traffic Shaping", correct: false }
      ],
      explanation: "QoS manages network resources by assigning priorities to different types of traffic (e.g., voice, video), ensuring critical services have the bandwidth and low latency they need."
    },
    {
      question: "What is the primary risk of using the deprecated WEP protocol for wireless security?",
      answers: [
        { text: "It is too slow for modern networks.", correct: false },
        { text: "It uses weak encryption that can be broken in minutes.", correct: true },
        { text: "It is incompatible with all modern devices.", correct: false },
        { text: "It requires expensive hardware.", correct: false }
      ],
      explanation: "WEP has critical cryptographic flaws that make it vulnerable to attacks, allowing an attacker to recover the network key with minimal effort. It should never be used."
    },
    {
      question: "Which wireless security protocol is currently considered the most secure for WPA2?",
      answers: [
        { text: "TKIP", correct: false },
        { text: "WEP", correct: false },
        { text: "AES-CCMP", correct: true },
        { text: "RSA", correct: false }
      ],
      explanation: "For WPA2, the AES-CCMP (Advanced Encryption Standard - Counter Mode Cipher Block Chaining Message Authentication Code Protocol) encryption mechanism is the strong, recommended standard."
    },
    {
      question: "What network tool is used to capture and analyze packets traversing the network?",
      answers: [
        { text: "Nmap", correct: false },
        { text: "Wireshark", correct: true },
        { text: "Nessus", correct: false },
        { text: "Metasploit", correct: false }
      ],
      explanation: "Wireshark is a widely-used network protocol analyzer that lets you see what's happening on your network at a microscopic level by capturing and displaying packet data."
    },
    {
      question: "What is the purpose of 802.1X in network access control?",
      answers: [
        { text: "To provide wireless encryption.", correct: false },
        { text: "To create virtual LANs.", correct: false },
        { text: "To provide port-based authentication for devices trying to connect to a LAN.", correct: true },
        { text: "To assign IP addresses automatically.", correct: false }
      ],
      explanation: "IEEE 802.1X is a standard for port-based Network Access Control (NAC). It prevents a device from accessing the network until it successfully authenticates, often using a RADIUS server."
    },
    {
      question: "A 'Ping of Death' attack is a type of attack that involves:",
      answers: [
        { text: "Sending an endless stream of ping requests.", correct: false },
        { text: "Sending a malformed or oversized ping packet to crash a system.", correct: true },
        { text: "Spoofing the source IP of a ping packet.", correct: false },
        { text: "Using ping to map a network.", correct: false }
      ],
      explanation: "The Ping of Death sends an IP packet larger than the maximum allowed 65,536 bytes, which can crash, freeze, or reboot vulnerable systems due to buffer overflows."
    },
    {
      question: "What security mechanism can be used to prevent a switch from forwarding BPDU frames that could be used to manipulate the Spanning Tree Protocol?",
      answers: [
        { text: "BPDU Guard", correct: true },
        { text: "Root Guard", correct: false },
        { text: "DHCP Snooping", correct: false },
        { text: "Dynamic ARP Inspection", correct: false }
      ],
      explanation: "BPDU Guard disables a port if it receives a BPDU (Bridge Protocol Data Unit), preventing an attacker from introducing a rogue switch that could become the root bridge and cause a topology change."
    },
    {
      question: "Which protocol is vulnerable to the 'Man-in-the-Middle' attack because it does not provide encryption?",
      answers: [
        { text: "HTTPS", correct: false },
        { text: "SSH", correct: false },
        { text: "Telnet", correct: true },
        { text: "IPsec", correct: false }
      ],
      explanation: "Telnet transmits all data, including usernames and passwords, in plaintext. This allows anyone on the network path to intercept and read the communication."
    },
    {
      question: "What is the main purpose of a 'Honeypot'?",
      answers: [
        { text: "To act as a decoy system to attract and study attackers.", correct: true },
        { text: "To store encrypted passwords.", correct: false },
        { text: "To serve as the primary web server.", correct: false },
        { text: "To automatically patch vulnerabilities.", correct: false }
      ],
      explanation: "A honeypot is a security mechanism designed to lure attackers away from legitimate systems and gather information about their tactics, techniques, and procedures."
    },
    {
      question: "Network segmentation primarily enhances security by:",
      answers: [
        { text: "Increasing internet speed.", correct: false },
        { text: "Containing breaches and limiting lateral movement.", correct: true },
        { text: "Making backups easier.", correct: false },
        { text: "Simplifying user management.", correct: false }
      ],
      explanation: "By dividing a network into smaller segments (e.g., using VLANs or firewalls), an attacker who compromises one segment is hindered from easily moving to others."
    },
    {
      question: "What type of DNS record is used to map a hostname to an IPv4 address?",
      answers: [
        { text: "AAAA Record", correct: false },
        { text: "CNAME Record", correct: false },
        { text: "MX Record", correct: false },
        { text: "A Record", correct: true }
      ],
      explanation: "An 'A' (Address) record is the fundamental DNS record that maps a domain name to the IP address (IPv4) of the server hosting the domain."
    },
    {
      question: "A 'DNS Cache Poisoning' attack works by:",
      answers: [
        { text: "Overloading the DNS server with requests.", correct: false },
        { text: "Exploiting a buffer overflow in the DNS server software.", correct: false },
        { text: "Injecting fraudulent DNS records into a resolver's cache.", correct: true },
        { text: "Changing the hosts file on a local computer.", correct: false }
      ],
      explanation: "In DNS cache poisoning, an attacker tricks a DNS server into caching incorrect mapping data, redirecting users to malicious sites without their knowledge."
    },
    {
      question: "What is the primary security benefit of using NAT (Network Address Translation)?",
      answers: [
        { text: "It encrypts all outbound traffic.", correct: false },
        { text: "It hides internal IP addresses from the public internet.", correct: true },
        { text: "It prevents all inbound connections.", correct: false },
        { text: "It authenticates users on the network.", correct: false }
      ],
      explanation: "NAT obscures internal network structure by mapping multiple private IP addresses to a single public IP. This makes it harder for an external attacker to directly target internal hosts."
    },
    {
      question: "Which tool is commonly used for network discovery and security auditing by sending crafted packets and analyzing responses?",
      answers: [
        { text: "Wireshark", correct: false },
        { text: "Nmap", correct: true },
        { text: "John the Ripper", correct: false },
        { text: "Burp Suite", correct: false }
      ],
      explanation: "Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It uses raw IP packets to determine what hosts are available, what services they offer, and what firewalls are in use."
    },
    {
      question: "What does the 'S' in HTTPS stand for, and what does it provide?",
      answers: [
        { text: "Simple; it makes the protocol easier to use.", correct: false },
        { text: "Secure; it provides encryption and authentication for web traffic.", correct: true },
        { text: "Speed; it accelerates web page loading.", correct: false },
        { text: "Service; it denotes a web service.", correct: false }
      ],
      explanation: "HTTPS (Hypertext Transfer Protocol Secure) uses TLS/SSL to encrypt data between the web browser and the server, protecting it from eavesdropping and tampering."
    },
    {
      question: "What is a 'SYN Flood' attack?",
      answers: [
        { text: "Sending a flood of emails to a mail server.", correct: false },
        { text: "Exploiting the three-way handshake by sending SYN packets but not completing the connection.", correct: true },
        { text: "Flooding a network with ARP reply packets.", correct: false },
        { text: "Overloading a DNS server with queries.", correct: false }
      ],
      explanation: "In a SYN flood, an attacker sends a rapid succession of SYN requests to a target, which then allocates resources for these half-open connections, eventually exhausting resources for legitimate users."
    },
    {
      question: "What is the key difference between an Intrusion Detection System (IDS) and an Intrusion Prevention System (IPS)?",
      answers: [
        { text: "An IDS is more expensive than an IPS.", correct: false },
        { text: "An IDS can block traffic, while an IPS cannot.", correct: false },
        { text: "An IDS monitors and alerts, while an IPS can actively block or prevent detected threats.", correct: true },
        { text: "An IPS is only used for wireless networks.", correct: false }
      ],
      explanation: "An IDS is a monitoring system, while an IPS is a control system. An IPS is placed in-line and can take automated actions like dropping packets or resetting connections to stop an attack."
    }
  ],
  "Cryptography": [
    {
      question: "Which cryptographic primitive uses a single key for both encryption and decryption?",
      answers: [
        { text: "Asymmetric Encryption", correct: false },
        { text: "Public Key Infrastructure (PKI)", correct: false },
        { text: "Symmetric Encryption", correct: true },
        { text: "Hashing", correct: false }
      ],
      explanation: "Symmetric encryption, like AES, uses the same secret key to scramble and unscramble the data. Asymmetric (public-key) encryption uses a key pair (public and private)."
    },
    {
      question: "What is the primary function of a cryptographic hash function like SHA-256?",
      answers: [
        { text: "To encrypt data for storage.", correct: false },
        { text: "To verify data integrity and authenticity.", correct: true },
        { text: "To securely transmit data over a network.", correct: false },
        { text: "To compress a file.", correct: false }
      ],
      explanation: "A hash function generates a unique fixed-length output (digest) for any input. If the input changes even slightly, the output changes drastically, making it perfect for verifying data integrity."
    },
    {
      question: "In PKI, which key is kept secret by the owner?",
      answers: [
        { text: "The Public Key", correct: false },
        { text: "The Private Key", correct: true },
        { text: "The Session Key", correct: false },
        { text: "The Symmetric Key", correct: false }
      ],
      explanation: "The private key is held securely by the owner and is used for decrypting messages and creating digital signatures. The public key is freely distributed."
    },
    // New questions start here
    {
      question: "What is the main advantage of asymmetric cryptography over symmetric cryptography?",
      answers: [
        { text: "It is significantly faster for bulk data encryption.", correct: false },
        { text: "It eliminates the need for secure key exchange.", correct: true },
        { text: "It uses simpler mathematical operations.", correct: false },
        { text: "It produces smaller ciphertexts.", correct: false }
      ],
      explanation: "Asymmetric cryptography solves the key distribution problem of symmetric crypto. Since the public key can be shared openly, two parties can establish secure communication without a pre-shared secret."
    },
    {
      question: "Which of the following is a fundamental property of a secure cryptographic hash function?",
      answers: [
        { text: "It is reversible.", correct: false },
        { text: "It is computationally infeasible to find two different inputs that produce the same output.", correct: true },
        { text: "The output is always shorter than the input.", correct: false },
        { text: "It requires a secret key.", correct: false }
      ],
      explanation: "This property is known as 'collision resistance'. If it's easy to find collisions, the hash function is considered broken and unsuitable for most security applications."
    },
    {
      question: "What is the purpose of a digital signature?",
      answers: [
        { text: "To encrypt a message so only the recipient can read it.", correct: false },
        { text: "To provide authenticity, integrity, and non-repudiation of a message.", correct: true },
        { text: "To compress a message for faster transmission.", correct: false },
        { text: "To hide the existence of a message.", correct: false }
      ],
      explanation: "A digital signature, created with the sender's private key, proves who sent the message, that it hasn't been altered, and that the sender cannot deny having sent it (non-repudiation)."
    },
    {
      question: "Which algorithm is a common example of symmetric-key encryption?",
      answers: [
        { text: "RSA", correct: false },
        { text: "Elliptic Curve Cryptography (ECC)", correct: false },
        { text: "Advanced Encryption Standard (AES)", correct: true },
        { text: "Digital Signature Algorithm (DSA)", correct: false }
      ],
      explanation: "AES is a widely adopted and trusted symmetric encryption algorithm used globally for securing sensitive data. RSA and ECC are asymmetric algorithms."
    },
    {
      question: "In a hybrid cryptosystem, what is the typical role of asymmetric encryption?",
      answers: [
        { text: "To encrypt the entire bulk message.", correct: false },
        { text: "To securely exchange the symmetric session key.", correct: true },
        { text: "To create a hash of the message.", correct: false },
        { text: "To authenticate the user's password.", correct: false }
      ],
      explanation: "Hybrid systems combine the strengths of both types: asymmetric encryption (like RSA) is used to securely transmit a symmetric key, which is then used with a faster symmetric algorithm (like AES) to encrypt the actual data."
    },
    {
      question: "What is the 'salt' in password hashing primarily used for?",
      answers: [
        { text: "To make the password longer.", correct: false },
        { text: "To make the hash output more aesthetically pleasing.", correct: false },
        { text: "To defend against precomputed rainbow table attacks.", correct: true },
        { text: "To encrypt the password hash.", correct: false }
      ],
      explanation: "A salt is a random value unique to each password. It is combined with the password before hashing, ensuring that even identical passwords have different hashes, thus nullifying precomputed attack tables."
    },
    {
      question: "Which of these is an example of an asymmetric encryption algorithm?",
      answers: [
        { text: "3DES", correct: false },
        { text: "Blowfish", correct: false },
        { text: "RSA", correct: true },
        { text: "SHA-3", correct: false }
      ],
      explanation: "RSA (Rivest–Shamir–Adleman) is one of the first and most widely used public-key cryptosystems. 3DES and Blowfish are symmetric ciphers, and SHA-3 is a hash function."
    },
    {
      question: "The process of proving one's knowledge of a secret (like a password) without revealing the secret itself is known as:",
      answers: [
        { text: "Zero-Knowledge Proof", correct: true },
        { text: "Steganography", correct: false },
        { text: "Obfuscation", correct: false },
        { text: "Digital Signing", correct: false }
      ],
      explanation: "A zero-knowledge proof allows one party (the prover) to prove to another (the verifier) that they know a value, without conveying any information apart from the fact that they know it."
    },
    {
      question: "What is a 'nonce' in the context of cryptography?",
      answers: [
        { text: "A type of symmetric cipher.", correct: false },
        { text: "A number used once to ensure the freshness of a communication and prevent replay attacks.", correct: true },
        { text: "A corrupted private key.", correct: false },
        { text: "An encrypted message.", correct: false }
      ],
      explanation: "A nonce is an arbitrary number that can be used just once in a cryptographic communication. It is critical for ensuring that old communications cannot be reused in replay attacks."
    },
    {
      question: "What cryptographic concept does 'Perfect Forward Secrecy' (PFS) provide?",
      answers: [
        { text: "Protection against quantum computer attacks.", correct: false },
        { text: "Ensuring that the compromise of a long-term private key does not compromise past session keys.", correct: true },
        { text: "Guaranteeing that data is never lost.", correct: false },
        { text: "Making encryption unbreakable forever.", correct: false }
      ],
      explanation: "PFS ensures that even if an attacker records an encrypted session and later obtains the server's private key, they cannot decrypt the recorded session. This is achieved by using ephemeral session keys."
    },
    {
      question: "Which protocol is commonly used to create a secure channel over an insecure network, like the internet, and often utilizes PFS?",
      answers: [
        { text: "HTTP", correct: false },
        { text: "FTP", correct: false },
        { text: "TLS (Transport Layer Security)", correct: true },
        { text: "SNMP", correct: false }
      ],
      explanation: "TLS (and its predecessor, SSL) is the standard protocol for encrypting web traffic (HTTPS). Modern TLS configurations can and should implement Perfect Forward Secrecy."
    },
    {
      question: "What is the primary vulnerability of using the ECB (Electronic Codebook) mode of operation for a block cipher?",
      answers: [
        { text: "It is too slow.", correct: false },
        { text: "Identical plaintext blocks result in identical ciphertext blocks, revealing patterns.", correct: true },
        { text: "It requires too much memory.", correct: false },
        { text: "It uses asymmetric encryption.", correct: false }
      ],
      explanation: "ECB mode is considered insecure because it does not hide data patterns well. For example, in an image encrypted with ECB, the outline of the original image might still be visible."
    },
    {
      question: "What is the main purpose of a 'Certificate Authority' (CA) in Public Key Infrastructure (PKI)?",
      answers: [
        { text: "To generate private keys for all users.", correct: false },
        { text: "To act as a trusted third party that issues and verifies digital certificates.", correct: true },
        { text: "To encrypt emails for users.", correct: false },
        { text: "To perform cryptographic hashing.", correct: false }
      ],
      explanation: "A CA is a trusted entity that signs digital certificates, thereby binding a public key to an identity. This allows users to trust that a public key genuinely belongs to the claimed owner."
    },
    {
      question: "The practice of hiding a secret message within an ordinary, non-secret file or message is called:",
      answers: [
        { text: "Cryptography", correct: false },
        { text: "Encryption", correct: false },
        { text: "Steganography", correct: true },
        { text: "Obfuscation", correct: false }
      ],
      explanation: "Steganography is about concealing the existence of the message itself (e.g., hiding text in an image), whereas cryptography is about concealing the content of a message."
    },
    {
      question: "Which of the following describes a 'rainbow table' attack?",
      answers: [
        { text: "A brute-force attack that tries every possible key.", correct: false },
        { text: "An attack that uses a precomputed table of hash values to reverse password hashes.", correct: true },
        { text: "An attack that exploits a flaw in the random number generator.", correct: false },
        { text: "An attack on the SSL/TLS handshake process.", correct: false }
      ],
      explanation: "A rainbow table is a precomputed table for reversing cryptographic hash functions. It's a time-memory trade-off, used to crack password hashes quickly, unless the passwords are salted."
    },
    {
      question: "What is the difference between a stream cipher and a block cipher?",
      answers: [
        { text: "Stream ciphers are always more secure.", correct: false },
        { text: "Stream ciphers encrypt data one bit/byte at a time, while block ciphers encrypt fixed-length groups of bits.", correct: true },
        { text: "Block ciphers are only used for hashing.", correct: false },
        { text: "Stream ciphers are a type of asymmetric encryption.", correct: false }
      ],
      explanation: "Stream ciphers (like RC4) typically execute faster in hardware and are used in real-time communications. Block ciphers (like AES) operate on fixed-size blocks and are more common for data-at-rest encryption."
    },
    {
      question: "What does 'key stretching' accomplish in cryptography?",
      answers: [
        { text: "It makes a short key longer to increase the keyspace.", correct: false },
        { text: "It increases the time required to test each possible password in a brute-force attack.", correct: true },
        { text: "It compresses the key for storage.", correct: false },
        { text: "It converts a symmetric key into an asymmetric key pair.", correct: false }
      ],
      explanation: "Key stretching techniques (like PBKDF2, bcrypt) intentionally slow down the key derivation process, making offline password cracking attempts much more resource-intensive and time-consuming."
    },
    {
      question: "Which algorithm is commonly used for generating digital signatures?",
      answers: [
        { text: "AES", correct: false },
        { text: "RSA", correct: true },
        { text: "MD5", correct: false },
        { text: "RC4", correct: false }
      ],
      explanation: "The RSA algorithm can be used for both encryption and creating digital signatures. The signature is created by encrypting a hash of the message with the sender's private key."
    },
    {
      question: "What is a 'digital certificate'?",
      answers: [
        { text: "A document that proves ownership of a physical asset.", correct: false },
        { text: "An electronic document that uses a digital signature to bind a public key with an identity.", correct: true },
        { text: "A license to use cryptographic software.", correct: false },
        { text: "A hash of a user's private key.", correct: false }
      ],
      explanation: "A digital certificate (or public key certificate) is issued by a Certificate Authority (CA) and contains the public key, owner's identity, and the CA's digital signature, establishing trust."
    },
    {
      question: "The cryptographic attack that involves observing the operation of a device to deduce information about secrets (like keys) is called:",
      answers: [
        { text: "A social engineering attack.", correct: false },
        { text: "A side-channel attack.", correct: true },
        { text: "A chosen-plaintext attack.", correct: false },
        { text: "A man-in-the-middle attack.", correct: false }
      ],
      explanation: "Side-channel attacks do not attack the mathematical properties of the algorithm, but rather its physical implementation, using information such as timing, power consumption, or sound emissions."
    },
    {
      question: "What is the main cryptographic weakness of the WPA2-Personal security protocol?",
      answers: [
        { text: "It uses weak AES encryption.", correct: false },
        { text: "It is vulnerable to offline brute-force or dictionary attacks on the pre-shared key (PSK).", correct: true },
        { text: "It does not use encryption.", correct: false },
        { text: "It uses a broken hash function.", correct: false }
      ],
      explanation: "While the four-way handshake in WPA2 is secure, an attacker can capture the handshake and then attempt to crack the pre-shared key (Wi-Fi password) offline without being on the network."
    },
    {
      question: "Which property ensures that a hash function's output provides no clue about the input?",
      answers: [
        { text: "Collision Resistance", correct: false },
        { text: "Avalanche Effect", correct: true },
        { text: "Pre-image Resistance", correct: false },
        { text: "Non-repudiation", correct: false }
      ],
      explanation: "The avalanche effect means that a small change in the input (even a single bit) should cause a drastic change in the output (about half the bits change), making the output appear random and unrelated to the input."
    },
    {
      question: "What is the purpose of a 'Message Authentication Code' (MAC)?",
      answers: [
        { text: "To encrypt a message for confidentiality.", correct: false },
        { text: "To provide integrity and authenticity assurance for a message using a shared secret key.", correct: true },
        { text: "To compress a message.", correct: false },
        { text: "To create a non-repudiable signature.", correct: false }
      ],
      explanation: "A MAC (e.g., HMAC) is a cryptographic checksum that is generated using a secret key and the message. The recipient can verify the message's integrity and authenticity by recomputing the MAC with the same key."
    },
    {
      question: "Which of the following is a significant threat that quantum computing poses to current cryptography?",
      answers: [
        { text: "It can break symmetric ciphers like AES-256 instantly.", correct: false },
        { text: "It can efficiently solve the integer factorization problem, breaking RSA.", correct: true },
        { text: "It can reverse any hash function.", correct: false },
        { text: "It makes all encryption obsolete.", correct: false }
      ],
      explanation: "Shor's algorithm, run on a sufficiently powerful quantum computer, could efficiently solve the mathematical problems (like integer factorization and discrete logarithms) that underpin RSA and ECC, breaking them. Symmetric ciphers are less affected but require larger key sizes."
    }
  ],
  "Malware & Attack Types": [
    {
      question: "Which type of malware disguises itself as a legitimate file or program?",
      answers: [
        { text: "Worm", correct: false },
        { text: "Trojan Horse", correct: true },
        { text: "Rootkit", correct: false },
        { text: "Adware", correct: false }
      ],
      explanation: "A Trojan Horse is a malicious program that appears harmless or legitimate. Unlike a virus or worm, it typically does not replicate itself."
    },
    {
      question: "What technique tricks a user into entering credentials on a malicious website that mimics a legitimate one?",
      answers: [
        { text: "Cross-Site Scripting (XSS)", correct: false },
        { text: "Phishing", correct: true },
        { text: "Vishing", correct: false },
        { text: "Smishing", correct: false }
      ],
      explanation: "Phishing is the fraudulent attempt to obtain sensitive information like usernames, passwords, and credit card details by disguising oneself as a trustworthy entity in an electronic communication."
    },
    {
      question: "A virus that hides itself within the boot sector of a hard drive is known as a:",
      answers: [
        { text: "Macro virus", correct: false },
        { text: "Polymorphic virus", correct: false },
        { text: "Boot sector virus", correct: true },
        { text: "File infector virus", correct: false }
      ],
      explanation: "Boot sector viruses modify the code in the initial sector of a hard disk (the Master Boot Record) to load the virus before the operating system boots."
    },
    // New questions start here
    {
      question: "What type of malware encrypts a victim's files and demands a ransom for the decryption key?",
      answers: [
        { text: "Spyware", correct: false },
        { text: "Ransomware", correct: true },
        { text: "Keylogger", correct: false },
        { text: "Botnet", correct: false }
      ],
      explanation: "Ransomware is a type of malware that blocks access to a system or its data until a ransom is paid. Modern ransomware typically uses strong encryption to lock the files."
    },
    {
      question: "Which malware type is designed to spread across a network without requiring user interaction?",
      answers: [
        { text: "Trojan", correct: false },
        { text: "Worm", correct: true },
        { text: "Virus", correct: false },
        { text: "Adware", correct: false }
      ],
      explanation: "A computer worm is a standalone malware program that replicates itself in order to spread to other computers, often exploiting vulnerabilities in network services."
    },
    {
      question: "What is a 'logic bomb'?",
      answers: [
        { text: "Malware that spreads through logical network partitions.", correct: false },
        { text: "A piece of code that lies dormant until a specific condition or time is met.", correct: true },
        { text: "A virus that causes system components to overheat.", correct: false },
        { text: "A social engineering attack that uses complex reasoning.", correct: false }
      ],
      explanation: "A logic bomb is a malicious program that remains hidden until a specific logical condition is met, such as a certain date, time, or the deletion of a specific user."
    },
    {
      question: "An attack that injects malicious scripts into otherwise benign and trusted websites is called:",
      answers: [
        { text: "SQL Injection", correct: false },
        { text: "Cross-Site Scripting (XSS)", correct: true },
        { text: "Cross-Site Request Forgery (CSRF)", correct: false },
        { text: "Phishing", correct: false }
      ],
      explanation: "In an XSS attack, an attacker injects client-side scripts into web pages viewed by other users. The code executes in the victim's browser, allowing the attacker to steal cookies or perform actions on their behalf."
    },
    {
      question: "What type of attack forces a user's browser to execute an unwanted action on a trusted site where they are authenticated?",
      answers: [
        { text: "Cross-Site Scripting (XSS)", correct: false },
        { text: "SQL Injection (SQLi)", correct: false },
        { text: "Cross-Site Request Forgery (CSRF)", correct: true },
        { text: "Man-in-the-Middle (MitM)", correct: false }
      ],
      explanation: "CSRF tricks the victim into submitting a malicious request. It uses the victim's existing authentication credentials (like session cookies) to perform an action without their consent, such as changing their password or making a transfer."
    },
    {
      question: "What is the primary purpose of spyware?",
      answers: [
        { text: "To damage hardware components.", correct: false },
        { text: "To secretly gather information about a person or organization.", correct: true },
        { text: "To use system resources for cryptocurrency mining.", correct: false },
        { text: "To display unwanted advertisements.", correct: false }
      ],
      explanation: "Spyware is software that aims to gather information about a person or organization without their knowledge and send that information to another entity."
    },
    {
      question: "A collection of compromised computers (zombies) controlled by an attacker is known as a:",
      answers: [
        { text: "Wormnet", correct: false },
        { text: "Botnet", correct: true },
        { text: "Trojan Network", correct: false },
        { text: "Virus Cluster", correct: false }
      ],
      explanation: "A botnet is a network of private computers infected with malicious software and controlled as a group without the owners' knowledge, often used for DDoS attacks or sending spam."
    },
    {
      question: "What type of malware is specifically designed to hide the existence of other malware?",
      answers: [
        { text: "Trojan", correct: false },
        { text: "Rootkit", correct: true },
        { text: "Ransomware", correct: false },
        { text: "Adware", correct: false }
      ],
      explanation: "A rootkit is a collection of software tools that enables unauthorized access to a computer and is designed to hide its presence or the presence of other software from normal detection methods."
    },
    {
      question: "What is a 'keylogger'?",
      answers: [
        { text: "Malware that logs system errors.", correct: false },
        { text: "Hardware or software that records every keystroke made by a user.", correct: true },
        { text: "A virus that corrupts keyboard drivers.", correct: false },
        { text: "A tool for managing encryption keys.", correct: false }
      ],
      explanation: "A keylogger is a type of surveillance technology used to monitor and record each keystroke typed on a specific computer's keyboard, often used to steal passwords and other sensitive data."
    },
    {
      question: "An attack that manipulates a database through unsanitized user input is a:",
      answers: [
        { text: "Cross-Site Scripting (XSS) attack", correct: false },
        { text: "SQL Injection (SQLi) attack", correct: true },
        { text: "Buffer Overflow attack", correct: false },
        { text: "LDAP Injection attack", correct: false }
      ],
      explanation: "SQL Injection occurs when an attacker is able to insert or 'inject' a malicious SQL query via the input data from the client to the application, potentially allowing them to view, manipulate, or delete database data."
    },
    {
      question: "What is 'cryptojacking'?",
      answers: [
        { text: "Hijacking a cryptographic key.", correct: false },
        { text: "Stealing cryptocurrency from a digital wallet.", correct: false },
        { text: "The unauthorized use of someone's computing resources to mine cryptocurrency.", correct: true },
        { text: "Breaking cryptocurrency encryption.", correct: false }
      ],
      explanation: "Cryptojacking involves secretly using a victim's computing power (CPU/GPU) to generate cryptocurrency for the attacker. It can be done through malware or by running scripts in a user's browser."
    },
    {
      question: "What is a 'polymorphic virus'?",
      answers: [
        { text: "A virus that infects multiple file types.", correct: false },
        { text: "A virus that changes its own code to avoid detection by signature-based antivirus.", correct: true },
        { text: "A virus that spreads through polymorphic networks.", correct: false },
        { text: "A virus that can run on multiple operating systems.", correct: false }
      ],
      explanation: "A polymorphic virus encrypts its code differently each time it infects a new system, using a mutation engine. This changes its 'signature,' making it harder for traditional antivirus software to detect."
    },
    {
      question: "What is the main characteristic of a 'fileless' malware attack?",
      answers: [
        { text: "It does not use any malicious code.", correct: false },
        { text: "It operates in memory without writing files to disk.", correct: true },
        { text: "It deletes all files on the system.", correct: false },
        { text: "It is invisible to the naked eye.", correct: false }
      ],
      explanation: "Fileless malware resides exclusively in the computer's memory (RAM), leveraging legitimate system tools and processes (like PowerShell or WMI) to execute its payload, leaving little to no trace on the hard drive."
    },
    {
      question: "What does 'APT' stand for in the context of cyber threats?",
      answers: [
        { text: "Automated Penetration Testing", correct: false },
        { text: "Advanced Persistent Threat", correct: true },
        { text: "Application Protocol Transfer", correct: false },
        { text: "Anti-Piracy Technology", correct: false }
      ],
      explanation: "An Advanced Persistent Threat (APT) is a prolonged, targeted cyberattack in which an intruder gains access to a network and remains undetected for an extended period, often with the goal of data exfiltration."
    },
    {
      question: "What is 'vishing'?",
      answers: [
        { text: "Phishing via text message (SMS).", correct: false },
        { text: "Phishing that targets high-level executives.", correct: false },
        { text: "Phishing conducted over voice calls, typically using VoIP.", correct: true },
        { text: "Phishing that uses highly visual emails.", correct: false }
      ],
      explanation: "Vishing, or voice phishing, is a social engineering attack where the attacker uses phone calls to trick individuals into revealing sensitive information, often by impersonating a trusted entity like a bank or tech support."
    },
    {
      question: "What is 'smishing'?",
      answers: [
        { text: "Phishing via text message (SMS).", correct: true },
        { text: "Phishing that uses smoke signals.", correct: false },
        { text: "A hybrid of spam and phishing.", correct: false },
        { text: "Phishing that targets social media platforms.", correct: false }
      ],
      explanation: "Smishing (SMS phishing) uses text messages to lure victims into clicking malicious links, calling fraudulent phone numbers, or revealing personal information."
    },
    {
      question: "An attack that intercepts and potentially alters communication between two parties is a:",
      answers: [
        { text: "Denial-of-Service (DoS) attack", correct: false },
        { text: "Man-in-the-Middle (MitM) attack", correct: true },
        { text: "Replay attack", correct: false },
        { text: "Phishing attack", correct: false }
      ],
      explanation: "In a MitM attack, the attacker secretly relays and possibly alters the communication between two parties who believe they are directly communicating with each other."
    },
    {
      question: "What is 'typosquatting'?",
      answers: [
        { text: "A keylogger that targets typing errors.", correct: false },
        { text: "Registering domain names based on common misspellings of popular websites.", correct: true },
        { text: "A DDoS attack that causes systems to make errors.", correct: false },
        { text: "Malware that auto-corrects text to malicious links.", correct: false }
      ],
      explanation: "Also known as URL hijacking, typosquatting relies on users making typographical errors when entering a website address into a web browser. These fake sites are often used for phishing or ad revenue."
    },
    {
      question: "What is a 'watering hole' attack?",
      answers: [
        { text: "Infecting a website that is frequently visited by a targeted group of users.", correct: true },
        { text: "Poisoning a company's water cooler with malware.", correct: false },
        { text: "A DDoS attack that overwhelms a site with requests, causing it to 'flood'.", correct: false },
        { text: "Phishing attack targeting employees on their lunch break.", correct: false }
      ],
      explanation: "In a watering hole attack, the attacker compromises a site that is likely to be visited by a specific target group. When the target group visits the site, they are infected with malware."
    },
    {
      question: "What type of attack uses a massive, distributed network of devices to overwhelm a target with traffic?",
      answers: [
        { text: "Phishing", correct: false },
        { text: "Distributed Denial-of-Service (DDoS)", correct: true },
        { text: "SQL Injection", correct: false },
        { text: "Man-in-the-Middle", correct: false }
      ],
      explanation: "A DDoS attack uses multiple compromised computer systems (a botnet) as sources of attack traffic. The goal is to exhaust the target's resources (bandwidth, CPU, memory), making it unavailable to legitimate users."
    },
    {
      question: "What is 'adware'?",
      answers: [
        { text: "Malware that creates backdoor access.", correct: false },
        { text: "Software that automatically displays or downloads advertising material.", correct: true },
        { text: "A virus that only affects advertising servers.", correct: false },
        { text: "A tool for blocking ads.", correct: false }
      ],
      explanation: "Adware is software that generates revenue for its developer by automatically displaying online advertisements. While not always malicious, it is often unwanted and can be bundled with spyware."
    },
    {
      question: "What is a 'backdoor' in the context of malware?",
      answers: [
        { text: "A vulnerability in a software's user interface.", correct: false },
        { text: "A method of bypassing normal authentication to gain remote access to a computer.", correct: true },
        { text: "A type of virus that infects backup files.", correct: false },
        { text: "A hardware failure that allows access.", correct: false }
      ],
      explanation: "A backdoor is a covert method of bypassing standard authentication or encryption in a computer system. It can be installed by malware to allow an attacker persistent access."
    },
    {
      question: "What is 'social engineering'?",
      answers: [
        { text: "The process of engineering more sociable software.", correct: false },
        { text: "Manipulating people into performing actions or divulging confidential information.", correct: true },
        { text: "A type of network architecture.", correct: false },
        { text: "Using social media to find software bugs.", correct: false }
      ],
      explanation: "Social engineering is the psychological manipulation of people into performing actions or divulging secrets, exploiting human trust rather than technical hacking techniques. Phishing is a common example."
    },
    {
      question: "What is a 'replay attack'?",
      answers: [
        { text: "An attack that repeatedly plays an annoying sound.", correct: false },
        { text: "A DDoS attack that replays the same request over and over.", correct: false },
        { text: "A fraudulent repetition of a valid data transmission.", correct: true },
        { text: "An attack that targets video streaming services.", correct: false }
      ],
      explanation: "In a replay attack, a valid data transmission is maliciously or fraudulently repeated or delayed. The attacker intercepts and then retransmits the data, often to authenticate themselves as a legitimate user."
    },
    {
      question: "What is 'whaling'?",
      answers: [
        { text: "Phishing attacks that target marine biologists.", correct: false },
        { text: "A type of spear phishing that specifically targets high-profile executives like CEOs or CFOs.", correct: true },
        { text: "Phishing attacks that use very large email attachments.", correct: false },
        { text: "A DDoS attack on a large scale.", correct: false }
      ],
      explanation: "Whaling is a highly targeted form of phishing aimed at senior executives. The content is often crafted to look like a critical business communication, such as a legal subpoena or a board matter, to trick the target into revealing sensitive information or authorizing a large financial transfer."
    }
  ],
  "Web Application Security (OWASP Top 10)": [
    {
      question: "Which OWASP Top 10 category is mitigated by input validation and prepared statements?",
      answers: [
        { text: "Broken Authentication", correct: false },
        { text: "Injection", correct: true },
        { text: "Cross-Site Scripting (XSS)", correct: false },
        { text: "Security Misconfiguration", correct: false }
      ],
      explanation: "Injection attacks (like SQL or command injection) occur when untrusted data is sent to an interpreter. Mitigation involves sanitizing all user input and using parameterized queries."
    },
    {
      question: "The 'S' in HTTPS stands for:",
      answers: [
        { text: "Site", correct: false },
        { text: "Secure", correct: true },
        { text: "Server", correct: false },
        { text: "System", correct: false }
      ],
      explanation: "The 'S' in HTTPS stands for Secure, indicating that communication between the browser and the website is encrypted using SSL/TLS."
    },
    {
      question: "An attack where a malicious script is injected into a trusted website to be executed in the victim's browser is called:",
      answers: [
        { text: "SQL Injection", correct: false },
        { text: "Cross-Site Request Forgery (CSRF)", correct: false },
        { text: "Cross-Site Scripting (XSS)", correct: true },
        { text: "DDoS", correct: false }
      ],
      explanation: "XSS attacks involve injecting client-side scripts (usually JavaScript) into a webpage viewed by other users, allowing the attacker to bypass access controls."
    },
    // New questions start here
    {
      question: "Which OWASP Top 10 category involves flaws that allow attackers to impersonate legitimate users?",
      answers: [
        { text: "Cryptographic Failures", correct: false },
        { text: "Broken Authentication", correct: true },
        { text: "Insecure Design", correct: false },
        { text: "Software and Data Integrity Failures", correct: false }
      ],
      explanation: "Broken Authentication encompasses weaknesses in session management, credential stuffing, and weak password recovery mechanisms that allow attackers to compromise user identities."
    },
    {
      question: "What is the primary defense against Cross-Site Request Forgery (CSRF) attacks?",
      answers: [
        { text: "Input Validation", correct: false },
        { text: "Using HTTPS", correct: false },
        { text: "Anti-CSRF Tokens", correct: true },
        { text: "Web Application Firewalls", correct: false }
      ],
      explanation: "Anti-CSRF tokens are unique, secret, and unpredictable values that are generated by the server-side application and transmitted to the client in a way that is included in subsequent HTTP requests, preventing forged requests."
    },
    {
      question: "Which OWASP category refers to the exposure of sensitive data like passwords or credit card numbers?",
      answers: [
        { text: "Cryptographic Failures", correct: true },
        { text: "Security Misconfiguration", correct: false },
        { text: "Vulnerable and Outdated Components", correct: false },
        { text: "Injection", correct: false }
      ],
      explanation: "Previously known as 'Sensitive Data Exposure,' this category focuses on failures to protect sensitive data in transit and at rest through strong encryption, hashing, and proper key management."
    },
    {
      question: "What does XXE stand for and what is it?",
      answers: [
        { text: "Extended XSS Execution; a more powerful form of XSS.", correct: false },
        { text: "XML External Entity; an attack that exploits XML parsers to read local files or perform SSRF.", correct: true },
        { text: "Cross-Site Execution Endpoint; a type of API vulnerability.", correct: false },
        { text: "External XML Encryption; a flawed encryption method.", correct: false }
      ],
      explanation: "An XML External Entity (XXE) attack exploits vulnerable XML processors by injecting malicious external entity references, which can lead to disclosure of internal files, internal port scanning, or denial of service."
    },
    {
      question: "Which OWASP category is about ensuring proper access controls so users cannot act outside their intended permissions?",
      answers: [
        { text: "Broken Access Control", correct: true },
        { text: "Broken Authentication", correct: false },
        { text: "Insecure Design", correct: false },
        { text: "Security Logging and Monitoring Failures", correct: false }
      ],
      explanation: "Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not properly enforced, allowing attackers to access unauthorized functionality or data (e.g., horizontal/vertical privilege escalation)."
    },
    {
      question: "What is a primary example of a 'Security Misconfiguration'?",
      answers: [
        { text: "Using weak passwords.", correct: false },
        { text: "Running an application with unnecessary privileges or with default accounts enabled.", correct: true },
        { text: "Not using the latest JavaScript framework.", correct: false },
        { text: "Having a complex user interface.", correct: false }
      ],
      explanation: "Security Misconfiguration can include unnecessary enabled features, unpatched flaws, unprotected files and directories, and default accounts with their passwords still enabled."
    },
    {
      question: "What is the main risk associated with 'Vulnerable and Outdated Components'?",
      answers: [
        { text: "They make the website load slower.", correct: false },
        { text: "They can introduce known vulnerabilities that attackers can easily exploit.", correct: true },
        { text: "They are always more expensive to maintain.", correct: false },
        { text: "They are incompatible with modern browsers.", correct: false }
      ],
      explanation: "Using libraries, frameworks, and other software modules with known vulnerabilities (e.g., listed in CVE) allows attackers to use public exploits to compromise the application."
    },
    {
      question: "What is the primary purpose of a Content Security Policy (CSP)?",
      answers: [
        { text: "To ensure website content is high quality.", correct: false },
        { text: "To prevent Cross-Site Scripting (XSS) and data injection attacks.", correct: true },
        { text: "To manage user access to different content sections.", correct: false },
        { text: "To compress web content for faster delivery.", correct: false }
      ],
      explanation: "CSP is a security standard that helps detect and mitigate XSS attacks by allowing developers to whitelist trusted sources of content, preventing the browser from loading assets from untrusted locations."
    },
    {
      question: "Which HTTP header is crucial for enforcing the Same-Origin Policy and preventing certain types of CSRF and data theft?",
      answers: [
        { text: "X-Frame-Options", correct: false },
        { text: "Strict-Transport-Security", correct: false },
        { text: "Content-Security-Policy", correct: false },
        { text: "SameSite Cookie Attribute", correct: true }
      ],
      explanation: "The `SameSite` attribute for cookies can be set to 'Strict' or 'Lax' to prevent the browser from sending the cookie along with cross-site requests, which is a key defense against CSRF attacks."
    },
    {
      question: "What does IDOR stand for?",
      answers: [
        { text: "Insecure Direct Object Reference", correct: true },
        { text: "Incorrect Data Output Response", correct: false },
        { text: "Indirect Database Operation Request", correct: false },
        { text: "Integrated Data Object Risk", correct: false }
      ],
      explanation: "IDOR is a type of Broken Access Control where an application provides direct access to objects (files, DB records) based on user-supplied input, allowing attackers to bypass authorization by modifying the value of a parameter."
    },
    {
      question: "What is the purpose of the `HttpOnly` flag on a cookie?",
      answers: [
        { text: "To ensure the cookie is only sent over HTTPS.", correct: false },
        { text: "To prevent the cookie from being accessed through client-side scripts (JavaScript).", correct: true },
        { text: "To restrict the cookie to the same domain.", correct: false },
        { text: "To make the cookie expire when the browser closes.", correct: false }
      ],
      explanation: "The `HttpOnly` flag is a critical security measure that mitigates the impact of XSS attacks by making cookies inaccessible to the Document.cookie API, thus preventing an attacker from stealing session tokens."
    },
    {
      question: "Which OWASP category involves risks from importing components from untrusted sources or with compromised integrity?",
      answers: [
        { text: "Vulnerable and Outdated Components", correct: false },
        { text: "Software and Data Integrity Failures", correct: true },
        { text: "Server-Side Request Forgery (SSRF)", correct: false },
        { text: "Insecure Design", correct: false }
      ],
      explanation: "This category focuses on failures to verify the integrity of software and data, such as using dependencies from untrusted repositories or accepting unsigned auto-update files, which can lead to supply chain attacks."
    },
    {
      question: "What is a Server-Side Request Forgery (SSRF) attack?",
      answers: [
        { text: "An attack that forges requests from the server to the client.", correct: false },
        { text: "An attack that makes the server send requests to an internal or external resource defined by the attacker.", correct: true },
        { text: "An attack that forces the server to restart.", correct: false },
        { text: "An attack that corrupts server-side data.", correct: false }
      ],
      explanation: "In an SSRF attack, an attacker can trick the server into making a connection to internal services or to arbitrary external systems, potentially exposing internal network data or bypassing firewall controls."
    },
    {
      question: "Which security control is specifically designed to prevent clickjacking?",
      answers: [
        { text: "The X-Content-Type-Options header", correct: false },
        { text: "The X-Frame-Options header", correct: true },
        { text: "The Public-Key-Pins header", correct: false },
        { text: "Input sanitization", correct: false }
      ],
      explanation: "The `X-Frame-Options` HTTP response header can be used to indicate whether a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`, thus protecting against clickjacking."
    },
    {
      question: "What is the main goal of the 'Insecure Design' category in the OWASP Top 10?",
      answers: [
        { text: "To find bugs in the code.", correct: false },
        { text: "To highlight risks related to flaws in the architecture and design of an application.", correct: true },
        { text: "To check if the user interface is user-friendly.", correct: false },
        { text: "To ensure the website is visually appealing.", correct: false }
      ],
      explanation: "Insecure Design focuses on missing or ineffective control design. This is different from 'Implementation' flaws; a secure design can still have implementation bugs, but a flawed design cannot be fixed by perfect implementation."
    },
    {
      question: "What is a primary mitigation for 'Security Logging and Monitoring Failures'?",
      answers: [
        { text: "Using the latest web framework.", correct: false },
        { text: "Ensuring all login attempts, access control failures, and server-side input validation failures are logged and monitored.", correct: true },
        { text: "Hiding all error messages from users.", correct: false },
        { text: "Disabling all logging to improve performance.", correct: false }
      ],
      explanation: "Effective logging and monitoring are essential for detecting, escalating, and responding to active breaches. Without them, attackers can operate unnoticed for long periods."
    },
    {
      question: "What is the difference between Stored (Persistent) XSS and Reflected XSS?",
      answers: [
        { text: "Stored XSS is more difficult to exploit.", correct: false },
        { text: "Reflected XSS is stored on the server, while Stored XSS is not.", correct: false },
        { text: "Stored XSS is persisted on the server (e.g., in a database) and reflected XSS is immediately returned by the server in an error message or search result.", correct: true },
        { text: "There is no significant difference.", correct: false }
      ],
      explanation: "Stored XSS is more critical as the payload is saved and served to multiple victims, while Reflected XSS requires tricking a specific user into clicking a crafted link."
    },
    {
      question: "Which practice is essential to prevent NoSQL injection?",
      answers: [
        { text: "Using prepared statements.", correct: false },
        { text: "Input validation and strict type checking of user input.", correct: true },
        { text: "Installing a network firewall.", correct: false },
        { text: "Disabling JavaScript.", correct: false }
      ],
      explanation: "While prepared statements are for SQL, NoSQL databases require different defenses. Validating and sanitizing input, and using an object-document mapping (ODM) library that enforces a strict schema, are key mitigations."
    },
    {
      question: "What is the purpose of the `Secure` flag on a cookie?",
      answers: [
        { text: "To encrypt the cookie's value.", correct: false },
        { text: "To prevent the cookie from being sent over unencrypted HTTP connections.", correct: true },
        { text: "To make the cookie inaccessible to JavaScript.", correct: false },
        { text: "To ensure the cookie is only used on the same site.", correct: false }
      ],
      explanation: "The `Secure` attribute ensures that the cookie is only sent to the server with an encrypted request over the HTTPS protocol, protecting it from being intercepted during transit."
    },
    {
      question: "What type of vulnerability is exposed when a web application reveals detailed error messages (e.g., stack traces) to users?",
      answers: [
        { text: "Security Misconfiguration", correct: true },
        { text: "Cryptographic Failures", correct: false },
        { text: "Broken Authentication", correct: false },
        { text: "Injection", correct: false }
      ],
      explanation: "Revealing detailed errors to users can provide attackers with valuable information about the application's structure, underlying technology, and potential weaknesses, which is a classic security misconfiguration."
    },
    {
      question: "Which OWASP category would a brute-force login attack fall under?",
      answers: [
        { text: "Identification and Authentication Failures", correct: true },
        { text: "Cryptographic Failures", correct: false },
        { text: "Insecure Design", correct: false },
        { text: "Software and Data Integrity Failures", correct: false }
      ],
      explanation: "The inability to effectively prevent or slow down automated attacks like credential stuffing or brute-forcing is a key failure under 'Identification and Authentication Failures' (formerly Broken Authentication)."
    },
    {
      question: "What is a common security risk associated with JWT (JSON Web Tokens) if not implemented correctly?",
      answers: [
        { text: "They are always too large.", correct: false },
        { text: "The signature is not validated, allowing tampering.", correct: true },
        { text: "They cannot be revoked.", correct: false },
        { text: "They require too much server CPU.", correct: false }
      ],
      explanation: "A critical mistake is failing to verify the signature of the JWT on the server side. If the signature isn't checked, an attacker can alter the token's payload (e.g., change the username to 'admin') and the server will accept it."
    },
    {
      question: "What is the primary security benefit of using the 'Strict' setting for the `SameSite` cookie attribute?",
      answers: [
        { text: "It prevents the cookie from being sent in any cross-site browsing context.", correct: true },
        { text: "It encrypts the cookie value.", correct: false },
        { text: "It makes the cookie expire faster.", correct: false },
        { text: "It allows the cookie to be shared with subdomains.", correct: false }
      ],
      explanation: "A cookie with `SameSite=Strict` will only be sent along with 'same-site' requests, completely preventing it from being sent on cross-site requests. This offers the strongest CSRF protection but can break functionality if a user follows a link from another site to your site while expecting to be logged in."
    },
    {
      question: "Which HTTP security header prevents browsers from MIME-sniffing a response away from the declared content-type?",
      answers: [
        { text: "X-Content-Type-Options", correct: true },
        { text: "Content-Security-Policy", correct: false },
        { text: "X-Frame-Options", correct: false },
        { text: "Referrer-Policy", correct: false }
      ],
      explanation: "The `X-Content-Type-Options: nosniff` header stops the browser from trying to guess the MIME type of a resource, forcing it to use the type declared in the `Content-Type` header. This mitigates certain attacks where a user-uploaded file is misinterpreted as HTML or JavaScript."
    },
    {
      question: "What is a common consequence of an insecure direct object reference (IDOR) vulnerability?",
      answers: [
        { text: "The website becomes unresponsive.", correct: false },
        { text: "An attacker can view or modify another user's data by changing an ID in the URL.", correct: true },
        { text: "User passwords are exposed in plaintext.", correct: false },
        { text: "The server's CPU usage spikes.", correct: false }
      ],
      explanation: "For example, if a URL is `https://example.com/account?user_id=123`, an attacker could change the `user_id` to `124` and potentially access another user's account information if proper authorization checks are not performed on the server."
    }
  ],
  "Incident Response & Forensics": [
    {
      question: "The first phase in a typical Incident Response life cycle is:",
      answers: [
        { text: "Containment", correct: false },
        { text: "Eradication", correct: false },
        { text: "Preparation", correct: true },
        { text: "Recovery", correct: false }
      ],
      explanation: "The common Incident Response phases are: Preparation, Detection & Analysis, Containment, Eradication & Recovery, and Post-Incident Activity (Lessons Learned)."
    },
    {
      question: "What is the most volatile type of digital evidence that should be collected first in forensic analysis?",
      answers: [
        { text: "Hard Drive Data", correct: false },
        { text: "System Logs", correct: false },
        { text: "CPU Cache and Register Contents", correct: true },
        { text: "Router Configurations", correct: false }
      ],
      explanation: "The order of volatility dictates that the most temporary data (like CPU registers and cache) should be collected first, as it is lost quickest."
    },
    {
      question: "Which of the following is an example of an Intrusion Detection System (IDS) that monitors network traffic?",
      answers: [
        { text: "Honeypot", correct: false },
        { text: "NIDS (Network IDS)", correct: true },
        { text: "HIPS (Host IDS)", correct: false },
        { text: "Firewall", correct: false }
      ],
      explanation: "A Network Intrusion Detection System (NIDS) analyzes traffic on a network segment to look for patterns that match known attacks. HIPS monitors a single host system."
    },
    // New questions start here
    {
      question: "What is the primary goal of the 'Containment' phase in incident response?",
      answers: [
        { text: "To completely remove the threat from the environment.", correct: false },
        { text: "To prevent the incident from causing further damage.", correct: true },
        { text: "To identify the root cause of the incident.", correct: false },
        { text: "To restore systems to normal operation.", correct: false }
      ],
      explanation: "Containment is about limiting the scope and impact of an incident. This can involve isolating network segments, disabling accounts, or taking systems offline to prevent the attack from spreading."
    },
    {
      question: "In digital forensics, what does 'write blocking' ensure?",
      answers: [
        { text: "That data can be written to a disk for analysis.", correct: false },
        { text: "That the forensic examiner cannot alter the original evidence during acquisition.", correct: true },
        { text: "That malware is prevented from writing to the disk.", correct: false },
        { text: "That log files are protected from deletion.", correct: false }
      ],
      explanation: "A write blocker is a hardware or software tool that prevents any write commands from being sent to a storage device, preserving the integrity of the original evidence for legal purposes."
    },
    {
      question: "What is a 'Chain of Custody' form used for?",
      answers: [
        { text: "To track the seizure, transfer, and storage of physical evidence.", correct: true },
        { text: "To list the commands used during forensic analysis.", correct: false },
        { text: "To document the containment strategies for an incident.", correct: false },
        { text: "To manage the incident response team's schedule.", correct: false }
      ],
      explanation: "The chain of custody documents every person who handled the evidence, when, and for what purpose. It is critical for proving the evidence has not been tampered with and is admissible in court."
    },
    {
      question: "Which term describes a calculated value that verifies the integrity of a file or disk image?",
      answers: [
        { text: "Checksum", correct: false },
        { text: "Hash", correct: true },
        { text: "Nonce", correct: false },
        { text: "Salt", correct: false }
      ],
      explanation: "A cryptographic hash (like MD5, SHA-1, or SHA-256) produces a unique digital fingerprint of data. If the data changes, the hash changes, proving the evidence is unaltered."
    },
    {
      question: "What is the primary purpose of a 'Forensic Image' of a hard drive?",
      answers: [
        { text: "To create a backup for disaster recovery.", correct: false },
        { text: "To run the operating system in a virtual machine.", correct: false },
        { text: "To have a bit-for-bit copy of the original media for analysis.", correct: true },
        { text: "To compress the data to save storage space.", correct: false }
      ],
      explanation: "A forensic image is a complete, sector-by-sector copy of the original storage device. All analysis is performed on this image to avoid modifying the original evidence."
    },
    {
      question: "During the 'Eradication' phase, what is the key action taken?",
      answers: [
        { text: "Identifying the attacker's identity.", correct: false },
        { text: "Removing the root cause of the incident (e.g., malware, attacker accounts).", correct: true },
        { text: "Notifying law enforcement.", correct: false },
        { text: "Calculating the financial impact of the breach.", correct: false }
      ],
      explanation: "Eradication involves eliminating the components of the incident from the environment. This includes removing malware, disabling breached accounts, and patching vulnerabilities."
    },
    {
      question: "What type of log is most critical for investigating a web server attack?",
      answers: [
        { text: "System Event Logs", correct: false },
        { text: "Web Server Access Logs", correct: true },
        { text: "DNS Query Logs", correct: false },
        { text: "Power Management Logs", correct: false }
      ],
      explanation: "Web server access logs record all HTTP requests, including the source IP, timestamp, requested resource, and user agent. This is essential for identifying malicious requests and understanding the attack vector."
    },
    {
      question: "The principle that all forensic analysis should be conducted without altering the original data is known as:",
      answers: [
        { text: "Chain of Custody", correct: false },
        { text: "Order of Volatility", correct: false },
        { text: "Data Integrity", correct: false },
        { text: "Evidence Preservation", correct: true }
      ],
      explanation: "Evidence preservation is the overarching practice of maintaining the original evidence in an unaltered state, typically achieved by working on forensic copies and using write blockers."
    },
    {
      question: "What is a 'SIEM' system used for in incident response?",
      answers: [
        { text: "Creating forensic images of hard drives.", correct: false },
        { text: "Providing real-time analysis of security alerts from various sources.", correct: true },
        { text: "Acting as a decoy for attackers.", correct: false },
        { text: "Encrypting sensitive data at rest.", correct: false }
      ],
      explanation: "A Security Information and Event Management (SIEM) system aggregates and correlates log data from networks, servers, and applications to help detect, analyze, and respond to security incidents."
    },
    {
      question: "In the NIST Incident Response lifecycle, what is the final phase?",
      answers: [
        { text: "Eradication", correct: false },
        { text: "Post-Incident Activity", correct: true },
        { text: "Recovery", correct: false },
        { text: "Lessons Learned", correct: false }
      ],
      explanation: "The final phase, often called 'Post-Incident Activity' or 'Lessons Learned,' involves creating a report, conducting a retrospective, and implementing improvements to prevent future incidents."
    },
    {
      question: "What does the 'IOC' acronym stand for in cybersecurity?",
      answers: [
        { text: "Index of Compromise", correct: false },
        { text: "Indicator of Compromise", correct: true },
        { text: "Incident of Compromise", correct: false },
        { text: "Integrity of Computer", correct: false }
      ],
      explanation: "An Indicator of Compromise (IOC) is a piece of forensic data, such as a virus signature, IP address, or hash value, that identifies potentially malicious activity on a system or network."
    },
    {
      question: "When should an organization consider involving law enforcement in an incident?",
      answers: [
        { text: "For every single security alert.", correct: false },
        { text: "Only when the incident is fully resolved.", correct: false },
        { text: "When there is evidence of a crime (e.g., data theft, fraud) or a legal requirement to report.", correct: true },
        { text: "Only if the attacker is identified.", correct: false }
      ],
      explanation: "Law enforcement should be involved when the incident constitutes a crime, or when there are regulatory requirements (e.g., for critical infrastructure). Early consultation is often advised."
    },
    {
      question: "What is a 'tabletop exercise' in the context of incident response?",
      answers: [
        { text: "A physical fitness test for the IR team.", correct: false },
        { text: "A simulated incident where team members walk through their roles and responses.", correct: true },
        { text: "An exercise in setting up emergency workstations.", correct: false },
        { text: "A review of the physical security of server racks.", correct: false }
      ],
      explanation: "A tabletop exercise is a discussion-based session where team members review and validate incident response plans by talking through a simulated scenario, identifying gaps in procedures and communication."
    },
    {
      question: "What is the primary purpose of memory forensics (RAM analysis)?",
      answers: [
        { text: "To recover deleted files from the hard drive.", correct: false },
        { text: "To find evidence of malware or attacker activity that only exists in memory.", correct: true },
        { text: "To analyze the system's BIOS settings.", correct: false },
        { text: "To check the health of the RAM hardware.", correct: false }
      ],
      explanation: "Memory forensics can uncover running processes, network connections, encryption keys, and rootkits that are active in RAM but may not be present on the disk, providing a real-time view of system activity."
    },
    {
      question: "What is a 'CSIRT' or 'CIRT'?",
      answers: [
        { text: "A type of firewall rule.", correct: false },
        { text: "A Computer Security Incident Response Team.", correct: true },
        { text: "A cryptographic algorithm.", correct: false },
        { text: "A standard for forensic image formats.", correct: false }
      ],
      explanation: "A CSIRT (Computer Security Incident Response Team) or CIRT (Computer Incident Response Team) is the group of personnel responsible for responding to security incidents."
    },
    {
      question: "During the 'Detection & Analysis' phase, what is a 'false positive'?",
      answers: [
        { text: "A correctly identified security incident.", correct: false },
        { text: "An alert that incorrectly indicates malicious activity.", correct: true },
        { text: "An incident that was missed by monitoring systems.", correct: false },
        { text: "A positive outcome from an incident.", correct: false }
      ],
      explanation: "A false positive is an alert that triggers but is later determined to be benign activity. A high rate of false positives can lead to 'alert fatigue' and cause real incidents to be missed."
    },
    {
      question: "What is the purpose of an 'Incident Response Plan'?",
      answers: [
        { text: "To guarantee that no incidents will ever occur.", correct: false },
        { text: "To provide a predefined set of instructions for detecting, responding to, and recovering from a security incident.", correct: true },
        { text: "To replace the need for security controls.", correct: false },
        { text: "To document the company's financial policies.", correct: false }
      ],
      explanation: "An IR plan is a living document that outlines roles, responsibilities, communication strategies, and procedures to ensure a swift, organized, and effective response to a security incident."
    },
    {
      question: "In forensics, what is 'slack space'?",
      answers: [
        { text: "The time between an incident and its detection.", correct: false },
        { text: "The unused space between the end of a file and the end of the last disk cluster allocated to that file.", correct: true },
        { text: "The memory not used by running applications.", correct: false },
        { text: "The delay in network traffic.", correct: false }
      ],
      explanation: "Slack space can contain remnants of previous files or data and is a valuable source of evidence for forensic investigators, as users are typically unaware of its existence."
    },
    {
      question: "What is the key difference between an IDS and an IPS?",
      answers: [
        { text: "An IDS is more expensive.", correct: false },
        { text: "An IDS monitors and alerts, while an IPS can actively block threats.", correct: true },
        { text: "An IPS only works on networks, while an IDS only works on hosts.", correct: false },
        { text: "An IDS uses signatures, while an IPS uses heuristics.", correct: false }
      ],
      explanation: "An Intrusion Detection System (IDS) is a passive monitoring system. An Intrusion Prevention System (IPS) is an active control system that can drop packets or reset connections to stop an attack in progress."
    },
    {
      question: "Why is documenting every action taken during an investigation critical?",
      answers: [
        { text: "To bill the client for hours worked.", correct: false },
        { text: "For reproducibility, legal admissibility, and to support the investigator's conclusions.", correct: true },
        { text: "To fill out daily time sheets.", correct: false },
        { text: "To create a script for automating future responses.", correct: false }
      ],
      explanation: "Meticulous documentation creates an audit trail that allows others to verify the steps taken, understand the thought process, and ensures the findings will hold up in a legal or disciplinary proceeding."
    },
    {
      question: "What does 'MTTD' stand for in security metrics?",
      answers: [
        { text: "Maximum Time to Deploy", correct: false },
        { text: "Mean Time to Detect", correct: true },
        { text: "Minimum Time to Disrupt", correct: false },
        { text: "Mean Time to Disclose", correct: false }
      ],
      explanation: "Mean Time to Detect (MTTD) is the average time it takes to discover a security incident. A lower MTTD is a key goal, as it limits the attacker's dwell time in the environment."
    },
    {
      question: "What is a 'honeypot' used for in security monitoring?",
      answers: [
        { text: "To store encrypted passwords.", correct: false },
        { text: "As a decoy system to attract and study attackers.", correct: true },
        { text: "To patch system vulnerabilities automatically.", correct: false },
        { text: "To back up critical data.", correct: false }
      ],
      explanation: "A honeypot is a sacrificial system designed to lure attackers. By studying the attacks against it, security teams can learn about new tactics and tools without risking production systems."
    },
    {
      question: "What is the principle of 'Least Privilege' and how does it relate to incident response?",
      answers: [
        { text: "Users should have minimal access; it limits the damage from a compromised account.", correct: true },
        { text: "Incidents should be handled by the least experienced staff first.", correct: false },
        { text: "Forensic tools should have the fewest features necessary.", correct: false },
        { text: "Backups should be kept for the least amount of time required.", correct: false }
      ],
      explanation: "Applying the principle of least privilege to user and service accounts means that if an account is compromised, the attacker has limited access to systems and data, making containment easier."
    },
    {
      question: "What is 'dwell time' in the context of a security incident?",
      answers: [
        { text: "The time an attacker remains undetected in a network.", correct: true },
        { text: "The time it takes for the IR team to assemble.", correct: false },
        { text: "The time a system is offline during recovery.", correct: false },
        { text: "The time data spends in an encrypted state.", correct: false }
      ],
      explanation: "Dwell time is the period between an attacker's initial compromise and the moment they are discovered. A shorter dwell time is a key measure of an effective security program."
    },
    {
      question: "What is the main purpose of the 'Recovery' phase in incident response?",
      answers: [
        { text: "To identify the attacker.", correct: false },
        { text: "To restore systems and services to normal operation.", correct: true },
        { text: "To contain the spread of the incident.", correct: false },
        { text: "To write the final report.", correct: false }
      ],
      explanation: "The recovery phase involves carefully returning affected systems to production, verifying they are functioning normally and are no longer compromised, and monitoring them for any signs of re-infection."
    }
  ],
  "Cloud Security": [
    {
      question: "What is the customer's primary responsibility in the Shared Responsibility Model for IaaS?",
      answers: [
        { text: "The physical security of the data center.", correct: false },
        { text: "The operating system and application security.", correct: true },
        { text: "The virtualization layer.", correct: false },
        { text: "The cloud infrastructure hardware.", correct: false }
      ],
      explanation: "In IaaS (Infrastructure as a Service), the provider manages the hardware and virtualization, while the customer is responsible for securing the operating system, applications, and data."
    },
    {
      question: "What term describes a service offering where the cloud provider manages all aspects except the code (like AWS Lambda)?",
      answers: [
        { text: "IaaS", correct: false },
        { text: "PaaS", correct: false },
        { text: "SaaS", correct: false },
        { text: "FaaS (Serverless)", correct: true }
      ],
      explanation: "Function as a Service (FaaS), often called Serverless, is a type of PaaS where the provider manages the operating system, runtime, and scaling, and the customer only provides the code function."
    },
    {
      question: "Unintentionally exposed storage buckets is a common security misconfiguration in which cloud service?",
      answers: [
        { text: "Cloud Databases (e.g., RDS)", correct: false },
        { text: "Object Storage (e.g., S3)", correct: true },
        { text: "Virtual Machines (e.g., EC2)", correct: false },
        { text: "Content Delivery Networks (CDN)", correct: false }
      ],
      explanation: "Cloud object storage services like Amazon S3 are frequently misconfigured with overly permissive public access policies, leading to massive data leaks."
    },
    // New questions start here
    {
      question: "In the Shared Responsibility Model for SaaS, what is typically the customer's responsibility?",
      answers: [
        { text: "Managing the underlying infrastructure and operating system.", correct: false },
        { text: "Configuring user access and data security settings.", correct: true },
        { text: "Patching the application.", correct: false },
        { text: "Securing the network controls.", correct: false }
      ],
      explanation: "In SaaS, the provider manages the application, infrastructure, and platform. The customer is primarily responsible for their own data, user access management, and configuring the provided security options."
    },
    {
      question: "What is the primary purpose of a 'Cloud Access Security Broker' (CASB)?",
      answers: [
        { text: "To provide internet bandwidth for cloud services.", correct: false },
        { text: "To act as an enforcement point for security policies between users and cloud applications.", correct: true },
        { text: "To broker cheaper prices with cloud providers.", correct: false },
        { text: "To manage virtual machine instances.", correct: false }
      ],
      explanation: "A CASB is an on-premises or cloud-based security policy enforcement point that sits between users and cloud services to apply security policies like authentication, encryption, and malware detection."
    },
    {
      question: "What does the principle of 'Least Privilege' mean in the context of cloud Identity and Access Management (IAM)?",
      answers: [
        { text: "Users should be given the minimum permissions necessary to perform their tasks.", correct: true },
        { text: "All users should have administrator access for efficiency.", correct: false },
        { text: "Permissions should be granted for the longest possible duration.", correct: false },
        { text: "Privileges should be assigned based on job title alone.", correct: false }
      ],
      explanation: "Applying least privilege in cloud IAM minimizes the attack surface by ensuring users and services can only access the specific resources and perform the actions they absolutely need."
    },
    {
      question: "What is a major security risk associated with public cloud 'snapshots' or 'images'?",
      answers: [
        { text: "They are too expensive to store.", correct: false },
        { text: "They can contain hardcoded secrets or sensitive data that is accidentally shared.", correct: true },
        { text: "They cannot be encrypted.", correct: false },
        { text: "They automatically make the instance public.", correct: false }
      ],
      explanation: "VM images or snapshots saved for backup or templating can include passwords, API keys, or other sensitive data in their configuration. If made public or shared, this can lead to a severe breach."
    },
    {
      question: "What is the main function of 'VPC Flow Logs' in AWS (or similar features in other clouds)?",
      answers: [
        { text: "To record all data packets for deep packet inspection.", correct: false },
        { text: "To capture information about the IP traffic going to and from network interfaces in a VPC.", correct: true },
        { text: "To log user login attempts to the cloud console.", correct: false },
        { text: "To monitor the CPU usage of virtual machines.", correct: false }
      ],
      explanation: "VPC Flow Logs are a vital tool for network monitoring and forensics, helping to diagnose overly restrictive security groups, monitor for suspicious traffic, and troubleshoot connectivity issues."
    },
    {
      question: "What does 'data egress' refer to in cloud computing?",
      answers: [
        { text: "The process of data entering the cloud from an on-premises network.", correct: false },
        { text: "The movement of data out of a cloud provider's network.", correct: true },
        { text: "The encryption of data at rest.", correct: false },
        { text: "The deletion of data from cloud storage.", correct: false }
      ],
      explanation: "Data egress is data transferred out of the cloud. It's important for both cost considerations (egress fees) and security, as unusual egress can indicate data exfiltration by an attacker."
    },
    {
      question: "Which tool provides a standardized way to assess the security state of cloud resources against best practices?",
      answers: [
        { text: "CloudTrail", correct: false },
        { text: "Config / Security Hub", correct: true },
        { text: "CloudWatch", correct: false },
        { text: "IAM Analyzer", correct: false }
      ],
      explanation: "Services like AWS Config (with conformance packs) and AWS Security Hub continuously assess cloud configurations against security best practices and compliance standards, flagging misconfigurations."
    },
    {
      question: "What is 'shadow IT' in a cloud context?",
      answers: [
        { text: "IT infrastructure that runs only at night.", correct: false },
        { text: "Cloud services used by employees without the explicit approval of the central IT department.", correct: true },
        { text: "The dark web.", correct: false },
        { text: "A backup data center.", correct: false }
      ],
      explanation: "Shadow IT creates security risks because these unsanctioned services are not managed according to organizational security policies, potentially leading to data leaks and compliance violations."
    },
    {
      question: "What is the primary security benefit of using 'Infrastructure as Code' (IaC) tools like Terraform or CloudFormation?",
      answers: [
        { text: "It makes infrastructure more expensive.", correct: false },
        { text: "It allows for repeatable, version-controlled, and auditable deployment of secure configurations.", correct: true },
        { text: "It automatically writes application code.", correct: false },
        { text: "It eliminates the need for a security team.", correct: false }
      ],
      explanation: "IaC enables 'security as code,' where security controls (like network configurations and IAM roles) are defined in templates, reducing human error and ensuring consistent, compliant deployments."
    },
    {
      question: "A security service that provides DDoS protection, a web application firewall, and a content delivery network is:",
      answers: [
        { text: "AWS Shield / CloudFront WAF", correct: true },
        { text: "AWS GuardDuty", correct: false },
        { text: "Azure Sentinel", correct: false },
        { text: "Google Cloud IAP", correct: false }
      ],
      explanation: "Services like AWS Shield (for DDoS protection) combined with AWS WAF (Web Application Firewall) and CloudFront (CDN) provide a layered defense for web applications at the network and application layers."
    },
    {
      question: "What is a 'managed service identity' in cloud platforms?",
      answers: [
        { text: "A user account for cloud administrators.", correct: false },
        { text: "An automatically managed identity for authenticating a service to other cloud services, eliminating the need for hardcoded credentials.", correct: true },
        { text: "A form of multi-factor authentication.", correct: false },
        { text: "A tool for identifying security incidents.", correct: false }
      ],
      explanation: "Identities like AWS IAM Roles, Azure Managed Identities, and Google Service Accounts allow services (e.g., a VM or a Lambda function) to securely access other services without storing API keys or passwords."
    },
    {
      question: "What does 'resource tagging' primarily help with in cloud security?",
      answers: [
        { text: "Making the console look more colorful.", correct: false },
        { text: "Organizing resources for billing, automation, and applying security policies based on attributes like owner or environment.", correct: true },
        { text: "Increasing the performance of resources.", correct: false },
        { text: "Hiding resources from unauthorized users.", correct: false }
      ],
      explanation: "Tags (e.g., 'Environment: Production', 'Owner: Finance') are metadata that can be used to enforce security policies, ensure only approved resources are running, and quickly identify the owner of a misconfigured resource."
    },
    {
      question: "What is the main risk of using long-lived access keys for cloud API access?",
      answers: [
        { text: "They are more expensive.", correct: false },
        { text: "They can be accidentally exposed and provide prolonged access to an attacker.", correct: true },
        { text: "They slow down API calls.", correct: false },
        { text: "They cannot be used with MFA.", correct: false }
      ],
      explanation: "Long-lived static credentials (access keys) are a major risk. Best practice is to use temporary security credentials (like those from AWS STS) or managed identities wherever possible."
    },
    {
      question: "What is 'cloud sprawl'?",
      answers: [
        { text: "The physical layout of a data center.", correct: false },
        { text: "The uncontrolled proliferation of cloud resources, leading to management difficulties and security gaps.", correct: true },
        { text: "A type of DDoS attack.", correct: false },
        { text: "The migration process to the cloud.", correct: false }
      ],
      explanation: "Cloud sprawl occurs when organizations rapidly provision cloud services without proper governance, resulting in forgotten, unpatched, and misconfigured resources that are easy targets for attackers."
    },
    {
      question: "Which service provides detailed logs of API calls and management events for accountability and security analysis?",
      answers: [
        { text: "CloudWatch Logs", correct: false },
        { text: "CloudTrail / Azure Activity Log", correct: true },
        { text: "Config", correct: false },
        { text: "VPC Flow Logs", correct: false }
      ],
      explanation: "Services like AWS CloudTrail are essential for security auditing and forensics, as they provide a history of who did what, when, and from where in the cloud management plane."
    },
    {
      question: "What is the purpose of a 'landing zone' in cloud architecture?",
      answers: [
        { text: "A designated IP range for incoming VPN connections.", correct: false },
        { text: "A pre-configured, secure, multi-account environment that aligns with best practices.", correct: true },
        { text: "The physical location where undersea cables connect.", correct: false },
        { text: "A testing environment for new developers.", correct: false }
      ],
      explanation: "A landing zone provides a secure, scalable, and well-architected foundation for workloads in the cloud, often including account structure, network design, and centralized security controls."
    },
    {
      question: "What is a 'security group' in cloud networking?",
      answers: [
        { text: "A group of security engineers.", correct: false },
        { text: "A stateful virtual firewall that controls inbound and outbound traffic for an instance.", correct: true },
        { text: "A chat channel for incident response.", correct: false },
        { text: "A compliance standard.", correct: false }
      ],
      explanation: "Security groups act as a virtual firewall for EC2 instances (or similar compute resources) to control traffic. They are stateful, meaning if you allow an inbound request, the outbound response is automatically allowed."
    },
    {
      question: "What does 'encryption at rest' protect against in cloud storage?",
      answers: [
        { text: "Data being intercepted in transit over the network.", correct: false },
        { text: "Unauthorized access to the physical storage media.", correct: true },
        { text: "DDoS attacks.", correct: false },
        { text: "Social engineering attacks.", correct: false }
      ],
      explanation: "Encryption at rest protects data stored on disk. If an attacker gains physical access to the storage device or a backup tape, the data remains unreadable without the encryption keys."
    },
    {
      question: "What is the difference between 'regional' and 'global' services in cloud providers?",
      answers: [
        { text: "Regional services are cheaper than global services.", correct: false },
        { text: "Regional services are scoped to a specific geographic region, while global services are not tied to a single region.", correct: true },
        { text: "Global services have better performance.", correct: false },
        { text: "Only global services can be highly available.", correct: false }
      ],
      explanation: "Understanding this distinction is critical for architecture and disaster recovery. IAM is a global service, while EC2 and S3 are regional. A failure in one region may not affect global services."
    },
    {
      question: "What is a 'bastion host' (or 'jump box') used for?",
      answers: [
        { text: "To serve public web traffic.", correct: false },
        { text: "As a securely configured server that provides controlled access to instances in a private subnet.", correct: true },
        { text: "To host a database.", correct: false },
        { text: "To act as a primary domain controller.", correct: false }
      ],
      explanation: "A bastion host is a single, hardened point of entry into a private network. Administrators first connect to the bastion host, and from there, they can connect to other internal resources."
    },
    {
      question: "What is the primary purpose of 'Cloud Security Posture Management' (CSPM) tools?",
      answers: [
        { text: "To scan source code for vulnerabilities.", correct: false },
        { text: "To identify and remediate misconfigurations and compliance risks in cloud infrastructure.", correct: true },
        { text: "To protect against viruses on virtual machines.", correct: false },
        { text: "To manage user passwords.", correct: false }
      ],
      explanation: "CSPM tools automatically detect drift from security best practices, such as unencrypted storage buckets, overly permissive IAM policies, and non-compliant network configurations."
    },
    {
      question: "What does the 'Well-Architected Framework' provide?",
      answers: [
        { text: "A set of pre-built virtual machine images.", correct: false },
        { text: "Guidance for designing and operating reliable, secure, efficient, and cost-effective systems in the cloud.", correct: true },
        { text: "A list of approved software vendors.", correct: false },
        { text: "A warranty for cloud services.", correct: false }
      ],
      explanation: "The Well-Architected Framework, offered by major cloud providers, is a collection of best practices across pillars like security, reliability, performance efficiency, and cost optimization."
    },
    {
      question: "What is a key security consideration when using 'container' services like EKS or AKS?",
      answers: [
        { text: "Containers cannot be encrypted.", correct: false },
        { text: "Securing the container images and the orchestration layer (e.g., Kubernetes).", correct: true },
        { text: "Containers are inherently insecure and should be avoided.", correct: false },
        { text: "They require no security management.", correct: false }
      ],
      explanation: "Container security involves scanning images for vulnerabilities, minimizing the attack surface of the base image, implementing network policies, and securing the Kubernetes control plane and worker nodes."
    },
    {
      question: "What is the principle of 'zero trust' networking in a cloud context?",
      answers: [
        { text: "Trusting all traffic from within the VPC.", correct: false },
        { text: "Never trusting any user or system, whether inside or outside the network perimeter, and verifying every request.", correct: true },
        { text: "Having zero firewalls to improve speed.", correct: false },
        { text: "Using only open-source software.", correct: false }
      ],
      explanation: "A zero-trust architecture in the cloud mandates strict identity verification, micro-segmentation, and least-privilege access, moving away from the traditional 'trust but verify' model based on network location."
    }
  ],
  "Identity & Access Management (IAM)": [
    {
      question: "Which access control model uses labels (e.g., Top Secret) assigned to both subjects and objects?",
      answers: [
        { text: "Role-Based Access Control (RBAC)", correct: false },
        { text: "Discretionary Access Control (DAC)", correct: false },
        { text: "Mandatory Access Control (MAC)", correct: true },
        { text: "Attribute-Based Access Control (ABAC)", correct: false }
      ],
      explanation: "Mandatory Access Control (MAC) is highly restrictive and often used in military/government settings, where security labels determine resource access, not the owner."
    },
    {
      question: "What is the benefit of using Multi-Factor Authentication (MFA)?",
      answers: [
        { text: "It requires a complex password.", correct: false },
        { text: "It verifies the user's location.", correct: false },
        { text: "It requires multiple types of verification (something you know, have, or are).", correct: true },
        { text: "It encrypts the password during transmission.", correct: false }
      ],
      explanation: "MFA strengthens security by requiring a combination of two or more distinct factors of authentication: knowledge (password), possession (token/phone), or inherence (biometrics)."
    },
    {
      question: "The security principle that states a user should have only the permissions necessary to perform their job is called:",
      answers: [
        { text: "Separation of Duties", correct: false },
        { text: "Least Privilege", correct: true },
        { text: "Need to Know", correct: false },
        { text: "Due Diligence", correct: false }
      ],
      explanation: "The Principle of Least Privilege (PoLP) minimizes the potential damage from a malicious action or compromise by restricting access rights for users and processes to the bare minimum required to perform their tasks."
    },
    // New questions start here
    {
      question: "In an access control model, what is a 'subject'?",
      answers: [
        { text: "The resource being accessed, like a file or database.", correct: false },
        { text: "The title of a security policy document.", correct: false },
        { text: "The user or process requesting access to a resource.", correct: true },
        { text: "The category of information.", correct: false }
      ],
      explanation: "In access control terminology, the 'subject' is the active entity (e.g., a user, a program) that requests access to an 'object' (the passive resource, like a file)."
    },
    {
      question: "What is the primary purpose of 'Separation of Duties' (SoD)?",
      answers: [
        { text: "To ensure no single individual has complete control over a critical process.", correct: true },
        { text: "To separate user data from system data on a hard drive.", correct: false },
        { text: "To create different office hours for IT staff.", correct: false },
        { text: "To use different passwords for different systems.", correct: false }
      ],
      explanation: "SoD is designed to prevent fraud and error by splitting critical tasks among multiple people, ensuring that no one person can compromise a system or process alone (e.g., requesting and approving a payment)."
    },
    {
      question: "Which IAM concept involves periodically reviewing user access to ensure it is still appropriate?",
      answers: [
        { text: "User Provisioning", correct: false },
        { text: "Access Recertification", correct: true },
        { text: "Privilege Escalation", correct: false },
        { text: "Single Sign-On", correct: false }
      ],
      explanation: "Access recertification (or user access review) is a critical control where managers or data owners periodically confirm that their employees' access rights are still needed for their jobs, reducing 'access creep'."
    },
    {
      question: "What is a 'federated identity'?",
      answers: [
        { text: "A national ID card.", correct: false },
        { text: "An identity that can be used across multiple separate systems or organizations.", correct: true },
        { text: "An identity created by the federal government.", correct: false },
        { text: "A backup identity used in emergencies.", correct: false }
      ],
      explanation: "Federated identity allows a user's authentication from one domain (their employer) to be trusted by another domain (a cloud application), enabling Single Sign-On (SSO) across organizational boundaries."
    },
    {
      question: "Which protocol is commonly used for implementing Single Sign-On (SSO) on the web?",
      answers: [
        { text: "SSH", correct: false },
        { text: "LDAP", correct: false },
        { text: "SAML", correct: true },
        { text: "RADIUS", correct: false }
      ],
      explanation: "SAML (Security Assertion Markup Language) is an open standard for exchanging authentication and authorization data between an identity provider (IdP) and a service provider (SP), enabling web-based SSO."
    },
    {
      question: "What is the main risk associated with 'privilege creep'?",
      answers: [
        { text: "Users forget their complex passwords.", correct: false },
        { text: "Users accumulate unnecessary access rights over time, increasing the impact of a compromised account.", correct: true },
        { text: "Administrative accounts become too expensive.", correct: false },
        { text: "It slows down the user's computer.", correct: false }
      ],
      explanation: "Privilege creep occurs when users move between roles or projects and gain new permissions without having their old ones revoked, violating the principle of least privilege."
    },
    {
      question: "In the context of IAM, what does 'JIT' (Just-In-Time) access refer to?",
      answers: [
        { text: "A method for delivering software.", correct: false },
        { text: "Elevating privileges only when needed and for a limited time.", correct: true },
        { text: "A type of fast authentication protocol.", correct: false },
        { text: "Granting access based on the user's timezone.", correct: false }
      ],
      explanation: "Just-In-Time access is a privileged access management (PAM) strategy where elevated permissions are granted temporarily and just for a specific task, rather than being permanently assigned, reducing the attack surface."
    },
    {
      question: "What is the primary function of an 'Identity Provider' (IdP) in a federated system?",
      answers: [
        { text: "To provide IP addresses to users.", correct: false },
        { text: "To authenticate users and issue security tokens to service providers.", correct: true },
        { text: "To store all the company's data.", correct: false },
        { text: "To manage the company's firewalls.", correct: false }
      ],
      explanation: "The Identity Provider is the authoritative source for user identities. It performs the authentication and then sends a signed assertion (e.g., a SAML token) to the Service Provider (the application) saying 'this user is who they claim to be'."
    },
    {
      question: "Which of the following is an example of 'something you are' in multi-factor authentication?",
      answers: [
        { text: "A password", correct: false },
        { text: "A fingerprint", correct: true },
        { text: "A smart card", correct: false },
        { text: "A PIN", correct: false }
      ],
      explanation: "Biometric factors ('something you are') include fingerprints, facial recognition, iris scans, and voice patterns. They are unique physical characteristics of an individual."
    },
    {
      question: "What is the purpose of 'time-based restrictions' in access control?",
      answers: [
        { text: "To make the system run faster.", correct: false },
        { text: "To limit user access to specific days or times, reducing the attack window.", correct: true },
        { text: "To synchronize clocks on all computers.", correct: false },
        { text: "To schedule system backups.", correct: false }
      ],
      explanation: "Time-of-day restrictions can enhance security by preventing access outside of normal business hours. For example, a user account might be disabled from logging in between 10 PM and 6 AM."
    },
    {
      question: "What does OAuth 2.0 primarily handle?",
      answers: [
        { text: "User Authentication", correct: false },
        { text: "Authorization for API access", correct: true },
        { text: "Network Encryption", correct: false },
        { text: "Password Hashing", correct: false }
      ],
      explanation: "OAuth 2.0 is an authorization framework that allows a user to grant a third-party application limited access to their resources on another service (e.g., using 'Login with Google') without sharing their password."
    },
    {
      question: "What is a 'service account'?",
      answers: [
        { text: "An account used by a customer to access a service.", correct: false },
        { text: "An account used by an application or service to interact with other services or resources.", correct: true },
        { text: "An account with discounted pricing.", correct: false },
        { text: "An account for IT support staff.", correct: false }
      ],
      explanation: "Service accounts are non-human identities used for machine-to-machine communication. They must be secured with strong credentials (or better, certificates) and assigned only the necessary permissions."
    },
    {
      question: "What is the 'default-deny' rule in access control?",
      answers: [
        { text: "Denying all requests by default and only allowing explicitly permitted actions.", correct: true },
        { text: "Denying access during system maintenance.", correct: false },
        { text: "Allowing all requests by default and denying known bad ones.", correct: false },
        { text: "A rule that denies access to default user accounts.", correct: false }
      ],
      explanation: "The default-deny (or whitelisting) approach is a security best practice. It states that anything not explicitly permitted is forbidden, which is much more secure than a default-allow (blacklisting) approach."
    },
    {
      question: "What is the main difference between 'authentication' and 'authorization'?",
      answers: [
        { text: "They are synonyms and can be used interchangeably.", correct: false },
        { text: "Authentication verifies identity, while authorization determines what that identity can access.", correct: true },
        { text: "Authorization verifies identity, while authentication determines access.", correct: false },
        { text: "Authentication is for users, authorization is for devices.", correct: false }
      ],
      explanation: "A simple analogy: Authentication is showing your ID card at the door (proving who you are). Authorization is being told which rooms in the building you are allowed to enter (what you can do)."
    },
    {
      question: "What is a 'password vault' used for in privileged access management?",
      answers: [
        { text: "To store user's personal passwords.", correct: false },
        { text: "To securely store, manage, and rotate privileged credentials for systems and applications.", correct: true },
        { text: "To encrypt the entire hard drive.", correct: false },
        { text: "To generate simple passwords.", correct: false }
      ],
      explanation: "A privileged access management (PAM) vault stores highly sensitive credentials (like admin passwords). It enforces check-in/check-out procedures, records sessions, and automatically rotates passwords to limit their exposure."
    },
    {
      question: "Which access control model is based on the identity of the subject and the owner's discretion?",
      answers: [
        { text: "Mandatory Access Control (MAC)", correct: false },
        { text: "Role-Based Access Control (RBAC)", correct: false },
        { text: "Discretionary Access Control (DAC)", correct: true },
        { text: "Rule-Based Access Control (RBAC)", correct: false }
      ],
      explanation: "In Discretionary Access Control (DAC), the owner of the resource (e.g., a file) decides who gets access to it. This is common in operating systems like Windows and Linux with file permissions."
    },
    {
      question: "What does 'PAM' stand for in the context of IAM?",
      answers: [
        { text: "Portable Application Manager", correct: false },
        { text: "Privileged Access Management", correct: true },
        { text: "Primary Account Method", correct: false },
        { text: "Public Authentication Module", correct: false }
      ],
      explanation: "Privileged Access Management (PAM) refers to the strategies and technologies for controlling and monitoring the use of elevated ('privileged') accounts, which have extensive permissions across systems."
    },
    {
      question: "What is the purpose of 'session management'?",
      answers: [
        { text: "To manage meeting schedules.", correct: false },
        { text: "To control the user's interaction with a system from login to logout.", correct: true },
        { text: "To manage network sessions between routers.", correct: false },
        { text: "To organize training sessions for users.", correct: false }
      ],
      explanation: "Secure session management involves generating unique session IDs, protecting them (e.g., using secure cookies), implementing session timeouts, and providing a secure logout function to prevent session hijacking."
    },
    {
      question: "What is a 'risk-based authentication' approach?",
      answers: [
        { text: "Authenticating only high-risk users.", correct: false },
        { text: "Adjusting authentication requirements based on the perceived risk of a login attempt.", correct: true },
        { text: "Using passwords that are difficult to guess.", correct: false },
        { text: "Authenticating users based on their job risk level.", correct: false }
      ],
      explanation: "Risk-based authentication analyzes context like geolocation, device fingerprint, IP reputation, and time of access. A low-risk login (from a known device/office) might require just a password, while a high-risk one (from a new country) might trigger MFA."
    },
    {
      question: "What is the 'key distribution problem' that Kerberos was designed to solve?",
      answers: [
        { text: "How to physically distribute cryptographic keys on floppy disks.", correct: false },
        { text: "How to allow users to authenticate to network services without transmitting passwords over the network.", correct: true },
        { text: "How to manage too many keys on a keyring.", correct: false },
        { text: "How to distribute public keys for asymmetric encryption.", correct: false }
      ],
      explanation: "Kerberos uses a trusted third-party (the Key Distribution Center) to issue time-limited 'tickets' that prove a user's identity to services. Passwords are never sent over the network, only used locally to decrypt the initial ticket."
    },
    {
      question: "What is 'access aggregation'?",
      answers: [
        { text: "Combining multiple access logs into one report.", correct: false },
        { text: "When a single account gains access to multiple systems, increasing its value to an attacker.", correct: true },
        { text: "A method for speeding up network access.", correct: false },
        { text: "The process of adding up all user access requests.", correct: false }
      ],
      explanation: "Access aggregation is a significant risk, especially with shared or service accounts. If one account is compromised and has broad access, the attacker can move laterally across the entire environment with ease."
    },
    {
      question: "What does the 'four-eyes principle' enforce?",
      answers: [
        { text: "That users must wear glasses for security.", correct: false },
        { text: "That a critical action requires approval from a second person.", correct: true },
        { text: "That biometric systems must scan both eyes.", correct: false },
        { text: "That security cameras must have a wide field of view.", correct: false }
      ],
      explanation: "The 'four-eyes principle' (or two-person rule) is a specific form of separation of duties where a sensitive transaction or operation must be approved by two authorized individuals to prevent unilateral action."
    },
    {
      question: "What is a primary security concern with 'bring your own identity' (BYOID) models?",
      answers: [
        { text: "It makes login times slower.", correct: false },
        { text: "The organization relies on the security practices of an external identity provider (e.g., a social media company).", correct: true },
        { text: "It requires expensive hardware.", correct: false },
        { text: "It is incompatible with MFA.", correct: false }
      ],
      explanation: "While BYOID (like 'Login with Facebook') is convenient, it creates a dependency. If the external IdP is compromised, the attacker may gain access to your application as well."
    },
    {
      question: "What is the purpose of 'privileged session monitoring'?",
      answers: [
        { text: "To watch over important business meetings.", correct: false },
        { text: "To record and audit all activities performed during a privileged session.", correct: true },
        { text: "To monitor the performance of privileged user's computers.", correct: false },
        { text: "To track the login times of administrators.", correct: false }
      ],
      explanation: "This PAM capability records video of privileged sessions (like RDP or SSH). It provides an undeniable audit trail for forensic investigations and can deter malicious insiders from abusing their access."
    }
  ],
  "Security Architecture & Design": [
    {
      question: "A dedicated machine that is intentionally exposed to attract and analyze cyber attacks is called a:",
      answers: [
        { text: "Firewall", correct: false },
        { text: "Intrusion Prevention System (IPS)", correct: false },
        { text: "Honeypot", correct: true },
        { text: "Load Balancer", correct: false }
      ],
      explanation: "A honeypot is a decoy system used to lure attackers away from real targets and collect information about their attack methods for defense improvement."
    },
    {
      question: "What concept separates a network into multiple, smaller, isolated broadcast domains to contain breaches?",
      answers: [
        { text: "Demilitarized Zone (DMZ)", correct: false },
        { text: "Virtual Private Network (VPN)", correct: false },
        { text: "Network Segmentation (VLANs)", correct: true },
        { text: "Network Address Translation (NAT)", correct: false }
      ],
      explanation: "Network Segmentation, often implemented with VLANs (Virtual Local Area Networks), divides a network into smaller zones, limiting an attacker's lateral movement if a segment is compromised."
    },
    {
      question: "Which architecture embeds security into the development process, rather than testing it at the end?",
      answers: [
        { text: "Waterfall Model", correct: false },
        { text: "DevOps", correct: false },
        { text: "SecDevOps (or DevSecOps)", correct: true },
        { text: "Agile Development", correct: false }
      ],
      explanation: "DevSecOps (or Secure DevOps) is the practice of integrating security controls and processes at every phase of the software development lifecycle (SDLC)."
    },
    // New questions start here
    {
      question: "What is the primary goal of the 'Defense in Depth' strategy?",
      answers: [
        { text: "To use the most powerful firewall available.", correct: false },
        { text: "To implement multiple, layered security controls to protect assets.", correct: true },
        { text: "To hide the network from attackers.", correct: false },
        { text: "To focus all security resources on the perimeter.", correct: false }
      ],
      explanation: "Defense in Depth (or layered defense) ensures that if one security control fails, others are in place to provide protection. Layers can include physical, network, host, application, and data security."
    },
    {
      question: "A network segment that contains an organization's public-facing services is called a:",
      answers: [
        { text: "Intranet", correct: false },
        { text: "DMZ (Demilitarized Zone)", correct: true },
        { text: "Backbone", correct: false },
        { text: "WAN", correct: false }
      ],
      explanation: "A DMZ is a semi-trusted network segment, isolated by firewalls, where an organization places its public servers (e.g., web, email) to provide a buffer between the internet and the internal network."
    },
    {
      question: "What does the 'Principle of Least Functionality' dictate for system configuration?",
      answers: [
        { text: "Systems should be as fast as possible.", correct: false },
        { text: "Systems should have only the services and ports enabled that are necessary for their function.", correct: true },
        { text: "Systems should have the most user-friendly interface.", correct: false },
        { text: "Systems should use the least expensive hardware.", correct: false }
      ],
      explanation: "This principle reduces the attack surface by disabling or removing unnecessary applications, services, ports, and protocols, leaving fewer avenues for an attacker to exploit."
    },
    {
      question: "What is 'microsegmentation' in a data center or cloud environment?",
      answers: [
        { text: "Making network cables shorter.", correct: false },
        { text: "Creating very small VLANs.", correct: false },
        { text: "Applying security policies at the individual workload level to control east-west traffic.", correct: true },
        { text: "Breaking a large file into smaller pieces.", correct: false }
      ],
      explanation: "Microsegmentation goes beyond traditional network segmentation by enabling fine-grained security policies for each server or workload, effectively isolating them from each other even within the same network segment."
    },
    {
      question: "Which security model is designed to prevent conflicts of interest by controlling access based on user roles and data classification?",
      answers: [
        { text: "Bell-LaPadula Model", correct: false },
        { text: "Biba Model", correct: false },
        { text: "Brewer-Nash Model (Chinese Wall)", correct: true },
        { text: "Clark-Wilson Model", correct: false }
      ],
      explanation: "The Brewer-Nash (Chinese Wall) model is designed for commercial environments, like consulting firms, to dynamically prevent a user who accesses one company's data from accessing a competitor's data, thus avoiding conflicts of interest."
    },
    {
      question: "What is the main purpose of a 'jump server' (or bastion host) in a secure network architecture?",
      answers: [
        { text: "To host the company's website.", correct: false },
        { text: "To serve as a single, hardened point of entry for administering systems in a secure zone.", correct: true },
        { text: "To improve network performance by caching data.", correct: false },
        { text: "To automatically patch vulnerable systems.", correct: false }
      ],
      explanation: "A jump server is a heavily fortified and monitored computer that provides the only means of accessing a protected network from an external one, reducing the attack surface for administrative access."
    },
    {
      question: "The concept of 'Fail Secure' in physical security means that if a system fails, it should:",
      answers: [
        { text: "Remain unlocked to allow for emergency exit.", correct: false },
        { text: "Default to a secure state (e.g., a door remains locked).", correct: true },
        { text: "Restart automatically.", correct: false },
        { text: "Send an alert to security personnel.", correct: false }
      ],
      explanation: "Fail Secure, also known as Fail Safe in some contexts (though this can be ambiguous), means that a failure (like a power outage) leaves the system in the most secure state, preventing unauthorized access."
    },
    {
      question: "What is 'Secure by Design'?",
      answers: [
        { text: "A process of adding security features after a product is built.", correct: false },
        { text: "An approach where security principles are integrated into the system architecture from the start.", correct: true },
        { text: "Using aesthetically pleasing security warning messages.", correct: false },
        { text: "Designing systems that are physically difficult to steal.", correct: false }
      ],
      explanation: "Secure by Design means that security is a core requirement, not an afterthought. It involves threat modeling, defining security requirements, and architecting the system to be inherently resilient to attacks."
    },
    {
      question: "Which model focuses on ensuring data integrity by using well-formed transactions and separation of duties?",
      answers: [
        { text: "Bell-LaPadula Model", correct: false },
        { text: "Biba Model", correct: false },
        { text: "Clark-Wilson Model", correct: true },
        { text: "Graham-Denning Model", correct: false }
      ],
      explanation: "The Clark-Wilson model is a integrity model for commercial environments. It uses 'Constrained Data Items' (CDIs), 'Transformation Procedures' (TPs), and 'Integrity Verification Procedures' (IVPs) to ensure data is manipulated in a controlled, auditable way."
    },
    {
      question: "What is the primary security benefit of using a 'reverse proxy'?",
      answers: [
        { text: "To hide the identities of internal clients on the internet.", correct: false },
        { text: "To hide the characteristics of the origin server(s) and provide a single point of enforcement for web traffic.", correct: true },
        { text: "To speed up internet browsing for users.", correct: false },
        { text: "To encrypt all outbound email.", correct: false }
      ],
      explanation: "A reverse proxy sits in front of web servers, terminating client connections. It can perform SSL offloading, load balancing, caching, and act as a Web Application Firewall (WAF), protecting the backend servers."
    },
    {
      question: "The 'Trusted Computing Base' (TCB) refers to:",
      answers: [
        { text: "All the software on a computer.", correct: false },
        { text: "The total cost of security software.", correct: false },
        { text: "All components (hardware, firmware, software) critical to a system's security policy.", correct: true },
        { text: "A list of trusted software vendors.", correct: false }
      ],
      explanation: "The TCB is the set of all components that are trusted to enforce the security policy. A failure in a TCB component can compromise the entire system's security. Its size should be minimized."
    },
    {
      question: "What does 'air gapping' a computer network achieve?",
      answers: [
        { text: "It improves wireless signal strength.", correct: false },
        { text: "It physically isolates a network from other, less secure networks.", correct: true },
        { text: "It creates a gap in the firewall rules for testing.", correct: false },
        { text: "It allows for faster data transfer.", correct: false }
      ],
      explanation: "An air-gapped network has no physical or wireless connection to any other network. This is the ultimate form of isolation, used for highly sensitive systems (e.g., nuclear power plant controls, classified military networks)."
    },
    {
      question: "Which security model enforces 'no read up, no write down'?",
      answers: [
        { text: "Biba Model", correct: false },
        { text: "Bell-LaPadula Model", correct: true },
        { text: "Brewer-Nash Model", correct: false },
        { text: "Clark-Wilson Model", correct: false }
      ],
      explanation: "The Bell-LaPadula model is designed for confidentiality. The 'Simple Security Property' (no read up) prevents a subject from reading an object at a higher classification. The '*-Property' (no write down) prevents a subject from writing to an object at a lower classification."
    },
    {
      question: "What is the purpose of a 'RAID' configuration in terms of security and resilience?",
      answers: [
        { text: "To protect against network intrusions.", correct: false },
        { text: "To provide redundancy and/or performance improvements for disk storage.", correct: true },
        { text: "To conduct a coordinated attack on a system.", correct: false },
        { text: "To configure a group of firewalls.", correct: false }
      ],
      explanation: "While not a security control in the cryptographic sense, RAID (Redundant Array of Independent Disks) provides fault tolerance. For example, RAID 1 (mirroring) or RAID 5 (parity) can allow a system to continue operating if a hard disk fails, supporting the security objective of Availability."
    },
    {
      question: "What concept involves designing systems to remain secure even if individual components are compromised?",
      answers: [
        { text: "Resilience", correct: false },
        { text: "Compartmentalization", correct: true },
        { text: "Obfuscation", correct: false },
        { text: "Redundancy", correct: false }
      ],
      explanation: "Compartmentalization (or isolation) limits the damage from a security breach by ensuring that a compromise in one area does not automatically grant access to all other areas. It's a key principle in zero-trust architectures."
    },
    {
      question: "What is a 'SOAR' platform used for in a Security Operations Center (SOC)?",
      answers: [
        { text: "To provide comfortable chairs for analysts.", correct: false },
        { text: "To manage and automate incident response workflows.", correct: true },
        { text: "To soar over network traffic for a better view.", correct: false },
        { text: "To act as a primary database server.", correct: false }
      ],
      explanation: "SOAR (Security Orchestration, Automation, and Response) platforms help SOCs standardize and automate their incident response processes, integrating various security tools to execute playbooks and reduce response times."
    },
    {
      question: "The 'Reference Monitor' is a security concept that describes:",
      answers: [
        { text: "A tool for monitoring network references.", correct: false },
        { text: "A device that displays security policies.", correct: false },
        { text: "An abstract machine that mediates all access to objects by subjects.", correct: true },
        { text: "A person who approves security changes.", correct: false }
      ],
      explanation: "The Reference Monitor is a conceptual model that must be always invoked, tamperproof, and verifiable. In practice, the 'security kernel' of an operating system implements the reference monitor concept."
    },
    {
      question: "What is the primary goal of 'threat modeling'?",
      answers: [
        { text: "To create a model of the most dangerous hacker.", correct: false },
        { text: "To identify potential threats, vulnerabilities, and countermeasures in the design phase.", correct: true },
        { text: "To predict the exact date of a cyber attack.", correct: false },
        { text: "To model network traffic patterns.", correct: false }
      ],
      explanation: "Threat modeling is a structured process used to optimize security by identifying objectives and vulnerabilities, and then defining countermeasures to prevent, or mitigate the effects of, threats to the system."
    },
    {
      question: "Which design principle suggests that a system should continue to operate correctly even when it is under attack?",
      answers: [
        { text: "Least Astonishment", correct: false },
        { text: "Psychological Acceptability", correct: false },
        { text: "Fail-Safe Defaults", correct: false },
        { text: "Robustness (or Defense in Depth)", correct: true }
      ],
      explanation: "Also related to resilience, this principle means that the system is designed to withstand a certain level of malicious activity without a complete failure of its security functions or core services."
    },
    {
      question: "What is 'cipher lock' used to secure?",
      answers: [
        { text: "Encryption keys.", correct: false },
        { text: "Physical doors.", correct: true },
        { text: "Wi-Fi networks.", correct: false },
        { text: "Database fields.", correct: false }
      ],
      explanation: "A cipher lock is a type of door access control that uses a keypad for entering a PIN code to gain entry. It's a physical security control that provides a higher level of security than a traditional key."
    },
    {
      question: "In the context of security architecture, what does 'EAL' stand for in the Common Criteria?",
      answers: [
        { text: "Evaluation Assurance Level", correct: true },
        { text: "Emergency Action Level", correct: false },
        { text: "Encrypted Access Log", correct: false },
        { text: "Enterprise Application Layer", correct: false }
      ],
      explanation: "The Common Criteria provides a framework for evaluating security products. The Evaluation Assurance Level (EAL) ranges from EAL1 (functionally tested) to EAL7 (formally verified design and tested), indicating the depth of the evaluation."
    },
    {
      question: "What is the purpose of a 'Unified Threat Management' (UTM) appliance?",
      answers: [
        { text: "To manage user identities.", correct: false },
        { text: "To consolidate multiple security features (firewall, IPS, antivirus, etc.) into a single platform.", correct: true },
        { text: "To unify all IT departments into one.", correct: false },
        { text: "To manage cloud threats only.", correct: false }
      ],
      explanation: "A UTM device simplifies security management for small to medium-sized businesses by combining several security functions, such as a stateful firewall, intrusion prevention, and anti-malware, in one box."
    },
    {
      question: "The 'Orange Book' is a historical U.S. Department of Defense standard that formally defined:",
      answers: [
        { text: "The color of secure server racks.", correct: false },
        { text: "The Trusted Computer System Evaluation Criteria (TCSEC).", correct: true },
        { text: "Guidelines for securing citrus fruit data.", correct: false },
        { text: "The standard for physical security badges.", correct: false }
      ],
      explanation: "The 'Orange Book' (TCSEC) was a seminal standard that defined criteria for evaluating the security of computer systems, with ratings from D (minimal protection) to A1 (verified design). It influenced later standards like the Common Criteria."
    },
    {
      question: "What is 'security through obscurity' and why is it considered a weak strategy?",
      answers: [
        { text: "Hiding security flaws in complex code; it's strong because it's complex.", correct: false },
        { text: "Relying on the secrecy of the design or implementation as the primary method of protection.", correct: true },
        { text: "Making security settings difficult to find; it's a best practice.", correct: false },
        { text: "Using dark colors for security equipment; it's weak because it's visible at night.", correct: false }
      ],
      explanation: "Security through obscurity is dangerous because it provides no real protection once the secret is discovered (e.g., a hidden port). Robust security should not depend on the attacker's ignorance of the system's internals."
    }
  ],
  "Governance, Risk, & Compliance (GRC)": [
    {
      question: "Which of the following is NOT a phase of the Risk Management process?",
      answers: [
        { text: "Risk Assessment", correct: false },
        { text: "Risk Treatment (Mitigation)", correct: false },
        { text: "Risk Acceptance", correct: false },
        { text: "Risk Creation", correct: true }
      ],
      explanation: "Risk management involves identifying, assessing, responding to (treating/accepting/transferring), and monitoring risks. 'Risk Creation' is not a formal phase."
    },
    {
      question: "What regulation specifies security and privacy standards for Protected Health Information (PHI) in the US?",
      answers: [
        { text: "GDPR", correct: false },
        { text: "HIPAA", correct: true },
        { text: "PCI DSS", correct: false },
        { text: "SOX", correct: false }
      ],
      explanation: "HIPAA (Health Insurance Portability and Accountability Act) sets the standards for protecting sensitive patient data in the US."
    },
    {
      question: "In the context of GRC, what is a 'vulnerability'?",
      answers: [
        { text: "A person or entity that carries out a threat.", correct: false },
        { text: "A weakness in a system that can be exploited by a threat.", correct: true },
        { text: "The potential harm caused by an attack.", correct: false },
        { text: "The likelihood of an attack occurring.", correct: false }
      ],
      explanation: "A vulnerability is a flaw or weakness in a system's design, implementation, or operation that could be exploited to violate the system's security policy."
    },
    // New questions start here
    {
      question: "What is the primary purpose of an 'Acceptable Use Policy' (AUP)?",
      answers: [
        { text: "To define how company IT resources can and cannot be used by employees.", correct: true },
        { text: "To set the price for using company software.", correct: false },
        { text: "To determine acceptable risk levels.", correct: false },
        { text: "To govern the use of personal devices at home.", correct: false }
      ],
      explanation: "An AUP is a key governance document that outlines the rules and constraints for using organizational networks, systems, and data, helping to protect assets and set clear expectations for employees."
    },
    {
      question: "What does the 'Residual Risk' represent?",
      answers: [
        { text: "The original risk before any controls are applied.", correct: false },
        { text: "The risk that remains after security controls have been implemented.", correct: true },
        { text: "The risk that is transferred to an insurance company.", correct: false },
        { text: "The risk associated with new, emerging threats.", correct: false }
      ],
      explanation: "Residual risk is the level of risk that remains after an organization has implemented all its planned risk treatment measures. Some residual risk is always present and must be formally accepted by management."
    },
    {
      question: "Which framework provides a set of best practices for IT service management and is often used for governance?",
      answers: [
        { text: "NIST CSF", correct: false },
        { text: "ITIL", correct: true },
        { text: "ISO 27001", correct: false },
        { text: "COBIT", correct: false }
      ],
      explanation: "ITIL (Information Technology Infrastructure Library) is a widely adopted framework for IT Service Management (ITSM) that provides practices for aligning IT services with business needs, which is a core aspect of IT governance."
    },
    {
      question: "What is the main goal of the 'Sarbanes-Oxley Act' (SOX)?",
      answers: [
        { text: "To protect the privacy of European citizens.", correct: false },
        { text: "To protect credit card data.", correct: false },
        { text: "To improve the accuracy and reliability of corporate financial disclosures.", correct: true },
        { text: "To secure the US power grid.", correct: false }
      ],
      explanation: "SOX was enacted in response to major corporate accounting scandals. It mandates strict reforms to improve financial disclosures from corporations and prevent accounting fraud, placing requirements on IT controls that support financial reporting."
    },
    {
      question: "In a risk assessment, what does 'Likelihood' refer to?",
      answers: [
        { text: "The potential damage caused by a risk event.", correct: false },
        { text: "The chance that a threat will exploit a vulnerability.", correct: true },
        { text: "The list of all possible threats.", correct: false },
        { text: "The cost of implementing a security control.", correct: false }
      ],
      explanation: "Likelihood (or probability) is a key component of risk analysis. It estimates how probable it is that a specific threat event will occur, often rated on a scale (e.g., Low, Medium, High)."
    },
    {
      question: "What is a 'Data Processing Agreement' (DPA) commonly used for under GDPR?",
      answers: [
        { text: "An agreement between a data controller and a data processor outlining the terms for processing personal data.", correct: true },
        { text: "An agreement between an employee and employer about personal data use.", correct: false },
        { text: "A license for data processing software.", correct: false },
        { text: "A patent for a new data processing algorithm.", correct: false }
      ],
      explanation: "Under GDPR, a DPA is a legally required contract that specifies the responsibilities of the data processor (e.g., a cloud provider) when handling personal data on behalf of the data controller (the organization that owns the data)."
    },
    {
      question: "Which of the following is a common risk treatment strategy?",
      answers: [
        { text: "Risk Ignorance", correct: false },
        { text: "Risk Acceptance", correct: true },
        { text: "Risk Amplification", correct: false },
        { text: "Risk Obfuscation", correct: false }
      ],
      explanation: "The four main risk treatment strategies are: Accept (consciously take on the risk), Mitigate (implement controls to reduce it), Transfer (e.g., buy insurance), and Avoid (stop the activity that causes the risk)."
    },
    {
      question: "What is the purpose of a 'Business Impact Analysis' (BIA)?",
      answers: [
        { text: "To analyze the impact of business decisions on stock price.", correct: false },
        { text: "To identify and evaluate the potential effects of an interruption to critical business operations.", correct: true },
        { text: "To assess the environmental impact of a business.", correct: false },
        { text: "To measure the impact of marketing campaigns.", correct: false }
      ],
      explanation: "A BIA is a core component of business continuity and disaster recovery planning. It helps identify critical systems and processes, and quantifies the impact (financial, operational, reputational) of their downtime."
    },
    {
      question: "The 'Payment Card Industry Data Security Standard' (PCI DSS) applies to organizations that:",
      answers: [
        { text: "Handle European citizen data.", correct: false },
        { text: "Accept, process, store, or transmit credit card information.", correct: true },
        { text: "Are publicly traded companies in the US.", correct: false },
        { text: "Provide health insurance.", correct: false }
      ],
      explanation: "PCI DSS is a mandatory set of security standards designed to ensure that all companies that handle credit card information maintain a secure environment, regardless of their size or transaction volume."
    },
    {
      question: "What is a 'Security Policy' in the context of governance?",
      answers: [
        { text: "A technical configuration on a firewall.", correct: false },
        { text: "A high-level management document that outlines an organization's security goals and expectations.", correct: true },
        { text: "An insurance policy for cyber attacks.", correct: false },
        { text: "A list of approved security software.", correct: false }
      ],
      explanation: "A security policy is a formal, top-level document that defines the organization's commitment to security and provides the framework for specific standards, procedures, and controls. It is a cornerstone of security governance."
    },
    {
      question: "What is the primary focus of the 'NIST Cybersecurity Framework' (CSF)?",
      answers: [
        { text: "Providing a checklist for HIPAA compliance.", correct: false },
        { text: "Offering a voluntary framework for managing and reducing cybersecurity risk.", correct: true },
        { text: "Mandating encryption standards for the US government.", correct: false },
        { text: "Certifying security professionals.", correct: false }
      ],
      explanation: "The NIST CSF provides a policy framework of computer security guidance for how private sector organizations can assess and improve their ability to prevent, detect, and respond to cyber attacks, based on five core functions: Identify, Protect, Detect, Respond, Recover."
    },
    {
      question: "What is 'Due Care' in a legal and security context?",
      answers: [
        { text: "The process of caring for IT equipment.", correct: false },
        { text: "The effort made by an ordinarily prudent or reasonable party to avoid harm to another.", correct: true },
        { text: "The care taken after a security incident.", correct: false },
        { text: "A specific type of insurance policy.", correct: false }
      ],
      explanation: "Due care refers to the level of judgment, vigilance, and activity a reasonable person would exercise in a given circumstance. In cybersecurity, it means implementing the necessary security controls that a prudent organization would have in place."
    },
    {
      question: "Which term describes the process of comparing an organization's security practices against an established standard?",
      answers: [
        { text: "Risk Assessment", correct: false },
        { text: "Gap Analysis", correct: true },
        { text: "Penetration Testing", correct: false },
        { text: "Vulnerability Scanning", correct: false }
      ],
      explanation: "A gap analysis identifies the differences ('gaps') between the current state of an organization's security program and the desired state defined by a framework or standard (e.g., ISO 27001, NIST CSF)."
    },
    {
      question: "What is the role of a 'Data Controller' under GDPR?",
      answers: [
        { text: "The entity that processes data on behalf of the controller.", correct: false },
        { text: "The entity that determines the purposes and means of the processing of personal data.", correct: true },
        { text: "A hardware device that manages data flow.", correct: false },
        { text: "A regulatory body that enforces GDPR.", correct: false }
      ],
      explanation: "The data controller is the organization that decides why and how personal data is processed. They bear the primary responsibility for ensuring compliance with data protection principles under GDPR."
    },
    {
      question: "What is an 'Inherent Risk'?",
      answers: [
        { text: "The risk that remains after controls are applied.", correct: false },
        { text: "The level of risk without considering any internal controls or mitigation efforts.", correct: true },
        { text: "A risk that is inherent to the IT industry.", correct: false },
        { text: "A risk that cannot be transferred.", correct: false }
      ],
      explanation: "Inherent risk is the natural, pre-mitigation level of risk that exists in an environment or process before any security controls are applied to reduce it."
    },
    {
      question: "Which regulation grants California residents enhanced privacy rights and consumer protections?",
      answers: [
        { text: "CCPA/CPRA", correct: true },
        { text: "GLBA", correct: false },
        { text: "FERPA", correct: false },
        { text: "FISMA", correct: false }
      ],
      explanation: "The California Consumer Privacy Act (CCPA) and its expansion, the California Privacy Rights Act (CPRA), are state statutes that provide privacy rights to California residents, similar in some ways to GDPR."
    },
    {
      question: "What is the purpose of a 'Risk Register'?",
      answers: [
        { text: "To register new employees for security training.", correct: false },
        { text: "To serve as a centralized repository for identified risks, their assessment, and treatment plans.", correct: true },
        { text: "To log all security incidents.", correct: false },
        { text: "To record user access requests.", correct: false }
      ],
      explanation: "A risk register is a key tool in risk management. It is a document that tracks all identified risks, their severity, the chosen response strategy, and the responsible party for managing them."
    },
    {
      question: "The 'Gramm-Leach-Bliley Act' (GLBA) requires financial institutions to protect:",
      answers: [
        { text: "Patient health information.", correct: false },
        { text: "Corporate financial reports.", correct: false },
        { text: "Nonpublic personal information.", correct: true },
        { text: "Credit card numbers only.", correct: false }
      ],
      explanation: "GLBA's Safeguards Rule requires financial institutions to develop a written information security plan that describes how they protect their customers' nonpublic personal information (NPI)."
    },
    {
      question: "What is 'Third-Party Risk Management' (TPRM)?",
      answers: [
        { text: "Managing the risk that a third-party vendor introduces to your organization.", correct: true },
        { text: "Transferring all risk to a third party.", correct: false },
        { text: "The risk of being third in a market race.", correct: false },
        { text: "A management structure with three parties.", correct: false }
      ],
      explanation: "TPRM is the process of identifying, assessing, and mitigating risks presented by suppliers, vendors, and other external partners who have access to your data, systems, or processes."
    },
    {
      question: "What does a 'SOC 2 Report' provide information about?",
      answers: [
        { text: "A company's financial controls.", correct: false },
        { text: "A service organization's controls related to security, availability, processing integrity, confidentiality, or privacy.", correct: true },
        { text: "The social media policies of a company.", correct: false },
        { text: "The societal impact of a corporation.", correct: false }
      ],
      explanation: "A SOC 2 (Service and Organization Control 2) report is an internal controls report capturing how a service organization safeguards customer data and how well those controls are operating, based on the AICPA's Trust Services Criteria."
    },
    {
      question: "What is 'Compliance' in the GRC context?",
      answers: [
        { text: "The act of compressing data to save space.", correct: false },
        { text: "The process of ensuring conformance with laws, regulations, standards, and internal policies.", correct: true },
        { text: "A list of all company employees.", correct: false },
        { text: "The speed at which a system operates.", correct: false }
      ],
      explanation: "Compliance is the outcome of adhering to prescribed guidelines, whether they are external (like laws) or internal (like corporate policies). It is a key driver for many security programs."
    },
    {
      question: "The 'ISO/IEC 27001' standard is primarily concerned with:",
      answers: [
        { text: "IT service management.", correct: false },
        { text: "Establishing, implementing, and maintaining an Information Security Management System (ISMS).", correct: true },
        { text: "Software development lifecycles.", correct: false },
        { text: "Project management.", correct: false }
      ],
      explanation: "ISO 27001 is an international standard that provides a framework for establishing, implementing, operating, monitoring, reviewing, maintaining, and improving an Information Security Management System (ISMS)."
    },
    {
      question: "What is the purpose of a 'Data Retention Policy'?",
      answers: [
        { text: "To ensure data is kept forever for historical purposes.", correct: false },
        { text: "To define how long different types of data should be kept and how they should be securely disposed of.", correct: true },
        { text: "To retain employees in the data department.", correct: false },
        { text: "To manage the performance of databases.", correct: false }
      ],
      explanation: "A data retention policy helps organizations manage legal and regulatory obligations, reduce storage costs, and minimize liability by systematically destroying data that is no longer needed."
    },
    {
      question: "What is a 'Control Objective'?",
      answers: [
        { text: "The target for a penetration test.", correct: false },
        { text: "A statement of the desired result or purpose to be achieved by implementing controls.", correct: true },
        { text: "The person responsible for a control.", correct: false },
        { text: "A budget for security tools.", correct: false }
      ],
      explanation: "Control objectives are high-level statements of what the organization wants to achieve with its security controls. They are often derived from business goals, risks, and compliance requirements (e.g., 'Ensure the confidentiality of customer data')."
    }
  ],
};