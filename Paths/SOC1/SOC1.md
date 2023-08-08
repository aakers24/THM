# SOC 1

Tags: Blue Team, Cyber Defense, MITRE, Cyber Threat Intelligence, IDS, IPS, Network Security, Traffic Analysis, Endpoint Security, EDR, SIEM, Digital Forensics, Incident Response, Windows, Linux, Phishing, Social Engineering

Tools: URL Shorteners, VirusTotal.com, Any.run, SysInternals Suite, Fuzzy hashing, MITRE ATT&CK, Shadow Copy, UrlScan.io, Abuse.ch, PhishTool, Talos Intelligence, Yara, Snort, Zeek, Brim, Wireshark, SysInternals Suite, OSQuery, Wazuh, ELK, Elasticsearch, Logshare, Kibana

Process/Notes:


## Cyber Defense Frameworks

### Pyramid of Pain

* In ascending order of difficulty for attackers:

    * Hash Values - Identifying malware or any other artifacts based on their hash values.

        * A change of a single bit completely alters a hash therefor bypassing this method. Fuzzy hashing aims to help remedy this for defenders.

    * IP Addresses - Identifying, blocking, and tracking attackers based on their IPs.

        * IP addresses can be changed or masked easily. For instance, proxies, vpns, etc.

    * Domains - Pretty much same as IPs but using Domains instead.

        * Again changable, but more involved.

        * URL shorteners are often used, but appending a "+" to the url will show you where the url actually leads.

    * Host Artifacts - Observable traces left behind. (e.g. files, registry values, records/logs, and other Indicators of Compromise (IoCs))

        * Forces attackers to change tools and methodologies.

    * Network Artifacts - Again observable traces left behind. (e.g. header information (like user-agents), C2 info, requests, etc.)

        * Forces attackers to change tools and methodologies.

    * Tools - Identification, blocking, removal, etc. of tools.

        * This shuts down use of these tools and forces attackers to find/create new ones. Fuzzy hashing helps to prevent attackers from making small changes to the same tools as referenced in the hash values section.

    * TTPs (Tactics, Techniques, and Procedures) - This basically covers all moves made by attackers.

        * This effectively shuts down attackers.

---

### Cyber Kill Chain

* Reconnaissance - Information Gathering

* Weaponization - Creation of harmful tools

* Delivery - Placement of harmful tools into/onto target infrastructure

* Exploitation - Execution of harmful tools

* Installation - Put stronger footholds into place (e.g. backdoors)

* Command and Control (C2) - Creation of a channel to remotely control and surveil the compromised target

* Actions on Objectives (Exfiltration) - Performing your end goals (e.g. Privesc, credential harvesting, data exfiltration, lateral recon and movement/pivoting, delete/corrupt data, etc.)

---

### Unified Kill Chain

* A more modern and detailed version of the previous Cyber Kill Chain

---

### Diamond Model

* Adversary - Attacker, Hacker, Cyber Threat Actor, APT (Advanced Persistent Threat)

    * Adversary Operator - Technical Attacker

    * Adversary Customer - Beneficiary of the attack

* Victim - Target of attack

    * Victim Personae - Targeted people and organizations

    * Victim Assets - Targeted systems, networks, etc.

* Capability - TTPs used in an event

    * Capability Capacity - Vulnerabilities a capability can take advantage of

    * Adversary Arsenal - Set of adversary's capabilities

* Infrastructure - Hardware and Software

    * Type 1 Infrastructure - Infrastructure owned by adversary

    * Type 2 Infrastructure - Infrastructure owned by an intermediary party- whether they're aware or not

    * Service Provider - Organizations required for the existance of previous 2 definitions (e.g. ISPs, power companies, domain registrars, etc.)

* Event Meta Features - Optional information

    * Timestamp of events

    * Phase of attack

    * Result / outcomes if known

    * Directions of attack

    * Methodology

    * Resources used

* Social-Political - Needs/Intent/Motive of attacker

* Technology - Technical methods of attacker such as capabilities and infrastructure

---

### MITRE

* ATT&CK (Adversarial Tactics, Techniques, & Common Knowledge) - Knowledge Base of TTPs from real world

* CAR (Cyber Analytics Repository) - Knowledge Base of analytics based on ATT&CK

* ENGAGE - Framework for planning and discussing adversary engagement operations

* D3FEND (Detection, Denial, and Disruption Framework Empowering Network Defense) - Knowledge graph of countermeasures

* AEP (ATT&CK Emulation Plans) - Knowledge base of plans to emulate adversarial operations

---
---

<br/>

## Cyber Threat Intelligence

### Cyber Threat Intelligence

* Strategic Intel: High-level view of threat landscape

* Technical Intel: Evidence and Artifacts used by adversaries

* Tactical Intel: Adversary TTPs

* Operation Intel: Adversary's motives for a specific attack

* CTI Lifecycle:

    * Direction - Planning and analysis of assets

    * Collection - Often automated, gathering data to address objectives made in Direction phase

    * Processing - Extraction and organization of collected data. SIEMs often used

    * Analysis - Insight derivation based on processed data

    * Dissemination - Informing all relavent parties across disciplines such as stakeholders and technical teams

    * Feedback - Incorporation of inputs from relavent parties

* CTI Standards and Frameworks - MITRE ATT&CK, TAXII, STIX, Cyber Kill Chain, Diamond Model

---

### Threat Intelligence Tools

* UrlScan.io - Website scanning and analysis

* Abuse.ch - Identify and track malware and botnets

    * MalwareBazaar - Share malware samples

    * FeodoTracker - Track botnet C2 infrastructure

    * SSLBlacklist - Collects and provides a blocklist for malicious SSL certs and JA3/JA3s fingerprints

    * URLHaus - Share malware distribution sites

    * ThreatFox - Share IoCs

* PhishTool - Email analysis

* Cisco Talos Intelligence - Actionable intelligence, indicator visibility, and protection against threats

---

### Yara

* Yara is basically a pattern matching tool.

* `yara <rule file>.yar <target file/dir/PID>`

* Rules require a name and a condition. The syntax is method-like (e.g. rule myRule { condition } )

* Satisfied rules will return their rule name and the file that satisfied it

* "any of them", "and", "not", and "or" can be used in the conditions section

* Rule syntax: 
    ```
    rule <ruleName> {
        <keyword>:
            $<varName1> = "String1"
            $<varName2> = "String2"

        condition:
            $<varName1> or $<varName2>
        }
    ```

* Some other libraries include Cuckoo Sandbox and Python PE

* LOKI is a FOSS(Free and Open Source Software) IoC scanner which detects based on:

    1. File name IoC check
    1. Yara rule check
    1. Hash check
    1. C2 back connect check

* Other Yara tools include THOR, Fenrir, YAYA, yarGen, and Valhalla

---

### OpenCTI

* OpenCTI is an open source platform that provides storage, analysis, visualization, and presentation of threat campaigns, malware, and IoCs.

---

### MISP

* MISP is open source and stands for Malware Information Sharing Platform

* It's used for Malware RE, security investigations, intel analysis, and risk and fraud analysis

---
---

<br/>

## Network Security and Traffic Analysis

### Snort

* Snort is an open source Network Intrusion Detection and Prevention System (NIDS/NIPS/IPS).

    * Intrusion Detection System (IDS):
    
        * Network Intrustion Detection System (NIDS) - Monitors traffic flow of the network and alerts on identified suspicious/malicious traffic.

        * Host-Based Intrustion Detection System (HIDS) - Monitors traffic flow of a system and alerts on identified suspicious/malicious traffic.

    * Intrusion Prevention System (IPS):

        * Network Intrusion Prevention System (NIPS) - Monitors traffic flow of the network and terminates identified malicious traffic.

        * Behavior-based Intrusion Prevention System (Network Behavior Analysis (NBA)) - Same as NIPS but requires a training/baselining period initially to learn to ID traffic.

        * Wireless Intrusion Prevention System (WIPS) - Monitors traffic flow of the wireless network and terminates identified malicious traffic.

        * Host-Based Intrusion Prevention System (HIPS) - Monitors traffic flow of a system and terminates identified malicious traffic.

* Snort uses rules to define malicious network traffic and identify such packets which also allows for the generation of alerts.

* Detection/Prevention Techniques:

    * Signature-Based - Uses rules to identify known patterns of behavior.

    * Behavior-Based - Identifies new patterns of behavior by matching them with old known patterns of behavior.

    * Policy-Based - Compares detected activities with system configs and security policies.

* Snort Rule Syntax is as follows in order from first to last - 

    * Action - Alert, Drop, Reject

    * Protocol - TCP, UDP, ICMP, IP

    * Source IP

    * Source Port

    * Direction - -> (src to dest flow), <> (bidirectional flow), (There is no <- (dest to src) option in Snort)

    * Destination IP

    * Destination Port

    * Options - Msg, Reference, Sid (Snort rule ID), Rev (Revision), Content, Nocase, Fast_pattern, ID, Flags, Dsize, Sameip

    * `alert <action> <src ip> <src port> <->, <>> <dest IP> <dest port> (<options>)`

    * E.g. `alert icmp 2.2.2.2 any <> 1.1.1.1 any (msg:"ICMP Packet!";reference:CVE-XXXX;sid:10100101;rev:1;)`

* Your created rules should be in your local.rules file

---

### NetworkMiner

* NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) that can be used as a passive sniffer/pcap tool without putting any traffic on the network as well as parse PCAPs. It has a GUI that organizes all of the data and does things like OS fingerprinting.

* It shouldn't be used as a primary tool, but instead a more passive, high-level overview tool that can be easily used because of the GUI.

* *A personal note: It looks like they're running NetworkMiner windows files using Mono(JIT Compiler)*

---

### Zeek

* Zeek was formerly named Bro and it is a platform for Network Security Monitoring (NSM) which is flexible, open-source, and passive. It also does some things outside of security such as performance measurements and troubleshooting.

*There is a fine distinction being made here that Network Monitoring is more than just Network Security Monitoring.*

* A major difference that sets Zeek apart from other NSMs (Network Security Monitor(s)) is that it allows for the creation of a very wide variety of log types and is event-based rather than other paradigms such as signature-based. *Zeek also does support signatures though.*

* Zeek generates well organized log files. These can be viewed and analyzed manually or run through other tools such as ELK or Splunk. There is also a tool called `zeek-cut` which can aid in manual analysis.

* Zeek supports `.zeek` scripts and has a package manager to download modules with that is called by `zkg` and the modules can be called like scripts or with their package name.

---

### Brim

* Brim is yet another pcap analysis and logging tool. It's open source and has a focus on search and analytics.

* Brim uses the Zeek log processing format, supports Zeek signatures, Suricata rules, and can analyze pcaps and logs with the Zeek structure.

* Brim, Wireshark, and Zeek have some overlapping features, but are best used together. Each one has a place where it stands out in the process. Common best practice includes using Wireshark for medium-sized pcaps, using Zeek for creating logs and correlating events, and processing multiple logs in Brim.

* Suricata is an open source threat detection engine that can act as a rule-based IDS/IPS. It is similar to Snort and can use the same signatures.

---

### Wireshark

* Wireshark is an open-source, cross-platform, tools for sniffing and analyzing live network traffic as well as creating and inspecting pcaps.

* *To satiate my own curiosity I wanted to know what a pcapng file was because I've seen things with ng appended before including this file extension and didn't know what it meant. Apparently the ng means next generation.*

* Packet or Protocol Dissection is investigating packet details by decoding available protocols and fields.

* DHCP (Dynamic Host Configuration Protocol) is resposible for managing automatic IP address and required communication parameters.

* NetBIOS (Network BIOS - Network Basic Input/Output System) is resposible for allowing applications on different hosts to communicate. NBNS (NetBIOS Name Service) is the abbreviation in Wireshark.

* Kerberos is the default authentication service for Windows domains and is responsible for service requests between two or more computers over the untrusted network. Its goal is to provide secure identity.

* ICMP (Internet Control Message Protocol) was made to diagnose and report network issues and is used in reporting and testing. It is often trusted and is used for DoS attacks and data exfiltration/tunneling by way of the addition data payload it can transfer.

    * Large volumes or packet sizes, especially after a security breach, are IoCs. A way around the size issue for attackers is to create custom packets only containing the usual 64 bytes.

    * The tunnelled data is often formatted to the TCP, HTTP, or SSH protocols.

* DNS (Domain Name System) is the system which maps IPs to domain names. As with ICMP it is often trusted and used for data exfiltration/tunneling.

    * DNS also has IoCs such as unusually high volumes and lengths, especially after a security breach.

    * The concept is that a domain is configured as a C2 channel and DNS queries are sent to this server. These queries are crafted as subdomain queries, but the subdomains are actually commands or data being encoded into the queries.<br/>`<command/data>.<C2server>.com`<br/>The commands are sent as responses.

*I already knew most if not all of this, but for some reason some things about ICMP and DNS wouldn't stick in my head like the SYN, ACK, RST of TCP and things like UDP's one-wayness, etc. Hopefully noting these things down help me remember more clearly.*

* http2 is https and you need to add the key to wireshark to view the traffic.

* In "tools" you can search for plaintext credentials as well as generate firewall rules.

---
---

<br/>

## Endpoint Security Monitoring

### Intro to Endpoint Security

* Windows logs are stored in .evt/.evtx files which are propriatary binary formats. They can be converted to XML using the Windows API. The files are normally stored in "C:\Windows\System32\winevt\Logs".

* The ways to view these logs include:

    * `Event Viewer` - GUI

    * `Wevtutil.exe` - cli

    * `Get-WinEvent` - Powershell cmdlet

* `Sysmon` is also a tool used for monitoring and logging events on windows and is part of the SysInternals suite.

* `OSQuery` by Facebook is an open-source tool that uses SQL syntax to query endpoints including Windows, Linux, Mac, and FreeBSD.

* `Wazuh` is an open-source, scalable, and extensive EDR tool which runs on a manager/agent paradigm or model.

* An Endpoint Detection and Response (EDR) tool is an application that monitors devices for IoCs through various means including vulnerability auditing, visualizing collected data, recording normal operational behavior, and proactive monitoring of things like logins, brute-force attacks, and privesc.

---

### Core Windows Processes

* System Idle Process (0) > System (PID 4, Session 0) > smss.exe (Session 0, 2 instances- parent & child. child self-terminates after session creation)

* smss.exe > csrss.exe (Session 0) && wininit.exe (Session 0, user: system, 1 instance)

* smss.exe > csrss.exe (Session 1) && winlogon.exe (Session 1, user: system, 1 instance regularly but more for additional logons/sessions)

* wininit.exe > services.exe (Session 0, user: system, 1 instance) > svchost.exe (Session 0, user: system, bin path called with -k)

* wininit.exe > lsass.exe (Session 0, user: system, 1 instance)

* winlogon.exe > userinit.exe (launches value in "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ShellPrograms" and/or explorer.exe then exits) > explorer.exe (Session 1+, 1 instance but more for additional interactive logons/sessions, user: user)

*Session 0 is an isolated session for the OS.*

---

### Sysinternals

*Some things in this section may get skipped as I already have the Sysinternals suite installed and have some experience using it.*

* `Sysinternals Live` lets you use the Sysinternals tools from the web instead of downloading them.

    * You can run a tool by entering `live.sysinternals.com/<tool>` or `\\live.sysinternals.com\tools\<tool>` into windows explorer or command prompt respectively.

    * Installing and running the WebDAV client on the machine allows the Live functionality. The WebDAV protocol allows remote access to the machine by way of the WebDAV share.

    * Network Discovery also needs to be enabled.

* Tools highlighted:

    * Sigcheck - CLI utility tool that displays some file information and offers some interoperability with VirusTotal

    * Streams - Allows you to view Alternate Data Streams (ADS)
    
        * NTFS allows applications the ability to create alternate streams of information. By default all data is stored in a file's main unnamed data stream. Using the `<file>:<stream>` syntax you can read and write to alternates. Every file has at least one data stream ($DATA), and by default this is the only one displayed to users.

        * <cmd> <File>:<Stream> - E.g. notepad File.exe:hiddenFile.txt

        *Linux/unix has many filesystems that support Extended Attributes (EA, xattr) which are basically the same thing as ADSs, though often very limited in size.*

    * SDelete (Secure Delete) - CLI tool to delete one or more files/directories or cleanse the free space on a logical disk.

        * It uses 3 passes. The first pass writes a zero and verifies the write. The second pass writes and verifies a 1. The third writes and verifies a random character.

    * TCPView - Shows detailed listing of all TCP and UDP endpoints on the system.

    * Autoruns - A utility that shows what automatically runs on the system including on boot, on logon, or on an application start.

    * ProcDump - CLI util primarily purposed for monitoring CPU usage and generating crash dumps for applications. This can also be done through Process Explorer.

    * Process Explorer (ProcExp) - Provides detailed information for all processes running on the system.

    * Process Monitor (ProcMon) - A monitoring tool that shows detailed, real-time information on the FS (file system), registry, and processes/threads activities. It is a continuation of two previous sysinternals tools filemon and regmon.

    * PsExec - A lightweight tool that allows execution of processes on other systems, including full interactivity for console applications. It is a replacement for Telnet.

    * Sysmon (System Monitor) - A windows system service and device driver that is persistent across reboots that monitors and logs system activity to the Windows event log.

    * WinObj - A 32-bit Windows NT program that accesses and displays information on the NT Object Manager's namespace.

    * BgInfo - A tool to automatically display relevant information about the computer.

    * RegJump - Opens regedit to a given registry path.

    * Strings - Scans the given file for UNICODE or ASCII strings. By default strings must be 3 or more characters.

        *On windows the `FindStr` command is a good replacement for the unix `grep` command*

---

### Windows Event Logs

*A note: On unix/linux logs are in text format and by default stored in /var/log/*

* The types of event logs on windows include:

    * System Logs - Records events relating to the OS including hardware, drivers, and system/device changes.

    * Security Logs - Records security events primarily including log on/off.

    * Application Logs - Records events related to the applications installed and/or running on the system.

    * Directory Service Logs - Records events related to active directory including changes and activities and are mainly logged on the Domain Controllers.

    * File Replication Service Logs - Records events related to Windows Servers during the sharing of group policies and logon scripts to domain controllers, from where they can be accessed by the users through the client servers.

    * DNS Event Logs - Records events related to DNS and DNS servers use these logs.

    * Custom Logs - Records events related to application that require custom data storage. These are partially dictated by the applications themselves based on the application's specific needs or operations.

* There are 5 event types in windows logs which include:

    * Error - Indicates significant problem which could be a loss of data or function.

    * Warning - Indicates a less significant problem than an Error, and this problem may indicate or lead to a future failure or loss of data.

    * Information - Indicates an event which resulted in a successful operation.

    * Success Audit - Indicates that a audited security access attempt was successful. E.g. successful user logon.

    * Failure Audit - Indicates that a audited security access attempt failed. E.g. a user tries to access a drive and fails.

* XPath is short for XML Path Language and it is meant to provide a standard syntax and functionality for addressing and manipulating parts of XML documents.

    * wevtutil.exe and Get-WinEvent both support XPath queries.

---

### Sysmon

* System Monitor, or Sysmon, is a tool in the Sysinternals Suite which is made for monitoring and logging Windows events. It is like a more detailed Windows Event Logs.

* Sysmon events are stored in "Applications and Services Logs/Microsoft/Windows/Sysmon/Operational".

* Sysmon can make use of a config file which you can make yourself or download a premade config.

* Sysmon monitoring and loggin in conjuction with some of the previously mentioned log inspection tools/methods such as Get-WinEvent and XPath can give very granular control and insight on the Windows machine.

---

### OSQuery

* OSQuery is an open-source and cross-platform tool that represents the operating system as a relational database, allowing queries using SQL syntax.

* OSQuery interactive mode is called by using `osqueryi`. Once run, `.help` runs the help command, as meta commands have a period prepended.

---

### Wazuh

* Wazuh is a free, open-source, scalable, and extensible EDR system that uses a management-agent paradigm.

* The Wazuh manager is installed on/as a server and the agent is installed on the endpoints that are being monitored. The Agents can be grouped, and are provided an address (Domain or IP) to send their logs to (the manager).

* Wazuh Agent vuln scans take the installed applications and their version numbers and send this information to the manager which has a database of CVEs that it compares with to check for vulnerabilities. This scan is performed on install and requires an interval be set at which the scan will run.

* The Agents can also be set to check their configuration against a ruleset for compliance. This can be checked against frameworks/standards such as MITRE and NIST. This is also run on install by default.

* As previously noted, the Wazuh agents collects logs and sends those logs to their manager. This works on all operating systems (obviously). Wazuh can be configured to grab and send any log. E.g.:

    * On Windows, Sysmon can be configured, then Wazuh can be configured to send those Sysmon logs, and the Wazuh manager can be configured to visualize this data.

    * On Linux, just as any system there are numerous logs, but an example is auditd. This can be configured in many ways and then the log can be collected using the Wazuh Log Collector, and sent to the manager.

* Wazuh has premade rules for log analysis, but custom rules are made using XML.

* Wazuh also features a web API. The client must authenticate and then use a token given by the manager. Once this is done, HTTP requests can be sent to the manager and can be used to interact with it. There is also an API console which is less flexible and powerful than the CLI, but allows use with a GUI.

* Wazuh can also create reports which give a summary of events on an agent. These can be easily generated and viewed through the manager server.

---
---

<br/>

## Security Information and Event Management

### Introduction to SIEM

* Security Information and Event Management (SIEM) tools collect data from endpoints across a network, store them in a central location, and performs correlation and analysis on them.

    * SIEMs use rules to analyze the ingested data. Once a detection happens or a set threshold is crossed, the SIEM creates an alert.

* Logs are generally split into host and network focused logs.

* One of the main benefits of SIEM is that it takes logs from all of the endpoints/network *and* allows for correlation of the events, searching all of the logs, and fast investigation/response to incidents. This cuts down on the enormous amount of work/time that goes into managing a network and its security.

* The logs collected on endpoints (e.g. Windows Event Viewer logs, Linux /var/log/, Webserver Logs, etc.) are ingested by the SIEM system. Common Log Ingestion techniques include:

    * Agent - A lightweight tool that is part of the SIEM system installed on the endpoint that captures the logs and sends them to the SIEM server. (In Splunk this is refered to as the Forwarder)

    * Syslog - This is a protocol in which data is collected in real-time and sent to the central locale.

    * Manual Upload - Title explains this method. Data is ingested offline, then once it is ingested and normalized it can be analyzed.

    * Port-Forwarding - SIEMs can listen on a port. Then the endpoints forward the data to the SIEM server's listening port.

* Correlation rules are the rules used when analyzing ingested data. These are logical statements correlation to certain events. E.g. login attempts in a set period of time or "If the log is windows and event ID is <EventID>, trigger an alert for <Event>". *Basically just what you'd think based on previous "rules" discussed in the path.*

* Rules often need to be tuned and are subject to company policies. Alerts that aren't false positives are investigated by the SOC or equivalent.

---

### ELK 101

* ELK is an open-source tech stack used as a SIEM solution consisting of Elasticsearch, Logstash, and Kibana.

    * Elasticsearch is an open-source search and analytics engine. It is text-based and stores documents in JSON format. It supports RESTful API interaction.

    * Logstash is an open-source server-side data processing pipeline. It ingests data from multiple sources simultaneously, transforms it, and sends it to a destination such as a "stash" like Elasticsearch.

        * The Logstash config file is split into 3 parts.

            * Input - The source of the data to be ingested.

            * Filter - Options used to normalize the ingested information.

            * Output - Where the filtered information is sent.

    * Kibana is an open-source, web-based data visualization dashboard for Elasticsearch.

    * Beats is an open-source host-based agent that is a Data-shipper which is used to transfer data from endpoints to Elasticsearch. 

* Kibana Query Language (KQL) is a query language used to search ingested information in Elasticsearch. Lucene Query Language is also supported.

---