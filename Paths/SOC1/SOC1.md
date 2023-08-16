# SOC 1

Tags: Blue Team, Cyber Defense, MITRE, Cyber Threat Intelligence, IDS, IPS, Network Security, Traffic Analysis, Endpoint Security, EDR, SIEM, Digital Forensics, Incident Response, DFIR, Windows, Registry, Linux, Malware Analysis, Virtual Machine, Sandbox, Phishing, Social Engineering

Tools: URL Shorteners, VirusTotal.com, Any.run, SysInternals Suite, Fuzzy hashing, MITRE ATT&CK, Shadow Copy, UrlScan.io, Abuse.ch, PhishTool, Talos Intelligence, Yara, Snort, Zeek, Brim, Wireshark, SysInternals Suite, OSQuery, Wazuh, ELK, Elasticsearch, Logshare, Kibana, Splunk, RegEdit, EZ Tools, KAPE, Autopsy, Volatility, Redline, Velociraptor, TheHive

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

* VirusTotal(.com) - Massive database with information on malware, IPs, etc.

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

### Splunk

* Splunk is one of the industry leaders in SIEMs. It is a paid product and is not open-source.

* It is comprised of three main components which are the Forwarder, Indexer, and Search Head.

    * Forwarder - Lightweight agent installed on endpoints which collects data and sends it to the Splunk instance. It is analogous to the previously mentioned SIEM agents.

    * Indexer - Main data processor of Splunk which takes data from Forwarders, normalizes, and stores them for search and analysis.

    * Search Head - Location in the Splunk App which allows for searching information processed by the indexer. It provides a search feature as well as use of Splunk Search Processing Language (SSPL). Requests are sent to the indexer which returns results.

---
---

<br/>

## Digital Forensics and Incident Response

### DFIR Introduction

* Digital Forensics and Incident Reponse (DFIR) is an essential part of Cybersecurity because there will always be a threat of an attack succeeding and therefore preparation for such an event must always be maintained; in the event of any sort of successful attack that isn't stopped by primary defenses, the defenders need to be technically and mentally prepared.

    * DFIR practices include collection of digital forensic artifacts for purposes including identifying evidence of the attack, determining the extent to which the assets/environment have been compromised, and restoring the environment to a fully secure and functional state as it was before the event.

    * DFIR also has a number of positive side-effects including:
    
        * Completely removing the attacker and their access to the environment/assets.

        * Improving future security of the environment and assets.

        * Information gathering and reporting.

            * Communication of information to relavent non-technical parties.

            * Communication of information to the Cybersecurity community.

    * Though they go together in concept and practice, DFIR is typically split up into the two fields which the name suggests- Forensics and Response.

* DFIR core concepts include:

    * Artifacts - Evidence left behind on a system.

    * Maintenance of the integrity of evidence -

        * Evidence Preservation -

            * Collected evidence is immediately write-protected.

            * Subsequently, a copy of the write-protected evidence is made and used for analysis.

        * Chain of Custody - 

            * Evidence is kept in secure custody. Anyone unqualified and apart from the investigation is not to take possession of the evidence; violation of this contaminates the Chain of Custody.

        * Order of Volatility - 

            * Evidence comes in varying degrees of volatility; some evidence will degrade or become unusable and must be processed before this happens. It is important to follow the order of volatility when prioritizing the order in which evidence is at least initially processed.

    * Timeline Creation -

        * Once evidence has been collected and processed without compromising it's integrity, the information extrapolated is used for many things such as analysis and reporting. One tool/deliverable is a timeline of events which plots all of the actions and evidence chronologically.

* Some common DFIR tools include:

    * Eric Zimmerman's tools (EZ Tools) - A security researcher wrote some open-source tools to perform forensic analysis on Windows systems.

        * KAPE (Kroll Artifact Parser and Extractor) - Free and written by Eric Zimmerman, it automates parsing/collection of artifacts.

    * Autopsy - Open-source platform for forensics which aids in data analysis.

    * Volatility - Open-source tool for Windows and Linux that aids in memory analysis of memory captures.

    * Redline - Free tool by FireEye that gathers forensic data from a system and aids with collected information.

    * Velociraptor - An open-source tool for endpoint-monitoring and DFIR.

Disk Image and Memory Capture -

    * Disk Images and Memory Captures are bitwise copies of the filesystem and volatile memory respectively.

    * Tools to create these include -

        * Forensic Tool Kit (FTK) - FTK Imager - An open-source, cross-platform tool for creating these images/captures from both Windows and Linux systems.

---

### *The Incident Response Lifecycle*

* As defined by NIST. (Incident Handler's handbook by SANS also has a definition that is basically the same but written differently which allows it to be abbreviated as PICERL)

1. Preparation - Readiness against attack. This includes documentation of requirements, definition of policies, inclusion and deployment of security tools, and training.

1. Detection & Analysis - The process of detecting and analysing events that qualify as incidents. This includes getting alerts from tools, investigation into alerts, and hunting for unknown threats.

1. Containment, Eradication, & Recovery - Preventing the spread of an incident and securing the system/network. This includes infected host isolation, removing infection artifacts, and regaining control.

1. Post-Incident Activity - Reflection and evaluation of security posture. This includes understanding the cause of the breach, ameliorating this cause as well as other vulnerabilities, creation of rules and policies which help detect or prevent a similar incident, and further training. This blends back into Preparation and the cycle continues.

---

### Windows Forensics

#### Windows Registry

* The Windows Registry is a database that hold the system's configuration data including information about the hardware, software, and users/accounts.

    * The Registry follows the key-value paradigm. A Registry Hive is a group of Keys, subkeys, and values stored in a single file on the disk.

    * Windows systems have 5 root keys - 

        * HKEY_CURRENT_USER (HKCU) - Root config information for the user currently logged on. A subkey of HKU.

        * HKEY_USERS (HKU) - Stores root config info for all actively loaded user profiles on the system.

        * HKEY_LOCAL_MACHINE (HKLM) - Root config info for the system itself.

        * HKEY_CLASSES_ROOT (HKCR) - Contains info that ensures windows explorer opens the correct programs. A subkey of HKLM\Software. This information is stored in HKLM\Software\Classes for the system config, but the information stored in HKCU\Software\Classes is essentially a modifiable config that will supersede the system config for that user. The HKCR key gives a merged view of these sources.

        * HKEY_CURRENT_CONFIG (HKCC) - Contains hardware profile information. Info is used by local computer at startup.

        *HKEY stands for Handle to registry KEY*

* The Registry Editor `RegEdit (regedit.exe)` is the inbuilt tool for viewing and modifying the registry through a GUI.

* If you don't have access to RegEdit for any reason, such as only having access to the disk or cli, it is necessary to know where the registry hives are located. Generally they can be found in "C:\Windows\System32\Config". Some of these files will be hidden.

    * "C:\Windows\System32\Config" contains -

        (Here "-" is read "mounted at")

        * DEFAULT - HKU\DEFAULT

        * SAM - HKLM\SAM

        * SECURITY - HKLM\Security

        * SOFTWARE - HKLM\Software

        * SYSTEM - HKLM\System

    * On Win7 and newer, "C:\Users\\\<User>" contains -

        (Here "-" is read "mounted at")

        * NTUSER.DAT - HKCU

        * USRCLASS.DAT - HKCU\Software\CLASSES

    * The AmCache hive, which stores information about the system's recently run programs, can be found at "C:\Windows\AppCompat\Programs\Amcache.hve"

* Registry transaction logs are essentially a changelog of the registry hive. Windows often uses these when writing data to hives, thus they can contain data not present yet in the hive itself. Each hive's transaction log is stored as a ".LOG" file in the same directory and with the same name as the hive.

* Registry backups are copies of the Sys32\config hives and are stored in "C:\Windows\System32\Config\RegBack". They are generally copied every 10 days.

#### Windows Registry Forensics

* In accordance with previous section notes, when performing forensic investigation it is generally best practice to image the system or make a copy of the data to be examined and perform forensics on the copy. This process is called data acquisition.

    * A copy of the registry can be more complicated than a simple copy of the files due to the restricted nature of the files/locations such as "%WINDIR%\System32\Config". There are methodologies, techniques, and tools to ameliorate this problem.

    * Some helpful tools for data extraction include -

        * KAPE - A primarily CLI live data acquisition and analysis tool that comes with a GUI whose purpose is to acquire forensic artifacts including registry data.

        * Autopsy - A tool for extracting data from live systems or disk images.

        * FTK Imager - Another tool for extracting data from live systems or disk images.

    * Some helpful tools for viewing extracted data include - 

        (RegEdit isn't applicable because it must be run on a live system)

        * Registry Viewer - Similar GUI to RegEdit.

        * Zimmerman's Registry Explorer - Excellent tool for viewing offline registry data.

        * RegRipper - Creates reports based on registry hive inputs.

* Some useful information that will be common points of interest include -

    * OS Version - SOFTWARE\Microsoft\Windows NT\CurrentVersion

    * Control Sets (Hives with system startup config for the machine) -

        * Generally there are 2 in SYSTEM - ControlSet001 contains the control set the machine booted with. ControlSet002 contains the last known good config.

            * SYSTEM\ControlSet001

            * SYSTEM\ControlSet002

        * There is a volatile control set while the machine is live called CurrentControlSet stored in HKLM\SYSTEM\CurrentControlSet. This is generally the most accurate information. Which control set is being used can be found in SYSTEM\Select\Current and the last known good control set can be found in SYSTEM\Select\LastKnownGood.

    * Computer Name - SYSTEM\\\<CurrentControlSet>\Control\ComputerName\ComputerName

    * Time Zone Info - SYSTEM\\\<CurrentControlSet>\Control\TimeZoneInformation

    * Network Interfaces - SYSTEM\\\<CurrentControlSet>\Services\Tcpip\Parameters\Interfaces

        * Past Networks -

            * SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed

            * SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged

    * Autostart Programs - 

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce

        * SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

        * SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run

    * Services - SYSTEM\\\<CurrentControlSet>\Services

        * Services with the start regkey set to 0x02 run at startup

    * SAM hive / User info - SAM\Domains\Account\Users

    * Windows stores a list of each user's recently opened files - NUTSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

        * This is also filtered by filetype - E.g. NUTSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt

    * Recent Microsoft Office files -

        * NTUSER.DAT\Software\Microsoft\Office\\\<Version>\\\<Program>

        * For office 365 - NTUSER.DAT\Software\Microsoft\Office\\\<Version>\UserMRU\LiveID_<User's live ID>\FileMRU

    * Windows ShellBags (The preferences of layouts and properties for when the Windows "Shell" opens a folder) and their most recently used files/folders -

        * USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags

        * USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU

        * NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags

        * NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU

        * ShellBag Explorer from EZ tools is a useful tool when dealing with ShellBags

    * MRU (Most Recently Used) Open/Save and LastVisited Dialogue -

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU

    * Windows Explorer address/search bars -

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery

    * UserAssist - Windows stores information including program names, launch times, and number of launches about programs launched from Windows Explorer and this data is stored in the User Assist registry keys.

        * NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\\\<GUID>\Count

    * ShimCache - Tracks backwards and application-OS compatibility as well as all applications launched on the system (Name, Size, Last Modified Time of the EXEs). It is also known as Application Compatibility Cache (AppCompatCache).

        * SYSTEM\\\<CurrentControlSet>\Control\Session Manager\AppCompatCache

    * Amcache - Stores execution path, installation, execution/deletion times, and SHA1 hashes of programs executed on the system.

        * Amcache.hve\Root\\\<File Type/Category>\\\<File>

    * Background Activity Monitor (BAM) / Desktop Activity Monitor (DAM) - Tracks activity of background applications and desktop applications respectively.

        * SYSTEM\\\<CurrentControlSet>\Services\bam\UserSettings\\\<SID>

        * SYSTEM\\\<CurrentControlSet>\Services\dam\UserSettings\\\<SID>

    * Device ID - Windows keeps track of USB keys plugged into the system and store information such as time of connection and IDs for vendor, product, and version.

        * SYSTEM\\\<CurrentControlSet>\Enum\USB

        * SYSTEM\\\<CurrentControlSet>\Enum\USBSTOR

        * Deeper inside these keys, the first and last connection time as well as last disconnection time are stored

            * SYSTEM\\\<CurrentControlSet>\Enum\\\<USB/USBSTOR>\\\<VID&PID>\\\<USBSerial#>\Properties\\\<ID>\\\<Value>

                * Where value is set to and corresponds with -

                    * 0064 - First Connection Time

                    * 0066 - Last Connection Time

                    * 0067 - Last Removal Time

    * USB volume names -

        * SOFTWARE\Microsoft\Windows Portable Devices\Devices

#### Windows File System

* A filesystem (fs) is a standardized way to organize the bits/files on a storage medium.

* A sector is the minimum storage unit of a drive.

* A cluster is a group of sectors that are allocated as a unit. The cluster size is the minimum size of a block that is readable/writeable by the OS.

* File Allocation Table (FAT) - The FAT fs is one file system used by Windows and used to be the default. It is a table that indexes the bit locations of files. It is fairly primitive and lacks in features outside of the ability to store/organize data.

    * FAT Data Structures -

        * Cluster - The basic storage unit of FAT. Each files is a group of clusters which are groups of bits.

        * Directory - Contains file ID info such as name, namelength, and first cluster.

        * File Allocation Table - A linked list of all clusters. Nodes contain cluster status and pointer to next cluster.

    * FAT, FAT12, FAT16, FAT32 - The numbers started at 8 with FAT and the numbers represent the length of the cluster addresses in bits.

    * exFAT - Dramatically increased volume capacity with less security and overhead than NTFS and therefore lighter-weight.

* New Technology File System (NTFS) - 

    *New Technology is what NT stands for (E.g. Windows NT) so it isn't wrong to think of it as NT file system*

    * NTFS was made to have more features than the previous FAT, including better security, reliability, and less limitation.

        * Journaling - A metadata changelog for the volume. Stored in $LOGFILE in the volumes root directory.

        * Access Controls - Definition of file/dir owners and permissions for each user.

        * Volume Shadow Copy - Keeps track of file changes and can be used to restore previous file/volume states for recovery.

        * Alternate Data Streams (ADS) - Allows a file to have multiple streams of data.

        * Master File Table (MFT) - Like a more evolved version of the FAT. It is implemented as an array of file records. Some notable and important files in the MFT include -

            * $MFT - The first record in the volume. The Volume Boot Record (VBR) points to the cluster containing $MFT. $MFT stores info about the clusters where all other objects on the volume are located and contains a directory of all files on the volume.

            * $LOGFILE - Stores the transactional logging of the fs.

            * $UsnJrnl (Update Sequence Number Journal) - Present in the $Extend record and holds info about all files changed and the reason for the changes. Basically a changelog and sometimes referred to as change journal.

    * MFT Explorer is from EZ tools and is a cli and/or gui tool used to explore the MFT files.

#### Data Recovery

* When a file is deleted, the filesystem removes the entry from the file table or it's equivalent. This means the data is still on the disk as long as it hasn't been overwritten or damaged.

* A disk image or disk image file is a bitwise copy of a disk drive.

    * There are many ways to make a disk image. A popular tool for this is FTK imager.

* Using a disk image, the entire drive can be scanned (manually or using tools for automating).

    * Autopsy is one tool that can be used to scan disk image.

#### Windows Filesystem Forensics

* Windows Prefetch Files - Information about run programs are stored in "C:\Windows\Prefetch" with an extension of `.pf` in case of further frequent use to increase efficiency.

    * pf files contain last run times, run count, and files/handles used.

    * Prefetch Parser from EZ tools is made for analysis of these files. Many of the EZ Tools can use EZ Viewer to view the output data.

* In Windows 10, there was a SQLite db called the Windows 10 Timeline that stored information on last executed programs. It is stored at "C:\Users\\\<User>\AppData\Local\ConnectedDevicesPlatform\\\<folder>\ActivitiesCache.db". There is also an EZ Tools tool for this.

* Windows Jump Lists - Meant to help users get to their recently used files from the taskbar by right-clicking an application and viewing it's recently used files. The data is stored in "C:\Users\\\<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations". Again, there is an EZ Tools tool for this.

* Shortcut Files - Windows makes shortcut files for every file opened both locally and remotely which contain data like opening times and file paths. Again, there's an EZ Tools for it.

    * C:\Users\\\<User>\AppData\Roaming\Microsoft\Windows\Recent\

    * C:\Users\\\<User>\AppData\Roaming\Microsoft\Office\Recent\

    * These can also sometimes contain information on USB devices.

* Internet Explorer and Edge History - The browsing history includes files opened on the system even those not opened using the browser. They have a prefix of "file:///". Many tools can analyze web cache data including Autopsy.

* Setupapi dev logs for USB devices - "C:\Windows\inf\setupapi.dev.log" stores setup information when any new device is attached to the system

---

### Linux Forensics

#### Linux System Config and Info

* In linux, instead of the registry database and special registry hive files, linux's configuration and information is held in regular files, most of which are usually located in the /etc/ directory.

* Some useful information that will be common points of interest include -

    * OS-Release - /etc/os-release

    * Accounts - /etc/passwd contains entries with 7 colon-seperated fields which contain username, password info, uid, gid, description, home dir info, and default shell. User created user accounts have uids of 1000+.
    
        * /etc/shadow may also contain password information for accounts.

    * Groups - /etc/group

    * Sudoers - Users may only elevate priviliges using sudo if present in the sudoers file /etc/sudoers

    * Login Info - In /var/log/, the btmp file contains info about failed logins and the wtmp file contains data about logins. These are binary files read using `last`.

    * Authentication Logs - Every user authentication on a linux system is logged. The auth log is /var/log/auth.log.

    * Hostname - /etc/hostname

    * Timezone - /etc/timezone

    * Network -
    
        * /etc/network/interfaces shows network interfaces

        * `ip` can be used for finding MAC and IP addresses of the interfaces and more

        * `netstat` can be used to monitor active network connections

    * DNS - /etc/hosts holds the DNS name assignment configuration

        * /etc/resolv.conf holds info regarding the DNS servers that the system uses for DNS resolution

    * Processes Running - `ps`

#### Linux Filesystems

* Since the early '90s Linux has used the EXT (Extended) file system. The first successful version was ext2. In 2001 ext3 was created and added journaling. In 2006 ext4 was created and is an improved ext3 which added more capacity and better performance. You can upgrade through the versions and ext4 can be mounted as ext3 if needed. ext4 is the current default fs for most Linux distributions.

* ext4 uses a unit called Blocks which is a group of sectors. The number of sectors must be an integral (integer) power of 2. Blocks are grouped into Block Groups. (From what I can tell the Block--rather a level of abstraction of many of them--is the functional equivalent of the FAT in the Windows FSs)

* Index Nodes known is inodes store all the metadata about files. The inode table is a linear array of inodes.

* ext4 fs splits the fs into a series of block groups and tries hard to keep files in the same block which reduces seek times.

* ext4 supports Extended Attributes which are similar to ADS in windows. Check documentation in regards to very large EAs as I thought I saw something about going beyond the size restrictions when I was reading through it.

#### Forensics

* Persistence Mechanisms - Ways for a program to remain/run on a system after a reboot.

    * Cron Jobs - Programs that run at set time intervals. /etc/crontab has the information on them.

    * Startup Services - /etc/init.d/ contains a list of services that start when the system boots.

    * .bashrc - A script that runs when a shell is spawned. There is usually a .bashrc file made for each user that is stored in their home directory. The system-wide settings are located at /etc/bash.bashrc and /etc/profile.

* Sudo execution history - Stored in the previously mentioned auth log /var/log/auth.log.

* Bash history - Every user has a bash history unless it's configured to be deleted or not stored in some way. The history is stored in the user's home directory ~/.bash_history.

* Text Editor Histories - A history of files accessed using vim or other very common text editors.

    * Vim stores logs for opened files in ~/.viminfo

* Logs - Generally found in /var/log/

    * Syslog - Configurable amount of detail stored regarding system activity. /var/log/syslog

    * Auth logs - Previously discussed twice. /var/log/auth.log but there can be multiple with appended indices (e.g. /var/log/auth.log.1) It is possible to access them all with /var/log/auth.log*

    * Other logs - Most logs will be located in /var/log/ including most application logs.

---

### Autopsy

* Autopsy is an open-source DF platform that can run cross-platform.

* Autopsy files have an extension of .aut

* Autopsy supports raw single, raw split, EnCase, and virtual machine disk image formats.

* Ingest Modules are made to analyze and retrieve specific data from the drive.

---

### Redline

* Redline is an open-source windows app intended to give a high-level view of memory analysis through a nice GUI.

* Redline provides the ability to capture and analyze various amounts of the disk/memory depends on the operating system.

* IOC files - They are basically just plaintext files containing indicators of compromise which are stored in .ioc files. They can be modified and shared with the security community.

* FireEye, the company that created Redline, also created a program called IOC Editor which can be used to create .ioc files.

* The IOC Search Collector in Redline uses IOC files and ignores data that doesn't match your IOCs.

---

### KAPE

* KAPE is essentially a solution for automating the processes discussed in the previous sections on Windows forensics.

* KAPE uses things called Targets and Modules. Targets are the desired artifacts to extract and Modules are programs that process the collected artifacts and extract the data from them.

* KAPE works in 2 passes to collect files. The first pass gets the files from the OS. The second pass uses raw disk reads to bypass the OS and grab files that the OS has locked.

* .tkape files are target files for kape. .mkape are module files for kape. There are guide files for creating these.

* Compound Targets are when a single command will collect multiple targets.

* The bin directory contains binaries that are being used but are not natively present on the system. EZ Tools are commonly found here as they aren't usually on a system, but are used for DFIR.

* The !Disabled directory is for targets that you want to keep but not to show up in the active list. The !Local directory is for those that you don't want to show up in remote repositories.

* The Flush option is used to delete information so be very careful to not use this option unless there is a very good reason.

* In gKAPE's current command line section, there is a display of what the command looks like and is updated while configuring using the GUI.

* When using Target and Module options at the same time, the Module Source shouldn't be necessary to configure. If no module source is included it will use the target destination by default.

* KAPE can be run in batch mode by putting all of your commands in a single line in a _kape.cli file in the same directory as kape.exe. Then when kape.exe is run as admin it will check for, and if found, execute the commands in the _kape.cli file.

---

### Volatility

* Volatility is a FOSS tool for memory forensics written in python and using python plugins/modules thus it is cross-platform. It is created by the VolatilityFoundation.

* It is the most popular framework for extracting artifacts from RAM samples/dumps.

* Volatility3 is the most recent version and uses python3 while the volatility2 versions use python2. The syntax changed between versions. As volatility has been around a long time, it is commonplace to see volatility2 syntax when looking through references and this should be kept in mind.

* Some ways of extracting the memory dumps themselves include -

    * FTK Imager
    * Redline
    * DumpIt.exe
    * dd / win32dd.exe / win64dd.exe
    * Memoryze
    * FastDump

    * Most of these tools will output a .raw file.

    * Grabbing this information from a VM is generally done by collecting a file on the host machine. Depending on the hyperviser the filetype/extension may differ -

        * Hyper-V (wsl uses this) - .bin
        * VirtualBox - .sav (partial) VolatilityFoundation has a wiki page on getting a full dump in the Volatility GitHub repo
        * VMWare - .vmem
        * Parallels - .mem

* Volatility has an `imageinfo` plugin to help identify images if you are just given a file and don't know what system it came from. The `windows.info`, `linux.info`, and `mac.info` plugins help by running the image through them and seeing what they say.

* Syntax - `python3 vol.py -f <memory file> <os>.<plugin/module/package>`

* `pslist`, `pstree`

* `psscan` - Rather than a regular pslist, this searches for data structures resembling _EPROCESS. This can find hiding processes than unlinked themselves from the pslist, but also can return false positives.

* `netstat` - If this is too unstable, there are other tools to help extract PCAPs from memory dumps such as bulk_extractor.

* `dlllist`

* `malfind` - Scans the heap to find processes that have the executable bit set (RWE or RX) and/or no memory-mapped file on disk (fileless malware).

* `yarascan` Checks the memory against Yara rules.

* Checking for evasion techniques -

    * Hooking -
    
        * Types include -

            * SSDT Hooking - System Service Descriptor Table

            * IRP Hooking - I/O Request Packet

            * IAT Hooking - Import Address Table

            * EAT Hooking - Export Address Table

            * Inline Hooking - Intercepting/hooking calls to target functions

    * `ssdt` - This plugin searches for ssdt hooks in the memory dump. Since ssdt hooking can be done for legitimate purposes, it may be a cumbersome task to identify any threat actors in the output. It may be better to find IOCs elsewhere and use this for correlation.

    * `modules` - Dumps all kernel modules. Can be hidden from.

        * `driverscan` - Can help find those missed by modules plugin.

    * `modscan`, `driverirp`, `callbacks`, `idt`, `apihooks`, `moddump`, `handles`, `memmap`

* It is possible to have an output file of a volatility command you run by using the -o option.

    * Some of the modules output a file and you can use other utilities to get information out of them. E.g. Using the memmap plugin yields a .dmp file and using `strings` and `grep` it is possible to extract some information.

* The `--help` option also contains a list of many inbuilt plugins.

---

### Velociraptor

* `Velociraptor` is an open-source, cross-platform endpoint monitoring DFIR tool.

* It is similar to a SIEM in that it can be installed as a server or as a client, following the agent/manager paradigm. There is also "Instant Velociraptor" which is a fully functional Velociraptor system deployed only to the local machine. All types of deployment are obviously covered in the Velociraptor documentation.

* When on the dashboard and then selecting an endpoint to view, the shell tab allows you to run commands remotely on the endpoint from the dashboard.

* Programs other than KAPE can use KAPE files. In Velociraptor you can create a new collection using `<os>.KapeFiles.Targets`

* The Velociraptor Virtual File System (VFS) is a server side cache of the files on the endpoint.

* Velociraptor Query Language (VQL) is a framework for creating customized artifacts which allows for collection, querying, and monitoring of almost any aspect of endpoints, groups of endpoints, or an entire network. It can also be used for automation.

    * Notebooks in Velociraptor consist of Markdown and VQL.

    * VQL can also be run from the command line.

    * VQL lets you package queries into mini-programs called Artifacts which are just structured YAML files containing a query with a name attached to it. This allows searching for and running queries by name.

    * Like most query language it is syntactically similar to others, specifically SQL.

* The Velociraptor site has an Artifact Exchange where you can share and search for VQL artifacts.

---

### TheHive

* `TheHive` is a FOSS, scalable Security Incident Response Platform integrated with Malware Information Sharing Platform (MISP).

    * It can be used to collaborate on investigations allowing for real-time information sharing.

* TheHive has 3 core operational principles -

    * Collaborate - Simultaneous, real-time collaboration and information sharing.

    * Elaborate - Cases and their tasks can be created by the template engine.

    * Act - Add observables (or import them from MISP) to each case. Once the case is closed you can export observables to MISP.

* Cases can be broken down into tasks and turned into templates. Analyst progress, pieces of evidence, tags, and other observables can be attached to cases.

    * Cases can be imported from SIEM alerts, email reports, and other event sources.

* Cortex is an open-source analysis and active response engine. It can be used for correlation analysis and recognition of developing patterns.

* Responders can be used to run actions to communicate, share info, and prevent or contain a threat.

* Users can create custom dashboards containing statistics on cases, tasks, observables, metrics, and more. These can generate key performance indicators (KPIs).

* Administrators can create an organization on the platform and organize their personnel.

* Traffic Light Protocol (TLP) - Set of designations to ensure approriate access to sensitive information. There are colors which indicate a scale of full disclosure / open access (white) to no disclosure / restricted access (red). For more information look to CISA.

* Permissable Actions Protocol (PAP) - Used to indicate what can be done with information, if an attacker can detect the current state of analysis, or defensive actions that are in place. It uses a color scheme similar to TLP. For more information look to MISP.

---

### Intro to Malware Analysis

* The term malware comes from the words "malicious" and "software" being put together.

    * Hardware came many centuries ago from putting the adjective "hard" and the noun "ware"- meaning an article of merchandise or manufactured good- together. Then when computers were invented software was created in the same way. Since then there have been many names derivative of software in the same way that malware is.

    * Thus any software with malicious purpose can be classified as malware. There are categorisations of malware made based on behaviour.

* Malware is inherently dangerous. Precautions to be taken before analyzing malware include -

    * Analyze malware on a dedicated system.

    * When not being analyzed, malware samples must be kept in password-protected zip/rar/other archives.

    * Only extract from the archive in the aforementioned dedicated system.

    * Created an isolated VM dedicated to malware analysis and ensure there is a clean state that can be reverted to.
    
    * Ensure all possible connections to the internet are severed. If an internet connection is absolutely necessary it must be closely monitored.

    * Always ensure a clean state after analysis. This could be reverted a VM to a clean state or if for some reason you had to run on a host system, then wiping and reinstalling everything.

* There are 2 main categories of malware analysis techniques -

    * Static Analysis - Analysis without execution/opening.

        * Evasion techniques for static analysis include obfuscation and packing.

    * Dynamic Analysis - Analysis of execution in a controlled environment.

        * Evasion techniques for dynamic analysis include environment detection.

* Static analysis is usually done first as it is comes with *less* (<b>NOT NONE</b>) risk and can inform the rest of the analysis.

* Remnux (Reverse Engineering Malware Linux) is a Linux distribution built for malware analysis.

* Some common static analysis techniques include -

    * `file` command will give the actual filetype information, as the file extension can be altered and misleading.

    * `strings` command will return UNICODE or ASCII strings at least 3 characters in length.

    * Common hashes for malware identification including md5, sha1, and sha256 can be retrieved using the commands `md5sum`, `sha1sum`, `sha256sum` respectively.

    * Antivirus and VirusTotal - Searching the hash from the previous point or scanning the file with an AV (Antivirus) can provide useful information. Uploading samples can help too, but should only be done with high condifence that this will not result in compromise of any systems or information.

    * The PE File Header - The PE File Header contains metadata about the Portable Executable file. The PE format is for executables, object code, DLLS, and more which are used in 32 and 64 bit Windows systems. These are common in malware analysis.

        * PE files usually don't contain all of the code they need to run. Very often they use code provided by the OS. This helps keep the PE small.

            * Imports are the functions that the PE is using but doesn't contain. These imports are vital to the operation of the PE and can give away what the file will do if run.

        * PE files are divided into sections. These are compiler/packer dependent, but can contain useful information. Some common sections include .text- generally CPU instructions and marked executable, .data- contains variables and other global data, and .rsc- contains resources such as images.

        * `pecheck` is a tool written in python to check PE headers. `pe-tree` is also written in python and allows you to view PE header info in tree format.

* A sandbox is an isolated environment where malware is run for information purposes. It is usually made to mimic the target environment of the malware. Sandboxes use virtualization technology (VMs).

    * The term sandbox comes from the military where it refers to a sandbox where terrain would be modeled and their operation would be dry-run to analyze possible situations and outcomes.

    * For malware analysis considerations in constructing a sandbox include -

        * A VM that mimcs the target environment. The VM requires the ability to take snapshots and revert to their states.

        * OS and Network monitoring tools/software.

        * Network control via dummy DNS server and web server.

        * A way to move analysis files, logs, and malware samples to and from the VM without compromising the host or anything else.

    * Building a sandbox from scratch is most often not necessary. It is often faster/easier to set up and open-source sandbox. They provide a framework for performing basic dynamic analysis and are customizable.

        * Some open-source sandboxes include -

            * Cuckoo's Sandbox - Popular and customizable with good documentation and lots of community.

            * CAPE Sandbox - One of the more advanced options.

    * Another option is using an online sandbox.

        * Some of these include -

            * Both of the previous open-source sandboxes have online sandbox versions.

            * Any.run

            * Intezer

            * Hybrid Analysis

        * Exercise caution when uploading malware samples to online sandboxes. It is often better to search the sample's hash and see if the sample you want to analyze has been sandboxed on the platform before.

* Malware can make use of various anti-analysis techniques.

    * Some of the main anti-analysis techniques used by malware authors are Obfuscation and Packing.

        * Obfuscation - The dictionary definition of Obfuscate is to render obscure, unclear, or unintelligible.

        * A packer obfuscates, compresses, and/or encrypts data. There are legitimate uses for this. One legit use is obfuscating proprietary software to make reverse engineering more difficult. However in the case of malware, packing is used to make analysis- especially static- more difficult for analysts and researchers.

            * Packed software can be unpacked. This can be done through various methods and tools including manually using debuggers.

    * Another anti-analysis technique is sandbox evasion. Some of the methods for this include -

        * Sleeping - When the malware executes it sleeps for a very long time. This is meant to timeout the sandbox.

        * User Activity Detection - The malware waits for user activity before it does anything malicious. Because a sandbox doesn't have a user, no malicious code runs.

        * User Footprinting - The malware checks for user files, browsing history, or similar evidence of a user. If not enough evidence of a user is found no malicious code runs.

        * VM detection - Since sandboxes run on VMs, if malware detects it is running on a VM then no malicious code runs. VMs leave artifacts such as certain drivers or files and if those artifacts are found then the system is a VM.

            * There are also VM *escape* vectors including vectors through the host-vm networking relationship and RAM.

---