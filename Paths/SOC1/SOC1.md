# SOC 1

Tags: Blue Team, Cyber Defense, MITRE, SIEM

Tools: URL Shorteners, VirusTotal.com, Any.run, SysInternals Suite, Fuzzy hashing, MITRE ATT&CK, Shadow Copy, UrlScan.io, Abuse.ch, PhishTool, Talos Intelligence, Yara

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

* 

---
---

<br/>

## Network Security and Traffic Analysis

###