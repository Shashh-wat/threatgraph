"""
ThreatGraph mock dataset.

Small demo set (per project scope): 8 threat actors, 15 CVEs, 12 software
products, 20 reports. Sized so every one of the 8 Cypher queries in the
assignment (Section 10) returns a non-trivial, non-empty result, and so the
many-to-many EXPLOITS / AFFECTS structure described in Section 8.1 actually
shows up (every actor exploits 2+ CVEs, every CVE is exploited by 1-3 actors,
every CVE affects 1 piece of software, every software is affected by 1+ CVEs).

`embedding` fields are intentionally omitted here — src/ingest.py computes
them at load time from `description`/`text` using the configured embedding
model, so this file has no model dependency and stays fast to edit.
"""

THREAT_ACTORS = [
    {
        "id": "actor-apt29",
        "name": "APT29 (Cozy Bear)",
        "origin": "Russia",
        "motivation": "Espionage",
        "summary": "State-sponsored group known for stealthy, long-dwell "
                    "intrusions against government and diplomatic targets, "
                    "frequently via cloud identity and mail infrastructure.",
    },
    {
        "id": "actor-fin7",
        "name": "FIN7",
        "origin": "Russia/Ukraine",
        "motivation": "Financial gain",
        "summary": "Financially motivated group that has shifted from "
                    "point-of-sale malware toward directly targeting "
                    "backend database systems to reach payment card data.",
    },
    {
        "id": "actor-lazarus",
        "name": "Lazarus Group",
        "origin": "North Korea",
        "motivation": "Financial gain / Espionage",
        "summary": "State-linked group blending large-scale cryptocurrency "
                    "theft with espionage operations against defense and "
                    "software supply-chain targets.",
    },
    {
        "id": "actor-apt41",
        "name": "APT41",
        "origin": "China",
        "motivation": "Espionage / Financial gain",
        "summary": "Dual-mission group conducting state-directed espionage "
                    "alongside self-funded intrusions, notable for rapidly "
                    "weaponising newly disclosed edge-device vulnerabilities.",
    },
    {
        "id": "actor-sandworm",
        "name": "Sandworm",
        "origin": "Russia",
        "motivation": "Sabotage",
        "summary": "Military-linked group focused on disruptive and "
                    "destructive operations against critical infrastructure "
                    "and government networks.",
    },
    {
        "id": "actor-scattered-spider",
        "name": "Scattered Spider",
        "origin": "International (English-speaking)",
        "motivation": "Financial gain",
        "summary": "Social-engineering-driven group that pairs help-desk "
                    "impersonation with exploitation of exposed network "
                    "edge appliances to gain initial access.",
    },
    {
        "id": "actor-volt-typhoon",
        "name": "Volt Typhoon",
        "origin": "China",
        "motivation": "Espionage / Pre-positioning",
        "summary": "State-sponsored group focused on living-off-the-land "
                    "persistence inside critical infrastructure networks "
                    "for potential future disruptive use.",
    },
    {
        "id": "actor-conti",
        "name": "Conti (successor collective)",
        "origin": "Russia",
        "motivation": "Financial gain (ransomware)",
        "summary": "Ransomware-as-a-service collective and its post-leak "
                    "successor cells, known for fast lateral movement after "
                    "exploiting unpatched remote-access flaws.",
    },
]

SOFTWARE = [
    {"id": "sw-oracledb", "name": "Oracle Database", "vendor": "Oracle", "category": "Database System"},
    {"id": "sw-mysql", "name": "MySQL", "vendor": "Oracle", "category": "Database System"},
    {"id": "sw-mongodb", "name": "MongoDB", "vendor": "MongoDB Inc.", "category": "Database System"},
    {"id": "sw-mssql", "name": "Microsoft SQL Server", "vendor": "Microsoft", "category": "Database System"},
    {"id": "sw-log4j", "name": "Apache Log4j", "vendor": "Apache Software Foundation", "category": "Logging Library"},
    {"id": "sw-exchange", "name": "Microsoft Exchange Server", "vendor": "Microsoft", "category": "Email Server"},
    {"id": "sw-fortios", "name": "Fortinet FortiOS", "vendor": "Fortinet", "category": "Network Device"},
    {"id": "sw-citrix-adc", "name": "Citrix ADC", "vendor": "Citrix", "category": "Network Device"},
    {"id": "sw-windows-server", "name": "Windows Server", "vendor": "Microsoft", "category": "Operating System"},
    {"id": "sw-vmware-esxi", "name": "VMware ESXi", "vendor": "VMware", "category": "Virtualization"},
    {"id": "sw-confluence", "name": "Atlassian Confluence", "vendor": "Atlassian", "category": "Collaboration Software"},
    {"id": "sw-cisco-iosxe", "name": "Cisco IOS XE", "vendor": "Cisco", "category": "Network Device"},
]

# Each CVE affects exactly one software product here (kept simple for the
# demo); AFFECTS is still modelled as a graph relationship, not a property,
# so extending a CVE to affect multiple products later needs no migration.
VULNERABILITIES = [
    {"id": "cve-2021-44228", "cve_id": "CVE-2021-44228", "severity": "Critical",
     "description": "Log4Shell: a remote code execution vulnerability in the Apache "
                     "Log4j logging library triggered via unsanitized JNDI lookups.",
     "affects": "sw-log4j"},
    {"id": "cve-2021-45046", "cve_id": "CVE-2021-45046", "severity": "High",
     "description": "An incomplete fix for Log4Shell that still allowed a "
                     "denial-of-service and, in some configurations, remote code "
                     "execution via crafted thread-context-map input.",
     "affects": "sw-log4j"},
    {"id": "cve-2012-2122", "cve_id": "CVE-2012-2122", "severity": "High",
     "description": "An authentication bypass in MySQL and MariaDB caused by an "
                     "incorrect memcmp() return-value check.",
     "affects": "sw-mysql"},
    {"id": "cve-2021-26855", "cve_id": "CVE-2021-26855", "severity": "Critical",
     "description": "ProxyLogon: a server-side request forgery in Microsoft Exchange "
                     "Server that lets an unauthenticated attacker send arbitrary HTTP "
                     "requests as the Exchange server itself.",
     "affects": "sw-exchange"},
    {"id": "cve-2023-27997", "cve_id": "CVE-2023-27997", "severity": "Critical",
     "description": "A heap-based buffer overflow in FortiOS SSL-VPN that allows an "
                     "unauthenticated attacker to execute arbitrary code via crafted "
                     "HTTP requests.",
     "affects": "sw-fortios"},
    {"id": "cve-2019-19781", "cve_id": "CVE-2019-19781", "severity": "Critical",
     "description": "A directory traversal vulnerability in Citrix ADC and Gateway "
                     "that allows unauthenticated remote code execution.",
     "affects": "sw-citrix-adc"},
    {"id": "cve-2020-1472", "cve_id": "CVE-2020-1472", "severity": "Critical",
     "description": "Zerologon: a cryptographic flaw in the Netlogon protocol that "
                     "lets an attacker impersonate a domain controller and take over "
                     "an Active Directory domain running on Windows Server.",
     "affects": "sw-windows-server"},
    {"id": "cve-2017-0144", "cve_id": "CVE-2017-0144", "severity": "Critical",
     "description": "EternalBlue: a remote code execution vulnerability in the "
                     "Windows SMBv1 server exploited via specially crafted packets.",
     "affects": "sw-windows-server"},
    {"id": "cve-2021-34527", "cve_id": "CVE-2021-34527", "severity": "Critical",
     "description": "PrintNightmare: a remote code execution vulnerability in the "
                     "Windows Print Spooler service.",
     "affects": "sw-windows-server"},
    {"id": "cve-2021-21985", "cve_id": "CVE-2021-21985", "severity": "Critical",
     "description": "A remote code execution vulnerability in the VMware vCenter "
                     "Server plug-in for vSAN, reachable via port 443 without prior "
                     "authentication.",
     "affects": "sw-vmware-esxi"},
    {"id": "cve-2022-26134", "cve_id": "CVE-2022-26134", "severity": "Critical",
     "description": "An unauthenticated OGNL injection vulnerability in Atlassian "
                     "Confluence Server and Data Center leading to remote code "
                     "execution.",
     "affects": "sw-confluence"},
    {"id": "cve-2023-20198", "cve_id": "CVE-2023-20198", "severity": "Critical",
     "description": "A privilege escalation vulnerability in the Cisco IOS XE web "
                     "UI feature that allows an attacker to create a local account "
                     "with full administrative privileges.",
     "affects": "sw-cisco-iosxe"},
    {"id": "cve-2018-3110", "cve_id": "CVE-2018-3110", "severity": "High",
     "description": "A privilege escalation vulnerability in Oracle Database's Java "
                     "VM component that allows a low-privileged, authenticated "
                     "attacker to compromise the database.",
     "affects": "sw-oracledb"},
    {"id": "cve-2020-0618", "cve_id": "CVE-2020-0618", "severity": "High",
     "description": "A remote code execution vulnerability in Microsoft SQL Server "
                     "Reporting Services caused by improper handling of page "
                     "requests.",
     "affects": "sw-mssql"},
    {"id": "cve-2017-15535", "cve_id": "CVE-2017-15535", "severity": "Medium",
     "description": "A denial-of-service vulnerability in MongoDB triggered by a "
                     "crafted BSON document that causes excessive memory allocation.",
     "affects": "sw-mongodb"},
]

# actor_id -> [cve_id, ...]
EXPLOITS = {
    "actor-apt29": ["cve-2021-44228", "cve-2021-26855", "cve-2020-1472"],
    "actor-fin7": ["cve-2012-2122", "cve-2018-3110", "cve-2020-0618", "cve-2021-44228", "cve-2021-45046"],
    "actor-lazarus": ["cve-2017-0144", "cve-2022-26134", "cve-2023-20198"],
    "actor-apt41": ["cve-2021-26855", "cve-2019-19781", "cve-2023-27997", "cve-2021-21985"],
    "actor-sandworm": ["cve-2023-27997", "cve-2021-34527", "cve-2020-1472"],
    "actor-scattered-spider": ["cve-2023-20198", "cve-2019-19781", "cve-2017-15535"],
    "actor-volt-typhoon": ["cve-2023-27997", "cve-2021-21985", "cve-2019-19781"],
    "actor-conti": ["cve-2021-44228", "cve-2021-34527", "cve-2017-0144"],
}

# Each report describes at least one CVE and/or one actor (may describe both,
# matching Section 8.1's "one Vulnerability and/or one ThreatActor").
REPORTS = [
    {"id": "report-1", "title": "FIN7 Pivots Toward Database-Layer Attacks",
     "text": "FIN7 has shifted from point-of-sale malware toward directly targeting "
             "backend database systems, exploiting authentication and "
             "privilege-escalation flaws in MySQL and Oracle Database to reach "
             "payment card data at the source.",
     "actor": "actor-fin7", "vuln": "cve-2012-2122"},
    {"id": "report-2", "title": "Log4Shell: A Retrospective on Internet-Scale Exploitation",
     "text": "Within days of disclosure, Log4Shell was mass-exploited by multiple "
             "unrelated actors including state-sponsored espionage groups and "
             "ransomware crews, underscoring how a single logging-library flaw can "
             "cascade across unrelated industries.",
     "actor": None, "vuln": "cve-2021-44228"},
    {"id": "report-3", "title": "APT29 Targets Cloud Mail Infrastructure",
     "text": "APT29 has continued to prioritise access to mail and identity systems, "
             "using server-side request forgery in Exchange to move from a single "
             "foothold to organisation-wide mailbox access without triggering "
             "endpoint alerts.",
     "actor": "actor-apt29", "vuln": "cve-2021-26855"},
    {"id": "report-4", "title": "Zerologon Remains a Post-Compromise Favourite",
     "text": "Nearly four years after disclosure, Zerologon is still observed as a "
             "late-stage privilege escalation step once an attacker has any "
             "foothold inside a Windows domain, because unpatched domain "
             "controllers remain common.",
     "actor": None, "vuln": "cve-2020-1472"},
    {"id": "report-5", "title": "Sandworm's Continued Interest in Domain Takeover",
     "text": "Sandworm has been observed chaining edge-device compromise with "
             "Zerologon-style domain controller takeover to move quickly from "
             "internet-facing access to full network control ahead of disruptive "
             "operations.",
     "actor": "actor-sandworm", "vuln": "cve-2020-1472"},
    {"id": "report-6", "title": "Edge Appliances as the New Perimeter Weak Point",
     "text": "FortiOS SSL-VPN and Citrix ADC remain two of the most exploited "
             "internet-facing appliances, valued by intrusion sets because a single "
             "unauthenticated flaw grants a foothold behind the firewall entirely.",
     "actor": None, "vuln": "cve-2023-27997"},
    {"id": "report-7", "title": "APT41's Rapid Weaponisation of Edge CVEs",
     "text": "APT41 has repeatedly been first-to-exploit newly disclosed edge-device "
             "vulnerabilities, moving from proof-of-concept to production tooling "
             "within days, spanning VPN gateways, hypervisor management planes, and "
             "mail servers.",
     "actor": "actor-apt41", "vuln": "cve-2021-21985"},
    {"id": "report-8", "title": "Citrix ADC Directory Traversal Still Under Active Abuse",
     "text": "Despite a patch being available for years, unpatched Citrix ADC "
             "instances continue to be scanned and exploited within hours of "
             "coming online, frequently as an initial access vector for "
             "ransomware affiliates.",
     "actor": None, "vuln": "cve-2019-19781"},
    {"id": "report-9", "title": "Scattered Spider's Help-Desk-to-Network Playbook",
     "text": "Scattered Spider pairs convincing help-desk impersonation with "
             "exploitation of exposed VPN and network appliances, using the "
             "initial foothold to escalate privileges before deploying "
             "ransomware or exfiltrating data.",
     "actor": "actor-scattered-spider", "vuln": "cve-2019-19781"},
    {"id": "report-10", "title": "Cisco IOS XE Web UI Flaw Enables Silent Admin Takeover",
     "text": "A privilege escalation bug in the Cisco IOS XE web interface allows "
             "an attacker to silently create a fully privileged local account, "
             "giving persistent administrative control over the affected network "
             "device.",
     "actor": None, "vuln": "cve-2023-20198"},
    {"id": "report-11", "title": "Lazarus Group Broadens Targeting to Network Infrastructure",
     "text": "Lazarus Group has expanded beyond cryptocurrency platforms to "
             "compromise network devices and collaboration software directly, "
             "using them as staging points for further intrusion into partner "
             "organisations.",
     "actor": "actor-lazarus", "vuln": "cve-2023-20198"},
    {"id": "report-12", "title": "Confluence OGNL Injection: A Year of Exploitation",
     "text": "The unauthenticated OGNL injection flaw in Atlassian Confluence has "
             "been used by multiple intrusion sets to gain code execution on "
             "internally hosted collaboration servers, often the most permissive "
             "system on an internal network.",
     "actor": None, "vuln": "cve-2022-26134"},
    {"id": "report-13", "title": "Volt Typhoon's Living-Off-the-Land Pre-Positioning",
     "text": "Volt Typhoon continues to favour quiet, living-off-the-land "
             "persistence inside critical infrastructure operators, entering via "
             "edge devices and hypervisor management interfaces rather than "
             "deploying custom malware that might be detected.",
     "actor": "actor-volt-typhoon", "vuln": "cve-2021-21985"},
    {"id": "report-14", "title": "Conti Successor Cells Favour Fast Ransomware Deployment",
     "text": "Groups descended from the leaked Conti playbook continue to "
             "prioritise speed, moving from initial exploitation of a public-facing "
             "flaw to full ransomware deployment across a network within 48 hours.",
     "actor": "actor-conti", "vuln": "cve-2021-34527"},
    {"id": "report-15", "title": "PrintNightmare Still Found in Unsegmented Networks",
     "text": "The Windows Print Spooler remote code execution flaw known as "
             "PrintNightmare continues to be found exposed on internal networks "
             "that lack segmentation, making it a reliable lateral movement "
             "technique long after patches became available.",
     "actor": None, "vuln": "cve-2021-34527"},
    {"id": "report-16", "title": "EternalBlue's Long Tail in Legacy Windows Estates",
     "text": "Years after WannaCry, unpatched SMBv1 remains reachable inside "
             "legacy Windows Server estates, and EternalBlue continues to appear "
             "in intrusion sets' toolkits as a dependable lateral movement "
             "exploit.",
     "actor": None, "vuln": "cve-2017-0144"},
    {"id": "report-17", "title": "Oracle Database Privilege Escalation in Managed Hosting",
     "text": "A privilege escalation flaw in Oracle Database's Java VM component "
             "has been used by financially motivated actors already holding "
             "low-privileged database credentials to reach full administrative "
             "control over managed hosting environments.",
     "actor": None, "vuln": "cve-2018-3110"},
    {"id": "report-18", "title": "SQL Server Reporting Services RCE Seen in the Wild",
     "text": "A remote code execution flaw in Microsoft SQL Server Reporting "
             "Services has been observed exploited against exposed reporting "
             "portals, frequently as a pivot point into the underlying database "
             "server.",
     "actor": None, "vuln": "cve-2020-0618"},
    {"id": "report-19", "title": "MongoDB Denial-of-Service via Crafted BSON",
     "text": "A denial-of-service flaw affecting MongoDB deployments can be "
             "triggered with a single crafted BSON document, and has been used by "
             "opportunistic actors to disrupt exposed database instances rather "
             "than exfiltrate data from them.",
     "actor": None, "vuln": "cve-2017-15535"},
    {"id": "report-20", "title": "FIN7's Continued Focus on Reporting Infrastructure",
     "text": "FIN7 has been observed probing SQL Server Reporting Services "
             "deployments as an entry point toward the payment data typically "
             "stored in adjacent database systems.",
     "actor": "actor-fin7", "vuln": "cve-2020-0618"},
]
