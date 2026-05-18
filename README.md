# Cybersecurity Tools and Resources

A curated collection of tools, scripts, and cheat sheets for penetration testing, exploit development, and security research. **For authorized security testing only.**

> Last updated: May 2026

## Table of Contents

1. [Active Directory](#active-directory)
2. [Web Application Security](#web-application-security)
3. [Network & Infrastructure](#network--infrastructure)
4. [Cloud Security](#cloud-security)
5. [Container & Kubernetes](#container--kubernetes)
6. [Privilege Escalation](#privilege-escalation)
7. [Post-Exploitation & C2](#post-exploitation--c2)
8. [Exploit Development](#exploit-development)
9. [OSINT & Recon](#osint--recon)
10. [Password & Hash Cracking](#password--hash-cracking)
11. [Cheat Sheets & References](#cheat-sheets--references)
12. [Files and Tools](#files-and-tools)
13. [Contributing](#contributing)
14. [License](#license)

---

## Active Directory

### Enumeration
- [**BloodHound**](https://github.com/BloodHoundAD/BloodHound) - Graph-based AD attack path analysis and visualization.
- [**BloodHound.py**](https://github.com/fox-it/BloodHound.py) - Agentless Python BloodHound data collector.
- [**BloodHound Custom Queries**](https://github.com/hausec/Bloodhound-Custom-Queries) - Community query pack for BloodHound.
- [**ADModule**](https://github.com/hashtaginfosec/ADModule) - Microsoft-signed PowerShell AD module (AMSI-safe for enumeration).
- [**ldapdomaindump**](https://github.com/dirkjanm/ldapdomaindump) - Dump all domain info over LDAP to JSON/HTML/CSV.

### Attacks
- [**Impacket**](https://github.com/fortra/impacket) - Python network protocol classes. Includes secretsdump, GetUserSPNs, psexec, wmiexec, and more.
- [**NetExec (nxc)**](https://github.com/Pennyw0rth/NetExec) - Actively maintained successor to CrackMapExec. SMB, RDP, SSH, LDAP, WinRM.
- [**Certipy**](https://github.com/ly4k/Certipy) - AD Certificate Services (ADCS) attack tool. ESC1–ESC13.
- [**Rubeus**](https://github.com/GhostPack/Rubeus) - Kerberos attack toolkit: AS-REP roasting, Kerberoasting, pass-the-ticket, S4U.
- [**Mimikatz**](https://github.com/gentilkiwi/mimikatz) - Credential extraction, pass-the-hash, pass-the-ticket, golden/silver tickets.
- [**Evil-WINRM**](https://github.com/Hackplayers/evil-winrm) - Feature-rich WinRM shell for pentesting.
- [**MitM6**](https://github.com/dirkjanm/mitm6) - IPv6 DNS takeover combined with NTLM relay attacks.
- [**Responder**](https://github.com/lgandx/Responder) - LLMNR/NBT-NS/mDNS poisoner for capturing NTLM credentials.

### References
- [**Active Directory Attack (PayloadsAllTheThings)**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md) - Comprehensive attack methodology.
- [**Active Directory Security (adsecurity.org)**](https://adsecurity.org/) - Sean Metcalf's definitive AD attack and defense blog.
- [**Active Directory Exploitation Cheat Sheet**](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) - Quick-reference enumeration and attack commands.
- [**AMSI Bypass (PowerShell)**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) - AMSI bypass techniques collection.
- [**NTLM Relaying Guide**](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html) - Practical NTLM relay attack walkthrough.

---

## Web Application Security

### Recon & Discovery
- [**Subfinder**](https://github.com/projectdiscovery/subfinder) - Passive subdomain enumeration using 50+ sources.
- [**httpx**](https://github.com/projectdiscovery/httpx) - Fast HTTP toolkit for probing live hosts and extracting metadata.
- [**katana**](https://github.com/projectdiscovery/katana) - High-speed web crawler and spider for attack surface mapping.
- [**ffuf**](https://github.com/ffuf/ffuf) - Fast web fuzzer for directories, parameters, vhosts, and more.
- [**feroxbuster**](https://github.com/epi052/feroxbuster) - Fast, recursive, Rust-based content discovery tool.
- [**ParamSpider**](https://github.com/devanshbatham/ParamSpider) - Parameter mining from web archives without touching the target.
- [**Arjun**](https://github.com/s0md3v/Arjun) - HTTP parameter discovery for hidden GET/POST parameters.
- [**gau**](https://github.com/lc/gau) - Fetch known URLs from Wayback Machine, OTX, and URLScan.

### Scanning & Exploitation
- [**Nuclei**](https://github.com/projectdiscovery/nuclei) - Template-based vulnerability scanner with 9,000+ community templates.
- [**SQLMap**](https://github.com/sqlmapproject/sqlmap) - Automated SQL injection detection and exploitation.
- [**Dalfox**](https://github.com/hahwul/dalfox) - XSS parameter analysis and automated scanning.
- [**JWT_Tool**](https://github.com/ticarpi/jwt_tool) - JWT security testing: alg:none, weak secrets, JWKS injection.
- [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings) - Comprehensive payload library for every vulnerability class.
- [**Big List of Naughty Strings**](https://github.com/minimaxir/big-list-of-naughty-strings) - Edge-case test strings for input validation testing.

### Proxies & Scanners
- [**Caido**](https://caido.io/) - Modern web security proxy and testing platform (Burp alternative).
- [**OWASP ZAP**](https://www.zaproxy.org/) - Open-source web application security scanner.

### References
- [**HackTricks — Web**](https://book.hacktricks.xyz/pentesting-web) - Web application attack techniques and methodology.
- [**PortSwigger Web Security Academy**](https://portswigger.net/web-security) - Free interactive labs covering all OWASP Top 10 vulnerabilities.
- [**OWASP Testing Guide**](https://owasp.org/www-project-web-security-testing-guide/) - Methodical web application testing methodology.

---

## Network & Infrastructure

- [**Nmap**](https://github.com/nmap/nmap) - The standard for network scanning and service/OS detection.
- [**Masscan**](https://github.com/robertdavidgraham/masscan) - Internet-scale port scanner. Scans the entire internet in under 5 minutes.
- [**RustScan**](https://github.com/RustScan/RustScan) - Fast port scanner frontend that feeds results directly into Nmap.
- [**NetExec (nxc)**](https://github.com/Pennyw0rth/NetExec) - Network service enumeration and exploitation (SMB, RDP, SSH, LDAP).
- [**MANSPIDER**](https://github.com/blacklanternsecurity/MANSPIDER) - SMB file spider for finding credentials and sensitive data.
- [**Ligolo-ng**](https://github.com/nicocha30/ligolo-ng) - Advanced tunneling/pivoting using a TUN interface — no SOCKS needed.
- [**Chisel**](https://github.com/jpillora/chisel) - Fast TCP/UDP tunnel over HTTP with SSH transport.
- [**Exploit-DB**](https://www.exploit-db.com/) - Searchable public exploit and vulnerability archive.

---

## Cloud Security

### AWS
- [**Pacu**](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework modeled after Metasploit.
- [**CloudMapper**](https://github.com/duo-labs/cloudmapper) - AWS network visualization and attack surface analysis.
- [**cloudsplaining**](https://github.com/salesforce/cloudsplaining) - AWS IAM policy security assessment and least-privilege analysis.
- [**s3scanner**](https://github.com/sa7mon/S3Scanner) - Find misconfigured open S3 buckets.

### Multi-Cloud
- [**Prowler**](https://github.com/prowler-cloud/prowler) - AWS/GCP/Azure security assessments and compliance (CIS, NIST, SOC2).
- [**ScoutSuite**](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing: AWS, GCP, Azure, OCI, Alibaba.
- [**CloudEnum**](https://github.com/initstring/cloud_enum) - OSINT enumeration for AWS, Azure, and GCP exposed resources.
- [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) - Find secrets in git history, S3, GCS, CircleCI, and more.
- [**Gitleaks**](https://github.com/gitleaks/gitleaks) - Fast secrets scanner for git repos and CI pipelines.

---

## Container & Kubernetes

- [**CDK (Container Toolkit)**](https://github.com/cdk-team/CDK) - Container escape, privilege escalation, and lateral movement toolkit.
- [**deepce**](https://github.com/stealthcopter/deepce) - Docker enumeration, escalation, and exploitation.
- [**kube-hunter**](https://github.com/aquasecurity/kube-hunter) - Active Kubernetes cluster penetration testing.
- [**kube-bench**](https://github.com/aquasecurity/kube-bench) - CIS Kubernetes benchmark compliance checks.
- [**Trivy**](https://github.com/aquasecurity/trivy) - Container image and IaC vulnerability scanner.
- [**Falco**](https://github.com/falcosecurity/falco) - Runtime security monitoring and anomaly detection.

---

## Privilege Escalation

### Linux
- [**LinPEAS**](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) - Automated Linux privilege escalation enumeration.
- [**GTFObins**](https://gtfobins.github.io/) - Unix binaries that can be abused for privilege escalation and shell escapes.
- [**Linux Exploit Suggester 2**](https://github.com/jondonas/linux-exploit-suggester-2) - Suggests kernel exploits based on running kernel version.

### Windows
- [**WinPEAS**](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) - Automated Windows privilege escalation enumeration.
- [**Seatbelt**](https://github.com/GhostPack/Seatbelt) - C# host security checks for post-exploitation enumeration.
- [**LOLBAS**](https://lolbas-project.github.io/) - Living Off the Land Binaries, Scripts, and Libraries for Windows.
- [**GodPotato**](https://github.com/BeichenDream/GodPotato) - Token impersonation for SYSTEM on Windows Server 2012–2022.
- [**SharpUp**](https://github.com/GhostPack/SharpUp) - C# port of PowerUp for local privilege escalation checks.

---

## Post-Exploitation & C2

> For authorized penetration testing engagements only.

- [**Sliver**](https://github.com/BishopFox/sliver) - Open-source adversary simulation framework. HTTP/S, DNS, WireGuard, mTLS.
- [**Havoc**](https://github.com/HavocFramework/Havoc) - Modern C2 framework with advanced evasion and BOF support.
- [**Metasploit Framework**](https://github.com/rapid7/metasploit-framework) - The industry-standard exploitation framework.
- [**Nishang**](https://github.com/samratashok/nishang) - PowerShell offensive framework: shells, pivoting, privilege escalation.
- [**pwncat-cs**](https://github.com/calebstewart/pwncat) - Post-exploitation platform with automated privesc and file transfer.
- [**Reverse Shell Generator**](https://www.revshells.com/) - One-liner reverse shells for every language and OS.

---

## Exploit Development

- [**pwntools**](https://github.com/Gallopsled/pwntools) - Python CTF and binary exploit development framework.
- [**GEF (GDB Enhanced Features)**](https://github.com/hugsy/gef) - GDB extension with heap analysis, ROP chain support, and exploit helpers.
- [**ROPgadget**](https://github.com/JonathanSalwan/ROPgadget) - ROP chain analysis and automated gadget search.
- [**one_gadget**](https://github.com/david942j/one_gadget) - Find one-gadget RCE execve("/bin/sh") in libc.
- [**checksec**](https://github.com/slimm609/checksec.sh) - Check binary hardening: NX, PIE, RELRO, canary, ASLR.

---

## OSINT & Recon

- [**theHarvester**](https://github.com/laramies/theHarvester) - Email, domain, and name enumeration from public sources.
- [**Amass**](https://github.com/owasp-amass/amass) - Deep attack surface mapping and DNS enumeration.
- [**Shodan**](https://www.shodan.io/) - Internet-wide device, service, and vulnerability search engine.
- [**crt.sh**](https://crt.sh/) - Certificate Transparency log search for subdomain discovery.
- [**OSINT Framework**](https://osintframework.com/) - Categorized directory of OSINT tools and techniques.
- [**Recon-ng**](https://github.com/lanmaster53/recon-ng) - Web reconnaissance framework with pluggable modules.
- [**SpiderFoot**](https://github.com/smicallef/spiderfoot) - Automated OSINT collection and relationship visualization.

---

## Password & Hash Cracking

- [**Hashcat**](https://hashcat.net/hashcat/) - GPU-accelerated password recovery. Supports 300+ hash algorithms.
- [**Hashcat Example Hashes**](https://hashcat.net/wiki/doku.php?id=example_hashes) - Hash type identification reference.
- [**John the Ripper**](https://github.com/openwall/john) - CPU-based password cracker with broad format support.
- [**Name That Hash**](https://github.com/HashPump/name-that-hash) - Automatically identify unknown hash types.
- [**CrackStation**](https://crackstation.net/) - Online hash lookup using large precomputed rainbow tables.
- [**SecLists**](https://github.com/danielmiessler/SecLists) - Wordlists for passwords, usernames, fuzzing, web shells, and more.

---

## Cheat Sheets & References

- [**HackTricks**](https://book.hacktricks.xyz/) - The definitive penetration testing knowledge base.
- [**GTFObins**](https://gtfobins.github.io/) - Unix binary abuse for shells, file operations, and privilege escalation.
- [**LOLBAS**](https://lolbas-project.github.io/) - Windows living-off-the-land techniques.
- [**Revshells**](https://www.revshells.com/) - Instant reverse shell one-liner generator for any language/OS.
- [**Active Directory Exploitation Cheat Sheet**](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) - AD attack quick reference.
- [**Active Directory Cheat Sheet**](https://github.com/drak3hft7/Cheat-Sheet---Active-Directory) - AD enumeration and exploitation command reference.
- [**OSCP Cheat Sheet (sushant747)**](https://sushant747.gitbooks.io/total-oscp-guide/content/) - Comprehensive OSCP exam preparation guide.
- [**bugbounty-oneliners**](https://github.com/dwisiswant0/awesome-oneliner-bugbounty) - One-liner commands for bug bounty recon pipelines.

---

## Files and Tools

| File | Description |
|---|---|
| `Accesschk.zip` | Sysinternals AccessChk — view effective permissions on objects |
| `CVE-2020-0796-POC.zip` | SMBGhost (CVE-2020-0796) proof-of-concept |
| `JuicyPotato.exe` | Token impersonation privilege escalation (pre-Server 2019) |
| `Nishang/` | PowerShell offensive scripts and payloads |
| `Rubeus.exe` | Kerberos attack toolkit |
| `Seatbelt.exe` | Windows host security enumeration |
| `amsibypass.txt` | AMSI bypass techniques for PowerShell |
| `bugbounty-onliners.md` | Bug bounty one-liners and recon commands |
| `evil-winrm/` | WinRM shell for pentesting |
| `kaliupdatescript` | Kali Linux update script |
| `python_rev_shell.py` | Python reverse shell |
| `windows_rev_shell_working.php` | PHP reverse shell (Windows targets) |
| `tools.sh` | Bash utility commands and shortcuts |

---

## Contributing

Contributions are welcome. Submit a pull request with new tools, updated links, or corrections. Please include a one-line description for each tool and verify links are active before submitting.

## License

MIT License. See [LICENSE](LICENSE) for details.
