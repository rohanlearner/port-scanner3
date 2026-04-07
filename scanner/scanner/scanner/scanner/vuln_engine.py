#!/usr/bin/env python3
"""
Vulnerability Analysis Engine
Detects and analyzes security vulnerabilities with exploitation guides and remediation.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class VulnSeverity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Detected vulnerability information."""

    port: int
    service: str
    vuln_type: str
    cve: Optional[str] = None
    severity: VulnSeverity = VulnSeverity.MEDIUM
    affected_versions: List[str] = field(default_factory=list)
    description: str = ""
    exploitation_method: List[str] = field(default_factory=list)
    business_impact: str = ""
    remediation: str = ""
    confidence: float = 0.8

    def __repr__(self) -> str:
        return f"Vulnerability(port={self.port}, type={self.vuln_type}, severity={self.severity.value})"


class VulnerabilityEngine:
    """Advanced vulnerability analysis and exploitation guide engine."""

    # CVE database (simplified)
    KNOWN_CVES: Dict[str, List[Tuple[str, str, str]]] = {
        "OpenSSH": [
            ("CVE-2018-15473", "2.x-7.7", "Username enumeration vulnerability"),
            ("CVE-2016-6210", "2.x-7.2p2", "Username enumeration via timing attack"),
            ("CVE-2014-6271", "All", "Shellshock - Bash code injection"),
            ("CVE-2015-3236", "6.0-7.0", "Challenge-response DoS"),
        ],
        "Apache": [
            ("CVE-2017-9788", "2.2.34, 2.4.27", "mod_auth_digest buffer overflow"),
            ("CVE-2017-10784", "2.4.0-2.4.29", "mod_session NULL pointer dereference"),
            ("CVE-2018-1312", "2.4.0-2.4.34", "Apache Struts bypass"),
            ("CVE-2017-5645", "1.3-2.4.23", "mod_ssl cookie handling"),
        ],
        "Nginx": [
            ("CVE-2019-9511", "All", "HTTP/2 protocol DoS"),
            ("CVE-2018-16844", "0.7-1.14", "Null byte injection"),
        ],
        "MySQL": [
            ("CVE-2019-2614", "5.5-8.0", "MySQL authentication bypass"),
            ("CVE-2018-3639", "5.5-8.0", "Spectre variant 4"),
            ("CVE-2017-3238", "5.5-5.7", "MySQL privilege escalation"),
        ],
        "PostgreSQL": [
            ("CVE-2019-9193", "9.3-11", "PostgreSQL function execution"),
            ("CVE-2018-10915", "9.3-11", "Password exposure in connection parameters"),
        ],
        "Redis": [
            ("CVE-2016-10553", "3.2.0-4.0.0", "Redis authentication bypass"),
            ("CVE-2015-4335", "2.8.0-3.0.3", "Redis BITFIELD command DoS"),
        ],
        "MongoDB": [
            ("CVE-2019-12103", "3.x-4.x", "MongoDB authentication bypass"),
            ("CVE-2018-7602", "3.0-4.0", "MongoDB injection vulnerability"),
        ],
        "IIS": [
            ("CVE-2015-1635", "6.0-10.0", "HTTP.sys remote code execution"),
            ("CVE-2017-6709", "7.0-10.0", "IIS authentication bypass"),
        ],
    }

    # Dangerous service configurations
    DANGEROUS_SERVICES: Dict[str, Tuple[VulnSeverity, str, List[str]]] = {
        "ftp": (
            VulnSeverity.HIGH,
            "Unencrypted file transfer",
            [
                "1. FTP transmits credentials in plaintext",
                "2. Attacker intercepts username and password",
                "3. Attacker gains file system access",
                "4. Modify files or upload webshells",
            ],
        ),
        "telnet": (
            VulnSeverity.CRITICAL,
            "Unencrypted remote access",
            [
                "1. Telnet transmits all data including passwords in plaintext",
                "2. Network sniffer captures credentials",
                "3. Attacker logs in to system with captured credentials",
                "4. Full system compromise achieved",
            ],
        ),
        "smtp": (
            VulnSeverity.MEDIUM,
            "Open mail relay",
            [
                "1. Verify SMTP server accepts external emails: telnet host 25",
                "2. Use VRFY command to enumerate valid users",
                "3. Send spam or phishing emails through open relay",
                "4. Tarnish company reputation and email reputation",
            ],
        ),
        "snmp": (
            VulnSeverity.MEDIUM,
            "SNMP enumeration",
            [
                "1. Use snmpwalk to enumerate system information",
                "2. Snmpwalk -c public host",
                "3. Extract configuration and system details",
                "4. Identify other systems for targeted attacks",
            ],
        ),
        "mysql": (
            VulnSeverity.CRITICAL,
            "Exposed database service",
            [
                "1. Scan for default credentials: root/root",
                "2. Connect: mysql -h host -u root",
                "3. List all databases and tables",
                "4. Extract sensitive customer data",
                "5. Modify data or install backdoors",
            ],
        ),
        "mongodb": (
            VulnSeverity.CRITICAL,
            "Unauthenticated database access",
            [
                "1. Connect directly without authentication",
                "2. Use MongoDB tools or Python to connect",
                "3. Read/write to all databases and collections",
                "4. Exfiltrate entire database",
                "5. Execute arbitrary JavaScript commands",
            ],
        ),
        "redis": (
            VulnSeverity.CRITICAL,
            "Unauthenticated cache access",
            [
                "1. Connect: redis-cli -h target",
                "2. Read all cached data and sessions",
                "3. Write malicious data to cache",
                "4. Potentially execute Lua code",
                "5. Compromise user sessions",
            ],
        ),
        "rdp": (
            VulnSeverity.CRITICAL,
            "Remote Desktop exposed",
            [
                "1. Brute force RDP credentials",
                "2. Use tools: xfreerdp, hydra for brute force",
                "3. Gain graphical access to system",
                "4. Full system control and data access",
                "5. Install persistence mechanisms",
            ],
        ),
        "smb": (
            VulnSeverity.CRITICAL,
            "SMB/CIFS exposed (EternalBlue vulnerable)",
            [
                "1. Scan for SMB version: nmap -p 445 --script smb-os-discovery",
                "2. Windows 7/2008/2012 vulnerable to EternalBlue",
                "3. Use Metasploit module exploit/windows/smb/ms17_010_eternalblue",
                "4. Gain SYSTEM level access",
                "5. Execute ransomware or malware",
            ],
        ),
        "http": (
            VulnSeverity.HIGH,
            "Unencrypted HTTP on port 80",
            [
                "1. Man-in-the-middle attack on unencrypted traffic",
                "2. Intercept credentials and session cookies",
                "3. Modify requests/responses in transit",
                "4. Inject malware into responses",
                "5. Redirect users to phishing sites",
            ],
        ),
    }

    # Web vulnerability patterns
    WEB_VULNERABILITIES: Dict[str, Tuple[VulnSeverity, List[str]]] = {
        "wordpress": (
            VulnSeverity.HIGH,
            [
                "1. Enumerate WordPress version: curl -s host | grep wp-content/themes",
                "2. Search for known vulnerabilities in that version",
                "3. Exploit plugin vulnerabilities or misconfiguration",
                "4. Gain admin access or shell execution",
            ],
        ),
        "joomla": (
            VulnSeverity.HIGH,
            [
                "1. Identify Joomla version from /administrator/",
                "2. Check for CVEs affecting that version",
                "3. Exploit SQL injection or file upload vulnerabilities",
                "4. Achieve remote code execution",
            ],
        ),
        "drupal": (
            VulnSeverity.HIGH,
            [
                "1. Check Drupal version from CHANGELOG.txt",
                "2. Search for known Drupal CVEs",
                "3. Exploit module vulnerabilities",
                "4. Gain admin access",
            ],
        ),
        "admin_panel": (
            VulnSeverity.MEDIUM,
            [
                "1. Locate admin panel at common paths",
                "2. Attempt default credentials (admin/admin, etc.)",
                "3. If successful, gain administrative access",
                "4. Create backdoor accounts or modify settings",
            ],
        ),
    }

    def __init__(self, verbose: int = 0) -> None:
        """
        Initialize vulnerability engine.

        Args:
            verbose: Verbosity level
        """
        self.verbose = verbose
        logger.info(f"VulnerabilityEngine initialized (verbose={verbose})")

    def analyze_services(self, scan_results: List) -> List[Vulnerability]:
        """
        Analyze scan results for vulnerabilities.

        Args:
            scan_results: List of ScanResult objects

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        for result in scan_results:
            for service in result.services:
                vulns = self._analyze_service(service)
                vulnerabilities.extend(vulns)

        logger.info(f"Identified {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _analyze_service(self, service) -> List[Vulnerability]:
        """
        Analyze a single service for vulnerabilities.

        Args:
            service: ServiceInfo object

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        # Check for dangerous services
        service_lower = service.service.lower()
        for dangerous_service, (severity, reason, steps) in self.DANGEROUS_SERVICES.items():
            if dangerous_service in service_lower or service.port in [
                21, 23, 25, 53, 110, 143, 3306, 3389, 445, 5432,
                6379, 27017, 8080, 9200
            ]:
                # Match dangerous services to ports
                port_service_map = {
                    21: "ftp",
                    23: "telnet",
                    25: "smtp",
                    53: "dns",
                    110: "pop3",
                    143: "imap",
                    3306: "mysql",
                    3389: "rdp",
                    445: "smb",
                    5432: "postgresql",
                    6379: "redis",
                    27017: "mongodb",
                    80: "http",
                    443: "https",
                }

                if service.port in port_service_map and dangerous_service == port_service_map[service.port]:
                    vuln = Vulnerability(
                        port=service.port,
                        service=service.service,
                        vuln_type=reason,
                        severity=severity,
                        description=reason,
                        exploitation_method=steps,
                        business_impact=self._get_web_impact(dangerous_service),
                        remediation=self._get_remediation_steps(service.service),
                        confidence=0.95,
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Dangerous service detected: {service.service} on port {service.port}")

        # Check for CVEs based on version
        if service.version:
            cves = self._check_cves(service.service, service.version)
            vulnerabilities.extend(cves)

        # Check for web vulnerabilities
        if service.port in [80, 443, 8080, 8443]:
            web_vulns = self._check_web_vulns(service)
            vulnerabilities.extend(web_vulns)

        return vulnerabilities

    def _check_cves(self, service: str, version: str) -> List[Vulnerability]:
        """Check for known CVEs."""
        vulnerabilities: List[Vulnerability] = []

        service_lower = service.lower()
        for known_service, cve_list in self.KNOWN_CVES.items():
            if known_service.lower() in service_lower:
                for cve_id, affected, description in cve_list:
                    if self._version_matches(version, affected):
                        vuln = Vulnerability(
                            port=0,  # Will be set by caller
                            service=service,
                            vuln_type=description,
                            cve=cve_id,
                            severity=VulnSeverity.HIGH,
                            affected_versions=[affected],
                            description=f"{cve_id}: {description}",
                            exploitation_method=[
                                f"1. Identify running version: {version}",
                                f"2. Search for {cve_id} exploit code",
                                f"3. Use exploit to gain unauthorized access",
                                f"4. Execute arbitrary code or escalate privileges",
                            ],
                            business_impact="Remote code execution, data breach, or service disruption",
                            remediation=f"Update {service} to patched version immediately",
                            confidence=0.9,
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"CVE detected: {cve_id} in {service} {version}")

        return vulnerabilities

    def _check_web_vulns(self, service) -> List[Vulnerability]:
        """Check for web application vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []

        # This would typically involve web scanning
        # For now, we check based on banner/version information
        if service.banner:
            for web_vuln, (severity, steps) in self.WEB_VULNERABILITIES.items():
                if web_vuln.lower() in service.banner.lower():
                    vuln = Vulnerability(
                        port=service.port,
                        service=service.service,
                        vuln_type=web_vuln,
                        severity=severity,
                        description=f"Web application vulnerability: {web_vuln}",
                        exploitation_method=steps,
                        business_impact="Website compromise, malware distribution, SEO poisoning",
                        remediation="Update CMS and plugins to latest versions, implement WAF",
                        confidence=0.8,
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _version_matches(version: str, affected: str) -> bool:
        """Check if a version matches affected versions pattern."""
        version_lower = version.lower()
        affected_lower = affected.lower()

        if "all" in affected_lower or "*" in affected_lower:
            return True

        if "-" in affected:
            # Range: 2.x-7.7
            parts = affected.split("-")
            if len(parts) == 2:
                return parts[0] in version or parts[1] in version

        return affected in version or version in affected

    @staticmethod
    def _get_web_impact(service: str) -> str:
        """Get business impact for web vulnerabilities."""
        impacts = {
            "ftp": "Attacker gains file system access, can upload webshells and deface website",
            "telnet": "Complete system compromise, all credentials exposed, ransomware deployment",
            "mysql": "Complete database breach, customer data stolen, reputation damage",
            "mongodb": "Unencrypted data access, customer records stolen, compliance violations",
            "redis": "Session hijacking, cache poisoning, user account compromise",
            "rdp": "Remote system control, ransomware deployment, lateral movement",
            "smb": "Network compromise via EternalBlue, ransomware deployment across infrastructure",
            "http": "Credential theft via MITM, website defacement, malware injection",
        }
        return impacts.get(service.lower(), "Security breach with significant business impact")

    @staticmethod
    def _get_remediation_steps(service: str) -> str:
        """Get remediation steps for a service."""
        remediation = {
            "ftp": "Disable FTP completely. Use SFTP or SCP with SSH keys instead.",
            "telnet": "Disable Telnet. Replace with SSH. Implement certificate-based authentication.",
            "mysql": "Restrict MySQL to localhost or specific IPs. Use strong passwords. Enable SSL/TLS.",
            "mongodb": "Enable authentication. Restrict network access. Use MongoDB encryption.",
            "redis": "Disable public access. Use firewall rules. Implement Redis authentication.",
            "rdp": "Limit RDP to VPN users. Use RDP Gateway. Enable NLA (Network Level Authentication).",
            "smb": "Apply Windows security updates immediately. Disable SMBv1. Restrict SMB access.",
            "http": "Redirect all HTTP to HTTPS. Use HSTS headers. Install valid SSL/TLS certificate.",
        }
        return remediation.get(
            service.lower(),
            "Update service to latest version and apply all security patches"
        )
