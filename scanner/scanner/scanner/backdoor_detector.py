#!/usr/bin/env python3
"""
Backdoor Detection Engine
Detects known backdoors, webshells, and suspicious service configurations.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class BackdoorSeverity(str, Enum):
    """Backdoor severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BackdoorDetection:
    """Detected backdoor information."""

    port: int
    service: str
    backdoor_type: str
    severity: BackdoorSeverity
    confidence: float
    indicators: List[str] = field(default_factory=list)
    banner: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    business_impact: str = ""
    remediation: str = ""

    def __repr__(self) -> str:
        return f"BackdoorDetection(port={self.port}, type={self.backdoor_type}, severity={self.severity.value})"


class BackdoorDetector:
    """Advanced backdoor and webshell detection engine."""

    # Known backdoor ports and their characteristics
    BACKDOOR_PORTS: Dict[int, Dict[str, str]] = {
        31337: {"name": "Elite", "type": "botnet"},
        1337: {"name": "Leet", "type": "trojan"},
        4444: {"name": "Blaster/Lovsan", "type": "worm"},
        12345: {"name": "NetBus", "type": "trojan"},
        27374: {"name": "SubSeven", "type": "backdoor"},
        6667: {"name": "IRC", "type": "botnet"},
        5555: {"name": "Personal Agent", "type": "backdoor"},
        7777: {"name": "Unreal Tour Server", "type": "backdoor"},
        9999: {"name": "Ince", "type": "trojan"},
        10000: {"name": "Socks Proxy", "type": "proxy"},
        666: {"name": "Doom", "type": "game"},
        1243: {"name": "BackDoor", "type": "backdoor"},
        1981: {"name": "Shivka-NEvil", "type": "backdoor"},
        2001: {"name": "Trojan Cow", "type": "trojan"},
        3128: {"name": "Squid Proxy", "type": "proxy"},
        4000: {"name": "Socks5", "type": "proxy"},
        5800: {"name": "VNC", "type": "remote-access"},
        5900: {"name": "VNC", "type": "remote-access"},
        8888: {"name": "HTTP-Alt", "type": "web"},
        9000: {"name": "SonicWALL", "type": "service"},
    }

    # Backdoor patterns in banners
    BACKDOOR_PATTERNS: List[Tuple[str, str, BackdoorSeverity]] = [
        (r"netcat|nc\s", "Netcat Backdoor", BackdoorSeverity.CRITICAL),
        (r"Meterpreter|msfpayload", "Metasploit Meterpreter", BackdoorSeverity.CRITICAL),
        (r"Weevely|weevely", "Weevely Webshell", BackdoorSeverity.CRITICAL),
        (r"China\s*Chopper|chopper", "China Chopper", BackdoorSeverity.CRITICAL),
        (r"B374K", "B374K Webshell", BackdoorSeverity.CRITICAL),
        (r"C99|c99\.php", "C99 Shell", BackdoorSeverity.CRITICAL),
        (r"R57|r57\.php", "R57 Shell", BackdoorSeverity.CRITICAL),
        (r"WSO|wso\.php", "WSO Webshell", BackdoorSeverity.CRITICAL),
        (r"DokuWiki|dokuwiki", "DokuWiki RCE", BackdoorSeverity.HIGH),
        (r"shell_exec|system\(|exec\(|passthru", "PHP Code Execution", BackdoorSeverity.CRITICAL),
        (r"cmd\.exe|powershell", "Windows Command Shell", BackdoorSeverity.CRITICAL),
        (r"/bin/bash|/bin/sh", "Unix Shell", BackdoorSeverity.CRITICAL),
        (r"ssh-rsa|SSH.*OpenSSH", "SSH Service", BackdoorSeverity.MEDIUM),
        (r"Microsoft-IIS|IIS", "IIS Web Server", BackdoorSeverity.MEDIUM),
        (r"Apache.*Struts", "Apache Struts", BackdoorSeverity.HIGH),
        (r"BadBlue", "BadBlue Server", BackdoorSeverity.HIGH),
        (r"tftpd", "TFTP Daemon", BackdoorSeverity.HIGH),
        (r"lpd|line printer daemon", "LPD Service", BackdoorSeverity.MEDIUM),
    ]

    # Webshell file paths
    WEBSHELL_PATHS: List[str] = [
        "shell.php",
        "shell.asp",
        "shell.aspx",
        "shell.jsp",
        "shell.jspx",
        "admin.php",
        "admin.asp",
        "index.php",
        "test.php",
        "upload.php",
        "cmd.php",
        "execute.php",
        "eval.php",
        "config.php",
        "db.php",
        ".htaccess",
        "web.config",
        "access.log",
        "error.log",
        "wp-admin/",
        "joomla/",
        "drupal/",
        "backup/",
        ".git/",
        ".svn/",
        ".env",
    ]

    # Suspicious service fingerprints
    SUSPICIOUS_SERVICES: Dict[str, Tuple[BackdoorSeverity, str]] = {
        "telnet": (BackdoorSeverity.HIGH, "Unencrypted remote access"),
        "ftp": (BackdoorSeverity.HIGH, "Anonymous FTP or weak credentials"),
        "smtp": (BackdoorSeverity.MEDIUM, "Open relay potential"),
        "snmp": (BackdoorSeverity.MEDIUM, "SNMP enumeration possible"),
        "rsh": (BackdoorSeverity.CRITICAL, "Unencrypted shell"),
        "rlogin": (BackdoorSeverity.CRITICAL, "Unencrypted login"),
        "fingerd": (BackdoorSeverity.MEDIUM, "User enumeration"),
        "nntp": (BackdoorSeverity.MEDIUM, "News service exposure"),
        "xdmcp": (BackdoorSeverity.HIGH, "X11 display protocol"),
        "bootps": (BackdoorSeverity.MEDIUM, "DHCP service"),
        "router": (BackdoorSeverity.HIGH, "Router management port"),
    }

    def __init__(self, verbose: int = 0) -> None:
        """
        Initialize backdoor detector.

        Args:
            verbose: Verbosity level
        """
        self.verbose = verbose
        logger.info(f"BackdoorDetector initialized (verbose={verbose})")

    def analyze_results(self, scan_results: List) -> List[BackdoorDetection]:
        """
        Analyze scan results for backdoors.

        Args:
            scan_results: List of ScanResult objects

        Returns:
            List of BackdoorDetection objects
        """
        detections: List[BackdoorDetection] = []

        for result in scan_results:
            for service in result.services:
                detection = self._analyze_service(service)
                if detection:
                    detections.append(detection)

        logger.info(f"Detected {len(detections)} potential backdoors")
        return detections

    def _analyze_service(self, service) -> Optional[BackdoorDetection]:
        """
        Analyze a single service for backdoor indicators.

        Args:
            service: ServiceInfo object

        Returns:
            BackdoorDetection if suspicious, None otherwise
        """
        indicators: List[str] = []
        severity = BackdoorSeverity.INFO
        backdoor_type = "Unknown"

        # Check if it's a known backdoor port
        if service.port in self.BACKDOOR_PORTS:
            bd_info = self.BACKDOOR_PORTS[service.port]
            backdoor_type = bd_info["name"]
            severity = BackdoorSeverity.CRITICAL if bd_info["type"] == "botnet" else BackdoorSeverity.HIGH
            indicators.append(f"Known backdoor port: {backdoor_type}")
            logger.warning(f"Detected known backdoor port: {service.port} ({backdoor_type})")

        # Check banner for backdoor patterns
        if service.banner:
            for pattern, bd_name, sev in self.BACKDOOR_PATTERNS:
                if re.search(pattern, service.banner, re.IGNORECASE):
                    backdoor_type = bd_name
                    severity = max(severity, sev)
                    indicators.append(f"Banner match: {bd_name}")
                    logger.warning(f"Detected backdoor pattern: {bd_name} on port {service.port}")

        # Check for suspicious services
        if service.service.lower() in self.SUSPICIOUS_SERVICES:
            sev, reason = self.SUSPICIOUS_SERVICES[service.service.lower()]
            severity = max(severity, sev)
            indicators.append(f"Suspicious service: {reason}")
            logger.warning(f"Suspicious service: {service.service} on port {service.port}")

        # Check version for known vulnerabilities
        if service.version:
            vuln_indicators = self._check_version_vulnerabilities(
                service.service, service.version
            )
            indicators.extend(vuln_indicators)
            if vuln_indicators:
                severity = max(severity, BackdoorSeverity.HIGH)

        # If we found indicators, create detection
        if indicators or severity != BackdoorSeverity.INFO:
            return BackdoorDetection(
                port=service.port,
                service=service.service,
                backdoor_type=backdoor_type,
                severity=severity,
                confidence=0.7 + (0.1 * len(indicators)),
                indicators=indicators,
                banner=service.banner[:100] if service.banner else "",
                exploitation_steps=self._get_exploitation_steps(
                    service.port, backdoor_type
                ),
                business_impact=self._get_business_impact(backdoor_type),
                remediation=self._get_remediation(service.service, service.port),
            )

        return None

    def _check_version_vulnerabilities(self, service: str, version: str) -> List[str]:
        """
        Check version for known vulnerabilities.

        Args:
            service: Service name
            version: Version string

        Returns:
            List of vulnerability indicators
        """
        indicators: List[str] = []

        # Common vulnerable versions
        vulnerable_versions = {
            "OpenSSH": ["2.x", "3.x", "4.0"],
            "Apache": ["1.3", "2.0", "2.2.0-2.2.15"],
            "IIS": ["5.0", "6.0"],
            "MySQL": ["4.x", "5.0.0-5.0.51"],
            "PostgreSQL": ["7.x", "8.0.0-8.0.11"],
        }

        service_lower = service.lower()
        for vuln_service, bad_versions in vulnerable_versions.items():
            if vuln_service.lower() in service_lower:
                for bad_ver in bad_versions:
                    if bad_ver in version:
                        indicators.append(
                            f"Vulnerable version detected: {version}"
                        )
                        logger.warning(
                            f"Vulnerable {service} version: {version}"
                        )
                        break

        return indicators

    @staticmethod
    def _get_exploitation_steps(port: int, backdoor_type: str) -> List[str]:
        """
        Get exploitation steps for a detected backdoor.

        Args:
            port: Backdoor port
            backdoor_type: Type of backdoor

        Returns:
            List of exploitation steps
        """
        steps = {
            "Elite": [
                "1. Attempt to connect on port 31337: nc -v target 31337",
                "2. Gain shell access to remote system",
                "3. Execute arbitrary commands with full privileges",
                "4. Establish persistent backdoor access",
            ],
            "NetBus": [
                "1. Use NetBus client or nc to connect on port 12345",
                "2. Retrieve system information and file access",
                "3. Install additional backdoor components",
                "4. Maintain persistent access for data exfiltration",
            ],
            "Netcat Backdoor": [
                "1. Identify Netcat listening on detected port",
                "2. Connect using: nc target port or telnet target port",
                "3. Execute shell commands directly",
                "4. Pivot to other systems on the network",
            ],
            "Metasploit Meterpreter": [
                "1. Confirm Meterpreter is running on target",
                "2. Use msfconsole to create handler",
                "3. Establish reverse shell connection",
                "4. Gain full control with persistence mechanisms",
            ],
            "Weevely Webshell": [
                "1. Locate webshell at detected HTTP path",
                "2. Connect using: weevely http://target/shell.php password",
                "3. Execute PHP code and system commands",
                "4. Upload additional payloads and webshells",
            ],
            "China Chopper": [
                "1. Identify China Chopper listening port",
                "2. Connect with China Chopper client",
                "3. Gain ASP/ASP.NET execution capabilities",
                "4. Access files and databases on web server",
            ],
        }.get(backdoor_type, [f"1. Connect to {backdoor_type} on port {port}"])

        return steps

    @staticmethod
    def _get_business_impact(backdoor_type: str) -> str:
        """Get business impact assessment."""
        impacts = {
            "Elite": "Complete system compromise, ransomware deployment, data theft",
            "NetBus": "Remote file access, credential theft, lateral movement capability",
            "Netcat Backdoor": "Persistent unauthorized access, system manipulation",
            "Metasploit Meterpreter": "Full system control, malware installation, data exfiltration",
            "Weevely Webshell": "Website defacement, malware distribution, SEO poisoning",
            "China Chopper": "Web application compromise, database breach, malware hosting",
        }
        return impacts.get(
            backdoor_type,
            "Unauthorized remote access, potential data breach, and system compromise"
        )

    @staticmethod
    def _get_remediation(service: str, port: int) -> str:
        """Get remediation steps."""
        if port in [31337, 1337, 4444, 12345, 27374]:
            return (
                "1. Immediately disconnect affected system from network\n"
                "2. Kill suspicious processes listening on this port\n"
                "3. Run comprehensive malware scan (Malwarebytes, etc.)\n"
                "4. Review system logs for unauthorized access\n"
                "5. Consider full OS reinstall if breach is confirmed\n"
                "6. Change all passwords and certificates\n"
                "7. Notify security team and management"
            )
        elif service.lower() in ["telnet", "ftp", "rsh"]:
            return (
                "1. Disable unencrypted protocols immediately\n"
                "2. Replace with SSH for remote access\n"
                "3. Use SFTP or SCP instead of FTP\n"
                "4. Implement network-level access controls\n"
                "5. Monitor for unauthorized login attempts"
            )
        else:
            return (
                "1. Update service to latest stable version\n"
                "2. Apply all available security patches\n"
                "3. Disable unnecessary services\n"
                "4. Implement firewall rules to restrict access\n"
                "5. Configure strong authentication mechanisms\n"
                "6. Enable service-level monitoring and logging"
            )
