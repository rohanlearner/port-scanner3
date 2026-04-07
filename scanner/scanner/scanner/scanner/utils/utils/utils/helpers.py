#!/usr/bin/env python3
"""
Helper Utilities
IP validation, port parsing, CIDR expansion, logging setup.
"""

import logging
import ipaddress
import socket
from typing import List, Optional, Set, Tuple
from pathlib import Path


# Global logger instance
_logger: Optional[logging.Logger] = None


def setup_logging(verbosity: int = 0) -> logging.Logger:
    """
    Setup logging configuration.

    Args:
        verbosity: Verbosity level (0=WARNING, 1=INFO, 2=DEBUG, 3+=TRACE)

    Returns:
        Configured logger instance
    """
    global _logger

    # Map verbosity to log level
    log_levels = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.DEBUG,
    }
    log_level = log_levels.get(verbosity, logging.DEBUG)

    # Create logs directory
    logs_dir = Path("./logs")
    logs_dir.mkdir(exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(logs_dir / "portscaneer.log"),
            logging.StreamHandler() if verbosity > 0 else logging.NullHandler(),
        ],
    )

    _logger = logging.getLogger("portscaneer")
    _logger.info(f"Logging initialized with level: {logging.getLevelName(log_level)}")

    return _logger


def get_logger(name: str) -> logging.Logger:
    """
    Get logger instance for a module.

    Args:
        name: Module name

    Returns:
        Logger instance
    """
    global _logger
    if _logger is None:
        setup_logging()
    return logging.getLogger(name)


def validate_target(target: str) -> bool:
    """
    Validate target IP or hostname.

    Args:
        target: IP address or hostname

    Returns:
        True if valid, False otherwise
    """
    try:
        # Try to parse as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        # Try to resolve as hostname
        socket.gethostbyname(target)
        return True
    except (socket.gaierror, socket.error):
        pass

    return False


def parse_port_string(port_string: str) -> List[int]:
    """
    Parse port string into list of ports.

    Args:
        port_string: Port specification (e.g., "80,443,8000-9000" or "common")

    Returns:
        List of port numbers
    """
    ports: Set[int] = set()

    if port_string.lower() == "common":
        # Top common ports
        return [
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
            1433, 3306, 3389, 5432, 5900, 8080, 8443,
        ]

    if port_string.lower() == "all":
        # All ports
        return list(range(1, 65536))

    parts = port_string.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            # Range: 8000-9000
            try:
                start, end = part.split("-")
                start = int(start.strip())
                end = int(end.strip())
                ports.update(range(start, end + 1))
            except ValueError:
                get_logger(__name__).warning(f"Invalid port range: {part}")
        else:
            # Single port
            try:
                ports.add(int(part.strip()))
            except ValueError:
                get_logger(__name__).warning(f"Invalid port: {part}")

    return sorted(list(ports))


def is_valid_cidr(cidr: str) -> bool:
    """
    Check if CIDR notation is valid.

    Args:
        cidr: CIDR notation (e.g., 192.168.1.0/24)

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    """
    Expand CIDR notation into list of IP addresses.

    Args:
        cidr: CIDR notation (e.g., 192.168.1.0/24)

    Returns:
        List of IP addresses (limited to prevent huge expansions)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)

        # Limit expansion to prevent DoS
        max_ips = 256
        ips = []

        for i, ip in enumerate(network.hosts()):
            if i >= max_ips:
                get_logger(__name__).warning(
                    f"CIDR expansion limited to {max_ips} hosts"
                )
                break
            ips.append(str(ip))

        # If no hosts (e.g., /32), include the network address
        if not ips:
            ips.append(str(network.network_address))

        return ips

    except ValueError as e:
        get_logger(__name__).error(f"Invalid CIDR: {cidr}: {e}")
        return []


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is in private range.

    Args:
        ip: IP address

    Returns:
        True if private, False otherwise
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_localhost(ip: str) -> bool:
    """
    Check if IP is localhost.

    Args:
        ip: IP address

    Returns:
        True if localhost, False otherwise
    """
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.

    Args:
        hostname: Hostname to resolve

    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_service_name(port: int) -> str:
    """
    Get common service name for a port.

    Args:
        port: Port number

    Returns:
        Service name
    """
    services = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        80: "http",
        110: "pop3",
        123: "ntp",
        135: "msrpc",
        139: "netbios",
        143: "imap",
        161: "snmp",
        162: "snmp-trap",
        389: "ldap",
        443: "https",
        445: "smb",
        465: "smtps",
        514: "syslog",
        587: "smtp-tls",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        27017: "mongodb",
        9200: "elasticsearch",
    }
    return services.get(port, "unknown")


def classify_port_risk(port: int) -> str:
    """
    Classify port risk level.

    Args:
        port: Port number

    Returns:
        Risk classification: "critical", "high", "medium", "low"
    """
    critical_ports = {3389, 445, 3306, 27017, 6379, 5432, 23, 21, 69}
    high_ports = {22, 80, 443, 1433, 8080, 8443, 9200}
    medium_ports = {25, 53, 110, 143, 389, 5900}

    if port in critical_ports:
        return "critical"
    elif port in high_ports:
        return "high"
    elif port in medium_ports:
        return "medium"
    else:
        return "low"


def format_bytes(bytes_count: int) -> str:
    """
    Format bytes to human-readable format.

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} TB"


def format_time(seconds: float) -> str:
    """
    Format seconds to human-readable time.

    Args:
        seconds: Number of seconds

    Returns:
        Formatted string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"
