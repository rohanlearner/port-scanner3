#!/usr/bin/env python3
"""
Core Port Scanner Engine
Performs multi-threaded port scanning using Nmap or socket-based fallback.
"""

import socket
import subprocess
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from pathlib import Path
from datetime import datetime

import nmap  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Discovered service information."""

    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    version: str = ""
    fingerprints: List[str] = field(default_factory=list)
    is_open: bool = False
    confidence: float = 0.0
    os_detected: Optional[str] = None
    ssl_info: Optional[str] = None

    def __repr__(self) -> str:
        return f"ServiceInfo(port={self.port}, service={self.service}, banner={self.banner[:50]})"


@dataclass
class ScanResult:
    """Scan result for a target."""

    target: str
    scan_time: datetime
    services: List[ServiceInfo] = field(default_factory=list)
    os_detected: Optional[str] = None
    total_ports_scanned: int = 0
    open_ports_count: int = 0
    scan_method: str = "nmap"

    def __repr__(self) -> str:
        return f"ScanResult(target={self.target}, open_ports={self.open_ports_count})"


class PortScanner:
    """Advanced multi-threaded port scanner using Nmap + socket fallback."""

    # Known service ports mapping
    COMMON_PORTS: Dict[int, str] = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        27017: "mongodb",
        8080: "http-proxy",
        8443: "https-proxy",
        9200: "elasticsearch",
        # Backdoor ports
        31337: "elite",
        1337: "leet",
        4444: "blaster",
        12345: "netbus",
        27374: "subseven",
    }

    def __init__(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        threads: int = 20,
        timeout: int = 5,
        aggressive: bool = False,
        stealth: bool = False,
        timing: int = 4,
        verbose: int = 0,
    ) -> None:
        """
        Initialize port scanner.

        Args:
            targets: List of target IPs/hostnames
            ports: List of ports to scan (None = top 1000)
            threads: Number of concurrent threads
            timeout: Connection timeout in seconds
            aggressive: Enable banner grabbing and version detection
            stealth: Use SYN scan (requires root)
            timing: Nmap timing template (0-5)
            verbose: Verbosity level
        """
        self.targets = targets
        self.ports = ports or self._get_top_ports(1000)
        self.threads = min(threads, 256)
        self.timeout = timeout
        self.aggressive = aggressive
        self.stealth = stealth
        self.timing = timing
        self.verbose = verbose

        self.scanner: Optional[nmap.PortScanner] = None
        self._setup_scanner()

        logger.info(
            f"PortScanner initialized: targets={len(targets)}, ports={len(self.ports)}, "
            f"threads={self.threads}, aggressive={aggressive}"
        )

    def _setup_scanner(self) -> None:
        """Setup Nmap scanner instance."""
        try:
            self.scanner = nmap.PortScanner()
            logger.debug("Nmap scanner initialized successfully")
        except Exception as e:
            logger.warning(f"Nmap initialization failed: {e}. Will use socket fallback.")
            self.scanner = None

    @staticmethod
    def _get_top_ports(count: int) -> List[int]:
        """Get top N common ports."""
        # Top ports by likelihood of being open
        top_ports = [
            80, 443, 22, 21, 25, 53, 110, 143, 3389, 445, 3306, 5432, 5900, 8080, 8443,
            1433, 27017, 6379, 9200, 5000, 5432, 8000, 8888, 9999, 10000, 4444, 8008,
            3000, 8081, 8082, 8888, 9000, 9200, 9300, 11211, 27017, 27018, 50070,
            # Common web ports
            8000, 8001, 8008, 8080, 8443, 8888, 9000, 9200,
            # Common database ports
            3306, 5432, 27017, 27018, 6379, 11211,
            # Backdoor ports
            31337, 1337, 4444, 12345, 27374, 6667, 5555, 7777, 9999, 10000,
        ]
        return sorted(list(set(top_ports)))[:count]

    async def scan_all(self) -> List[ScanResult]:
        """
        Scan all targets asynchronously.

        Returns:
            List of ScanResult objects
        """
        logger.info(f"Starting scan of {len(self.targets)} targets")

        results: List[ScanResult] = []
        loop = asyncio.get_event_loop()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = [
                loop.run_in_executor(executor, self._scan_target, target)
                for target in self.targets
            ]
            results = await asyncio.gather(*tasks)

        logger.info(f"Scan complete. Found {sum(r.open_ports_count for r in results)} open ports")
        return results

    def _scan_target(self, target: str) -> ScanResult:
        """
        Scan a single target.

        Args:
            target: Target IP or hostname

        Returns:
            ScanResult object
        """
        logger.debug(f"Scanning target: {target}")
        result = ScanResult(target=target, scan_time=datetime.now())

        try:
            if self.scanner:
                result = self._nmap_scan(target, result)
            else:
                result = self._socket_scan(target, result)
        except Exception as e:
            logger.error(f"Error scanning {target}: {e}")

        result.open_ports_count = len([s for s in result.services if s.is_open])
        return result

    def _nmap_scan(self, target: str, result: ScanResult) -> ScanResult:
        """
        Perform Nmap-based scan.

        Args:
            target: Target to scan
            result: ScanResult object to populate

        Returns:
            Updated ScanResult
        """
        try:
            if not self.scanner:
                raise RuntimeError("Nmap scanner not initialized")

            # Build Nmap arguments
            port_str = ",".join(map(str, self.ports))
            args = f"-p {port_str}"

            if self.stealth:
                args += " -sS"  # SYN scan
            else:
                args += " -sT"  # Connect scan

            if self.aggressive:
                args += " -sV"  # Service detection
                args += " -O"  # OS detection
                args += " --script banner"

            args += f" -T{self.timing}"

            logger.debug(f"Running Nmap scan: {target} {args}")
            self.scanner.scan(target, arguments=args)

            result.scan_method = "nmap"

            # Parse results
            if target in self.scanner.all_hosts():
                host_data = self.scanner[target]

                # OS detection
                if "osmatch" in host_data:
                    result.os_detected = host_data["osmatch"][0]["name"]

                # Port information
                for proto in host_data.all_protocols():
                    ports = host_data[proto].keys()
                    for port in ports:
                        port_info = host_data[proto][port]
                        state = port_info.get("state", "closed")

                        if state == "open":
                            service_info = ServiceInfo(
                                port=int(port),
                                protocol=proto,
                                is_open=True,
                            )

                            # Service detection
                            if "name" in port_info:
                                service_info.service = port_info["name"]
                            elif int(port) in self.COMMON_PORTS:
                                service_info.service = self.COMMON_PORTS[int(port)]

                            # Version detection
                            if "version" in port_info:
                                service_info.version = port_info["version"]

                            # Banner
                            if "extrainfo" in port_info:
                                service_info.banner = port_info["extrainfo"]

                            result.services.append(service_info)

                result.total_ports_scanned = len(ports)

        except Exception as e:
            logger.warning(f"Nmap scan failed for {target}: {e}. Falling back to socket scan.")
            result = self._socket_scan(target, result)

        return result

    def _socket_scan(self, target: str, result: ScanResult) -> ScanResult:
        """
        Perform socket-based port scan (fallback).

        Args:
            target: Target to scan
            result: ScanResult object to populate

        Returns:
            Updated ScanResult
        """
        logger.debug(f"Using socket scan for {target}")
        result.scan_method = "socket"

        with ThreadPoolExecutor(max_workers=min(self.threads, 50)) as executor:
            futures = {
                executor.submit(self._check_port, target, port): port
                for port in self.ports
            }

            for future in futures:
                try:
                    is_open, service, banner = future.result(timeout=self.timeout * 2)
                    port = futures[future]

                    if is_open:
                        service_info = ServiceInfo(
                            port=port,
                            service=service or self.COMMON_PORTS.get(port, "unknown"),
                            banner=banner,
                            is_open=True,
                        )
                        result.services.append(service_info)
                except Exception as e:
                    logger.debug(f"Error checking port {futures[future]}: {e}")

        result.total_ports_scanned = len(self.ports)
        return result

    def _check_port(
        self, host: str, port: int, timeout: Optional[int] = None
    ) -> Tuple[bool, str, str]:
        """
        Check if a single port is open and grab banner.

        Args:
            host: Target host
            port: Port to check
            timeout: Connection timeout

        Returns:
            Tuple of (is_open, service, banner)
        """
        timeout = timeout or self.timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                # Port is open, grab banner if aggressive
                banner = ""
                if self.aggressive:
                    try:
                        sock.send(b"HELP\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore")[:100]
                    except Exception:
                        pass

                service = self.COMMON_PORTS.get(port, "unknown")
                logger.debug(f"Port {port} open on {host}")
                return True, service, banner

            return False, "", ""

        except socket.timeout:
            return False, "", ""
        except Exception as e:
            logger.debug(f"Socket error on {host}:{port}: {e}")
            return False, "", ""
        finally:
            sock.close()

    def _grab_banner(self, host: str, port: int) -> str:
        """
        Grab service banner.

        Args:
            host: Target host
            port: Target port

        Returns:
            Banner string
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # Try common banner grab methods
            prompts = [b"HELP\r\n", b"\r\n", b""]
            banner = b""

            for prompt in prompts:
                try:
                    sock.send(prompt)
                    banner = sock.recv(1024)
                    if banner:
                        break
                except Exception:
                    pass

            sock.close()
            return banner.decode("utf-8", errors="ignore")[:200]

        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return ""

    @staticmethod
    def parse_nmap_output(output: str) -> Dict[int, Dict[str, str]]:
        """
        Parse Nmap output.

        Args:
            output: Nmap output string

        Returns:
            Dictionary of ports and their details
        """
        results = {}
        for line in output.split("\n"):
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if parts:
                    port_proto = parts[0].split("/")
                    if len(port_proto) == 2:
                        port = int(port_proto[0])
                        state = parts[1] if len(parts) > 1 else "unknown"
                        service = parts[2] if len(parts) > 2 else "unknown"
                        results[port] = {"state": state, "service": service}

        return results
