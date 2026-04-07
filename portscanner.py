#!/usr/bin/env python3
"""
Portscaneer - Advanced Network Backdoor & Vulnerability Scanner
Production-ready security tool designed for business website protection.

Author: Security Team
Version: 1.0.0
License: MIT
"""

import sys
import asyncio
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.banner import display_banner, display_disclaimer, get_user_consent
from utils.helpers import (
    setup_logging,
    validate_target,
    parse_port_string,
    is_valid_cidr,
    expand_cidr,
    get_logger,
)
from scanner.core_scanner import PortScanner
from scanner.backdoor_detector import BackdoorDetector
from scanner.vuln_engine import VulnerabilityEngine
from scanner.reporter import SecurityReporter

# Initialize CLI app
app = typer.Typer(
    help="🔍 Portscaneer - Advanced Network Security Scanner for Business Protection",
    pretty_exceptions_enable=False,
)
console = Console()
logger = get_logger(__name__)


def show_welcome() -> None:
    """Display welcome banner and legal disclaimer."""
    display_banner(console)
    if not get_user_consent(console):
        console.print(
            Panel(
                "[red]❌ Authorization denied. Exiting.[/red]",
                title="Authorization Required",
                border_style="red",
            )
        )
        raise typer.Exit(1)


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Target IP, hostname, or CIDR range (e.g., 192.168.1.1 or example.com)"
    ),
    ports: Optional[str] = typer.Option(
        None,
        "--ports",
        "-p",
        help="Specific ports to scan (e.g., 80,443,8080-9000 or 'common')",
    ),
    range_cidr: Optional[str] = typer.Option(
        None,
        "--range",
        "-r",
        help="CIDR range for network scanning (e.g., 192.168.1.0/24)",
    ),
    aggressive: bool = typer.Option(
        False,
        "--aggressive",
        "-a",
        help="Enable aggressive scanning (banner grabbing, version detection)",
    ),
    web: bool = typer.Option(
        False,
        "--web",
        "-w",
        help="Business web server mode (focus on ports 80/443)",
    ),
    backdoor: bool = typer.Option(
        False,
        "--backdoor",
        "-b",
        help="Focus on backdoor and webshell detection",
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        "-s",
        help="Use stealth mode (SYN scan, slower but less detectable)",
    ),
    timing: int = typer.Option(
        4, "--timing", "-t", min=0, max=5, help="Nmap timing template (T0-T5)"
    ),
    threads: int = typer.Option(
        20,
        "--threads",
        "-j",
        min=1,
        max=256,
        help="Number of concurrent threads",
    ),
    report_format: str = typer.Option(
        "html",
        "--report",
        "-R",
        help="Report format: html, json, pdf, or all",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for reports (default: ./reports)",
    ),
    timeout: int = typer.Option(
        5, "--timeout", help="Connection timeout in seconds"
    ),
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        help="Verbosity level (-v, -vv, -vvv)",
    ),
) -> None:
    """
    🔍 Perform comprehensive network security scan.

    Examples:
        portscaneer scan 192.168.1.1 --web --aggressive --report html
        portscaneer scan example.com --backdoor --stealth
        portscaneer scan 192.168.0.0/24 --aggressive --threads 50 --report all
    """
    show_welcome()

    # Setup logging
    setup_logging(verbose)
    logger.info(f"Starting Portscaneer scan on {target}")

    try:
        # Validate and prepare targets
        targets = [target]

        if range_cidr:
            if not is_valid_cidr(range_cidr):
                console.print(
                    f"[red]❌ Invalid CIDR range: {range_cidr}[/red]"
                )
                raise typer.Exit(1)
            targets.extend(expand_cidr(range_cidr))
            console.print(
                f"[yellow]📍 Expanded CIDR range to {len(targets)} targets[/yellow]"
            )

        # Validate all targets
        for t in targets:
            if not validate_target(t):
                console.print(
                    f"[red]❌ Invalid target: {t}[/red]"
                )
                raise typer.Exit(1)

        # Parse ports
        if ports:
            port_list = parse_port_string(ports)
        elif web:
            port_list = [80, 443, 8080, 8443]
        elif backdoor:
            port_list = [
                31337,
                1337,
                4444,
                12345,
                27374,
                6667,
                5555,
                7777,
                9999,
                10000,
            ]
        else:
            port_list = None  # Default to top 1000

        console.print(
            Panel(
                f"[cyan]🎯 Target[/cyan]: {target}\n"
                f"[cyan]🔌 Ports[/cyan]: {port_list or 'Top 1000'}\n"
                f"[cyan]👥 Threads[/cyan]: {threads}\n"
                f"[cyan]⚔️  Mode[/cyan]: {'Web' if web else 'Backdoor' if backdoor else 'Full'}",
                title="Scan Configuration",
                border_style="cyan",
            )
        )

        # Run scanner
        scanner = PortScanner(
            targets=targets,
            ports=port_list,
            threads=threads,
            timeout=timeout,
            aggressive=aggressive,
            stealth=stealth,
            timing=timing,
            verbose=verbose,
        )

        with console.status("[bold cyan]🔍 Scanning ports...", spinner="dots"):
            results = asyncio.run(scanner.scan_all())

        console.print(
            f"[green]✅ Port scan complete: {len(results)} services discovered[/green]"
        )

        # Backdoor detection
        if backdoor or not web:
            with console.status("[bold cyan]🕵️ Detecting backdoors...", spinner="dots"):
                detector = BackdoorDetector(verbose=verbose)
                backdoor_results = detector.analyze_results(results)

            console.print(
                f"[yellow]⚠️  {len(backdoor_results)} potential backdoors detected[/yellow]"
            )

        # Vulnerability analysis
        if not backdoor:
            with console.status(
                "[bold cyan]🔎 Analyzing vulnerabilities...", spinner="dots"
            ):
                vuln_engine = VulnerabilityEngine(verbose=verbose)
                vulnerabilities = vuln_engine.analyze_services(results)

            console.print(
                f"[red]🚨 {len(vulnerabilities)} vulnerabilities found[/red]"
            )

        # Generate report
        output_dir = Path(output or "./reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        with console.status("[bold cyan]📝 Generating report...", spinner="dots"):
            reporter = SecurityReporter(output_dir=output_dir)
            report_path = reporter.generate_report(
                target=target,
                results=results,
                backdoors=backdoor_results if (backdoor or not web) else [],
                vulnerabilities=vulnerabilities if not backdoor else [],
                format_type=report_format,
            )

        console.print(
            Panel(
                f"[green]✅ Scan Complete![/green]\n"
                f"[cyan]📁 Report saved to[/cyan]: {report_path}\n"
                f"[yellow]🔒 Review findings and apply hardening recommendations[/yellow]",
                title="Portscaneer Scan Results",
                border_style="green",
            )
        )

    except KeyboardInterrupt:
        console.print("[red]❌ Scan interrupted by user[/red]")
        raise typer.Exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        console.print(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def quick(
    target: str = typer.Argument(
        ..., help="Target IP or hostname to scan quickly"
    ),
    mode: str = typer.Option(
        "web",
        "--mode",
        "-m",
        help="Quick scan mode: web, backdoor, or all",
    ),
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        help="Verbosity level",
    ),
) -> None:
    """
    ⚡ Quick security scan with preset configurations.

    Examples:
        portscaneer quick 192.168.1.1 --mode web
        portscaneer quick example.com --mode backdoor
        portscaneer quick 10.0.0.1 --mode all
    """
    show_welcome()
    setup_logging(verbose)

    # Define mode configurations
    mode_configs = {
        "web": {
            "ports": "80,443,8080,8443",
            "aggressive": True,
            "web": True,
            "threads": 30,
        },
        "backdoor": {
            "ports": "31337,1337,4444,12345,27374",
            "aggressive": True,
            "backdoor": True,
            "threads": 20,
        },
        "all": {
            "ports": None,
            "aggressive": True,
            "threads": 50,
        },
    }

    if mode not in mode_configs:
        console.print(f"[red]❌ Invalid mode: {mode}. Use web, backdoor, or all[/red]")
        raise typer.Exit(1)

    config = mode_configs[mode]
    console.print(
        f"[cyan]⚡ Running quick {mode} scan on {target}...[/cyan]"
    )

    # Run full scan with preset config
    try:
        scanner = PortScanner(
            targets=[target],
            ports=parse_port_string(config["ports"]) if config["ports"] else None,
            threads=config["threads"],
            timeout=5,
            aggressive=config.get("aggressive", False),
            verbose=verbose,
        )

        with console.status("[bold cyan]🔍 Scanning...", spinner="dots"):
            results = asyncio.run(scanner.scan_all())

        console.print(
            f"[green]✅ Found {len(results)} open services[/green]"
        )

        # Show results summary
        for result in results[:10]:  # Show top 10
            console.print(
                f"  [yellow]{result.port}/tcp[/yellow] - [cyan]{result.service}[/cyan]"
            )

    except Exception as e:
        logger.error(f"Quick scan failed: {e}", exc_info=True)
        console.print(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """📌 Show Portscaneer version and system information."""
    console.print(
        Panel(
            "[bold cyan]Portscaneer v1.0.0[/bold cyan]\n"
            "Advanced Network Backdoor & Vulnerability Scanner\n\n"
            "[yellow]Python Version:[/yellow] 3.11+\n"
            "[yellow]License:[/yellow] MIT\n"
            "[yellow]Author:[/yellow] Security Team",
            title="About Portscaneer",
            border_style="cyan",
        )
    )


@app.command()
def help_vulnerabilities() -> None:
    """📚 Display common vulnerability types and exploitation methods."""
    console.print(
        Panel(
            "[bold cyan]Common Network Vulnerabilities[/bold cyan]\n\n"
            "[red]1. Open RDP (3389)[/red] - Brute force attacks, RansomWare\n"
            "[red]2. Open SMB (445)[/red] - EternalBlue, Ransomware, Data theft\n"
            "[red]3. Default SSH (22)[/red] - Dictionary attacks, lateral movement\n"
            "[red]4. Open Databases[/red] - Direct data breach, ransomware\n"
            "[red]5. Unencrypted HTTP[/red] - MITM attacks, credential theft\n"
            "[red]6. Known CVEs[/red] - Remote code execution, DoS\n"
            "[red]7. Backdoors[/red] - Full system compromise, persistent access\n"
            "[red]8. Webshells[/red] - Website defacement, malware distribution",
            title="Vulnerability Guide",
            border_style="red",
        )
    )


def main() -> None:
    """Entry point for CLI application."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
