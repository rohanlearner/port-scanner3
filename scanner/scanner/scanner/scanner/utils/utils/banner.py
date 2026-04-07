#!/usr/bin/env python3
"""
Banner and Display Utilities
Shows welcome banner, legal disclaimers, and user authorization.
"""

from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table


def display_banner(console: Console) -> None:
    """Display Portscaneer banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║                    🔐 PORTSCANEER v1.0.0 🔐                  ║
    ║                                                               ║
    ║         Advanced Network Backdoor & Vulnerability Scanner     ║
    ║               Business Website Security Assessment            ║
    ║                                                               ║
    ║              [ Professional Ethical Hacking Tool ]            ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="cyan")


def display_disclaimer(console: Console) -> None:
    """Display legal disclaimer and ethical warning."""
    disclaimer_text = """
[bold red]⚠️  LEGAL DISCLAIMER & ETHICAL WARNING ⚠️[/bold red]

[bold yellow]UNAUTHORIZED ACCESS IS ILLEGAL[/bold yellow]

This tool is designed for authorized security testing only. Unauthorized
network scanning, port scanning, or any attempt to access computer systems
without explicit permission is ILLEGAL under:

  • Computer Fraud and Abuse Act (CFAA) - USA
  • Computer Misuse Act - UK
  • German Criminal Code (StGB § 202)
  • Similar laws in most jurisdictions

[bold red]CRIMINAL LIABILITY:[/bold red]
  ✗ Fines up to $250,000+
  ✗ Prison sentences up to 10+ years
  ✗ Civil lawsuits and damages
  ✗ Permanent criminal record

[bold red]CIVIL LIABILITY:[/bold red]
  ✗ Damages for unauthorized access
  ✗ Business interruption costs
  ✗ Reputation and data loss claims

[bold green]AUTHORIZED USE ONLY:[/bold green]
  ✓ Your own infrastructure
  ✓ With explicit written permission from the system owner
  ✓ As part of an authorized penetration testing engagement
  ✓ In controlled lab environments

[bold yellow]By proceeding, you confirm:[/bold yellow]
  ☑ You have authorization to scan the target systems
  ☑ You understand the legal consequences
  ☑ You take full responsibility for your actions
  ☑ You will use this tool ethically and legally

[bold cyan]RESPONSIBLE DISCLOSURE:[/bold cyan]
If you discover vulnerabilities, please:
  1. Document findings securely
  2. Report to affected organization privately
  3. Give reasonable time to patch (typically 90 days)
  4. Never publicly disclose before patch is available
  5. Follow responsible disclosure guidelines
"""
    console.print(Panel(disclaimer_text, border_style="red", title="LEGAL & ETHICAL NOTICE"))


def get_user_consent(console: Console) -> bool:
    """
    Get explicit user consent to proceed.

    Args:
        console: Rich console instance

    Returns:
        True if user accepts, False otherwise
    """
    display_disclaimer(console)

    console.print()
    user_input = console.input(
        "[bold yellow]Do you confirm you have AUTHORIZATION to scan these systems? "
        "[Type 'yes' to continue]: [/bold yellow]"
    ).strip().lower()

    if user_input == "yes":
        console.print("[green]✅ Authorization confirmed. Proceeding with scan...[/green]")
        return True
    else:
        return False


def display_scan_results_summary(
    console: Console,
    total_ports: int,
    open_ports: int,
    backdoors: int,
    vulnerabilities: int,
) -> None:
    """Display scan results summary table."""
    table = Table(title="Scan Results Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="yellow")

    table.add_row("Total Ports Scanned", str(total_ports))
    table.add_row("Open Ports Found", f"[bold green]{open_ports}[/bold green]")
    table.add_row("Backdoors Detected", f"[bold red]{backdoors}[/bold red]" if backdoors > 0 else str(backdoors))
    table.add_row(
        "Vulnerabilities Found",
        f"[bold red]{vulnerabilities}[/bold red]" if vulnerabilities > 0 else str(vulnerabilities)
    )

    console.print(table)


def display_findings_table(
    console: Console,
    services: list,
    title: str = "Open Services"
) -> None:
    """Display findings in a formatted table."""
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Threat Level", justify="center")

    for service in services[:20]:  # Limit to 20 rows
        threat = "[bold red]HIGH[/bold red]" if service.port in [
            3389, 445, 3306, 27017, 6379
        ] else "[yellow]MEDIUM[/yellow]"
        table.add_row(
            str(service.port),
            service.service or "unknown",
            service.version or "unknown",
            threat
        )

    console.print(table)


def display_progress_bar(console: Console, current: int, total: int, label: str = "Progress") -> None:
    """Display progress bar."""
    percentage = (current / total) * 100
    bar_length = 30
    filled = int(bar_length * current / total)
    bar = "█" * filled + "░" * (bar_length - filled)
    console.print(f"[cyan]{label}[/cyan]: [{bar}] {percentage:.1f}% ({current}/{total})")
