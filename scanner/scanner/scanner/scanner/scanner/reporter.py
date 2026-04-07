#!/usr/bin/env python3
"""
Security Report Generator
Generates professional HTML, JSON, and PDF reports.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import asdict

logger = logging.getLogger(__name__)


class SecurityReporter:
    """Professional security report generator."""

    def __init__(self, output_dir: Path = Path("./reports")) -> None:
        """
        Initialize reporter.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"SecurityReporter initialized: output_dir={self.output_dir}")

    def generate_report(
        self,
        target: str,
        results: List,
        backdoors: List = None,
        vulnerabilities: List = None,
        format_type: str = "html",
    ) -> Path:
        """
        Generate security report in specified format.

        Args:
            target: Target that was scanned
            results: Scan results
            backdoors: Detected backdoors
            vulnerabilities: Detected vulnerabilities
            format_type: Report format (html, json, pdf, all)

        Returns:
            Path to generated report
        """
        backdoors = backdoors or []
        vulnerabilities = vulnerabilities or []

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"portscaneer_report_{target.replace('.', '_')}_{timestamp}"

        paths = []

        if format_type in ["html", "all"]:
            path = self._generate_html_report(
                base_filename, target, results, backdoors, vulnerabilities
            )
            paths.append(path)

        if format_type in ["json", "all"]:
            path = self._generate_json_report(
                base_filename, target, results, backdoors, vulnerabilities
            )
            paths.append(path)

        if format_type in ["pdf", "all"]:
            path = self._generate_pdf_report(
                base_filename, target, results, backdoors, vulnerabilities
            )
            paths.append(path)

        return paths[0] if paths else self.output_dir / f"{base_filename}.html"

    def _generate_html_report(
        self,
        filename: str,
        target: str,
        results: List,
        backdoors: List,
        vulnerabilities: List,
    ) -> Path:
        """Generate HTML report."""
        output_path = self.output_dir / f"{filename}.html"

        html_content = self._build_html(target, results, backdoors, vulnerabilities)

        with open(output_path, "w") as f:
            f.write(html_content)

        logger.info(f"HTML report saved: {output_path}")
        return output_path

    def _generate_json_report(
        self,
        filename: str,
        target: str,
        results: List,
        backdoors: List,
        vulnerabilities: List,
    ) -> Path:
        """Generate JSON report."""
        output_path = self.output_dir / f"{filename}.json"

        report_data = {
            "metadata": {
                "scanner": "Portscaneer",
                "version": "1.0.0",
                "scan_time": datetime.now().isoformat(),
                "target": target,
            },
            "summary": {
                "total_targets": len(results),
                "total_open_ports": sum(r.open_ports_count for r in results),
                "backdoors_detected": len(backdoors),
                "vulnerabilities_detected": len(vulnerabilities),
            },
            "scan_results": [self._serialize_result(r) for r in results],
            "backdoors": [self._serialize_backdoor(b) for b in backdoors],
            "vulnerabilities": [self._serialize_vulnerability(v) for v in vulnerabilities],
        }

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"JSON report saved: {output_path}")
        return output_path

    def _generate_pdf_report(
        self,
        filename: str,
        target: str,
        results: List,
        backdoors: List,
        vulnerabilities: List,
    ) -> Path:
        """Generate PDF report (simplified - uses HTML as fallback)."""
        # Note: Full PDF generation would require reportlab
        # For now, we generate a formatted text-based PDF content
        output_path = self.output_dir / f"{filename}.pdf"

        pdf_content = self._build_pdf_content(target, results, backdoors, vulnerabilities)

        with open(output_path, "w") as f:
            f.write(pdf_content)

        logger.info(f"PDF report saved: {output_path}")
        return output_path

    def _build_html(
        self,
        target: str,
        results: List,
        backdoors: List,
        vulnerabilities: List,
    ) -> str:
        """Build HTML report content."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_open = sum(r.open_ports_count for r in results)

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portscaneer Security Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .content {{
            padding: 40px;
        }}
        .section {{
            margin: 30px 0;
            padding: 20px;
            border-left: 5px solid #667eea;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .section h2 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.8em;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-card .label {{
            color: #666;
            margin-top: 10px;
        }}
        .severity-critical {{
            color: #dc3545;
            font-weight: bold;
        }}
        .severity-high {{
            color: #fd7e14;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #ffc107;
            font-weight: bold;
        }}
        .severity-low {{
            color: #28a745;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        table th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        table td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        table tr:hover {{
            background: #f5f5f5;
        }}
        .finding {{
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid #dc3545;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding.high {{
            border-left-color: #fd7e14;
        }}
        .finding.medium {{
            border-left-color: #ffc107;
        }}
        .finding h3 {{
            margin-bottom: 10px;
            color: #333;
        }}
        .exploitation {{
            background: #fff3cd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid #ffc107;
        }}
        .remediation {{
            background: #d4edda;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid #28a745;
        }}
        .remediation h4 {{
            color: #155724;
            margin-bottom: 10px;
        }}
        .remediation ol {{
            margin-left: 20px;
            color: #155724;
        }}
        .exploitation h4 {{
            color: #856404;
            margin-bottom: 10px;
        }}
        .exploitation ol {{
            margin-left: 20px;
            color: #856404;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 0.9em;
        }}
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Portscaneer Security Report</h1>
            <p>Advanced Network Vulnerability Assessment</p>
        </div>

        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2>📋 Executive Summary</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Date:</strong> {timestamp}</p>
                <p><strong>Scanner:</strong> Portscaneer v1.0.0</p>

                <div class="stats">
                    <div class="stat-card">
                        <div class="number">{total_open}</div>
                        <div class="label">Open Ports</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{len(backdoors)}</div>
                        <div class="label">Backdoors</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{len(vulnerabilities)}</div>
                        <div class="label">Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{len(results)}</div>
                        <div class="label">Hosts Scanned</div>
                    </div>
                </div>

                <p style="margin-top: 20px; color: #666;">
                    <strong>Risk Level:</strong>
                    <span class="severity-critical">CRITICAL</span> if backdoors found |
                    <span class="severity-high">HIGH</span> if multiple vulnerabilities found |
                    <span class="severity-medium">MEDIUM</span> if few vulnerabilities found
                </p>
            </div>

            <!-- Open Ports -->
            <div class="section">
                <h2>🔌 Open Ports & Services</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
"""

        for result in results:
            for service in result.services:
                if service.is_open:
                    html += f"""
                        <tr>
                            <td>{service.port}</td>
                            <td>{service.service}</td>
                            <td>{service.version or 'Unknown'}</td>
                            <td>{service.banner[:50] if service.banner else 'N/A'}</td>
                        </tr>
"""

        html += """
                    </tbody>
                </table>
            </div>
"""

        # Backdoors
        if backdoors:
            html += f"""
            <div class="section">
                <h2>🚨 Detected Backdoors ({len(backdoors)})</h2>
"""
            for bd in backdoors:
                html += f"""
                <div class="finding">
                    <h3>
                        Port {bd.port}: {bd.backdoor_type}
                        <span class="severity-{bd.severity.value}">[{bd.severity.value.upper()}]</span>
                    </h3>
                    <p><strong>Service:</strong> {bd.service}</p>
                    <p><strong>Indicators:</strong> {', '.join(bd.indicators)}</p>

                    <div class="exploitation">
                        <h4>⚔️  How It's Exploited:</h4>
                        <ol>
"""
                for step in bd.exploitation_steps[:5]:
                    html += f"<li>{step}</li>"
                html += """
                        </ol>
                    </div>

                    <div class="remediation">
                        <h4>🔒 Immediate Actions Required:</h4>
                        <ol>
                            <li>Isolate the affected system from the network immediately</li>
                            <li>Kill the suspicious process</li>
                            <li>Run comprehensive malware scan</li>
                            <li>Check system logs for unauthorized access</li>
                            <li>Consider full OS reinstall</li>
                        </ol>
                    </div>

                    <p style="margin-top: 15px;"><strong>Business Impact:</strong> {bd.business_impact}</p>
                </div>
"""
            html += """
            </div>
"""

        # Vulnerabilities
        if vulnerabilities:
            html += f"""
            <div class="section">
                <h2>🛡️ Detected Vulnerabilities ({len(vulnerabilities)})</h2>
"""
            for vuln in vulnerabilities:
                html += f"""
                <div class="finding {vuln.severity.value}">
                    <h3>
                        {vuln.vuln_type}
                        <span class="severity-{vuln.severity.value}">[{vuln.severity.value.upper()}]</span>
                    </h3>
                    <p><strong>Port:</strong> {vuln.port} | <strong>Service:</strong> {vuln.service}</p>
                    {f'<p><strong>CVE:</strong> {vuln.cve}</p>' if vuln.cve else ''}

                    <div class="exploitation">
                        <h4>⚔️  Exploitation Steps:</h4>
                        <ol>
"""
                for step in vuln.exploitation_method[:4]:
                    html += f"<li>{step}</li>"
                html += f"""
                        </ol>
                    </div>

                    <div class="remediation">
                        <h4>🔒 Remediation:</h4>
                        <p>{vuln.remediation}</p>
                    </div>

                    <p style="margin-top: 15px;"><strong>Business Impact:</strong> {vuln.business_impact}</p>
                </div>
"""
            html += """
            </div>
"""

        # Recommendations
        html += """
            <div class="section">
                <h2>✅ Recommended Actions</h2>
                <ol style="margin-left: 20px;">
                    <li><strong>Immediate:</strong> Address all CRITICAL findings within 24 hours</li>
                    <li><strong>Urgent:</strong> Patch HIGH severity vulnerabilities within 1 week</li>
                    <li><strong>Short-term:</strong> Implement network segmentation and access controls</li>
                    <li><strong>Medium-term:</strong> Deploy Web Application Firewall (WAF)</li>
                    <li><strong>Long-term:</strong> Implement continuous vulnerability scanning</li>
                    <li><strong>Always:</strong> Keep systems updated with latest security patches</li>
                    <li><strong>Defense:</strong> Implement intrusion detection/prevention systems</li>
                </ol>
            </div>

            <div class="section">
                <h2>⚖️ Legal & Ethical Notice</h2>
                <p>
                    This security assessment was conducted with proper authorization.
                    Unauthorized network scanning is illegal in most jurisdictions.
                    Use this tool only on systems you own or have explicit permission to test.
                </p>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Portscaneer v1.0.0 | Enterprise Security Scanning Tool</p>
            <p>For professional security assessments, contact your security team.</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _build_pdf_content(
        self,
        target: str,
        results: List,
        backdoors: List,
        vulnerabilities: List,
    ) -> str:
        """Build PDF content (text-based format)."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_open = sum(r.open_ports_count for r in results)

        pdf_content = f"""
================================================================================
                    PORTSCANEER SECURITY REPORT
================================================================================

TARGET: {target}
SCAN DATE: {timestamp}
SCANNER: Portscaneer v1.0.0

================================================================================
EXECUTIVE SUMMARY
================================================================================

Total Open Ports: {total_open}
Backdoors Detected: {len(backdoors)}
Vulnerabilities Found: {len(vulnerabilities)}
Hosts Scanned: {len(results)}

================================================================================
OPEN PORTS & SERVICES
================================================================================

"""
        for result in results:
            pdf_content += f"\n{result.target}:\n"
            for service in result.services:
                if service.is_open:
                    pdf_content += f"  {service.port}/tcp - {service.service} {service.version}\n"

        if backdoors:
            pdf_content += f"""
================================================================================
DETECTED BACKDOORS ({len(backdoors)})
================================================================================

"""
            for bd in backdoors:
                pdf_content += f"""
Port: {bd.port}
Backdoor Type: {bd.backdoor_type}
Severity: {bd.severity.value.upper()}
Confidence: {bd.confidence * 100:.0f}%
Indicators: {', '.join(bd.indicators)}

Business Impact: {bd.business_impact}

Exploitation Steps:
"""
                for i, step in enumerate(bd.exploitation_steps[:5], 1):
                    pdf_content += f"{i}. {step}\n"

        if vulnerabilities:
            pdf_content += f"""
================================================================================
DETECTED VULNERABILITIES ({len(vulnerabilities)})
================================================================================

"""
            for vuln in vulnerabilities:
                pdf_content += f"""
Type: {vuln.vuln_type}
Severity: {vuln.severity.value.upper()}
Port: {vuln.port}
Service: {vuln.service}
{f'CVE: {vuln.cve}' if vuln.cve else ''}

Remediation: {vuln.remediation}
Business Impact: {vuln.business_impact}

"""

        pdf_content += """
================================================================================
RECOMMENDATIONS
================================================================================

1. IMMEDIATE: Address all CRITICAL findings within 24 hours
2. URGENT: Patch HIGH severity vulnerabilities within 1 week
3. Implement network segmentation and access controls
4. Deploy Web Application Firewall (WAF)
5. Implement continuous vulnerability scanning
6. Keep systems updated with latest security patches
7. Implement intrusion detection/prevention systems

================================================================================
LEGAL NOTICE
================================================================================

This security assessment was conducted with proper authorization.
Unauthorized network scanning is illegal in most jurisdictions.
Use this tool only on systems you own or have explicit permission to test.

================================================================================
Generated by Portscaneer v1.0.0 | Enterprise Security Scanning Tool
================================================================================
"""
        return pdf_content

    @staticmethod
    def _serialize_result(result) -> Dict[str, Any]:
        """Serialize scan result to dictionary."""
        return {
            "target": result.target,
            "scan_time": result.scan_time.isoformat(),
            "scan_method": result.scan_method,
            "os_detected": result.os_detected,
            "open_ports_count": result.open_ports_count,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service": s.service,
                    "version": s.version,
                    "banner": s.banner,
                    "is_open": s.is_open,
                }
                for s in result.services
            ],
        }

    @staticmethod
    def _serialize_backdoor(backdoor) -> Dict[str, Any]:
        """Serialize backdoor detection to dictionary."""
        return {
            "port": backdoor.port,
            "service": backdoor.service,
            "backdoor_type": backdoor.backdoor_type,
            "severity": backdoor.severity.value,
            "confidence": backdoor.confidence,
            "indicators": backdoor.indicators,
            "business_impact": backdoor.business_impact,
        }

    @staticmethod
    def _serialize_vulnerability(vuln) -> Dict[str, Any]:
        """Serialize vulnerability to dictionary."""
        return {
            "port": vuln.port,
            "service": vuln.service,
            "type": vuln.vuln_type,
            "cve": vuln.cve,
            "severity": vuln.severity.value,
            "description": vuln.description,
            "remediation": vuln.remediation,
            "business_impact": vuln.business_impact,
        }
