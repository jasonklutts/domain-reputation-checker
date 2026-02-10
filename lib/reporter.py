"""
Report Generator for Domain Reputation Checker

Formats domain analysis results into readable reports.
"""

import json
from datetime import datetime
from typing import TextIO
import sys

from .analyzer import DomainReport


class ReportGenerator:
    """
    Generates reports from domain analysis results.
    """
    
    def __init__(self, report: DomainReport):
        self.report = report
    
    def _risk_indicator(self, level: str) -> str:
        """Return visual indicator for risk level."""
        indicators = {
            'low': '[LOW]',
            'medium': '[MEDIUM]',
            'high': '[HIGH]',
            'critical': '[CRITICAL]'
        }
        return indicators.get(level, '[UNKNOWN]')
    
    def generate_text_report(self, output: TextIO = sys.stdout) -> None:
        """Generate human-readable text report."""
        r = self.report
        
        output.write("\n")
        output.write("=" * 50 + "\n")
        output.write("   DOMAIN REPUTATION REPORT\n")
        output.write("=" * 50 + "\n\n")
        
        output.write(f"Domain:    {r.domain}\n")
        output.write(f"Analyzed:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Risk summary at top
        output.write("-" * 30 + "\n")
        output.write("RISK ASSESSMENT\n")
        output.write("-" * 30 + "\n")
        output.write(f"Risk Score: {r.risk_score}/100\n")
        output.write(f"Risk Level: {self._risk_indicator(r.risk_level)}\n\n")
        
        if r.risk_factors:
            output.write("Risk Factors:\n")
            for factor in r.risk_factors:
                output.write(f"  - {factor}\n")
            output.write("\n")
        
        # DNS info
        output.write("-" * 30 + "\n")
        output.write("DNS RESOLUTION\n")
        output.write("-" * 30 + "\n")
        if r.dns_resolved:
            output.write("Status: Resolved\n")
            output.write(f"IPs:    {', '.join(r.ip_addresses)}\n")
        else:
            output.write("Status: FAILED - Domain does not resolve\n")
        output.write("\n")
        
        # SSL info
        output.write("-" * 30 + "\n")
        output.write("SSL CERTIFICATE\n")
        output.write("-" * 30 + "\n")
        if r.has_ssl:
            output.write("Status:  Valid\n")
            output.write(f"Issuer:  {r.ssl_issuer}\n")
            if r.ssl_expiry:
                output.write(f"Expires: {r.ssl_expiry.strftime('%Y-%m-%d')}\n")
                output.write(f"Days remaining: {r.ssl_days_remaining}\n")
        else:
            output.write("Status: No SSL certificate\n")
        output.write("\n")
        
        # Domain characteristics
        output.write("-" * 30 + "\n")
        output.write("DOMAIN CHARACTERISTICS\n")
        output.write("-" * 30 + "\n")
        output.write(f"Length: {r.domain_length} characters\n")
        output.write(f"Subdomains: {r.subdomain_count}\n")
        
        if r.suspicious_keywords_found:
            output.write(f"Suspicious keywords: {', '.join(r.suspicious_keywords_found)}\n")
        else:
            output.write("Suspicious keywords: None\n")
        
        output.write("\n" + "=" * 50 + "\n")
    
    def generate_json_report(self) -> str:
        """Generate JSON report for SIEM ingestion."""
        r = self.report
        
        report = {
            "domain": r.domain,
            "analyzed_at": datetime.now().isoformat(),
            "risk": {
                "score": r.risk_score,
                "level": r.risk_level,
                "factors": r.risk_factors
            },
            "dns": {
                "resolved": r.dns_resolved,
                "ip_addresses": r.ip_addresses
            },
            "ssl": {
                "has_ssl": r.has_ssl,
                "issuer": r.ssl_issuer,
                "expiry": r.ssl_expiry.isoformat() if r.ssl_expiry else None,
                "days_remaining": r.ssl_days_remaining
            },
            "characteristics": {
                "length": r.domain_length,
                "subdomain_count": r.subdomain_count,
                "suspicious_keywords": r.suspicious_keywords_found
            }
        }
        
        return json.dumps(report, indent=2)


def create_report(report: DomainReport) -> ReportGenerator:
    """Factory function to create a report generator."""
    return ReportGenerator(report)
