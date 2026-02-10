"""
Domain Reputation Analyzer

Performs various checks on a domain to assess its reputation.
"""

import socket
import ssl
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from urllib.parse import urlparse


@dataclass
class DomainReport:
    """
    Complete reputation report for a domain.
    
    Each field represents one check we performed.
    The risk_score summarizes overall suspiciousness.
    """
    domain: str
    
    # DNS checks
    ip_addresses: List[str] = field(default_factory=list)
    dns_resolved: bool = False
    
    # SSL checks
    has_ssl: bool = False
    ssl_issuer: str = ""
    ssl_expiry: Optional[datetime] = None
    ssl_days_remaining: int = 0
    
    # Domain characteristics
    domain_length: int = 0
    has_suspicious_keywords: bool = False
    suspicious_keywords_found: List[str] = field(default_factory=list)
    has_excessive_subdomains: bool = False
    subdomain_count: int = 0
    
    # Risk assessment
    risk_factors: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100, higher = more suspicious
    risk_level: str = "unknown"  # low, medium, high, critical


class DomainAnalyzer:
    """
    Analyzes domains for suspicious characteristics.
    
    This mimics what threat intelligence platforms do when
    you submit a domain for analysis.
    """
    
    # Keywords commonly found in phishing domains
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'secure', 'account',
        'update', 'confirm', 'bank', 'paypal', 'microsoft',
        'apple', 'google', 'amazon', 'netflix', 'support',
        'help', 'service', 'alert', 'suspend', 'locked',
        'password', 'credential', 'wallet', 'crypto'
    ]
    
    def __init__(self, timeout: int = 5):
        """
        Initialize the analyzer.
        
        Args:
            timeout: Seconds to wait for network operations
        """
        self.timeout = timeout
    
    def extract_domain(self, input_str: str) -> str:
        """
        Extract clean domain from URL or domain string.
        
        Handles inputs like:
        - https://example.com/path
        - http://sub.example.com
        - example.com
        - www.example.com
        """
        # Remove whitespace
        input_str = input_str.strip()
        
        # If it looks like a URL, parse it
        if '://' in input_str:
            parsed = urlparse(input_str)
            domain = parsed.netloc
        else:
            # Remove any path components
            domain = input_str.split('/')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Remove www. prefix for consistency
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain.lower()
    
    def check_dns(self, domain: str) -> List[str]:
        """
        Resolve domain to IP addresses.
        
        A domain that doesn't resolve could be:
        - Typosquatting that's not set up yet
        - Taken down by hosting provider
        - Just broken
        """
        try:
            # gethostbyname_ex returns (hostname, aliases, ip_list)
            _, _, ip_list = socket.gethostbyname_ex(domain)
            return ip_list
        except socket.gaierror:
            # Domain doesn't resolve
            return []
        except socket.timeout:
            return []
    
    def check_ssl(self, domain: str) -> Dict:
        """
        Check SSL certificate details.
        
        Phishing sites often have:
        - No SSL at all
        - Self-signed certificates
        - Recently issued certificates
        - Certificates about to expire
        """
        result = {
            'has_ssl': False,
            'issuer': '',
            'expiry': None,
            'days_remaining': 0,
            'error': None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    result['has_ssl'] = True
                    
                    # Extract issuer
                    issuer_parts = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer_parts.get('organizationName', 'Unknown')
                    
                    # Extract expiry
                    expiry_str = cert.get('notAfter', '')
                    if expiry_str:
                        # Format: 'Dec 31 23:59:59 2025 GMT'
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        result['expiry'] = expiry
                        result['days_remaining'] = (expiry - datetime.now()).days
                        
        except ssl.SSLCertVerificationError as e:
            result['error'] = f"SSL verification failed: {e}"
        except ssl.SSLError as e:
            result['error'] = f"SSL error: {e}"
        except socket.timeout:
            result['error'] = "Connection timeout"
        except ConnectionRefusedError:
            result['error'] = "Connection refused (no HTTPS)"
        except socket.gaierror:
            result['error'] = "Domain does not resolve"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_suspicious_keywords(self, domain: str) -> List[str]:
        """
        Check if domain contains phishing-related keywords.
        
        Example: 'secure-paypal-login.com' contains 'secure', 'paypal', 'login'
        """
        found = []
        domain_lower = domain.lower()
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in domain_lower:
                found.append(keyword)
        
        return found
    
    def count_subdomains(self, domain: str) -> int:
        """
        Count subdomain levels.
        
        Excessive subdomains can indicate phishing:
        'login.secure.account.verify.example.com' = 4 subdomains
        """
        parts = domain.split('.')
        # Subtract 2 for the main domain and TLD
        # e.g., 'sub.example.com' = 3 parts, 1 subdomain
        return max(0, len(parts) - 2)
    
    def calculate_risk_score(self, report: DomainReport) -> None:
        """
        Calculate overall risk score based on all factors.
        
        This is simplified - real threat intel platforms use
        machine learning and more data sources.
        """
        score = 0
        factors = []
        
        # DNS checks
        if not report.dns_resolved:
            score += 20
            factors.append("Domain does not resolve")
        
        # SSL checks
        if not report.has_ssl:
            score += 15
            factors.append("No SSL certificate")
        elif report.ssl_days_remaining < 30:
            score += 10
            factors.append(f"SSL expires in {report.ssl_days_remaining} days")
        
        # Suspicious keywords
        if report.has_suspicious_keywords:
            keyword_score = min(30, len(report.suspicious_keywords_found) * 10)
            score += keyword_score
            factors.append(f"Suspicious keywords: {', '.join(report.suspicious_keywords_found)}")
        
        # Domain length (very long domains are suspicious)
        if report.domain_length > 30:
            score += 10
            factors.append(f"Unusually long domain ({report.domain_length} chars)")
        
        # Excessive subdomains
        if report.has_excessive_subdomains:
            score += 15
            factors.append(f"Excessive subdomains ({report.subdomain_count})")
        
        # Cap at 100
        score = min(100, score)
        
        # Determine risk level
        if score >= 70:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"
        
        report.risk_score = score
        report.risk_level = level
        report.risk_factors = factors
    
    def analyze(self, domain_input: str) -> DomainReport:
        """
        Perform complete analysis on a domain.
        
        Args:
            domain_input: Domain name or URL to analyze
            
        Returns:
            DomainReport with all findings
        """
        # Clean the input
        domain = self.extract_domain(domain_input)
        
        # Initialize report
        report = DomainReport(domain=domain)
        
        # DNS check
        ips = self.check_dns(domain)
        report.ip_addresses = ips
        report.dns_resolved = len(ips) > 0
        
        # SSL check
        ssl_info = self.check_ssl(domain)
        report.has_ssl = ssl_info['has_ssl']
        report.ssl_issuer = ssl_info['issuer']
        report.ssl_expiry = ssl_info['expiry']
        report.ssl_days_remaining = ssl_info['days_remaining']
        
        # Domain characteristics
        report.domain_length = len(domain)
        
        keywords = self.check_suspicious_keywords(domain)
        report.has_suspicious_keywords = len(keywords) > 0
        report.suspicious_keywords_found = keywords
        
        subdomain_count = self.count_subdomains(domain)
        report.subdomain_count = subdomain_count
        report.has_excessive_subdomains = subdomain_count > 2
        
        # Calculate risk
        self.calculate_risk_score(report)
        
        return report


def create_analyzer(timeout: int = 5) -> DomainAnalyzer:
    """Factory function to create an analyzer."""
    return DomainAnalyzer(timeout=timeout)
