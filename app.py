#!/usr/bin/env python3
"""
Domain Reputation Checker - Web Interface
"""

from flask import Flask, render_template, request, jsonify
import socket
import ssl
import whois
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)


class DomainAnalyzer:
    """Analyzes domains for suspicious characteristics."""
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'secure', 'account',
        'update', 'confirm', 'bank', 'paypal', 'microsoft',
        'apple', 'google', 'amazon', 'netflix', 'support',
        'help', 'service', 'alert', 'suspend', 'locked',
        'password', 'credential', 'wallet', 'crypto'
    ]
    
    # Security headers that should be present
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy'
    ]
    
    def __init__(self, timeout=5):
        self.timeout = timeout
    
    def extract_domain(self, input_str):
        input_str = input_str.strip()
        if '://' in input_str:
            parsed = urlparse(input_str)
            domain = parsed.netloc
        else:
            domain = input_str.split('/')[0]
        domain = domain.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower()
    
    def check_dns(self, domain):
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
            return ip_list
        except:
            return []
    
    def check_ssl(self, domain):
        result = {
            'has_ssl': False,
            'issuer': '',
            'expiry': None,
            'days_remaining': 0
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result['has_ssl'] = True
                    issuer_parts = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer_parts.get('organizationName', 'Unknown')
                    expiry_str = cert.get('notAfter', '')
                    if expiry_str:
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        result['expiry'] = expiry.strftime('%Y-%m-%d')
                        result['days_remaining'] = (expiry - datetime.now()).days
        except:
            pass
        return result
    
    def check_whois(self, domain):
        """Check WHOIS data for domain age and registrar info."""
        result = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_age_days': None,
            'error': None
        }
        try:
            w = whois.whois(domain)
            
            if w.registrar:
                result['registrar'] = w.registrar
            
            # Handle creation_date (can be list or single value)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                result['creation_date'] = creation.strftime('%Y-%m-%d')
                result['domain_age_days'] = (datetime.now() - creation).days
            
            # Handle expiration_date
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if expiration:
                result['expiration_date'] = expiration.strftime('%Y-%m-%d')
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_security_headers(self, domain):
        """Check for presence of security headers."""
        result = {
            'headers_present': [],
            'headers_missing': [],
            'score': 0,
            'error': None
        }
        try:
            url = f'https://{domain}'
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                for header in self.SECURITY_HEADERS:
                    if header.lower() in headers:
                        result['headers_present'].append(header)
                    else:
                        result['headers_missing'].append(header)
                
                # Score out of 100
                result['score'] = int((len(result['headers_present']) / len(self.SECURITY_HEADERS)) * 100)
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_suspicious_keywords(self, domain):
        found = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in domain.lower():
                found.append(keyword)
        return found
    
    def count_subdomains(self, domain):
        parts = domain.split('.')
        return max(0, len(parts) - 2)
    
    def analyze(self, domain_input):
        domain = self.extract_domain(domain_input)
        
        # DNS check
        ips = self.check_dns(domain)
        dns_resolved = len(ips) > 0
        
        # SSL check
        ssl_info = self.check_ssl(domain)
        
        # WHOIS check
        whois_info = self.check_whois(domain)
        
        # Security headers check
        headers_info = self.check_security_headers(domain)
        
        # Domain characteristics
        keywords = self.check_suspicious_keywords(domain)
        subdomain_count = self.count_subdomains(domain)
        
        # Calculate risk score
        score = 0
        factors = []
        
        if not dns_resolved:
            score += 20
            factors.append("Domain does not resolve")
        
        if not ssl_info['has_ssl']:
            score += 15
            factors.append("No SSL certificate")
        elif ssl_info['days_remaining'] < 30:
            score += 10
            factors.append(f"SSL expires in {ssl_info['days_remaining']} days")
        
        if keywords:
            score += min(30, len(keywords) * 10)
            factors.append(f"Suspicious keywords: {', '.join(keywords)}")
        
        if len(domain) > 30:
            score += 10
            factors.append(f"Long domain ({len(domain)} chars)")
        
        if subdomain_count > 2:
            score += 15
            factors.append(f"Excessive subdomains ({subdomain_count})")
        
        # WHOIS-based risk factors
        if whois_info['domain_age_days'] is not None:
            if whois_info['domain_age_days'] < 30:
                score += 25
                factors.append(f"Domain is very new ({whois_info['domain_age_days']} days old)")
            elif whois_info['domain_age_days'] < 90:
                score += 15
                factors.append(f"Domain is relatively new ({whois_info['domain_age_days']} days old)")
        
        # Security headers risk
        if headers_info['score'] < 50 and not headers_info['error']:
            score += 10
            factors.append(f"Poor security headers ({headers_info['score']}% present)")
        
        score = min(100, score)
        
        if score >= 70:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"
        
        return {
            'domain': domain,
            'risk_score': score,
            'risk_level': level,
            'risk_factors': factors,
            'dns': {
                'resolved': dns_resolved,
                'ip_addresses': ips
            },
            'ssl': ssl_info,
            'whois': whois_info,
            'security_headers': headers_info,
            'characteristics': {
                'length': len(domain),
                'subdomain_count': subdomain_count,
                'suspicious_keywords': keywords
            }
        }


analyzer = DomainAnalyzer()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    result = analyzer.analyze(domain)
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
