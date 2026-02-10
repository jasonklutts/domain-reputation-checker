# Domain Reputation Checker

A Python tool that analyzes domains for suspicious characteristics commonly associated with phishing and malicious sites. Available as both a CLI tool and web interface.

## Live Demo

Try it now: [jasonklutts.com/lab/domain-checker](https://jasonklutts.com/lab/domain-checker)

## Purpose

SOC analysts frequently need to quickly assess whether a domain is suspicious when:
- Investigating phishing emails
- Reviewing firewall/proxy logs
- Triaging security alerts

This tool automates those initial checks.

## Features

- **WHOIS Lookup** - Domain age, registrar, creation/expiration dates
- **DNS Resolution** - Verifies domain resolves and lists IP addresses
- **SSL Certificate** - Validates HTTPS and certificate details
- **Security Headers** - Checks for CSP, HSTS, X-Frame-Options, etc.
- **Suspicious Keywords** - Detects phishing-related terms
- **Risk Scoring** - 0-100 score with risk level classification

## Why Each Check Matters

| Check | Why It Matters |
|-------|----------------|
| WHOIS/Domain Age | Phishing domains are often days old |
| DNS Resolution | Failed resolution may indicate inactive typosquatting |
| SSL Certificate | Missing/expiring SSL suggests hasty attack setup |
| Security Headers | Legitimate sites implement protections; phishing sites don't |
| Suspicious Keywords | Terms like "login," "verify," "secure" are phishing indicators |
| Domain Length | Excessively long domains hide malicious intent |

## Requirements

- Python 3.8+
- python-whois (`pip install python-whois`)
- Flask (for web interface)

## Installation
```bash
git clone https://github.com/jasonklutts/domain-reputation-checker.git
cd domain-reputation-checker
pip install python-whois flask
```

## Usage

### Command Line
```bash
# Check a single domain
python3 checker.py example.com

# Check a URL (extracts domain automatically)
python3 checker.py https://suspicious-site.com/path

# JSON output for SIEM ingestion
python3 checker.py example.com --format json
```

### Web Interface
```bash
python3 app.py
# Open http://localhost:5001
```

## Risk Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 0-29 | Low | Likely legitimate |
| 30-49 | Medium | Some suspicious traits |
| 50-69 | High | Multiple red flags |
| 70-100 | Critical | Likely malicious |

## Author

Jason Klutts - [jasonklutts.com](https://jasonklutts.com)

## License

MIT License
