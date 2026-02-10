# Domain Reputation Checker

A Python tool that analyzes domains for suspicious characteristics commonly associated with phishing and malicious sites.

## Purpose

SOC analysts frequently need to quickly assess whether a domain is suspicious when:
- Investigating phishing emails
- Reviewing firewall/proxy logs
- Triaging security alerts

This tool automates those initial checks.

## Features

- DNS resolution check
- SSL certificate validation
- Suspicious keyword detection
- Domain characteristic analysis
- Risk scoring (0-100)
- Text and JSON output formats

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Installation
```bash
git clone https://github.com/jasonklutts/domain-reputation-checker.git
cd domain-reputation-checker
```

## Usage
```bash
# Check a single domain
python3 checker.py example.com

# Check a URL (extracts domain automatically)
python3 checker.py https://suspicious-site.com/path

# Check multiple domains from file
python3 checker.py -f domains.txt

# JSON output for SIEM ingestion
python3 checker.py example.com --format json
```

## Risk Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 0-29 | Low | Likely legitimate |
| 30-49 | Medium | Some suspicious traits |
| 50-69 | High | Multiple red flags |
| 70-100 | Critical | Likely malicious |

## Checks Performed

| Check | Risk Indicator |
|-------|----------------|
| DNS resolution fails | +20 points |
| No SSL certificate | +15 points |
| SSL expiring soon | +10 points |
| Suspicious keywords | +10 per keyword |
| Domain over 30 chars | +10 points |
| Excessive subdomains | +15 points |

## Author

Jason Klutts - [jasonklutts.com](https://jasonklutts.com)

## License

MIT License
