#!/usr/bin/env python3
"""
Domain Reputation Checker

Analyzes domains for suspicious characteristics.

Usage:
    python3 checker.py example.com
    python3 checker.py https://suspicious-site.com/path
    python3 checker.py -f domains.txt
    python3 checker.py example.com --format json

Author: Jason Klutts
Website: jasonklutts.com
"""

import argparse
import sys

from lib.analyzer import create_analyzer
from lib.reporter import create_report


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Check domain reputation and identify suspicious characteristics"
    )
    
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain or URL to analyze"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="File containing domains (one per line)"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout for network operations in seconds (default: 5)"
    )
    
    return parser.parse_args()


def analyze_domain(domain: str, analyzer, output_format: str) -> None:
    """Analyze a single domain and print results."""
    result = analyzer.analyze(domain)
    reporter = create_report(result)
    
    if output_format == "json":
        print(reporter.generate_json_report())
    else:
        reporter.generate_text_report()


def main():
    args = parse_arguments()
    
    # Must provide either domain or file
    if not args.domain and not args.file:
        print("Error: Provide a domain or use -f with a file", file=sys.stderr)
        return 1
    
    analyzer = create_analyzer(timeout=args.timeout)
    
    if args.file:
        # Analyze multiple domains from file
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1
        
        for domain in domains:
            analyze_domain(domain, analyzer, args.format)
    else:
        # Single domain
        analyze_domain(args.domain, analyzer, args.format)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
