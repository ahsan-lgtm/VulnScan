#!/usr/bin/env python3
import sys
import os
import argparse
from colorama import Fore, Style

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vulnscanner.utils.helpers import (
    BANNER, INFO_ICON, OK_ICON, VULN_ICON, WARN_ICON, SEPARATOR,
    validate_ip_or_domain, resolve_target, timestamp
)
from vulnscanner.scanner.network import NetworkScanner
from vulnscanner.scanner.web_scanner import WebScanner
from vulnscanner.scanner.ssl_scanner import SSLScanner
from vulnscanner.db.cve_lookup import CVEDatabase
from vulnscanner.reporter.report import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description="Advanced Vulnerability Analysis Tool - Cyber Security Project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python main.py example.com
  python main.py 192.168.1.1 --web --ssl --all-reports
  python main.py example.com --ports 21,22,80,443 --threads 200
  python main.py example.com --ssl-only
  python main.py example.com --web-only --xss --sqli
        """
    )
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("--ports", help="Comma-separated port list (e.g., 21,22,80,443)")
    parser.add_argument("--threads", type=int, default=150, help="Scan threads (default: 150)")
    parser.add_argument("--timeout", type=int, default=2, help="Socket timeout in seconds (default: 2)")

    scan_group = parser.add_argument_group("Scan Modules")
    scan_group.add_argument("--no-network", action="store_true", help="Skip network port scan")
    scan_group.add_argument("--web", action="store_true", help="Enable web vulnerability scanning")
    scan_group.add_argument("--ssl", action="store_true", help="Enable SSL/TLS scanning")
    scan_group.add_argument("--ssl-only", action="store_true", help="Run SSL/TLS scan only")
    scan_group.add_argument("--web-only", action="store_true", help="Run web scan only")

    report_group = parser.add_argument_group("Reports")
    report_group.add_argument("--json", action="store_true", help="Save JSON report")
    report_group.add_argument("--txt", action="store_true", help="Save TXT report")
    report_group.add_argument("--html", action="store_true", help="Save HTML report")
    report_group.add_argument("--all-reports", action="store_true", help="Generate all report formats")

    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    target_type = validate_ip_or_domain(args.target)
    if not target_type:
        print(f"{VULN_ICON} {Fore.RED}Invalid target: {args.target}{Style.RESET_ALL}")
        print(f"{INFO_ICON} Enter a valid IP address or domain name")
        sys.exit(1)

    resolved = resolve_target(args.target)
    if not resolved and target_type == "domain":
        print(f"{WARN_ICON} {Fore.YELLOW}Could not resolve domain: {args.target}{Style.RESET_ALL}")
    else:
        print(f"{INFO_ICON} Target resolved to: {Fore.CYAN}{resolved}{Style.RESET_ALL}")

    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"{VULN_ICON} {Fore.RED}Invalid port list. Use comma-separated numbers.{Style.RESET_ALL}")
            sys.exit(1)

    all_results = {}

    run_network = not args.no_network and not args.ssl_only and not args.web_only
    run_web = args.web or args.web_only
    run_ssl = args.ssl or args.ssl_only

    # Default: if no specific module selected, run network scan + CVE
    if not run_network and not run_web and not run_ssl:
        run_network = True

    if run_network:
        scanner = NetworkScanner(
            target=args.target,
            ports=ports,
            timeout=args.timeout,
            threads=args.threads
        )
        all_results["network"] = scanner.scan()

        cve_db = CVEDatabase()
        all_results["cve"] = cve_db.scan_from_banners(all_results["network"])

    if run_web:
        print(f"\n{WARN_ICON} {Fore.YELLOW}Web scanner will make HTTP requests to the target{Style.RESET_ALL}")
        web = WebScanner(target=args.target, ssl=True)
        all_results["web"] = web.scan()

        if not run_network:
            cve_db = CVEDatabase()
            all_results["cve"] = cve_db.scan_from_banners(all_results["web"])

    if run_ssl:
        ssl = SSLScanner(target=args.target)
        all_results["ssl"] = ssl.scan()

    # If only CVE was from web, try SSL as well
    if run_ssl and "cve" in all_results and "network" not in all_results:
        pass

    print(f"\n{SEPARATOR}")
    print(f"{INFO_ICON} {Fore.GREEN}Scan Complete{Style.RESET_ALL}")
    print(f"{SEPARATOR}")

    report = ReportGenerator(target=args.target, results=all_results)
    report.generate_summary()

    if args.all_reports:
        paths = report.save_all()
        print(f"\n{OK_ICON} Reports generated in '{Fore.CYAN}reports/{Style.RESET_ALL}' directory")
    else:
        if args.json:
            report.save_json()
        if args.txt:
            report.save_txt()
        if args.html:
            report.save_html()

    if not any([args.json, args.txt, args.html, args.all_reports]):
        print(f"\n{INFO_ICON} Use --json, --txt, --html, or --all-reports to save reports")

    print(f"\n{OK_ICON} {Fore.GREEN}Analysis finished at {timestamp()}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{VULN_ICON} {Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{VULN_ICON} {Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
