# Advanced Vulnerability Analysis Tool

Python-based modular security scanner for network reconnaissance, web application testing, SSL/TLS analysis, and CVE correlation.

![Image Alt[](](https://github.com/ahsan-lgtm/VulnScan/blob/48e0d7a26c91c8abe9ad6a13d6c248378c793196/Screenshot%202026-06-03%20234922.png)

## Features

| Module | Description |
|--------|-------------|
| **Network Scan** | Port scanning (150-thread), banner grabbing, service fingerprinting, automatic vulnerability detection (EternalBlue, BlueKeep, vsFTPd backdoor, etc.) |
| **Web Scan** | XSS, SQLi, CORS misconfiguration, missing security headers, directory listing, open redirect, CSRF analysis, sensitive endpoint enumeration |
| **SSL/TLS Scan** | Certificate validation, weak cipher detection, protocol checks (SSLv2/3, TLS), expiry monitoring, self-signed/wildcard alerts |
| **CVE Engine** | 30+ built-in CVE signatures with version-based matching and remediation recommendations |
| **Reporting** | HTML dashboard, JSON export, plain-text reports with risk scoring |

## Quick Start

```bash
pip install requests colorama packaging
python main.py example.com

# Full scan
python main.py example.com --web --ssl --all-reports

# Custom ports
python main.py 192.168.1.1 --ports 21,22,80,443,8080,3306

# Targeted scans
python main.py example.com --web-only
python main.py example.com --ssl-only
```

## Options

```
positional arguments:
  target              Target IP address or domain name

scan modules:
  --no-network        Skip network port scan
  --web               Enable web vulnerability scanning
  --ssl               Enable SSL/TLS scanning
  --ssl-only          Run SSL/TLS scan only
  --web-only          Run web scan only

performance:
  --ports PORTS       Comma-separated port list
  --threads N         Scan threads (default: 150)
  --timeout SEC       Socket timeout (default: 2s)

reports:
  --json              Save JSON report
  --txt               Save TXT report
  --html              Save HTML report
  --all-reports       Generate all report formats
```

## Output

Reports are saved to `./reports/` directory:
- `report_<target>_<timestamp>.html` — Interactive dashboard
- `report_<target>_<timestamp>.json` — Machine-readable data
- `report_<target>_<timestamp>.txt` — Plain-text summary

## Requirements

- Python 3.8+
- requests
- colorama
- packaging

## Project Structure

```
├── main.py                    # CLI entry point
├── requirements.txt
└── vulnscanner/
    ├── scanner/
    │   ├── network.py         # Port scanning + service detection
    │   ├── web_scanner.py     # Web vulnerability checks
    │   └── ssl_scanner.py     # SSL/TLS certificate analysis
    ├── db/
    │   └── cve_lookup.py      # CVE signature database
    ├── reporter/
    │   └── report.py          # HTML/JSON/TXT report generation
    └── utils/
        └── helpers.py         # Colors, banners, utilities
```

## License

MIT
