# TechackZ 🛡️

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

TechackZ is an advanced, asynchronous web technology detection and vulnerability assessment tool. It combines multiple technology detection methods (Wappalyzer, custom fingerprinting, and BuiltWith) with Nuclei's security scanning capabilities, enriching findings with data from NVD, OSV, ExploitDB, Vulners, and Metasploit module lookups.

## 🚀 Features

- **Asynchronous Scanning:** High-speed, concurrent scanning of multiple targets and enrichment lookups using `asyncio` and `aiohttp`.
- **Comprehensive Technology Stack Detection:**
    - **Wappalyzer Integration:** Leverages Wappalyzer to identify web technologies, frameworks, and versions.
    - **Custom Fingerprinting:** Advanced pattern-based detection for 25+ technologies including CMS, web servers, frameworks, CDNs, WAFs, and development tools.
    - **BuiltWith API Support:** Optional integration with BuiltWith API for enhanced commercial-grade detection.
    - **Multi-Method Validation:** Combines multiple detection methods for higher accuracy and confidence scoring.
    - **Version Extraction:** Intelligent version detection from headers, HTML content, and application responses.
- **Enhanced Detection Features:**
    - Confidence scoring (0-100%) for each detected technology
    - Configurable confidence thresholds for Nuclei scanning
    - Support for enabling/disabling specific detection methods
    - Color-coded confidence display in terminal output
- **Multi-Source Vulnerability Enrichment:**
    - Queries **NIST NVD** for known CVEs based on detected technology/version (fallback).
    - Queries **OSV (Open Source Vulnerability database)** for vulnerabilities affecting detected packages/versions.
    - Searches **Exploit-DB** for publicly available exploits linked to identified CVEs.
    - Retrieves additional context, CVSS scores, and references from **Vulners**.
    - Checks for related **Metasploit modules** via GitHub metadata.
    - Caches enrichment results per run to avoid redundant API calls.
- **Targeted Nuclei Scanning:**
    - Runs Nuclei scans focused on tags related to detected technologies and versions.
    - Confidence-based filtering to reduce false positives and noise.
    - Option to run broader scans (`--no-tech`) or scan for a single specified technology (`-t`).
    - Gracefully handles and skips scans for common technologies unlikely to have specific Nuclei templates.
- **Customizable & User-Friendly:**
    - Control concurrency (`-c`) for optimal performance.
    - Set detection method preferences (`--detection-methods`).
    - Configure confidence thresholds (`--confidence-threshold`).
    - Filter results by severity (`-s`).
    - Ignore SSL errors (`--ignore-ssl`).
    - Progress bar (`tqdm`) when scanning multiple targets from a file.
    - Debug logging (`-d`) for detailed insight.
- **Comprehensive Reporting:**
    - Structured JSON output (`-o`) containing detected tech, confidence scores, Nuclei findings, and all enrichment data.
    - Colorized console output with clear severity indicators and confidence levels.

## 📋 Prerequisites

- Python 3.8+ (due to `asyncio` features and type hinting)
- Go (for Nuclei installation)
- Nuclei installed and available in your system's PATH.
- Internet connection for API access (NVD, OSV, Vulners, ExploitDB, GitHub).
- _(Optional)_ BuiltWith API key for enhanced commercial detection.

## 🔧 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/gotr00t0day/TechackZ.git
    cd TechackZ
    ```
2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Install or Update Nuclei:
    Follow the official Nuclei installation guide: [https://nuclei.projectdiscovery.io/nuclei/install/](https://nuclei.projectdiscovery.io/nuclei/install/)
    Ensure Nuclei templates are up-to-date:
    ```bash
    nuclei -update-templates
    ```
4.  _(Optional)_ Get a BuiltWith API key:
    - Visit [BuiltWith API](https://builtwith.com/api) to get an API key
    - Use `--builtwith-key YOUR_KEY` or set `BUILTWITH_API_KEY` environment variable

## 📖 Usage

```bash
usage: techackz.py [-h] [-u URL | -f FILE] [-o OUTPUT]
                   [-s {info,low,medium,high,critical}] [--no-tech]
                   [--ignore-ssl] [-t TECHNOLOGY] [-c CONCURRENCY] [-d]
                   [--builtwith-key BUILTWITH_KEY]
                   [--confidence-threshold CONFIDENCE_THRESHOLD]
                   [--detection-methods {wappalyzer,custom,builtwith} [...]]
                   [--show-all-detections]

Detect web technologies and run targeted Nuclei scans with CVE enrichment.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL to scan
  -f FILE, --file FILE  File containing list of URLs/subdomains to scan (one
                        per line)
  -o OUTPUT, --output OUTPUT
                        Output file to save results (JSON format)
  -s {info,low,medium,high,critical}, --severity {info,low,medium,high,critical}
                        Minimum severity level to report (default: info)
  --no-tech             Skip technology detection and run broader Nuclei scans
  --ignore-ssl          Ignore SSL/TLS certificate verification errors
  -t TECHNOLOGY, --technology TECHNOLOGY
                        Scan ONLY for this specific technology (e.g.,
                        "wordpress", "nginx"). Skips tech detection.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent URL processing tasks (default: 10)
  -d, --debug           Enable debug logging for verbose output
  --builtwith-key BUILTWITH_KEY
                        BuiltWith API key for enhanced technology detection
  --confidence-threshold CONFIDENCE_THRESHOLD
                        Minimum confidence threshold for running Nuclei scans
                        (default: 50)
  --detection-methods {wappalyzer,custom,builtwith} [{wappalyzer,custom,builtwith} ...]
                        Technology detection methods to use (default:
                        wappalyzer custom)
  --show-all-detections
                        Show all technology detections regardless of confidence

Examples:
  # Basic scan with comprehensive detection
  python techackz.py -u https://example.com
  
  # High-confidence detection only
  python techackz.py -u https://example.com --confidence-threshold 80
  
  # Custom fingerprinting only (fastest)
  python techackz.py -u https://example.com --detection-methods custom
  
  # All detection methods with BuiltWith API
  python techackz.py -u https://example.com --detection-methods wappalyzer custom builtwith --builtwith-key YOUR_KEY
  
  # Show all detections regardless of confidence
  python techackz.py -u https://example.com --show-all-detections
  
  # Multiple URLs with custom settings
  python techackz.py -f urls.txt -o results.json --confidence-threshold 70 --concurrency 20
```

## 🎯 Detection Methods

### 1. Wappalyzer Detection
- Uses the python-Wappalyzer library
- Excellent for modern web technologies and frameworks
- High accuracy for popular technologies
- **Confidence:** 95%

### 2. Custom Fingerprinting
- Advanced pattern-based detection engine
- Covers 25+ technology categories:
  - **CMS:** WordPress, Drupal, Joomla, Shopify, Magento
  - **Web Servers:** Apache, Nginx, IIS
  - **Frameworks:** Django, Flask, Laravel, Rails
  - **CDNs:** Cloudflare, AWS, CloudFront
  - **WAF/Security:** Incapsula, F5 Big-IP
  - **Development Tools:** phpMyAdmin, Adminer
  - **And many more...**
- Analyzes headers, HTML content, cookies, and response patterns
- **Confidence:** 30-90% based on detection strength

### 3. BuiltWith API
- Commercial-grade detection service
- Comprehensive technology database
- Requires API key (paid service)
- **Confidence:** 90%

## 📊 Confidence Scoring

TechackZ assigns confidence scores (0-100%) to each detected technology:

- **90-100%:** High confidence (green) - Very reliable detection
- **70-89%:** Medium confidence (yellow) - Good detection with minor uncertainty  
- **50-69%:** Low confidence (red) - Detection present but may need verification
- **Below 50%:** Not used for Nuclei scanning by default

Use `--confidence-threshold` to control which detections trigger Nuclei scans.

## ⚠️ Disclaimer

This tool is intended for educational purposes and **authorized security testing only**. Running scans against systems without explicit permission is illegal and unethical. The authors and contributors are not responsible for any misuse or damage caused by this tool. Use responsibly.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Wappalyzer](https://github.com/AliasIO/Wappalyzer) / [python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [BuiltWith](https://builtwith.com/)
- [NIST NVD](https://nvd.nist.gov/)
- [OSV (Open Source Vulnerability database)](https://osv.dev/)
- [Exploit-DB](https://www.exploit-db.com/)
- [Vulners](https://vulners.com/)
- [aiohttp](https://github.com/aio-libs/aiohttp)
- [tqdm](https://github.com/tqdm/tqdm)

---
<p align="center">
Made with ❤️ by c0deninja
</p>
