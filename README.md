# TechackZ 🛡️

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

TechackZ is an advanced, asynchronous web technology detection and vulnerability assessment tool. It combines Wappalyzer's technology detection with Nuclei's security scanning capabilities, enriching findings with data from NVD, OSV, ExploitDB, Vulners, and Metasploit module lookups.

## 🚀 Features

- **Asynchronous Scanning:** High-speed, concurrent scanning of multiple targets and enrichment lookups using `asyncio` and `aiohttp`.
- **Technology Stack Detection:**
    - Leverages Wappalyzer to identify web technologies, frameworks, and versions.
    - Normalizes version numbers for accurate matching.
- **Multi-Source Vulnerability Enrichment:**
    - Queries **NIST NVD** for known CVEs based on detected technology/version (fallback).
    - Queries **OSV (Open Source Vulnerability database)** for vulnerabilities affecting detected packages/versions.
    - Searches **Exploit-DB** for publicly available exploits linked to identified CVEs.
    - Retrieves additional context, CVSS scores, and references from **Vulners**.
    - Checks for related **Metasploit modules** via GitHub metadata.
    - Caches enrichment results per run to avoid redundant API calls.
- **Targeted Nuclei Scanning:**
    - Runs Nuclei scans focused on tags related to detected technologies and versions.
    - Option to run broader scans (`--no-tech`) or scan for a single specified technology (`-t`).
    - Gracefully handles and skips scans for common technologies unlikely to have specific Nuclei templates (e.g., analytics, CDNs).
- **Customizable & User-Friendly:**
    - Control concurrency (`-c`) for optimal performance.
    - Set network timeouts (`--timeout`).
    - Filter results by severity (`-s`).
    - Ignore SSL errors (`--ignore-ssl`).
    - Progress bar (`tqdm`) when scanning multiple targets from a file.
    - Debug logging (`-d`) for detailed insight.
- **Comprehensive Reporting:**
    - Structured JSON output (`-o`) containing detected tech, Nuclei findings, and all enrichment data.
    - Colorized console output with clear severity indicators.

## 📋 Prerequisites

- Python 3.8+ (due to `asyncio` features and type hinting)
- Go (for Nuclei installation)
- Nuclei installed and available in your system's PATH.
- Internet connection for API access (NVD, OSV, Vulners, ExploitDB, GitHub).

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
4.  _(Optional)_ Run the old install script if needed (may be outdated):
    ```bash
    chmod +x install.sh
    ./install.sh
    ```
    _(Note: Prefer manual installation of Nuclei as described above)_

## 📖 Usage

```bash
usage: techackz.py [-h] [-u URL | -f FILE] [-o OUTPUT]
                   [-s {info,low,medium,high,critical,unknown}] [--no-tech]
                   [--ignore-ssl] [-t TECHNOLOGY] [-c CONCURRENCY] [-d]
                   [--timeout TIMEOUT]

Detect web technologies, run targeted Nuclei scans, and enrich findings with
CVE/exploit data.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL to scan
  -f FILE, --file FILE  File containing list of URLs/subdomains to scan (one
                        per line)
  -o OUTPUT, --output OUTPUT
                        Output file to save results (JSON format)
  -s {info,low,medium,high,critical,unknown}, --severity {info,low,medium,high,critical,unknown}
                        Minimum severity level to report (default: info)
  --no-tech             Skip Wappalyzer technology detection; run broader
                        Nuclei scans only.
  --ignore-ssl          Ignore SSL/TLS certificate verification errors (use
                        with caution!).
  -t TECHNOLOGY, --technology TECHNOLOGY
                        Scan ONLY for this specific technology (e.g.,
                        "wordpress", "nginx"). Skips Wappalyzer.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent URL processing tasks (default:
                        10)
  -d, --debug           Enable debug logging for verbose output.
  --timeout TIMEOUT     Overall timeout in seconds for network requests per
                        URL (default: 120)

Example: python techackz.py -u https://example.com -o results.json -s medium --concurrency 20
```

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
