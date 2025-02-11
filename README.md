# TechackZ 🛡️

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

TechackZ is an advanced web technology detection and vulnerability assessment tool that combines the power of Wappalyzer's technology detection with Nuclei's security scanning capabilities. It automatically identifies web technologies, checks for known vulnerabilities in the National Vulnerability Database (NVD), and performs targeted security scans.

## 🚀 Features

- **Technology Stack Detection**
  - Automatically identifies web technologies and frameworks
  - Accurate version detection and normalization
  - Categories and confidence scoring

- **Vulnerability Assessment**
  - Queries NIST NVD for known CVEs
  - Version-specific vulnerability matching
  - Real-time security scanning with Nuclei

- **Customizable Scanning**
  - Severity-based filtering (info to critical)
  - Technology-specific targeted scans
  - Configurable output formats

- **Comprehensive Reporting**
  - Structured JSON output
  - Detailed vulnerability descriptions
  - Severity-based categorization

## 📋 Prerequisites

- Python 3.x
- Go (for Nuclei installation)
- Internet connection for NVD API access

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/gotr00t0day/TechackZ.git
cd TechackZ
````
2. Install Python dependencies:
```bash
pip install -r requirements.txt
```
3. Install Tools
```bash
chmod +x install.sh
./install.sh
```

## 📖 Usage
```bash
usage: techackz.py [-h] [-u URL | -f FILE] [-o OUTPUT]
                   [-s {info,low,medium,high,critical}] [--no-tech] [--ignore-ssl]
                   [-t TECHNOLOGY] [-d]

Detect web technologies and run targeted Nuclei scans

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL to scan
  -f, --file FILE       File containing list of subdomains to scan
  -o, --output OUTPUT   Output file to save results (JSON format)
  -s, --severity {info,low,medium,high,critical}
                        Minimum severity level to report
  --no-tech             Skip technology detection and run all Nuclei scans
  --ignore-ssl          Ignore SSL certificate verification
  -t, --technology TECHNOLOGY
                        Specify technology to scan for (e.g., "wordpress", "nginx")
  -d, --debug           Enable debug mode         Skip technology detection and run all Nuclei scan
```

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan the target systems. The authors are not responsible for any misuse or damage caused by this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Wappalyzer](https://github.com/AliasIO/Wappalyzer)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [NIST NVD](https://nvd.nist.gov/)

---
<p align="center">
Made with ❤️ by c0deninja
</p>
