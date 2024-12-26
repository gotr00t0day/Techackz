from Wappalyzer import Wappalyzer, WebPage
from colorama import Fore, Style
import urllib3
import warnings
import subprocess
import json
import os
from datetime import datetime
import argparse
import requests
from time import sleep
import re
from packaging import version as pkg_version

# Suppress all warnings
warnings.filterwarnings("ignore")

banner = f"""

{Fore.WHITE}

▄▄▄█████▓▓█████  ▄████▄   ██░ ██  ▄▄▄       ▄████▄   ██ ▄█▀▒███████▒
▓  ██▒ ▓▒▓█   ▀ ▒██▀ ▀█  ▓██░ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▒ ▒ ▒ ▄▀░
▒ ▓██░ ▒░▒███   ▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ░ ▒ ▄▀▒░ 
░ ▓██▓ ░ ▒▓█  ▄ ▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄   ▄▀▒   ░
  ▒██▒ ░ ░▒████▒▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄▒███████▒
  ▒ ░░   ░░ ▒░ ░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░▒▒ ▓░▒░▒
    ░     ░ ░  ░  ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░░░▒ ▒ ░ ▒
  ░         ░   ░         ░  ░░ ░  ░   ▒   ░        ░ ░░ ░ ░ ░ ░ ░ ░
            ░  ░░ ░       ░  ░  ░      ░  ░░ ░      ░  ░     ░ ░    
                ░                          ░               ░ {Fore.MAGENTA}by c0deninja{Style.RESET_ALL}


"""

def parse_nuclei_output(output):
    """
    Parse Nuclei scan output and return structured results
    """
    if not output:
        return None
        
    findings = []
    for line in output.splitlines():
        try:
            if line.strip():
                finding = json.loads(line)
                findings.append({
                    'template': finding.get('template-id', 'Unknown'),
                    'severity': finding.get('info', {}).get('severity', 'Unknown'),
                    'name': finding.get('info', {}).get('name', 'Unknown'),
                    'description': finding.get('info', {}).get('description', ''),
                    'matched_at': finding.get('matched-at', ''),
                    'timestamp': finding.get('timestamp', '')
                })
        except json.JSONDecodeError:
            continue
    
    return findings

def run_nuclei_scan(url, tech_name, version=None):
    """
    Run a Nuclei scan targeting specific technology
    """
    # Base command with JSON output
    command = ["nuclei", "-u", url, "-json"]
    
    # Add technology-specific templates
    command.extend(["-t", f"technologies/{tech_name.lower()}"])
    
    # If version is provided, add version-specific templates
    if version:
        command.extend(["-t", f"technologies/{tech_name.lower()}/{version}"])
    
    try:
        print(f"\nRunning Nuclei scan for {tech_name}...")
        process = subprocess.run(command, capture_output=True, text=True)
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running Nuclei scan: {str(e)}")
        return None

def parse_arguments():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(
        description='Detect web technologies and run targeted Nuclei scans',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file to save results (JSON format)',
        type=str
    )
    
    parser.add_argument(
        '-s', '--severity',
        choices=['info', 'low', 'medium', 'high', 'critical'],
        help='Minimum severity level to report',
        default='info'
    )
    
    parser.add_argument(
        '--no-tech',
        help='Skip technology detection and run all Nuclei scans',
        action='store_true'
    )
    
    return parser.parse_args()

def normalize_version(version_str):
    """
    Normalize version string to standard format
    """
    try:
        # Remove any non-version characters (like 'v' prefix)
        version_str = re.sub(r'^[v]+', '', str(version_str))
        
        # Try to parse as a standard version
        return str(pkg_version.parse(version_str))
    except:
        return version_str

def extract_version(tech_info):
    """
    Extract and validate version information from technology info
    Returns the most specific version found
    """
    versions = tech_info.get('versions', [])
    if not versions:
        return None
        
    # Filter out invalid or generic versions
    valid_versions = []
    for v in versions:
        # Skip obviously invalid versions
        if not v or v in ['0', 'null', 'undefined']:
            continue
            
        # Try to normalize the version
        normalized = normalize_version(v)
        if normalized:
            valid_versions.append(normalized)
    
    if not valid_versions:
        return None
        
    try:
        # Sort versions and return the most specific one
        return str(max(valid_versions, key=pkg_version.parse))
    except:
        # If version comparison fails, return the first valid version
        return valid_versions[0]

def check_cves(tech_name, version):
    """
    Check for known CVEs for a specific technology and version
    """
    if not version:
        return None
        
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Clean up technology name and version for better matching
    tech_name = tech_name.lower().strip()
    version = normalize_version(version)
    
    # Try different search patterns
    search_patterns = [
        f"{tech_name} {version}",  # Exact version
        f"{tech_name} {version.split('.')[0]}",  # Major version
        tech_name  # Just the technology name
    ]
    
    all_vulnerabilities = []
    
    for pattern in search_patterns:
        params = {
            "keywordSearch": pattern,
            "keywordExactMatch": False
        }
        
        try:
            response = requests.get(base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    
                    # Check if the vulnerability applies to this version
                    configurations = cve.get('configurations', [])
                    version_match = False
                    
                    for config in configurations:
                        for node in config.get('nodes', []):
                            for cpe_match in node.get('cpeMatch', []):
                                if version in cpe_match.get('criteria', ''):
                                    version_match = True
                                    break
                    
                    if version_match:
                        all_vulnerabilities.append({
                            'id': cve.get('id'),
                            'description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'severity': cve.get('metrics', {}).get('cvssMetrics', [{}])[0].get('baseScore', 'N/A'),
                            'published': cve.get('published'),
                            'lastModified': cve.get('lastModified')
                        })
                
            sleep(1)  # Respect API rate limits
            
        except Exception as e:
            print(f"Error checking CVEs: {str(e)}")
            continue
    
    return all_vulnerabilities

def main():
    args = parse_arguments()
    
    try:
        if not args.no_tech:
            # Initialize Wappalyzer
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(args.url)
            
            # Analyze the webpage
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            # Check for CVEs
            print("\nChecking for known vulnerabilities...")
            for tech_name, tech_info in technologies.items():
                version = extract_version(tech_info)
                if version:
                    print(f"\n{tech_name} {version}:")
                    
                    vulnerabilities = check_cves(tech_name, version)
                    if vulnerabilities:
                        print(f"Found {len(vulnerabilities)} potential vulnerabilities:")
                        for vuln in vulnerabilities:
                            print(f"\n  [CVE] {vuln['id']}")
                            print(f"  Severity: {vuln['severity']}")
                            print(f"  Description: {vuln['description']}")
                            print(f"  Published: {vuln['published']}")
                    else:
                        print("  No known vulnerabilities found")
                    
                    sleep(1)  # Rate limiting
        
        # Pretty print the results and run Nuclei scans
        scan_results = {}
        for tech_name, tech_info in technologies.items():
            print(f"\n{tech_name}:")
            if 'versions' in tech_info:
                versions = tech_info['versions']
                print(f"  Versions: {Fore.YELLOW}{', '.join(versions)}{Style.RESET_ALL}")
                scan_output = run_nuclei_scan(args.url, tech_name, versions[0] if versions else None)
            else:
                scan_output = run_nuclei_scan(args.url, tech_name)
                
            if scan_output:
                findings = parse_nuclei_output(scan_output)
                if findings:
                    # Filter findings based on severity
                    severity_levels = ['info', 'low', 'medium', 'high', 'critical']
                    min_severity_index = severity_levels.index(args.severity)
                    
                    filtered_findings = [
                        f for f in findings 
                        if severity_levels.index(f['severity'].lower()) >= min_severity_index
                    ]
                    
                    if filtered_findings:
                        scan_results[tech_name] = filtered_findings
                        print(f"\nFindings for {tech_name}:")
                        for finding in filtered_findings:
                            print(f"\n  [{finding['severity'].upper()}] {finding['name']}")
                            print(f"  Template: {finding['template']}")
                            print(f"  Description: {finding['description']}")
                            print(f"  Matched at: {finding['matched_at']}")
                    else:
                        print(f"{Fore.RED}  No vulnerabilities found matching severity criteria{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}  No vulnerabilities found{Style.RESET_ALL}")
        
        # Save results to file if specified
        if args.output and scan_results:
            with open(args.output, 'w') as f:
                json.dump(scan_results, f, indent=2)
                print(f"\nResults saved to {args.output}")
                
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    print(f"{Fore.MAGENTA}{banner}{Style.RESET_ALL}")
    main()
