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
from bs4 import BeautifulSoup

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
        except KeyError as e:
            print(f"{Fore.YELLOW}Warning: Missing field in finding: {e}{Style.RESET_ALL}")
            continue
    
    return findings

def run_nuclei_scan(url, tech_name, version=None):
    """
    Run a Nuclei scan targeting specific technology
    """
    # Base command with JSON output and silent mode
    command = ["nuclei", "-u", url, "-j", "-silent"]  # Added -silent flag
    
    tech_name_lower = tech_name.lower()
    
    if tech_name_lower == "php":
        # For PHP, we need a broader scan approach
        command = ["nuclei", "-u", url, "-j", "-silent",
            "-tags", "php",
            "-severity", "low,medium,high,critical",
        ]
        
        if version:
            command.extend([
                "-tags", f"php-{version}",
                "-tags", f"php/{version}"
            ])
    else:
        # Regular technology scanning
        command.extend(["-tags", tech_name_lower])
        if version:
            command.extend(["-tags", f"{tech_name_lower}-{version}"])
    
    try:
        process = subprocess.run(command, capture_output=True, text=True)
        return process.stdout
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running Nuclei scan: {str(e)}{Style.RESET_ALL}")
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
    
    parser.add_argument(
        '--ignore-ssl',
        help='Ignore SSL certificate verification',
        action='store_true'
    )
    
    parser.add_argument(
        '-t', '--technology',
        help='Specify technology to scan for (e.g., "wordpress", "nginx")',
        type=str
    )

    parser.add_argument(
        '-d', '--debug',
        help='Enable debug mode',
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

def check_cves(tech_name, version, args):
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
            response = requests.get(
                base_url,
                params=params,
                verify=not args.ignore_ssl
            )
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

def check_exploit_db(cve):
    """
    Check ExploitDB for available exploits
    """
    try:
        url = f"https://www.exploit-db.com/search?cve={cve}"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            exploits = []
            
            # Parse exploit-db results
            for row in soup.find_all('tr')[1:]:  # Skip header row
                cols = row.find_all('td')
                if cols:
                    exploit = {
                        'title': cols[1].text.strip(),
                        'type': cols[2].text.strip(),
                        'platform': cols[3].text.strip(),
                        'date': cols[4].text.strip(),
                        'url': f"https://www.exploit-db.com{cols[1].find('a')['href']}"
                    }
                    exploits.append(exploit)
            return exploits
    except Exception as e:
        print(f"{Fore.RED}Error checking ExploitDB: {str(e)}{Style.RESET_ALL}")
    return None

def check_vulners(cve):
    """
    Check Vulners database for additional information
    """
    try:
        url = f"https://vulners.com/api/v3/search/id/?id={cve}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get('data', {}).get('documents', {}):
                vuln_info = data['data']['documents'][cve]
                return {
                    'description': vuln_info.get('description'),
                    'cvss_score': vuln_info.get('cvss', {}).get('score'),
                    'published': vuln_info.get('published'),
                    'modified': vuln_info.get('modified'),
                    'references': vuln_info.get('references', [])
                }
    except Exception as e:
        print(f"{Fore.RED}Error checking Vulners: {str(e)}{Style.RESET_ALL}")
    return None

def check_metasploit(cve):
    """
    Check for Metasploit modules related to the CVE
    """
    try:
        url = f"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
        response = requests.get(url)
        if response.status_code == 200:
            modules = []
            data = response.json()
            
            for module in data:
                if 'references' in module and any(cve in ref for ref in module['references']):
                    modules.append({
                        'name': module['name'],
                        'path': module['fullname'],
                        'description': module.get('description', ''),
                        'rank': module.get('rank', '')
                    })
            return modules
    except Exception as e:
        print(f"{Fore.RED}Error checking Metasploit: {str(e)}{Style.RESET_ALL}")
    return None

def enrich_vulnerability_data(finding):
    """
    Enrich vulnerability data with information from multiple sources
    """
    enriched_data = {
        'original': finding,
        'exploit_db': None,
        'vulners': None,
        'metasploit': None
    }
    
    try:
        # Extract CVE from finding
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        name = finding.get('name', '')
        description = finding.get('description', '')
        cves = re.findall(cve_pattern, name) or re.findall(cve_pattern, description)
        
        if cves:
            for cve in cves:
                print(f"\n{Fore.CYAN}Checking databases for {cve}...{Style.RESET_ALL}")
                
                # Check ExploitDB
                exploits = check_exploit_db(cve)
                if exploits:
                    enriched_data['exploit_db'] = exploits
                    print(f"{Fore.YELLOW}Found {len(exploits)} exploits in ExploitDB{Style.RESET_ALL}")
                
                # Check Vulners
                vulners_info = check_vulners(cve)
                if vulners_info:
                    enriched_data['vulners'] = vulners_info
                    print(f"{Fore.YELLOW}Found additional information in Vulners{Style.RESET_ALL}")
                
                # Check Metasploit
                msf_modules = check_metasploit(cve)
                if msf_modules:
                    enriched_data['metasploit'] = msf_modules
                    print(f"{Fore.YELLOW}Found {len(msf_modules)} Metasploit modules{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error enriching vulnerability data: {str(e)}{Style.RESET_ALL}")
    
    return enriched_data

def main():
    args = parse_arguments()
    
    try:
        if args.ignore_ssl:
            # Disable SSL warnings and certificate verification
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            requests.packages.urllib3.disable_warnings()
            
        if not args.no_tech:
            # Initialize Wappalyzer
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(
                args.url,
                verify=not args.ignore_ssl
            )
            
            # Analyze the webpage
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
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
                        scan_results[tech_name] = []
                        print(f"\nFindings for {tech_name}:")
                        for finding in findings:
                            try:
                                severity = finding.get('severity', 'Unknown').upper()
                                name = finding.get('name', 'Unknown')
                                template = finding.get('template', 'Unknown')
                                description = finding.get('description', '')
                                matched_at = finding.get('matched_at', '')
                                
                                print(f"\n  [{severity}] {name}")
                                print(f"  Template: {template}")
                                if description:
                                    print(f"  Description: {description}")
                                if matched_at:
                                    print(f"  Matched at: {matched_at}")
                                
                                # Enrich vulnerability data
                                enriched_finding = enrich_vulnerability_data(finding)
                                scan_results[tech_name].append(enriched_finding)
                                
                                # Display additional information
                                if enriched_finding['exploit_db']:
                                    print(f"\n  {Fore.RED}Available Exploits:{Style.RESET_ALL}")
                                    for exploit in enriched_finding['exploit_db']:
                                        print(f"    - {exploit['title']}")
                                        print(f"      URL: {exploit['url']}")
                                
                                if enriched_finding['metasploit']:
                                    print(f"\n  {Fore.RED}Metasploit Modules:{Style.RESET_ALL}")
                                    for module in enriched_finding['metasploit']:
                                        print(f"    - {module['name']}")
                                        print(f"      Path: {module['path']}")
                                
                                if enriched_finding['vulners']:
                                    vuln_info = enriched_finding['vulners']
                                    print(f"\n  {Fore.YELLOW}Additional Information:{Style.RESET_ALL}")
                                    print(f"    CVSS Score: {vuln_info.get('cvss_score', 'N/A')}")
                                    print(f"    Published: {vuln_info.get('published', 'N/A')}")
                                    if vuln_info.get('references', []):
                                        print("    References:")
                                        for ref in vuln_info['references'][:3]:  # Show first 3 references
                                            print(f"      - {ref}")
                                            
                            except Exception as e:
                                print(f"{Fore.RED}Error processing finding: {str(e)}{Style.RESET_ALL}")
                                continue
                    else:
                        print(f"{Fore.GREEN}  No vulnerabilities found for {tech_name}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}  No vulnerabilities found for {tech_name}{Style.RESET_ALL}")
        
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



