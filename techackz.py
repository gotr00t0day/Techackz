import asyncio
import aiohttp
import json
import os
import subprocess
import logging
import sys
import shutil
from datetime import datetime
import argparse
import re
from time import sleep
from packaging import version as pkg_version
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urlparse
import warnings # Keep warnings import if needed elsewhere, but disable specific ones
from tqdm.asyncio import tqdm_asyncio # Import tqdm for asyncio

# --- Configuration ---
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(__name__)

# API Endpoints
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_SEARCH_URL = "https://www.exploit-db.com/search"
VULNERS_API_URL = "https://vulners.com/api/v3/search/id/"
METASPLOIT_MODULES_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
OSV_API_URL = "https://api.osv.dev/v1/query"

# Severity mapping for filtering
SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

# Suppress InsecureRequestWarning if SSL verification is disabled
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
                                                             {Fore.MAGENTA}Version: {Style.RESET_ALL}1.0.0
"""

# --- Helper Functions ---

# Set of common technology slugs (lowercase) that often lack specific vuln templates
# Add more as needed based on common Wappalyzer detections without Nuclei templates
IGNORED_NUCLEI_TECH_TAGS = {
    "recaptcha", "google tag manager", "google font api", "google analytics",
    "fonts", "font awesome", "bootstrap", "jquery", "react", "vue.js", "angularjs",
    "modernizr", "jsdelivr", "cloudflare", "akamai", "amazon cloudfront", "fastly",
    # Add common CMS plugins/themes if they cause noise and lack specific templates
    # "elementor", "wp-rocket", etc. - Be cautious adding these without verification
}

def parse_nuclei_output(output):
    """Parses Nuclei JSON output line by line."""
    if not output:
        return []
    findings = []
    for line in output.splitlines():
        try:
            if line.strip():
                finding = json.loads(line)
                findings.append({
                    'template': finding.get('template-id', 'Unknown'),
                    'severity': finding.get('info', {}).get('severity', 'unknown').lower(),
                    'name': finding.get('info', {}).get('name', 'Unknown'),
                    'description': finding.get('info', {}).get('description', ''),
                    'matched_at': finding.get('matched-at', ''),
                    'timestamp': finding.get('timestamp', ''),
                    'curl_command': finding.get('curl-command', ''), # Added curl command
                    'extracted_results': finding.get('extracted-results', []), # Added extracted results
                })
        except json.JSONDecodeError:
            log.warning(f"Skipping invalid JSON line from Nuclei: {line}")
        except KeyError as e:
            log.warning(f"Missing field in Nuclei finding: {e} in line: {line}")
    return findings

async def run_nuclei_scan_async(target_url, tech_name=None, version=None):
    """Runs Nuclei scan asynchronously, skipping common non-vulnerable tech."""
    command = ["nuclei", "-u", target_url, "-j", "-silent", "-nc"] # Added -silent, -nc (no color)

    if tech_name:
        tech_name_lower = tech_name.lower().strip()

        # --- Skip ignored tags ---
        if tech_name_lower in IGNORED_NUCLEI_TECH_TAGS:
            log.info(f"Skipping Nuclei scan for ignored/common tag: {tech_name}")
            return None # Don't run Nuclei for these tags

        # Basic tag: just the tech name
        tags_to_add = {tech_name_lower}
        if version:
             # Try common version tagging conventions
            version_tag_base = f"{tech_name_lower}-{version}"
            tags_to_add.add(version_tag_base)
            # Sometimes tags might just use major version
            major_version = version.split('.')[0]
            if major_version != version:
                 tags_to_add.add(f"{tech_name_lower}-{major_version}")

    else: # If no specific tech, run a broader default set (adjust as needed)
        command.extend(["-tags", "cve,default,config,exposed-panels"])
        command.extend(["-severity", "medium,high,critical"]) # Focus severity if no tech

    log.debug(f"Running Nuclei command: {' '.join(command)}")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        stderr_decoded = stderr.decode(errors='ignore')

        if process.returncode != 0:
            # Check specifically for the "no templates found" error
            if "[FTL] Could not run nuclei: no templates provided for scan" in stderr_decoded:
                log.warning(f"Nuclei found no templates for tags associated with {tech_name or 'Broad Scan'} on {target_url}")
            # Log other errors as ERROR
            elif "ERR" in stderr_decoded or "WRN" in stderr_decoded or "FTL" in stderr_decoded:
                 log.error(f"Nuclei scan failed for {target_url} (Tech: {tech_name or 'All'}). Error: {stderr_decoded}")
            else:
                 log.warning(f"Nuclei scan process for {target_url} (Tech: {tech_name or 'All'}) exited non-zero ({process.returncode}), but no critical errors in stderr.")
            return None
        log.debug(f"Nuclei stdout for {target_url} (Tech: {tech_name or 'All'}):\n{stdout.decode(errors='ignore')[:500]}...") # Log snippet
        return stdout.decode(errors='ignore')
    except FileNotFoundError:
        log.critical("Nuclei command not found. Make sure Nuclei is installed and in your PATH.")
        sys.exit(1) # Exit if Nuclei is essential and not found
    except Exception as e:
        log.error(f"Error running Nuclei scan for {target_url}: {e}")
        return None

def normalize_version(version_str):
    """Normalizes version string."""
    if not version_str: return None
    try:
        version_str = re.sub(r'^[vV]+', '', str(version_str).strip())
        # Handle potential extra info like '-stable'
        version_str = re.split(r'[ -]', version_str)[0]
        parsed_version = pkg_version.parse(version_str)
        # Return the standard representation
        return str(parsed_version)
    except pkg_version.InvalidVersion:
        log.warning(f"Could not normalize version: {version_str}. Using original.")
        return str(version_str).strip() # Return original cleaned string if parsing fails
    except Exception as e:
        log.error(f"Unexpected error normalizing version '{version_str}': {e}")
        return str(version_str).strip()


def extract_tech_version(tech_info):
    """Extracts and validates the most specific version."""
    versions = tech_info.get('versions', [])
    if not versions: return None

    valid_normalized_versions = {}
    for v in versions:
        if v and str(v).lower() not in ['0', 'null', 'undefined', '']:
            normalized = normalize_version(v)
            if normalized:
                try:
                    # Store parsed version for comparison, original normalized for return
                    valid_normalized_versions[pkg_version.parse(normalized)] = normalized
                except pkg_version.InvalidVersion:
                     log.debug(f"Discarding invalid version after normalization: {normalized}")
                     continue


    if not valid_normalized_versions: return None

    # Return the normalized string of the highest parsed version
    return valid_normalized_versions[max(valid_normalized_versions.keys())]

# --- Async API Interaction Functions ---

async def fetch_url(session, url, params=None, method='GET', data=None, headers=None):
    """Generic async URL fetcher with error handling."""
    try:
        async with session.request(method, url, params=params, json=data, headers=headers, ssl=False) as response: # ignore_ssl handled here
            log.debug(f"Requesting {method} {response.url} - Status: {response.status}")
            if response.status == 200:
                try:
                    # Try JSON first, fall back to text
                    return await response.json()
                except aiohttp.ContentTypeError:
                     log.debug(f"Response from {url} not JSON, returning text.")
                     return await response.text()
            elif response.status == 429: # Rate limited
                 log.warning(f"Rate limited by {url}. Consider adding delays or backoff.")
                 await asyncio.sleep(5) # Basic sleep, implement proper backoff if needed
                 return None # Or retry logic
            else:
                log.error(f"Error fetching {url}: Status {response.status} - {await response.text()}")
                return None
    except aiohttp.ClientConnectorError as e:
        log.error(f"Connection error fetching {url}: {e}")
        return None
    except asyncio.TimeoutError:
         log.error(f"Timeout error fetching {url}")
         return None
    except Exception as e:
        log.error(f"Unexpected error fetching {url}: {type(e).__name__} - {e}")
        return None

async def check_cves_async(session, tech_name, version):
    """Checks NVD for CVEs asynchronously."""
    if not version: return None
    tech_name = tech_name.lower().strip()
    norm_version = normalize_version(version)
    if not norm_version: return None

    search_keywords = f"{tech_name} {norm_version}"
    params = {
        "keywordSearch": search_keywords,
        "resultsPerPage": 50 # Fetch more results if needed
        # "keywordExactMatch": True # Might be too restrictive initially
    }

    log.info(f"Checking NVD for {tech_name} version {norm_version}...")
    data = await fetch_url(session, NVD_API_URL, params=params)

    if not data or 'vulnerabilities' not in data:
        log.debug(f"No CVEs found in NVD for pattern: {search_keywords}")
        return None

    vulnerabilities = []
    for vuln_item in data.get('vulnerabilities', []):
        cve = vuln_item.get('cve', {})
        cve_id = cve.get('id')
        descriptions = cve.get('descriptions', [])
        description = descriptions[0].get('value', '') if descriptions else 'N/A'
        cvss_metrics_v3 = cve.get('metrics', {}).get('cvssMetricV31', []) # Prefer CVSS v3.1
        base_score = 'N/A'
        severity = 'N/A'
        if cvss_metrics_v3:
            base_score = cvss_metrics_v3[0].get('cvssData', {}).get('baseScore', 'N/A')
            severity = cvss_metrics_v3[0].get('cvssData', {}).get('baseSeverity', 'N/A')
        else: # Fallback to CVSS v2 if v3 not available
            cvss_metrics_v2 = cve.get('metrics', {}).get('cvssMetricV2', [])
            if cvss_metrics_v2:
                 base_score = cvss_metrics_v2[0].get('cvssData', {}).get('baseScore', 'N/A')
                 severity = cvss_metrics_v2[0].get('baseSeverity', 'N/A')


        published = cve.get('published')
        last_modified = cve.get('lastModified')

        # Basic check if the version is mentioned in description or CPEs (Improve CPE matching if needed)
        # This is a simplification; proper CPE matching is complex.
        version_mentioned = norm_version in description or any(norm_version in str(cfg) for cfg in cve.get('configurations', []))

        if version_mentioned and cve_id: # Only add if version seems relevant
            vulnerabilities.append({
                'id': cve_id,
                'description': description,
                'score': base_score,
                'severity': severity.lower() if isinstance(severity, str) else 'unknown',
                'published': published,
                'lastModified': last_modified
            })

    log.info(f"Found {len(vulnerabilities)} potentially relevant CVEs in NVD for {tech_name} {norm_version}")
    return vulnerabilities if vulnerabilities else None


async def check_exploit_db_async(session, cve_id):
    """Checks ExploitDB for exploits asynchronously."""
    log.info(f"Checking ExploitDB for {cve_id}...")
    params = {'cve': cve_id.split('-')[-1]} # ExploitDB search often uses just the number part
    html_content = await fetch_url(session, EXPLOITDB_SEARCH_URL, params=params)

    if not html_content or not isinstance(html_content, str):
        log.debug(f"No results or error fetching ExploitDB for {cve_id}")
        return None

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        exploits = []
        exploit_table = soup.find('table', {'id': 'exploits-table'})
        if not exploit_table:
            log.debug(f"No exploit table found on ExploitDB page for {cve_id}")
            # Check for messages like "No results"
            if "No results" in html_content:
                log.debug(f"ExploitDB page explicitly stated 'No results' for {cve_id}")
            return None

        # --- Add check: Ensure tbody exists before searching within it ---
        tbody = exploit_table.find('tbody')
        if not tbody:
            log.warning(f"No tbody found within exploit table for {cve_id}. HTML structure might have changed.")
            return None # Cannot proceed without tbody
        # --- End Check ---

        # Now it's safe to search tbody for rows
        for row in tbody.find_all('tr'):
            cols = row.find_all('td')
            if len(cols) < 5: continue # Need at least 5 columns usually
            link_tag = cols[4].find('a', href=True) # Exploit title/link is often 5th col
            if not link_tag: continue

            edb_id_tag = cols[0].find('a', href=True)
            edb_id = edb_id_tag.text.strip() if edb_id_tag else 'N/A'
            exploit_link = f"https://www.exploit-db.com{link_tag['href']}"
            title = link_tag.text.strip()
            # Extract other details - indices might change based on site structure
            date = cols[1].text.strip() if len(cols) > 1 else 'N/A'
            type_col = cols[5].text.strip() if len(cols) > 5 else 'N/A'
            platform_col = cols[6].text.strip() if len(cols) > 6 else 'N/A'

            exploits.append({
                'edb_id': edb_id,
                'title': title,
                'url': exploit_link,
                'date': date,
                'type': type_col,
                'platform': platform_col,
            })
        log.info(f"Found {len(exploits)} exploits in ExploitDB for {cve_id}")
        return exploits if exploits else None
    except Exception as e:
        log.error(f"Error parsing ExploitDB results for {cve_id}: {e}")
        return None


async def check_vulners_async(session, cve_id):
    """Checks Vulners database asynchronously with robust parsing."""
    if not cve_id: return None
    log.info(f"Checking Vulners for {cve_id}...")
    url = f"{VULNERS_API_URL}?id={cve_id}"
    data = await fetch_url(session, url)

    # Check response structure carefully
    if not data or isinstance(data, str) or data.get('result') != 'OK' or not data.get('data', {}).get('documents'):
        log.debug(f"No results or error fetching Vulners for {cve_id}. Response: {str(data)[:100]}...")
        return None

    try:
        vuln_docs = data['data']['documents']
        vuln_info = vuln_docs.get(cve_id)

        if not vuln_info or not isinstance(vuln_info, dict):
            log.warning(f"Received non-dictionary data or CVE ID {cve_id} not found within Vulners documents.")
            return None

        log.info(f"Found info in Vulners for {cve_id}")

        # --- Safely extract CVSS info ---
        cvss_info = vuln_info.get('cvss')
        cvss3_info = vuln_info.get('cvss3')
        score = None
        vector = None
        severity = 'unknown'

        # Prefer CVSS3, ensure it's a dict before accessing
        if isinstance(cvss3_info, dict):
            score = cvss3_info.get('score')
            vector = cvss3_info.get('vector')
            severity = cvss3_info.get('severity', 'unknown').lower()

        # Fallback to CVSS2 if CVSS3 info missing or incomplete, ensure it's a dict
        if (score is None or vector is None) and isinstance(cvss_info, dict):
            if score is None: # Only overwrite score if not found in CVSS3
                score = cvss_info.get('score')
            if vector is None: # Only overwrite vector if not found in CVSS3
                vector = cvss_info.get('vectorString') # Key is different in CVSSv2
                # Use CVSSv2 severity only if CVSSv3 severity wasn't found
                if severity == 'unknown':
                    severity = cvss_info.get('severity', 'unknown').lower()

        # Normalize score/vector to N/A if still None
        score = score if score is not None else 'N/A'
        vector = vector if vector is not None else 'N/A'

        # Ensure severity is valid
        if severity not in SEVERITY_LEVELS:
            severity = 'unknown'
        # --- End CVSS extraction ---

        # --- Safely extract exploit links ---
        exploit_links = []
        bulletin_family = vuln_info.get('bulletinFamily')
        if isinstance(bulletin_family, dict):
            exploit_list = bulletin_family.get('exploit')
            if isinstance(exploit_list, list):
                for ref in exploit_list:
                    if isinstance(ref, dict) and ref.get('href'):
                        exploit_links.append(ref['href'])
        # --- End exploit link extraction ---

        return {
            'title': vuln_info.get('title'),
            'description': vuln_info.get('description'),
            'cvss_score': score,
            'cvss_vector': vector,
            'severity': severity,
            'published': vuln_info.get('published'),
            'modified': vuln_info.get('modified'),
            'references': vuln_info.get('references', []), # Assume references is usually a list
            'exploit_links': exploit_links
        }
    except Exception as e:
        log.error(f"Error parsing Vulners results for {cve_id}: {e}", exc_info=True) # Log traceback
        return None

async def check_metasploit_async(session, cve_id):
    """Checks for Metasploit modules asynchronously."""
    log.info(f"Checking Metasploit GitHub for {cve_id}...")
    data = await fetch_url(session, METASPLOIT_MODULES_URL)

    if not data or not isinstance(data, dict): # Expecting a dict mapping fullpath -> metadata
        log.debug(f"No results or error fetching Metasploit data.")
        return None

    modules = []
    try:
        cve_pattern = re.compile(re.escape(cve_id), re.IGNORECASE)
        for path, meta in data.items():
             # Check 'references' if available, fallback to searching description/name
            refs = meta.get('references', [])
            found_in_refs = any(cve_pattern.search(ref.get('url', '')) for ref in refs if isinstance(ref, dict))

            if found_in_refs or cve_pattern.search(meta.get('description','')) or cve_pattern.search(meta.get('name','')):
                 modules.append({
                    'name': meta.get('name', 'Unknown'),
                    'path': path,
                    'description': meta.get('description', ''),
                    'rank': meta.get('rank_string', meta.get('rank', '')), # Prefer rank_string
                    'references': [ref.get('url') for ref in refs if ref.get('url')]
                })
        log.info(f"Found {len(modules)} potential Metasploit modules for {cve_id}")
        return modules if modules else None
    except Exception as e:
         log.error(f"Error processing Metasploit data for {cve_id}: {e}")
         return None

async def check_osv_async(session, tech_name, version=None):
    """Queries OSV database asynchronously."""
    log.info(f"Checking OSV database for {tech_name} {version or ''}...")
    query = {"package": {"name": tech_name.lower(), "ecosystem": "OSS-Fuzz"}} # Default ecosystem, adjust if needed
    if version:
        query["version"] = normalize_version(version) # Use normalized version

    data = await fetch_url(session, OSV_API_URL, method='POST', data={"query": query}) # OSV uses POST with query in body

    if not data or not data.get('vulns'):
        log.debug(f"No vulnerabilities found in OSV for {tech_name} {version or ''}")
        return None

    formatted_vulns = []
    try:
        for vuln in data['vulns']:
            affected_info = []
            for affected in vuln.get('affected', []):
                 pkg = affected.get('package', {})
                 ranges = affected.get('ranges', [])
                 db_specific = affected.get('database_specific', {})
                 affected_info.append({
                     "package": f"{pkg.get('ecosystem', '?')}:{pkg.get('name', '?')}",
                     "ranges": ranges,
                     "versions": affected.get('versions', []),
                     "db_specific": db_specific
                 })

            severity_obj = next((s for s in vuln.get('severity', []) if s.get('type') == 'CVSS_V3'), None)
            severity_score = "N/A"
            if severity_obj:
                 severity_score = severity_obj.get('score', 'N/A')

            formatted_vuln = {
                'id': vuln.get('id'),
                'summary': vuln.get('summary', ''),
                'details': vuln.get('details', ''),
                'aliases': vuln.get('aliases', []),
                'severity_score': severity_score, # Using CVSS v3 score if available
                'affected': affected_info,
                'published': vuln.get('published'),
                'modified': vuln.get('modified'),
                'references': [ref.get('url') for ref in vuln.get('references', []) if ref.get('url')]
            }
            formatted_vulns.append(formatted_vuln)
        log.info(f"Found {len(formatted_vulns)} vulnerabilities in OSV for {tech_name} {version or ''}")
        return formatted_vulns if formatted_vulns else None
    except Exception as e:
        log.error(f"Error parsing OSV results for {tech_name} {version or ''}: {e}")
        return None

# --- Enrichment and Processing ---

async def enrich_vulnerability_data(session, finding, tech_name=None, tech_version=None, cve_cache=None):
    """Enriches a single Nuclei finding with data from various sources asynchronously."""
    if cve_cache is None: cve_cache = {} # Initialize cache if not provided

    enriched_data = {
        'original': finding,
        'nvd_cves': None,
        'osv_vulns': None,
        'exploits': {}, # Store by CVE ID
        'vulners': {}, # Store by CVE ID
        'metasploit': {}, # Store by CVE ID
    }

    tasks = []

    # --- OSV Check based on Wappalyzer tech/version ---
    if tech_name:
         # Schedule OSV check if tech detected
         tasks.append(asyncio.create_task(check_osv_async(session, tech_name, tech_version)))
    else:
         tasks.append(asyncio.create_task(asyncio.sleep(0, result=None))) # Placeholder if no tech_name


    # --- CVE-based Enrichment ---
    # Extract CVEs from Nuclei finding name or template ID (more reliable than description)
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    potential_cves = set(re.findall(cve_pattern, finding.get('template', '')) +
                         re.findall(cve_pattern, finding.get('name', '')))

    if not potential_cves and tech_name and tech_version:
        # If no CVE in template/name, check NVD based on tech/version as fallback
         log.debug(f"No CVE in finding, checking NVD for {tech_name} {tech_version} as fallback.")
         nvd_task = asyncio.create_task(check_cves_async(session, tech_name, tech_version))
         tasks.append(nvd_task)
    else:
         tasks.append(asyncio.create_task(asyncio.sleep(0, result=None))) # Placeholder if CVEs found or no tech info

    # --- Run OSV/NVD checks ---
    enrichment_results = await asyncio.gather(*tasks)
    osv_results = enrichment_results[0]
    nvd_results_fallback = enrichment_results[1] if len(enrichment_results) > 1 else None

    if osv_results:
        enriched_data['osv_vulns'] = osv_results
        log.info(f"Enriched with {len(osv_results)} OSV results for {tech_name or 'finding'} {tech_version or ''}")

    # Combine CVEs found in template/name with any found via NVD fallback
    if nvd_results_fallback:
        enriched_data['nvd_cves'] = nvd_results_fallback
        for cve_info in nvd_results_fallback:
             potential_cves.add(cve_info['id']) # Add CVEs found via NVD lookup


    # --- Enrichment tasks for each unique CVE ---
    cve_enrichment_tasks = {}
    cves_to_check = list(potential_cves)

    if not cves_to_check and not osv_results:
        log.debug(f"No CVEs or OSV vulns found for finding: {finding.get('template')}")
        return enriched_data # Nothing more to enrich

    log.info(f"Found CVEs to enrich: {cves_to_check}")

    for cve_id in cves_to_check:
        if cve_id in cve_cache:
            log.debug(f"Using cached enrichment data for {cve_id}")
            enriched_data['exploits'][cve_id] = cve_cache[cve_id].get('exploit_db')
            enriched_data['vulners'][cve_id] = cve_cache[cve_id].get('vulners')
            enriched_data['metasploit'][cve_id] = cve_cache[cve_id].get('metasploit')
        else:
             # Schedule tasks only if not cached
             cve_enrichment_tasks[cve_id] = [
                 asyncio.create_task(check_exploit_db_async(session, cve_id)),
                 asyncio.create_task(check_vulners_async(session, cve_id)),
                 asyncio.create_task(check_metasploit_async(session, cve_id))
             ]

    # --- Run CVE enrichment tasks ---
    for cve_id, tasks_for_cve in cve_enrichment_tasks.items():
         results = await asyncio.gather(*tasks_for_cve)
         exploit_db_res, vulners_res, metasploit_res = results

         # Store results in cache and enrichment data
         cve_cache[cve_id] = {
             'exploit_db': exploit_db_res,
             'vulners': vulners_res,
             'metasploit': metasploit_res
         }
         enriched_data['exploits'][cve_id] = exploit_db_res
         enriched_data['vulners'][cve_id] = vulners_res
         enriched_data['metasploit'][cve_id] = metasploit_res
         log.info(f"Finished enrichment lookups for {cve_id}")

    return enriched_data


def print_enriched_finding(finding_data, min_severity_level):
    """Prints the enriched finding details respecting severity level."""
    original = finding_data['original']
    severity = original.get('severity', 'unknown')
    severity_num = SEVERITY_LEVELS.get(severity, -1)

    if severity_num < min_severity_level:
        log.debug(f"Skipping finding '{original.get('name')}' due to severity '{severity}' < minimum '{min_severity_level}'")
        return # Skip printing if below threshold

    # --- Print Core Finding ---
    severity_upper = severity.upper()
    color = Fore.GREEN
    if severity in ['medium', 'high']: color = Fore.YELLOW
    if severity == 'critical': color = Fore.RED
    print(f"\n{color}[{severity_upper}]{Style.RESET_ALL} {Fore.CYAN}{original.get('name', 'Unknown')}{Style.RESET_ALL}")
    print(f"  Template: {original.get('template', 'Unknown')}")
    if original.get('description'):
        print(f"  Description: {original['description']}")
    if original.get('matched_at'):
        print(f"  Matched at: {Style.BRIGHT}{original['matched_at']}{Style.RESET_ALL}")
    if original.get('extracted_results'):
        print(f"  Extracted Results: {Fore.MAGENTA}{original['extracted_results']}{Style.RESET_ALL}")
    if original.get('curl_command'):
         print(f"  Curl Command: {Fore.LIGHTBLACK_EX}{original['curl_command']}{Style.RESET_ALL}")


    # --- Print Enrichment Data ---
    cves_found = list(finding_data['exploits'].keys()) # Get CVEs for which we have enrichment

    if finding_data.get('osv_vulns'):
        print(f"\n  {Fore.YELLOW}OSV Database Findings:{Style.RESET_ALL}")
        for vuln in finding_data['osv_vulns']:
            print(f"    - ID: {vuln['id']} (Score: {vuln.get('severity_score', 'N/A')})")
            print(f"      Summary: {vuln['summary']}")
            # Optionally print affected packages/versions/references from OSV
            if vuln.get('references'):
                 print(f"      References: {', '.join(vuln['references'][:2])}...") # Show a few refs
            print()


    if finding_data.get('nvd_cves'):
         print(f"\n  {Fore.YELLOW}NVD CVE Check Results:{Style.RESET_ALL}")
         for cve_info in finding_data['nvd_cves']:
             print(f"    - {cve_info['id']} (Score: {cve_info['score']}, Severity: {cve_info['severity']})")
             print(f"      Description: {cve_info['description'][:100]}...") # Truncate description
             cves_found.append(cve_info['id']) # Ensure NVD CVEs are considered for exploit printing


    unique_cves = sorted(list(set(cves_found)))

    for cve_id in unique_cves:
         printed_cve_header = False
         def print_cve_header():
             nonlocal printed_cve_header
             if not printed_cve_header:
                 print(f"\n  --- Enrichment for {Fore.CYAN}{cve_id}{Style.RESET_ALL} ---")
                 printed_cve_header = True

         if finding_data['exploits'].get(cve_id):
             print_cve_header()
             print(f"  {Fore.RED}ExploitDB:{Style.RESET_ALL}")
             for exploit in finding_data['exploits'][cve_id]:
                 print(f"    - [{exploit.get('edb_id','N/A')}] {exploit.get('title', 'N/A')}")
                 print(f"      URL: {exploit.get('url', 'N/A')}")

         if finding_data['metasploit'].get(cve_id):
             print_cve_header()
             print(f"  {Fore.RED}Metasploit Modules:{Style.RESET_ALL}")
             for module in finding_data['metasploit'][cve_id]:
                 print(f"    - {module.get('name', 'N/A')} (Rank: {module.get('rank', 'N/A')})")
                 print(f"      Path: {module.get('path', 'N/A')}")

         if finding_data['vulners'].get(cve_id):
             print_cve_header()
             vuln_info = finding_data['vulners'][cve_id]
             print(f"  {Fore.YELLOW}Vulners Info:{Style.RESET_ALL}")
             print(f"    Score: {vuln_info.get('cvss_score', 'N/A')} ({vuln_info.get('severity', 'N/A')})")
             print(f"    Title: {vuln_info.get('title', 'N/A')}")
             if vuln_info.get('references'):
                 print(f"    References: {', '.join(vuln_info['references'][:2])}...") # Show a few refs
             if vuln_info.get('exploit_links'):
                  print(f"    Exploit Links: {', '.join(vuln_info['exploit_links'])}")



async def process_url(url, session, args, cve_cache):
    """Processes a single URL: Detect tech, run Nuclei, enrich results."""
    log.info(f"Processing URL: {url}")
    results = {'url': url, 'technologies': {}, 'errors': []}
    min_severity_level = SEVERITY_LEVELS.get(args.severity, 0)

    try:
        # --- Technology Detection ---
        detected_technologies = {}
        if not args.no_tech and not args.technology: # Skip Wappalyzer if specific tech or no-tech flag
            try:
                # Wappalyzer setup (sync, consider running in executor if it blocks heavily)
                from Wappalyzer import Wappalyzer, WebPage
                wappalyzer = Wappalyzer.latest()
                # Fetch webpage content using aiohttp for consistency
                page_content = await fetch_url(session, url)
                if not page_content or not isinstance(page_content, str):
                     raise ValueError("Failed to fetch webpage content for Wappalyzer")

                # Analyze with Wappalyzer (this part is synchronous)
                # To make fully async, Wappalyzer would need async support or run in executor
                webpage = WebPage(url, html=page_content, headers={}) # Basic usage
                detected_raw = wappalyzer.analyze_with_versions_and_categories(webpage)
                log.info(f"Detected {len(detected_raw)} technologies for {url}")

                for tech, info in detected_raw.items():
                     version = extract_tech_version(info)
                     detected_technologies[tech] = {'version': version, 'categories': info.get('categories', [])}
                     print(f"\n{Fore.GREEN}Detected: {tech}{Style.RESET_ALL} {Fore.YELLOW}{version or ''}{Style.RESET_ALL}")

            except ImportError:
                 log.warning("Wappalyzer not found. Skipping technology detection. Install with 'pip install python-Wappalyzer'")
                 args.no_tech = True # Force no-tech mode if import fails
            except Exception as e:
                log.error(f"Error during technology detection for {url}: {e}")
                results['errors'].append(f"Wappalyzer error: {e}")
                # Continue without tech detection if Wappalyzer fails

        results['technologies'] = detected_technologies

        # --- Nuclei Scanning ---
        nuclei_tasks = []
        tech_scan_map = {} # To map task index back to tech name

        if args.technology:
             # Scan only for the specified technology
             log.info(f"Running Nuclei specifically for technology: {args.technology}")
             task = asyncio.create_task(run_nuclei_scan_async(url, args.technology))
             nuclei_tasks.append(task)
             tech_scan_map[0] = args.technology # Map index 0 to this tech
        elif args.no_tech:
            # Run broad Nuclei scan if --no-tech is specified
            log.info(f"Running broad Nuclei scan (no technology focus) for {url}")
            task = asyncio.create_task(run_nuclei_scan_async(url))
            nuclei_tasks.append(task)
            tech_scan_map[0] = "Broad Scan"
        else:
            # Scan for each detected technology concurrently
            if detected_technologies:
                 log.info(f"Running Nuclei scans for {len(detected_technologies)} detected technologies...")
                 for i, (tech_name, tech_info) in enumerate(detected_technologies.items()):
                    task = asyncio.create_task(run_nuclei_scan_async(url, tech_name, tech_info.get('version')))
                    nuclei_tasks.append(task)
                    tech_scan_map[i] = tech_name # Map index i to this tech name
            else:
                 log.info("No technologies detected and --no-tech not specified. Running broad Nuclei scan.")
                 task = asyncio.create_task(run_nuclei_scan_async(url)) # Default broad scan
                 nuclei_tasks.append(task)
                 tech_scan_map[0] = "Broad Scan"


        nuclei_outputs = await asyncio.gather(*nuclei_tasks, return_exceptions=True)

        # --- Process and Enrich Nuclei Results ---
        all_findings_enriched = []
        enrichment_tasks = []

        for i, output in enumerate(nuclei_outputs):
            tech_name = tech_scan_map.get(i) # Get tech name corresponding to this output
            tech_info = detected_technologies.get(tech_name, {}) if tech_name and tech_name != "Broad Scan" else {}
            tech_version = tech_info.get('version')

            if isinstance(output, Exception):
                log.error(f"Nuclei scan task failed for {tech_name or 'Broad Scan'} on {url}: {output}")
                results['errors'].append(f"Nuclei failed for {tech_name or 'Broad Scan'}: {output}")
                continue
            if not output:
                log.info(f"No Nuclei findings for {tech_name or 'Broad Scan'} on {url}")
                continue

            findings = parse_nuclei_output(output)
            log.info(f"Found {len(findings)} Nuclei findings for {tech_name or 'Broad Scan'} on {url}")

            if findings:
                 print(f"\n--- Findings for {Fore.CYAN}{tech_name or 'Broad Scan'}{Style.RESET_ALL} on {url} ---")
                 # Schedule enrichment tasks for all findings of this tech
                 for finding in findings:
                      # Pass tech_name/version from Wappalyzer if available for better context
                      current_tech_name = tech_name if tech_name != "Broad Scan" else None
                      task = asyncio.create_task(
                          enrich_vulnerability_data(session, finding, current_tech_name, tech_version, cve_cache)
                      )
                      enrichment_tasks.append(task)


        # --- Gather Enrichment Results ---
        if enrichment_tasks:
            enriched_results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
            log.info(f"Finished enrichment for {len(enriched_results)} findings for {url}")
            for enriched_data in enriched_results:
                 if isinstance(enriched_data, Exception):
                      log.error(f"Enrichment task failed for {url}: {enriched_data}")
                      results['errors'].append(f"Enrichment failed: {enriched_data}")
                      continue
                 if enriched_data:
                    all_findings_enriched.append(enriched_data)
                    # Print results immediately after enrichment
                    print_enriched_finding(enriched_data, min_severity_level)


        results['findings'] = all_findings_enriched

    except Exception as e:
        log.exception(f"Unhandled exception processing URL {url}: {e}") # Log full traceback
        results['errors'].append(f"General error: {e}")

    return results


def parse_arguments():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description='Detect web technologies and run targeted Nuclei scans with CVE enrichment.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target URL to scan')
    group.add_argument('-f', '--file', help='File containing list of URLs/subdomains to scan')
    parser.add_argument('-o', '--output', help='Output file to save results (JSON format)')
    parser.add_argument(
        '-s', '--severity', choices=SEVERITY_LEVELS.keys(), default='info',
        help='Minimum severity level to report (default: info)'
    )
    parser.add_argument('--no-tech', action='store_true', help='Skip Wappalyzer technology detection and run broader Nuclei scans')
    parser.add_argument('--ignore-ssl', action='store_true', help='Ignore SSL certificate verification errors')
    parser.add_argument('-t', '--technology', help='Specify a single technology to scan for (e.g., "wordpress", "nginx"). Skips Wappalyzer.')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Number of concurrent URL/enrichment tasks (default: 10)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Validate concurrency
    if args.concurrency < 1:
        parser.error("Concurrency must be at least 1")

    return args

# --- Main Execution ---

async def main():
    """Main async function."""
    print(f"{Fore.MAGENTA}{banner}{Style.RESET_ALL}")
    args = parse_arguments()

    # --- Setup ---
    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug mode enabled.")

    # Check for Nuclei dependency
    if not shutil.which("nuclei"):
        log.critical("Nuclei command not found. Please install Nuclei and ensure it's in your system's PATH.")
        sys.exit(1)

    # Setup semaphore for concurrency control
    semaphore = asyncio.Semaphore(args.concurrency)
    # Use a single session for all requests
    connector = aiohttp.TCPConnector(limit=args.concurrency, ssl=not args.ignore_ssl) # Control connection pool and SSL verification
    timeout = aiohttp.ClientTimeout(total=120) # Set a total timeout for requests

    # Global cache for CVE enrichment data across all processed URLs in this run
    global_cve_cache = {}

    all_results = []
    start_time = datetime.now()

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        if args.url:
            # Process single URL
            async with semaphore: # Acquire semaphore slot
                 result = await process_url(args.url, session, args, global_cve_cache)
                 all_results.append(result)
        elif args.file:
            # Process URLs from file
            try:
                with open(args.file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')] # Ignore empty lines and comments
                log.info(f"Loaded {len(urls)} URLs from {args.file}")

                # --- Create and Run Processing Tasks ---
                tasks = []
                processed_urls = set() # Avoid duplicates from file/args
                valid_urls_to_process = [] # Keep a list of URLs we *will* process

                for raw_url in urls:
                    # Basic URL validation and scheme addition
                    try:
                        parsed = urlparse(raw_url)
                        if not parsed.scheme:
                            url_to_scan = f"https://{raw_url}" # Default to HTTPS
                            log.debug(f"Assuming HTTPS for '{raw_url}' -> {url_to_scan}")
                        elif parsed.scheme not in ['http', 'https']:
                             log.warning(f"Skipping invalid URL scheme: {raw_url}")
                             continue
                        else:
                            url_to_scan = raw_url

                        if url_to_scan in processed_urls:
                            log.debug(f"Skipping duplicate URL: {url_to_scan}")
                            continue
                        processed_urls.add(url_to_scan)
                        valid_urls_to_process.append(url_to_scan) # Add to the list for tqdm

                    except Exception as url_parse_err:
                         log.error(f"Failed to parse or prepare URL '{raw_url}': {url_parse_err}")

                # --- Create tasks for valid URLs ---
                for url_to_scan in valid_urls_to_process:
                    task = asyncio.create_task(process_url_with_semaphore(url_to_scan, session, args, semaphore, global_cve_cache))
                    tasks.append(task)

                # --- Execute tasks with progress bar ---
                log.info(f"Starting processing for {len(tasks)} unique URLs..." if tasks else "No valid URLs to process.")
                results_list = []
                if tasks:
                     # Use tqdm_asyncio.gather to show progress
                     results_list = await tqdm_asyncio.gather(
                         *tasks,
                         desc="Processing URLs",
                         total=len(tasks),
                         unit="URL",
                         ncols=100 # Adjust width as needed
                     )
                # else: # No need for else block, results_list is already []
                #    log.warning("No valid URLs found to process.")

                # --- Collect Results --- (Handle potential exceptions from gather)
                log.info("Collecting results...") # Log after gather finishes
                for i, res_or_exc in enumerate(results_list):
                     # Trying to get the URL back is tricky after gather, might need a different approach
                     # if mapping URL to result is critical.
                     if isinstance(res_or_exc, Exception):
                         # Log the exception, but associating with the specific URL is hard here.
                         log.error(f"A URL processing task failed with exception: {res_or_exc}")
                         # Optionally add a generic error entry
                         all_results.append({'url': f'unknown_task_{i}', 'errors': [f"Task failed: {res_or_exc}"], 'findings': []})
                     elif res_or_exc:
                         all_results.append(res_or_exc)
                     # else: No need to log if a task returned None intentionally

            except FileNotFoundError:
                log.critical(f"Error: Input file '{args.file}' not found.")
                sys.exit(1)
            except Exception as e:
                log.critical(f"Error reading or processing file '{args.file}': {e}")
                sys.exit(1)


    # --- Save Results ---
    if args.output:
        log.info(f"Saving results to {args.output}")
        # Filter results based on errors or empty findings if desired
        final_output_data = [res for res in all_results if res and (res.get('findings') or res.get('errors'))]
        try:
            with open(args.output, 'w') as f:
                json.dump(final_output_data, f, indent=2, default=str) # Use default=str for non-serializable types like datetime
            log.info(f"Successfully saved {len(final_output_data)} results to {args.output}")
        except IOError as e:
            log.error(f"Error writing output file {args.output}: {e}")
        except TypeError as e:
            log.error(f"Error serializing results to JSON: {e}")


    end_time = datetime.now()
    log.info(f"Scan finished in {end_time - start_time}")

async def process_url_with_semaphore(url, session, args, semaphore, cve_cache):
     """Wrapper to use semaphore with process_url"""
     async with semaphore:
         return await process_url(url, session, args, cve_cache)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
         log.critical(f"A critical error occurred: {e}", exc_info=True)
         sys.exit(1)
