import argparse
import requests
import csv
import time
import logging
import os
import re
import json
from typing import Dict, List, Optional
from datetime import datetime
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CACHE_FILE = 'cve_cache.json'

VULN_TYPES = {
    "Remote Code Execution (RCE)": ["remote code execution", "rce", "execute arbitrary code", "arbitrary code execution"],
    "Privilege Escalation": ["privilege escalation", "gain elevated privileges", "escalate privileges"],
    "Authentication Bypass": ["authentication bypass", "bypass authentication", "unauthorized access", "login bypass"],
    "Arbitrary File Upload": ["arbitrary file upload", "upload arbitrary file", "unrestricted file upload"],
    "SQL Injection (SQLi)": ["sql injection", "sqli", "inject sql", "database injection"],
    "Command Injection": ["command injection", "inject command", "os command injection"],
    "Path Traversal": ["path traversal", "directory traversal", "traverse directories", "read arbitrary file"],
    "Cross-Site Scripting (XSS)": ["cross-site scripting", "xss", "inject script", "javascript injection"],
    "Denial of Service (DoS)": ["denial of service", "dos", "service disruption", "resource exhaustion"],
    "Open Redirect": ["open redirect", "url redirection", "unvalidated redirect"]
}

def detect_vuln_type(description: str) -> str:
    """Detect vulnerability type from description using keywords."""
    desc_lower = description.lower()
    for vuln_type, keywords in VULN_TYPES.items():
        for kw in keywords:
            if kw in desc_lower:
                return vuln_type
    return "Other"

def normalize_field(field: str) -> str:
    """Normalize technology/version fields for better matching."""
    return re.sub(r'[^a-zA-Z0-9.\-_]', '', field).lower()

class CVEFinder:
    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = None  # Set your API key here if available
        self.headers = {"apiKey": self.api_key} if self.api_key else {}
        self.requests_per_window = 50
        self.window_duration = 30  # seconds
        self.request_times = []
        self.cache = self._load_cache()
        self.cache_hits = 0
        self.cache_misses = 0

    def _load_cache(self) -> Dict:
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                    logger.info(f"Loaded {len(cache)} cached CVE entries")
                    return cache
            except Exception as e:
                logger.warning(f"Could not load cache: {e}")
        return {}

    def _save_cache(self):
        try:
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2)
            logger.info(f"Saved {len(self.cache)} CVE entries to cache")
        except Exception as e:
            logger.warning(f"Could not save cache: {e}")

    def _rate_limit(self):
        now = time.time()
        self.request_times = [req_time for req_time in self.request_times if now - req_time < self.window_duration]
        
        if len(self.request_times) >= self.requests_per_window:
            sleep_time = self.window_duration - (now - self.request_times[0]) + 1
            if sleep_time > 0:
                logger.info(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds.")
                print(f"[*] Rate limit - waiting {sleep_time:.1f}s...")
                time.sleep(sleep_time)
            self.request_times = self.request_times[1:]
        
        self.request_times.append(time.time())

    def fetch_nvd(self, tech: str, version: str, retries=3) -> Optional[List[Dict]]:
        """Fetch vulnerabilities for a given technology and version from NVD API with caching."""
        key = f"{tech}:{version}"
        
        # Check cache first
        if key in self.cache:
            self.cache_hits += 1
            logger.info(f"Cache hit for {key}")
            return self.cache[key]
        
        self.cache_misses += 1
        
        if not tech or not version or tech.lower() == "unknown" or version.lower() == "unknown":
            logger.warning("Empty or unknown technology/version provided, skipping NVD query.")
            return None
        
        for attempt in range(retries):
            try:
                self._rate_limit()
                params = {"keywordSearch": f"{tech} {version}"}
                
                logger.info(f"Querying NVD for {tech} {version} (attempt {attempt+1}/{retries})")
                response = requests.get(self.nvd_base_url, headers=self.headers, params=params, timeout=45)
                response.raise_for_status()
                
                data = response.json()
                vulns = []
                for vuln in data.get('vulnerabilities', []):
                    info = self._extract_nvd_info(vuln)
                    if info:
                        vulns.append(info)
                
                # Cache the result
                self.cache[key] = vulns
                
                # Periodically save cache
                if len(self.cache) % 10 == 0:
                    self._save_cache()
                
                return vulns
                
            except requests.exceptions.RequestException as e:
                logger.error(f"NVD API error for {tech} {version} (attempt {attempt+1}): {e}")
                if attempt < retries - 1:
                    wait_time = (2 ** attempt) * 2
                    logger.info(f"Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    logger.warning(f"NVD API failed for {tech} {version}. Falling back to CVE Details scraping.")
        
        return None

    def _extract_nvd_info(self, vuln_data: Dict) -> Optional[Dict]:
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            descriptions = cve.get('descriptions', [])
            description = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), 'No description available')
            vuln_type = detect_vuln_type(description)
            
            metrics = cve.get('metrics', {})
            severity = 'Unknown'
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get('cvssData', {})
                    severity = cvss_data.get('baseSeverity', 'Unknown')
                    break
            
            published = cve.get('published', 'Unknown')
            
            return {
                'cve_id': cve_id,
                'vulnerability_type': vuln_type,
                'severity': severity,
                'description': description[:200],
                'published': published
            }
        except Exception as e:
            logger.error(f"Error extracting NVD vulnerability info: {e}")
            return None

    def fetch_cvedetails(self, tech: str, version: str) -> List[Dict]:
        """Scrape CVE Details for CVEs matching technology and version."""
        results = []
        try:
            search_url = f"https://www.cvedetails.com/version-search.php?product={tech}&version={version}"
            resp = requests.get(search_url, timeout=30)
            resp.raise_for_status()
            
            soup = BeautifulSoup(resp.text, "html.parser")
            table = soup.find("table", {"id": "vulnslisttable"})
            
            if not table:
                logger.warning(f"No CVE table found for {tech} {version} on CVE Details.")
                return results
            
            for row in table.find_all("tr")[1:]:
                cols = row.find_all("td")
                if len(cols) < 2:
                    continue
                
                cve_id = cols[1].get_text(strip=True)
                description = cols[4].get_text(strip=True) if len(cols) > 4 else ""
                severity = cols[7].get_text(strip=True) if len(cols) > 7 else "Unknown"
                published = cols[10].get_text(strip=True) if len(cols) > 10 else "Unknown"
                vuln_type = detect_vuln_type(description)
                
                results.append({
                    'cve_id': cve_id,
                    'vulnerability_type': vuln_type,
                    'severity': severity,
                    'description': description[:200],
                    'published': published
                })
                
        except Exception as e:
            logger.error(f"Error scraping CVE Details for {tech} {version}: {e}")
        
        return results

    def get_vulnerabilities(self, tech: str, version: str) -> List[Dict]:
        """Get vulnerabilities for a technology and version, using NVD API or CVE Details scraping."""
        vulns = self.fetch_nvd(tech, version)
        if vulns is not None and len(vulns) > 0:
            return vulns
        # Fallback to scraping CVE Details
        return self.fetch_cvedetails(tech, version)

    def search_vulnerabilities_by_url(self, url_tech_map: Dict[str, List[Dict]], severity_filter=None) -> Dict[str, List[Dict]]:
        url_vuln_map = {}
        total_techs = sum(len(techs) for techs in url_tech_map.values())
        processed = 0
        
        print(f"[*] Processing {total_techs} technology/version combinations")
        
        for url, tech_list in url_tech_map.items():
            url_vuln_map[url] = []
            
            for tech in tech_list:
                processed += 1
                progress = (processed / total_techs) * 100
                
                tech_name = normalize_field(tech['Technology'])
                tech_version = normalize_field(tech['Version'])
                
                if processed % 5 == 0:
                    print(f"[*] Progress: {processed}/{total_techs} ({progress:.1f}%) - Cache hits: {self.cache_hits}, misses: {self.cache_misses}")
                
                if tech_name == 'unknown' or tech_version == 'unknown':
                    continue
                
                try:
                    vulns = self.get_vulnerabilities(tech_name, tech_version)
                    
                    if vulns:
                        for vuln_info in vulns:
                            vuln_info['technology'] = tech_name
                            vuln_info['version'] = tech_version
                            
                            if severity_filter and vuln_info['severity'].upper() not in severity_filter:
                                continue
                            
                            url_vuln_map[url].append(vuln_info)
                    else:
                        url_vuln_map[url].append({
                            'technology': tech_name,
                            'version': tech_version,
                            'cve_id': 'None',
                            'vulnerability_type': 'None',
                            'severity': 'None',
                            'description': 'None',
                            'published': 'None'
                        })
                        
                except Exception as e:
                    logger.error(f"Error processing {tech_name} {tech_version} for {url}: {e}")
                    url_vuln_map[url].append({
                        'technology': tech_name,
                        'version': tech_version,
                        'cve_id': 'Error',
                        'vulnerability_type': 'Error',
                        'severity': 'Error',
                        'description': str(e),
                        'published': 'Error'
                    })
        
        # Final cache save
        self._save_cache()
        print(f"[*] CVE scan complete - Cache hits: {self.cache_hits}, misses: {self.cache_misses}")
        
        return url_vuln_map

    def save_results_to_csv(self, url_vuln_map: Dict[str, List[Dict]], output_file: str):
        """Save vulnerability results to CSV file under each URL."""
        fieldnames = [
            'url', 'technology', 'version', 'cve_id', 'vulnerability_type', 'severity', 'description', 'published'
        ]
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                
                for url, vulns in url_vuln_map.items():
                    for vuln in vulns:
                        vuln_copy = vuln.copy()
                        vuln_copy['url'] = url
                        writer.writerow(vuln_copy)
            
            logger.info(f"Results saved to {output_file}")
            print(f"[+] Results saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving results to CSV: {e}")
            raise

def prepare_url_tech_map(scan_results_csv: str) -> Dict[str, List[Dict]]:
    url_tech_map = {}
    
    with open(scan_results_csv, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        
        for row in reader:
            tech = row['Technology'].strip()
            version = row['Version'].strip()
            url = row['URL'].strip()
            
            if tech.lower() == 'unknown' or version.lower() == 'unknown':
                continue
            if tech.isdigit() or len(tech) < 2:
                continue
            
            if url not in url_tech_map:
                url_tech_map[url] = []
            tech_entry = {'Technology': tech, 'Version': version}
            if tech_entry not in url_tech_map[url]:
                url_tech_map[url].append(tech_entry)
    
    return url_tech_map

def main():
    parser = argparse.ArgumentParser(description="Fetch CVEs for technologies and versions from scan results CSV.")
    parser.add_argument("-i", "--input", type=str, default="scan_results.csv", help="Input CSV file with scan results")
    parser.add_argument("-o", "--output", type=str, default="cve_scan_results.csv", help="Output CSV file for CVE results")
    parser.add_argument("--severity", nargs='*', help="Filter by severity (e.g., HIGH CRITICAL)")
    parser.add_argument("--clear-cache", action='store_true', help="Clear CVE cache before running")
    args = parser.parse_args()

    if args.clear_cache and os.path.exists(CACHE_FILE):
        os.remove(CACHE_FILE)
        print("[*] CVE cache cleared")

    input_file = args.input
    output_file = args.output
    severity_filter = [s.upper() for s in args.severity] if args.severity else None

    print(f"[*] Starting CVE analysis from {input_file}")
    start_time = time.time()
    
    url_tech_map = prepare_url_tech_map(input_file)
    print(f"[*] Found {len(url_tech_map)} URLs with technologies to analyze")
    
    finder = CVEFinder()
    url_vuln_map = finder.search_vulnerabilities_by_url(url_tech_map, severity_filter=severity_filter)
    finder.save_results_to_csv(url_vuln_map, output_file)
    
    elapsed = time.time() - start_time
    print(f"[+] CVE analysis completed in {elapsed/60:.1f} minutes")

if __name__ == "__main__":
    main()