import warnings
warnings.filterwarnings("ignore", category=UserWarning, message="pkg_resources is deprecated as an API*")
import requests
import ssl
import socket
import datetime
import os
import logging
import csv
from urllib.parse import urlparse
import re
import subprocess
import argparse
import urllib3
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False
    print("[!] Wappalyzer not available, using manual detection only")

def get_ssl_info(hostname):
    """Return SSL validity, expiry date, and certificate details."""
    try:
        # Skip SSL check for IP addresses (SNI requires domain)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            logger.warning(f"SSL check skipped for IP address: {hostname}")
            return {'valid': False, 'expiry': None, 'subject': None}
            
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z') if not_after else None
                now = datetime.datetime.utcnow()
                valid = expire_date and expire_date > now
                return {
                    'valid': valid,
                    'expiry': expire_date,
                    'subject': cert.get('subject', [])
                }
    except Exception as e:
        logger.warning(f"SSL check failed for {hostname}: {e}")
        return {'valid': False, 'expiry': None, 'subject': None}

def check_waf(url):
    """Detect WAF using HTTP headers, response content, and manual methods."""
    waf_detected = False
    waf_name = None
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        
        # Check headers for WAF signatures
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
            'Akamai': ['akamai', 'x-akamai', 'akamai-origin-hop'],
            'Imperva': ['x-iinfo', 'incapsula', 'visid_incap'],
            'F5_BIGIP': ['bigip', 'x-f5', 'f5-trace-id'],
            'Sucuri': ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
            'AWS_WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'ModSecurity': ['mod_security', 'modsecurity']
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        content = response.text.lower()
        
        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if any(sig in header_val for header_val in headers_lower.values()) or sig in content:
                    waf_detected = True
                    waf_name = waf
                    break
            if waf_detected:
                break

        # Manual testing: send suspicious payloads and check for block/altered responses
        if not waf_detected:
            test_payloads = [
                "' OR 1=1--", "<script>alert(1)</script>", "../../etc/passwd", 
                "UNION SELECT", "<img src=x onerror=alert(1)>"
            ]
            
            original_length = len(response.text)
            original_status = response.status_code
            
            for payload in test_payloads:
                try:
                    test_url = url
                    if "?" in url:
                        test_url += f"&test={payload}"
                    else:
                        test_url += f"?test={payload}"
                        
                    test_resp = requests.get(test_url, headers=headers, timeout=5, verify=False)
                    
                    # Check for WAF blocking patterns
                    if (test_resp.status_code in [403, 406, 501, 503] or 
                        "access denied" in test_resp.text.lower() or 
                        "blocked" in test_resp.text.lower() or
                        "security" in test_resp.text.lower() or
                        abs(len(test_resp.text) - original_length) > 1000):
                        waf_detected = True
                        waf_name = "Generic/Manual"
                        break
                except Exception:
                    continue

        # Try WafW00f integration if available
        if not waf_detected:
            try:
                result = subprocess.run(
                    ["wafw00f", url],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )
                output = result.stdout.lower()
                if "is behind" in output:
                    match = re.search(r'is behind (?:a |an )?([\w\s\-]+?) (?:web application firewall|waf)', output)
                    if match:
                        waf_detected = True
                        waf_name = match.group(1).strip().title()
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                logger.info(f"WafW00f not available or failed for {url}: {e}")

        return (1 if waf_detected else 0), (waf_name if waf_detected else None)
        
    except Exception as e:
        logger.error(f"WAF detection failed for {url}: {e}")
        return 0, None

def manual_tech_version(response, url):
    """Enhanced manual checks for technology and version detection."""
    techs = []
    
    server_headers = ['Server', 'X-Powered-By', 'X-Generator', 'X-CMS-Version', 
                     'X-Drupal-Cache', 'X-Varnish', 'X-Cache']
    
    for key in server_headers:
        value = response.headers.get(key, '')
        if value:
            tech_patterns = [
                r'([a-zA-Z0-9\-]+)[ /:v]([0-9][0-9\.\-_]+)',
                r'([a-zA-Z0-9\-]+)/([0-9][0-9\.\-_]+)',
                r'([a-zA-Z0-9\-]+)\s+([0-9][0-9\.\-_]+)'
            ]
            
            for pattern in tech_patterns:
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    tech = match.group(1)
                    version = match.group(2)
                    techs.append({'technology': tech, 'version': version, 'method': f'Header-{key}'})
                    break
            else:
                if re.match(r'^[a-zA-Z0-9\-]{2,}$', value):
                    techs.append({'technology': value, 'version': 'unknown', 'method': f'Header-{key}'})
                    
    # Meta generator tags
    meta_patterns = [
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']generator["\']',
    ]
    
    for pattern in meta_patterns:
        meta_matches = re.findall(pattern, response.text, re.IGNORECASE)
        for meta in meta_matches:
            tech_match = re.search(r'([a-zA-Z0-9\-]+)[ /:v]?([0-9][0-9\.\-_]+)?', meta)
            if tech_match:
                tech = tech_match.group(1)
                version = tech_match.group(2) if tech_match.group(2) else 'unknown'
                techs.append({'technology': tech, 'version': version, 'method': 'Meta-Generator'})

    # JavaScript/CSS framework detection
    js_css_patterns = [
        (r'jquery[/-]([0-9][0-9\.\-_]+)', 'jQuery'),
        (r'bootstrap[/-]([0-9][0-9\.\-_]+)', 'Bootstrap'),
        (r'angular[/-]([0-9][0-9\.\-_]+)', 'AngularJS'),
        (r'react[/-]([0-9][0-9\.\-_]+)', 'React'),
        (r'vue[/-]([0-9][0-9\.\-_]+)', 'Vue.js')
    ]
    
    for pattern, tech_name in js_css_patterns:
        matches = re.findall(pattern, response.text, re.IGNORECASE)
        for version in matches:
            techs.append({'technology': tech_name, 'version': version, 'method': 'Asset-Analysis'})

    # CMS Detection patterns
    cms_patterns = [
        (r'wp-content|wp-includes|wordpress', 'WordPress'),
        (r'/sites/default/files|drupal', 'Drupal'), 
        (r'/media/system|joomla', 'Joomla'),
        (r'typo3conf|typo3temp', 'TYPO3'),
        (r'skin/frontend|magento', 'Magento')
    ]
    
    for pattern, cms_name in cms_patterns:
        if re.search(pattern, response.text, re.IGNORECASE):
            # Try to find version
            version_patterns = [
                rf'{cms_name.lower()}[ /:v]?([0-9][0-9\.\-_]+)',
                r'version["\']?\s*[:=]\s*["\']?([0-9][0-9\.\-_]+)'
            ]
            
            version_found = False
            for ver_pattern in version_patterns:
                ver_match = re.search(ver_pattern, response.text, re.IGNORECASE)
                if ver_match:
                    techs.append({'technology': cms_name, 'version': ver_match.group(1), 'method': 'CMS-Detection'})
                    version_found = True
                    break
            
            if not version_found:
                techs.append({'technology': cms_name, 'version': 'unknown', 'method': 'CMS-Detection'})

    return techs

def detect_technologies(url):
    """Detect technologies and versions using Wappalyzer and manual methods."""
    results = []
    
    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        response = session.get(url, timeout=15, verify=False, allow_redirects=True)
        
        # Use Wappalyzer if available
        wapp_techs = {}
        if WAPPALYZER_AVAILABLE:
            try:
                webpage = WebPage(response.url, response.text, response.headers)
                wappalyzer = Wappalyzer.latest()
                wapp_techs = wappalyzer.analyze_with_versions_and_categories(webpage)
                for tech, info in wapp_techs.items():
                    version = info.get('version', ['unknown'])[0] if isinstance(info.get('version', ['unknown']), list) else info.get('version', 'unknown')
                    if not version or version == 'unknown':
                        manual_version = None
                        # Try to extract version from response text using regex
                        version_patterns = [
                            rf'{tech.lower()}[ /:v]?([0-9][0-9\.\-_]+)',
                            r'version["\']?\s*[:=]\s*["\']?([0-9][0-9\.\-_]+)'
                        ]
                        for ver_pattern in version_patterns:
                            ver_match = re.search(ver_pattern, response.text, re.IGNORECASE)
                            if ver_match:
                                manual_version = ver_match.group(1)
                                break
                        version = manual_version if manual_version else 'unknown'
                    results.append({
                        'technology': tech,
                        'version': str(version) if version else 'unknown',
                        'categories': ', '.join(info.get('categories', [])),
                        'confidence': info.get('confidence', 90) / 100.0,
                        'method': 'Wappalyzer'
                    })
            except Exception as e:
                logger.warning(f"Wappalyzer analysis failed for {url}: {e}")

        # Manual detection methods
        manual_results = manual_tech_version(response, url)
        for manual_tech in manual_results:
            already_found = any(
                t['technology'].lower() == manual_tech['technology'].lower() and t['version'] == manual_tech['version']
                for t in results
            )
            if not already_found:
                results.append({
                    'technology': manual_tech['technology'],
                    'version': manual_tech['version'],
                    'categories': '',
                    'confidence': 0.8,
                    'method': manual_tech['method']
                })

        # If no results found, add basic web server info
        if not results:
            server = response.headers.get('Server', 'Unknown')
            results.append({
                'technology': server if server != 'Unknown' else 'HTTP Server',
                'version': 'unknown',
                'categories': 'Web Servers',
                'confidence': 0.5,
                'method': 'Fallback'
            })

        return results
        
    except Exception as e:
        logger.error(f"Technology detection failed for {url}: {e}")
        return [{
            'technology': 'unknown', 
            'version': 'unknown', 
            'categories': '', 
            'confidence': 0.0, 
            'method': 'Error'
        }]

def extract_base_domain(url):
    """Extract base domain from URL"""
    try:
        if '://' in url:
            return url.split('://')[1].split('/')[0].split(':')[0]
        else:
            return url.split('/')[0].split(':')[0]
    except:
        return url

def main():
    print("Starting technology, SSL, and WAF scanning...")
    
    parser = argparse.ArgumentParser(description="Scan technologies, SSL, and WAF for URLs.")
    parser.add_argument("-i", "--input", type=str, default="active_subdomains_urls.txt", help="Input file with URLs")
    parser.add_argument("-c", "--csv", type=str, default="scan_results.csv", help="Output CSV file")
    parser.add_argument("-t", "--txt", type=str, default="scan_results_output.txt", help="Output TXT file")
    args = parser.parse_args()

    input_file = args.input
    scan_results_csv = args.csv
    output_file = args.txt

    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} not found")
        print(f"[!] Input file {input_file} not found")
        return

    # Read URLs from file
    with open(input_file, 'r', encoding='utf-8') as f:
        urls = []
        for line in f:
            line = line.strip()
            if line and (line.startswith('http://') or line.startswith('https://')):
                urls.append(line)

    if not urls:
        logger.error("No valid URLs found in input file")
        print("[!] No valid URLs found in input file")
        return

    print(f"[+] Found {len(urls)} URLs to scan")

    with open(scan_results_csv, 'w', encoding='utf-8', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'URL', 'Base Domain', 'Technology', 'Version', 'Categories', 
            'Confidence', 'Detection Method', 'SSL Valid', 'SSL Expiry', 
            'WAF Detected', 'WAF Name', 'Timestamp'
        ])

    # Initialize TXT output
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("Technology, SSL, and WAF Scan Results\n")
        out.write("=" * 60 + "\n\n")

    # Process each URL
    processed_count = 0
    for url in urls:
        try:
            print(f"[+] Scanning {url}...")
            
            parsed = urlparse(url)
            hostname = parsed.hostname
            base_domain = extract_base_domain(url)
            timestamp = datetime.datetime.now().isoformat()
            
            if not hostname:
                logger.warning(f"Invalid URL: {url}")
                continue

            # Detect technologies
            techs = detect_technologies(url)
            
            # Get SSL info
            ssl_info = get_ssl_info(hostname)
            ssl_valid = 'True' if ssl_info['valid'] else 'False'
            
            # Check WAF
            waf_detected, waf_name = check_waf(url)
            waf_detected_val = '1' if waf_detected else '0'
            
            # Write results for each technology found
            for tech in techs:
                with open(scan_results_csv, 'a', encoding='utf-8', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        url,
                        base_domain,
                        tech['technology'],
                        tech['version'],
                        tech['categories'],
                        tech['confidence'],
                        tech['method'],
                        ssl_valid,
                        ssl_info['expiry'],
                        waf_detected_val,
                        waf_name or 'None',
                        timestamp
                    ])
                
                # Write to text file
                with open(output_file, 'a', encoding='utf-8') as out:
                    out.write(f"URL: {url}\n")
                    out.write(f"  Base Domain: {base_domain}\n")
                    out.write(f"  Technology: {tech['technology']}\n")
                    out.write(f"  Version: {tech['version']}\n")
                    out.write(f"  Categories: {tech['categories']}\n")
                    out.write(f"  Detection Method: {tech['method']}\n")
                    out.write(f"  Confidence: {tech['confidence']:.2f}\n")
                    out.write(f"  SSL Valid: {ssl_valid} (Expiry: {ssl_info['expiry'] or 'N/A'})\n")
                    out.write(f"  WAF Detected: {waf_detected_val} (Name: {waf_name or 'None'})\n")
                    out.write(f"  Timestamp: {timestamp}\n")
                    out.write('-' * 50 + "\n")
            
            processed_count += 1
            
        except Exception as e:
            logger.error(f"Error processing URL {url}: {e}")
            print(f"[!] Error processing {url}: {e}")

    print(f"[+] Scanning completed. Processed {processed_count} URLs")
    print(f"[+] Results saved to {scan_results_csv} and {output_file}")

if __name__ == "__main__":
    main()