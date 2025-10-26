import subprocess
import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

NON_WEB_PATTERNS = [
    r'^mail\d*\.', r'^smtp\d*\.', r'^pop\d*\.', r'^imap\d*\.',
    r'^mx\d*\.', r'^webmail\d*\.', r'^email\d*\.',
    r'^ns\d+\.', r'^dns\d*\.', r'^nameserver\d*\.',
    r'^_dmarc\.', r'^_domainkey\.', r'^.*\._domainkey\.',
    r'^dkim\.', r'^spf\.',
    r'^autoconfig\.', r'^autodiscover\.', r'^_autodiscover\.',
    r'^cdn\d*\.', r'^static\d*\.', r'^assets\d*\.',
    r'^img\d*\.', r'^images\d*\.', r'^media\d*\.', r'^files\d*\.',
    r'^ftp\d*\.', r'^ftps\d*\.', r'^sftp\d*\.',
    r'^vpn\d*\.', r'^remote\d*\.', r'^rdp\d*\.',
    r'^monitor\d*\.', r'^monitoring\d*\.', r'^logs\d*\.', r'^syslog\d*\.',
    r'^db\d*\.', r'^database\d*\.', r'^mysql\d*\.', r'^postgres\d*\.',
    r'^mongo\d*\.', r'^redis\d*\.',
    r'^backup\d*\.', r'^bak\d*\.', r'^storage\d*\.',
    r'^localhost\.', r'^internal\d*\.', r'^intranet\d*\.'
]

def is_web_subdomain(subdomain):
    """
    Filter out non-web subdomains to reduce unnecessary checks.
    Returns True if subdomain is likely a web service.
    """
    subdomain_lower = subdomain.lower()
    
    # Check against non-web patterns
    for pattern in NON_WEB_PATTERNS:
        if re.match(pattern, subdomain_lower):
            return False
    
    # Additional checks for asset file extensions (shouldn't be subdomains)
    if subdomain_lower.endswith(('.jpg', '.png', '.gif', '.css', '.js', '.svg', '.ico', 
                                  '.woff', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz')):
        return False
    
    # Filter out IP addresses (should be hostnames)
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', subdomain_lower):
        return False
    
    return True

def run_amass(domain, output_file, resolvers_file=None, dns_qps=150, timeout=10, wordlist=None):
    try:
        print(f"[*] Running Amass (passive) for domain: {domain}")
        cmd = ["amass", "enum", "-passive", "-d", domain, "-o", output_file]
        if resolvers_file and os.path.isfile(resolvers_file):
            cmd.extend(["-rf", resolvers_file])
        cmd.extend(["-dns-qps", str(dns_qps)])
        cmd.extend(["-timeout", str(timeout)])
        if wordlist and os.path.isfile(wordlist):
            cmd.extend(["-w", wordlist])
        
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
        print("[*] Amass passive scan completed.")
    except subprocess.TimeoutExpired:
        print("[!] Amass timed out after 10 minutes - using partial results")
    except subprocess.CalledProcessError as e:
        print(f"[!] Amass failed: {e.stderr}")
        # Don't exit - continue with partial results
    except FileNotFoundError:
        print("[!] Amass not found. Please install Amass and ensure it's in your PATH.")
        sys.exit(1)

def check_subdomain_httpx(url):
    try:
        result = subprocess.run(
            ["httpx", "-silent", "-no-color", "-timeout", "10", "-status-code", "-title", "-u", url],  # Increased from 5
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            timeout=15  # Overall timeout for httpx
        )
        if result.stdout.strip():
            return result.stdout.strip().split()[0]
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout checking {url}")
        return None
    except UnicodeDecodeError as e:
        print(f"[!] Unicode decode error for {url}: {e}")
        return None
    return None

def run_httpx_parallel(input_file, output_file, max_workers=150):
    """
    Check active subdomains with httpx in parallel with optimized settings.
    Increased workers from 50 to 150 for faster processing.
    """
    print(f"[*] Checking active subdomains with httpx (parallel workers: {max_workers})...")
    
    with open(input_file, "r", encoding="utf-8") as infile:
        urls = []
        for line in infile:
            match = re.match(r'^(https?://[^\s]+)', line.strip())
            if match:
                urls.append(match.group(1))
    
    total_urls = len(urls)
    print(f"[*] Total URLs to check: {total_urls}")
    
    if total_urls == 0:
        print("[!] No URLs to check")
        open(output_file, 'w').close()
        return
    
    active = set()
    completed = 0
    start_time = time.time()
    
    # Single parallel execution (removed batch processing overhead)
    print(f"[*] Starting parallel verification with {max_workers} workers...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_subdomain_httpx, url): url for url in urls}
        
        for future in as_completed(future_to_url):
            completed += 1
            
            # Progress indicator every 25 URLs (reduced from 10 for less output)
            if completed % 25 == 0:
                elapsed = time.time() - start_time
                progress = (completed / total_urls) * 100
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_urls - completed) / rate if rate > 0 else 0
                print(f"[*] Progress: {completed}/{total_urls} ({progress:.1f}%) | "
                      f"Rate: {rate:.1f} URLs/sec | ETA: {eta/60:.1f} min")
            
            result = future.result()
            if result:
                active.add(result)
                print(f"[+] Active: {result}")
    
    # Write results
    with open(output_file, "w", encoding="utf-8") as out:
        for url in sorted(active):
            out.write(url + "\n")
    
    elapsed = time.time() - start_time
    print(f"[*] Active subdomains saved to {output_file}")
    print(f"[*] Found {len(active)} active subdomains out of {total_urls} checked")
    print(f"[*] Verification completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"[*] Average rate: {total_urls/elapsed:.1f} URLs/second")

def filter_urls_from_file(input_file, output_file):
    seen = set()
    count = 0
    with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8") as outfile:
        for line in infile:
            match = re.match(r'^(https?://[^\s]+)', line.strip())
            if match:
                url = match.group(1)
                if url not in seen:
                    outfile.write(url + "\n")
                    seen.add(url)
                    count += 1
    print(f"[*] Filtered {count} unique URLs from {input_file}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(__file__)} <domain|all_subdomains_urls.txt> [resolvers.txt] [wordlist.txt]")
        sys.exit(1)

    arg1 = sys.argv[1]
    resolvers_file = sys.argv[2] if len(sys.argv) > 2 else None
    wordlist = sys.argv[3] if len(sys.argv) > 3 else None

    all_subdomains_file = "all_subdomains.txt"
    all_subdomains_urls_file = "all_subdomains_urls.txt"
    filtered_urls_file = "filtered_urls.txt"
    active_subdomains_urls_file = "active_subdomains_urls.txt"

    try:
        if os.path.isfile(arg1):
            print(f"[*] Filtering URLs from {arg1}")
            filter_urls_from_file(arg1, filtered_urls_file)
            run_httpx_parallel(filtered_urls_file, active_subdomains_urls_file)
        else:
            domain = arg1
            print(f"[*] Starting subdomain enumeration for {domain}")
            print(f"[+] Optimizations: 150 parallel workers + smart pre-filtering")
            start_time = time.time()
            
            run_amass(domain, all_subdomains_file, resolvers_file=resolvers_file, wordlist=wordlist)
            
            # Check if we got any results
            if not os.path.exists(all_subdomains_file) or os.path.getsize(all_subdomains_file) == 0:
                print("[!] No subdomains found by Amass")
                # Create empty files to prevent downstream errors
                open(active_subdomains_urls_file, 'w').close()
                return
            
            # Read and filter subdomains
            print(f"[*] Filtering non-web subdomains...")
            subdomains = []
            filtered_count = 0
            
            with open(all_subdomains_file, "r", encoding="utf-8") as infile:
                for line in infile:
                    sub = line.strip()
                    if sub:
                        if is_web_subdomain(sub):
                            subdomains.append(sub)
                        else:
                            filtered_count += 1
            
            print(f"[*] Filtered out {filtered_count} non-web subdomains")
            print(f"[*] Remaining {len(subdomains)} web-likely subdomains")
            
            if len(subdomains) == 0:
                print("[!] No web-likely subdomains found after filtering")
                open(active_subdomains_urls_file, 'w').close()
                return
            
            # Generate URLs (both http and https)
            urls = set()
            for sub in subdomains:
                urls.add(f"http://{sub}")
                urls.add(f"https://{sub}")
            
            print(f"[*] Generated {len(urls)} URLs from filtered subdomains")
            
            with open(all_subdomains_urls_file, "w", encoding="utf-8") as outfile:
                for url in sorted(urls):
                    outfile.write(url + "\n")

            # Verify active subdomains with optimized parallel processing
            run_httpx_parallel(all_subdomains_urls_file, active_subdomains_urls_file, max_workers=150)
            
            elapsed = time.time() - start_time
            print(f"\n[+] Subdomain discovery completed in {elapsed/60:.1f} minutes")
            print(f"[+] Optimizations applied: 150 workers + pre-filtering")
            
    except Exception as e:
        print(f"[!] Error in main: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()