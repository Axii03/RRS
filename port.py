import socket
from urllib.parse import urlparse
import os
import re
import concurrent.futures
import argparse
import subprocess
import logging
import time

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[!] python-nmap not available, using socket-based scanning")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def read_subdomains(file_path):
    """Read subdomains from file and resolve to IPs with caching"""
    print("[+] Reading subdomains and resolving IPs...")
    dns_cache = {}
    
    try:
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
            
        hosts = []
        failed_resolutions = 0
        
        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname or url.replace('http://', '').replace('https://', '').split('/')[0]
                
                if hostname:
                    if hostname in dns_cache:
                        ip = dns_cache[hostname]
                    else:
                        try:
                            ip = socket.gethostbyname(hostname)
                            dns_cache[hostname] = ip
                            logger.info(f"Resolved {hostname} -> {ip}")
                        except socket.gaierror as e:
                            failed_resolutions += 1
                            logger.warning(f"Could not resolve hostname: {hostname} - {e}")
                            continue
                    
                    hosts.append((hostname, ip))
                    
            except Exception as e:
                logger.warning(f"Error processing URL {url}: {e}")
                continue
        
        print(f"[*] Successfully resolved {len(hosts)} hosts ({failed_resolutions} failed)")
        logger.info(f"Successfully resolved {len(hosts)} hosts")
        return hosts
        
    except FileNotFoundError:
        logger.error(f"File {file_path} not found.")
        print(f"[!] Error: File {file_path} not found.")
        return []
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        print(f"[!] Error reading file: {e}")
        return []

def scan_port_socket(ip, port, timeout=2):
    """Scan a single port using socket connection with reduced timeout"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def scan_ports_manual(hostname, ip, port_list, timeout=2):
    """Manual port scanning using socket connections with batch processing"""
    open_ports = []
    
    logger.info(f"Manual scanning {hostname} ({ip}) for {len(port_list)} ports")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port_socket, ip, port, timeout): port 
            for port in port_list
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
                    logger.info(f"Port {port} open on {hostname}")
            except Exception as e:
                logger.warning(f"Error scanning port {port} on {hostname}: {e}")
    
    return open_ports

def scan_single_host_nmap(nm, hostname, ip, port_list):
    """Scan single host using nmap with optimized settings"""
    try:
        ports_str = ','.join(map(str, port_list))
        logger.info(f"Nmap scanning {hostname} ({ip}) for ports: {ports_str}")
        
        # Optimized Nmap scan with faster timing
        nm.scan(ip, arguments=f'-sS -T4 -p {ports_str} --open --host-timeout 120s --max-retries 2')
        
        open_ports = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                scanned_ports = nm[ip][proto].keys()
                for port in scanned_ports:
                    state = nm[ip][proto][port]['state']
                    if state == 'open':
                        open_ports.append(port)
                        logger.info(f"Port {port} open on {hostname}")
        
        return open_ports
        
    except Exception as e:
        logger.error(f"Nmap scan error for {hostname}: {e}")
        return []

def scan_single_host(hostname, ip, port_list):
    """Scan single host - use nmap if available, otherwise manual"""
    if NMAP_AVAILABLE:
        try:
            nm = nmap.PortScanner()
            return scan_single_host_nmap(nm, hostname, ip, port_list)
        except Exception as e:
            logger.warning(f"Nmap failed for {hostname}, falling back to manual: {e}")
            return scan_ports_manual(hostname, ip, port_list)
    else:
        return scan_ports_manual(hostname, ip, port_list)

def scan_ports(hosts, ports, output_file):
    """Scan ports on all hosts with progress tracking and batching"""
    print(f"[+] Starting port scan for {len(hosts)} hosts...")
    print(f"[+] Target ports: {ports}")
    
    results = []
    total_hosts = len(hosts)
    
    batch_size = 50
    batches = [hosts[i:i+batch_size] for i in range(0, len(hosts), batch_size)]
    overall_completed = 0
    
    for batch_num, batch in enumerate(batches, 1):
        print(f"[*] Processing batch {batch_num}/{len(batches)} ({len(batch)} hosts)")
        batch_start = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_host = {
                executor.submit(scan_single_host, hostname, ip, ports): (hostname, ip)
                for hostname, ip in batch
            }
            
            for future in concurrent.futures.as_completed(future_to_host):
                hostname, ip = future_to_host[future]
                overall_completed += 1
                
                try:
                    open_ports = future.result()
                    
                    host_result = f"Host: {hostname} ({ip})\n"
                    if open_ports:
                        for port in open_ports:
                            host_result += f"Port {port}\n"
                        print(f"[+] {hostname}: {len(open_ports)} open ports found")
                    else:
                        print(f"[+] {hostname}: No open ports found")
                        
                    results.append(host_result)
                    
                    # Progress update
                    progress = (overall_completed / total_hosts) * 100
                    print(f"[*] Overall progress: {overall_completed}/{total_hosts} ({progress:.1f}%)")
                    
                except Exception as e:
                    logger.error(f"Error scanning {hostname}: {e}")
                    results.append(f"Host: {hostname} ({ip})\nError: {e}\n")
        
        batch_elapsed = time.time() - batch_start
        print(f"[*] Batch {batch_num} completed in {batch_elapsed:.1f} seconds")
        
        if batch_num < len(batches):
            time.sleep(0.5)

    # Save results
    try:
        with open(output_file, 'w') as f:
            for result in results:
                f.write(result + "\n")
        
        print(f"[+] Port scan completed. Results saved to {output_file}")
        logger.info(f"Port scan results saved to {output_file}")
        
    except Exception as e:
        logger.error(f"Error saving results to {output_file}: {e}")
        print(f"[!] Error saving results: {e}")

def main():
    print("[+] Starting port scanning...")
    
    parser = argparse.ArgumentParser(description="Scan specified ports on hosts from a file.")
    parser.add_argument("-i", "--input", type=str, default="active_subdomains_urls.txt", 
                       help="Input file with subdomain URLs")
    parser.add_argument("-o", "--output", type=str, default="nmap_scan_results.txt",
                       help="Output file for port scan results")
    parser.add_argument("-p", "--ports", type=str, 
                       default="21,22,25,53,80,135,139,443,445,993,995,1433,3389,5985,5986",
                       help="Comma-separated list of ports to scan")
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output
    
    try:
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        else:
            ports = [21, 22, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3389, 5985, 5986]
    except ValueError as e:
        logger.error(f"Invalid port specification: {e}")
        print(f"[!] Invalid port specification: {e}")
        return

    # Check if input file exists
    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} not found")
        print(f"[!] Input file {input_file} not found")
        return

    # Read and resolve hosts
    start_time = time.time()
    hosts = read_subdomains(input_file)
    
    if not hosts:
        print("[!] No valid hosts to scan.")
        return

    print(f"[+] Loaded {len(hosts)} hosts for scanning")
    print(f"[+] Scanning {len(ports)} ports per host")
    print(f"[+] Estimated time: {(len(hosts) * len(ports) * 0.1) / 60:.1f} minutes")
    
    # Start port scanning
    scan_ports(hosts, ports, output_file)
    
    elapsed = time.time() - start_time
    print(f"[+] Total scan time: {elapsed/60:.1f} minutes")

if __name__ == "__main__":
    main()