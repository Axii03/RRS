import argparse
import csv
import json
import os
import math
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from datetime import datetime

class RRSCalculator:
    def __init__(self):
        self.R = 8.0
        
        self.normalized_scores = {
            'PORT_445': 9.35,
            'PORT_3389': 9.83,
            'PORT_135': 8.25,
            'PORT_1433': 6.95,
            'PORT_5985': 6.80,
            'PORT_5986': 6.80,
            'PORT_21': 5.40,
            'PORT_139': 7.20,
            'PORT_25': 4.43,
            'PORT_53': 4.30,
            'REMOTE_CODE_EXECUTION': 9.17,
            'PRIVILEGE_ESCALATION': 8.08,
            'AUTHENTICATION_BYPASS': 7.03,
            'ARBITRARY_FILE_UPLOAD': 8.95,
            'SQL_INJECTION': 5.81,
            'COMMAND_INJECTION': 6.35,
            'PATH_TRAVERSAL': 4.83,
            'CROSS_SITE_SCRIPTING': 5.58,
            'DENIAL_OF_SERVICE': 3.31,
            'OPEN_REDIRECT': 6.85,
            'WEB_APPLICATION': 7.73,
            'SSL_CERTIFICATES': 7.73
        }

    def load_data(self) -> Tuple[Dict, Dict, Dict, Dict]:
        port_data = self._load_port_data()
        vuln_data = self._load_vulnerability_data()
        admin_data = self._load_admin_panel_data()
        exploit_data = self._load_exploit_data()
        
        return port_data, vuln_data, admin_data, exploit_data

    def _load_port_data(self) -> Dict:
        """Load port scan results from nmap_scan_results.txt"""
        port_data = {}
        if not os.path.exists('nmap_scan_results.txt'):
            print("Warning: nmap_scan_results.txt not found")
            return port_data
            
        try:
            with open('nmap_scan_results.txt', 'r') as f:
                content = f.read()
                current_host = None
                
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('Host:'):
                        # Extract hostname from "Host: hostname (ip)"
                        parts = line.split()
                        if len(parts) >= 2:
                            current_host = parts[1]
                            port_data[current_host] = []
                    elif line.startswith('Port') and current_host:
                        # Extract port info from "Port 22/tcp: open (ssh)"
                        try:
                            port_info = line.split(':')[0].replace('Port ', '')
                            port_num = port_info.split('/')[0]
                            port_data[current_host].append(int(port_num))
                        except (ValueError, IndexError):
                            continue
        except Exception as e:
            print(f"Error loading port data: {e}")
            
        return port_data

    def _load_vulnerability_data(self) -> Dict:
        """Load vulnerability data from cve_scan_results.csv"""
        vuln_data = defaultdict(list)
        if not os.path.exists('cve_scan_results.csv'):
            print("Warning: cve_scan_results.csv not found")
            return dict(vuln_data)
            
        try:
            with open('cve_scan_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = row.get('url', '')
                    vuln_type = row.get('vulnerability_type', '')
                    severity = row.get('severity', '')
                    cve_id = row.get('cve_id', '')
                    
                    if url and cve_id and cve_id != 'None':
                        vuln_data[url].append({
                            'type': vuln_type,
                            'severity': severity,
                            'cve_id': cve_id
                        })
        except Exception as e:
            print(f"Error loading vulnerability data: {e}")
            
        return dict(vuln_data)

    def _load_admin_panel_data(self) -> Dict:
        """Load admin panel exposure data"""
        admin_data = {}
        if not os.path.exists('exposed_admin_panels.txt'):
            print("Warning: exposed_admin_panels.txt not found")
            return admin_data
            
        try:
            with open('exposed_admin_panels.txt', 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        base_url = self._extract_base_url(url)
                        admin_data[base_url] = True
        except Exception as e:
            print(f"Error loading admin panel data: {e}")
            
        return admin_data

    def _load_exploit_data(self) -> Dict:
        """Load exploit availability data"""
        exploit_data = {}
        if not os.path.exists('exploit_results.json'):
            print("Warning: exploit_results.json not found")
            return exploit_data
            
        try:
            with open('exploit_results.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                for cve_id, exploits in data.items():
                    exploit_data[cve_id] = len(exploits) > 0
        except Exception as e:
            print(f"Error loading exploit data: {e}")
            
        return exploit_data

    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from full URL"""
        if '://' in url:
            return url.split('://')[1].split('/')[0]
        return url.split('/')[0]

    def _get_port_score(self, ports: List[int]) -> Tuple[float, List[Dict]]:
        """Calculate port-based risk scores and return detailed breakdown"""
        if not ports:
            return 0.0, []
            
        port_details = []
        max_impact = 0.0
        
        for port in ports:
            port_key = f'PORT_{port}'
            if port_key in self.normalized_scores:
                impact = self.normalized_scores[port_key]
            else:
                if port in [21, 22, 1433, 3306, 3389]:
                    impact = 8.0
                elif port in [80, 443, 25, 53]:
                    impact = 5.0
                else:
                    impact = 3.0
            service_names = {
                21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 443: 'HTTPS', 139: 'NetBIOS',
                1433: 'MS-SQL', 3306: 'MySQL', 3389: 'RDP'
            }
            service = service_names.get(port, 'Unknown')
            
            port_details.append({
                'port': port,
                'service': service,
                'impact_score': impact
            })
            
            max_impact = max(max_impact, impact)
        
        return max_impact, port_details

    def _get_vulnerability_score(self, vulnerabilities: List[Dict], exploit_data: Dict) -> Tuple[float, List[Dict], List[str]]:
        """Calculate vulnerability-based risk scores with exploit information"""
        if not vulnerabilities:
            return 0.0, [], []
            
        vuln_details = []
        exploitable_cves = []
        max_impact = 0.0
        
        for vuln in vulnerabilities:
            vuln_type = vuln['type'].upper().replace(' ', '_').replace('(', '').replace(')', '')
            cve_id = vuln['cve_id']
            
            # Check if exploit is available
            has_exploit = exploit_data.get(cve_id, False)
            if has_exploit:
                exploitable_cves.append(cve_id)
            
            # Get impact score
            if vuln_type in self.normalized_scores:
                impact = self.normalized_scores[vuln_type]
            else:
                # Default scores based on severity
                severity = vuln['severity'].lower()
                if severity == 'critical':
                    impact = 9.0
                elif severity == 'high':
                    impact = 7.5
                elif severity == 'medium':
                    impact = 5.0
                else:
                    impact = 3.0
            
            vuln_details.append({
                'cve_id': cve_id,
                'type': vuln['type'],
                'severity': vuln['severity'],
                'impact_score': impact,
                'has_exploit': has_exploit
            })
            
            max_impact = max(max_impact, impact)
        
        return max_impact, vuln_details, exploitable_cves

    def _calculate_likelihood(self, port_max_impact: float, vuln_max_impact: float, 
                            admin_impact: float, exploit_available: bool) -> Dict:
        max_category_impact = max(port_max_impact, vuln_max_impact, admin_impact)
        B = 1 if exploit_available else 0
        raw_likelihood = (max_category_impact + B * 10) / 2
        
        return {
            'port_max_impact': port_max_impact,
            'vuln_max_impact': vuln_max_impact,
            'admin_impact': admin_impact,
            'exploit_factor_B': B,
            'max_category_impact': max_category_impact,
            'raw_likelihood_1_10': raw_likelihood  # 1-10 scale
        }

    def _calculate_mitigation_factor(self, has_waf: bool, has_ssl: bool, waf_name: str = None) -> Dict:
        M_waf = 6.85 if has_waf else 0.0
        M_ssl = 7.29 if has_ssl else 0.0
        MI = (M_waf + M_ssl) / 2
        
        return {
            'waf': {'present': has_waf, 'name': waf_name},
            'ssl': has_ssl,
            'mitigation_factor': MI / 10.0
        }

    def calculate_rrs_detailed(self, url: str, port_data: Dict, vuln_data: Dict, 
                              admin_data: Dict, exploit_data: Dict, scan_data: Dict) -> Optional[Dict]:
        """Calculate detailed Ransomware Risk Score for a given URL"""
        hostname = self._extract_base_url(url)
        
        # Get data for this URL/hostname
        ports = port_data.get(hostname, [])
        vulnerabilities = vuln_data.get(url, [])
        has_admin = admin_data.get(hostname, False)
        
        # Get WAF and SSL info from scan results
        has_waf = False
        has_ssl = False
        waf_name = None
        if url in scan_data:
            for entry in scan_data[url]:
                if entry.get('WAF Detected', 0) == 1 or entry.get('WAF Detected') == '1':
                    has_waf = True
                    waf_name = entry.get('WAF Name', 'Unknown')
                if entry.get('SSL Valid', False) or entry.get('SSL Valid') == 'True':
                    has_ssl = True
        
        # If no risk factors present, return None (no output)
        if not ports and not vulnerabilities and not has_admin:
            return None
        
        # Calculate component scores
        port_max_impact, port_details = self._get_port_score(ports)
        vuln_max_impact, vuln_details, exploitable_cves = self._get_vulnerability_score(vulnerabilities, exploit_data)
        admin_impact = 6.42 if has_admin else 0.0  # From documentation

        # --- NEW TOTAL IMPACT CALCULATION ---
        avg_port_impact = (sum([p['impact_score'] for p in port_details]) / len(port_details)) if port_details else 0.0
        avg_vuln_impact = (sum([v['impact_score'] for v in vuln_details]) / len(vuln_details)) if vuln_details else 0.0
        I_total = (avg_port_impact * 0.4) + (avg_vuln_impact * 0.4) + (admin_impact * 0.2)
        I_total = round(I_total, 2)
        # -------------------------------------

        # Check for exploits
        exploit_available = len(exploitable_cves) > 0
        
        # Calculate likelihood
        likelihood_details = self._calculate_likelihood(port_max_impact, vuln_max_impact, admin_impact, exploit_available)
        L = likelihood_details['raw_likelihood_1_10']  # Use 1-10 scale directly
        
        # Calculate mitigation
        security_controls = self._calculate_mitigation_factor(has_waf, has_ssl, waf_name)
        Mi = security_controls['mitigation_factor']
        
        # Calculate RRS using formula: RRS = ((I_total × L) / 10 - Mi)
        rrs_component = (I_total * L) / 10
        rrs = rrs_component - Mi

        # Ensure RRS is not negative
        rrs = max(rrs, 0.0)
        rrs = round(rrs, 2)
        
        return {
            'url': url,
            'rrs_score': rrs,
            'risk_level': self._get_risk_level(rrs),
            'calculation_details': {
                'ports': {
                    'found': ports,
                    'impact_score': port_max_impact,
                    'individual_scores': port_details,
                    'average_impact': avg_port_impact
                },
                'vulnerabilities': {
                    'found': len(vulnerabilities),
                    'impact_score': vuln_max_impact,
                    'details': vuln_details,
                    'exploitable_cves': exploitable_cves,
                    'average_impact': avg_vuln_impact
                },
                'admin_panel': {
                    'exposed': has_admin,
                    'impact_score': admin_impact
                },
                'security_controls': security_controls,
                'formula_breakdown': {
                    # Removed regional_factor_R
                    'total_impact_I': I_total,
                    'likelihood_L': L,
                    'mitigation_Mi': Mi,
                    'rrs_calculation': f"(({I_total} × {L}) / 10 - {Mi}) = {rrs}",
                    'likelihood_details': likelihood_details
                }
            }
        }

    def _load_scan_data(self) -> Dict:
        """Load scan results for WAF and SSL information"""
        scan_data = defaultdict(list)
        if not os.path.exists('scan_results.csv'):
            print("Warning: scan_results.csv not found")
            return dict(scan_data)
            
        try:
            with open('scan_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = row.get('URL', '')
                    if url:
                        scan_data[url].append(row)
        except Exception as e:
            print(f"Error loading scan data: {e}")
            
        return dict(scan_data)

    def process_all_urls(self, output_csv='rrs_results.csv', output_txt='rrs_calculation_breakdown.txt'):
        """Process all URLs and calculate RRS scores"""
        # Load all data
        port_data, vuln_data, admin_data, exploit_data = self.load_data()
        scan_data = self._load_scan_data()
        
        print(f"Loaded data:")
        print(f"  Port data: {len(port_data)} hosts")
        print(f"  Vulnerability data: {len(vuln_data)} URLs")
        print(f"  Admin panel data: {len(admin_data)} hosts")
        print(f"  Exploit data: {len(exploit_data)} CVEs")
        print(f"  Scan data: {len(scan_data)} URLs")
        
        # Get all unique URLs
        all_urls = set()
        
        # Add URLs from vulnerability data
        all_urls.update(vuln_data.keys())
        
        # Add URLs from active subdomains
        if os.path.exists('active_subdomains_urls.txt'):
            with open('active_subdomains_urls.txt', 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        all_urls.add(url)
        
        print(f"DEBUG - Total unique URLs to process: {len(all_urls)}")
        
        results = []
        detailed_results = []
        
        for url in sorted(all_urls):
            detailed_result = self.calculate_rrs_detailed(url, port_data, vuln_data, admin_data, exploit_data, scan_data)
            
            # Only include results with RRS score >= 1.0
            if detailed_result is not None and detailed_result['rrs_score'] >= 1.0:
                results.append({
                    'url': detailed_result['url'],
                    'rrs_score': detailed_result['rrs_score'],
                    'risk_level': detailed_result['risk_level']
                })
                detailed_results.append(detailed_result)
        
        # Sort by RRS score (highest first)
        results.sort(key=lambda x: x['rrs_score'], reverse=True)
        detailed_results.sort(key=lambda x: x['rrs_score'], reverse=True)
        
        # Output results
        self._output_results(results, detailed_results, output_csv, output_txt)

        # Save filtered results (RRS >= 1) to url_risk_data.json for Flask
        with open('url_risk_data.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        return results

    def _output_results(self, results: List[Dict], detailed_results: List[Dict], csv_filename='rrs_results.csv', calc_filename='rrs_calculation_breakdown.txt'):
        """Output results to console and files"""
        if not results:
            print("No URLs with significant risk found.")
            return
            
        print(f"\nRansomware Risk Score (RRS) Results")
        print("=" * 60)
        print(f"{'URL':<40} {'RRS Score':<12} {'Risk Level'}")
        print("-" * 60)
        
        for result in results:
            print(f"{result['url']:<40} {result['rrs_score']:<12} {result['risk_level']}")
        
        # Save to CSV file with comprehensive details
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'rrs_score', 'risk_level', 'ports', 'vulnerabilities', 'admin_panel', 'waf', 'ssl'])
            writer.writeheader()
            
            for detail in detailed_results:
                writer.writerow({
                    'url': detail['url'],
                    'rrs_score': detail['rrs_score'],
                    'risk_level': detail['risk_level'],
                    'ports': '; '.join(map(str, detail['calculation_details']['ports']['found'])) if detail['calculation_details']['ports']['found'] else 'None',
                    'vulnerabilities': f"{detail['calculation_details']['vulnerabilities']['found']} found",
                    'admin_panel': 'Yes' if detail['calculation_details']['admin_panel']['exposed'] else 'No',
                    'waf': 'Yes' if detail['calculation_details']['security_controls']['waf']['present'] else 'No',
                    'ssl': 'Yes' if detail['calculation_details']['security_controls']['ssl'] else 'No'
                })
        
        # Save DETAILED CALCULATION BREAKDOWN
        with open(calc_filename, 'w', encoding='utf-8') as f:
            f.write("RANSOMWARE RISK SCORE (RRS) - CALCULATION BREAKDOWN\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            # Removed Regional Amplification Factor (R)
            f.write(f"Formula: RRS = ((I_total × L) / 10 - Mi)\n\n")
            
            for i, detail in enumerate(detailed_results, 1):
                calc = detail['calculation_details']
                f.write(f"{i}. {detail['url']}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Final RRS Score: {detail['rrs_score']} ({detail['risk_level']})\n\n")
                
                # Ports section
                f.write("OPEN PORTS:\n")
                if calc['ports']['found']:
                    for port_info in calc['ports']['individual_scores']:
                        f.write(f"  - Port {port_info['port']} ({port_info['service']}): Impact Score = {port_info['impact_score']}\n")
                    f.write(f"  Maximum Port Impact: {calc['formula_breakdown']['likelihood_details']['port_max_impact']}\n")
                else:
                    f.write("  - No open ports detected\n")
                # Show average impact for Port Impact Component
                f.write(f"  Port Impact Component: {calc['ports']['average_impact']}\n\n")
                
                # Vulnerabilities section
                f.write("VULNERABILITIES:\n")
                if calc['vulnerabilities']['found'] > 0:
                    for vuln in calc['vulnerabilities']['details']:
                        f.write(
                            f"  - {vuln['cve_id']}: {vuln['type']} (Severity: {vuln['severity']})"
                            f" | Impact Score = {vuln['impact_score']}"
                        )
                        if vuln['has_exploit']:
                            f.write(" [EXPLOIT AVAILABLE]")
                        f.write("\n")
                    
                    if calc['vulnerabilities']['exploitable_cves']:
                        f.write(f"  Exploitable CVEs: {', '.join(calc['vulnerabilities']['exploitable_cves'])}\n")
                    
                    f.write(f"  Maximum Vulnerability Impact: {calc['formula_breakdown']['likelihood_details']['vuln_max_impact']}\n")
                else:
                    f.write("  - No vulnerabilities found\n")
                # Show average impact for Vulnerability Impact Component
                f.write(f"  Vulnerability Impact Component: {calc['vulnerabilities']['average_impact']}\n\n")
                
                # Admin panels
                f.write("ADMIN PANEL EXPOSURE:\n")
                if calc['admin_panel']['exposed']:
                    f.write(f"  - Admin panels exposed: YES\n")
                    f.write(f"  - Admin Panel Impact: {calc['admin_panel']['impact_score']}\n")
                else:
                    f.write("  - Admin panels exposed: NO\n")
                f.write("\n")
                
                # Security controls
                f.write("SECURITY CONTROLS (Mitigation):\n")
                waf_info = calc['security_controls']['waf']
                f.write(f"  - WAF Protection: {'YES' if waf_info['present'] else 'NO'}")
                if waf_info['present'] and waf_info['name']:
                    f.write(f" ({waf_info['name']})")
                f.write("\n")
                f.write(f"  - SSL Certificate: {'VALID' if calc['security_controls']['ssl'] else 'INVALID/MISSING'}\n")
                # Mitigation to two decimals
                f.write(f"  - Total Mitigation Factor: {round(calc['security_controls']['mitigation_factor'], 2)}\n\n")
                
                # Formula breakdown
                f.write("CALCULATION BREAKDOWN:\n")
                formula = calc['formula_breakdown']
                # Removed Regional Factor (R)
                f.write(f"  - Total Impact (I): {formula['total_impact_I']}\n")
                f.write(f"  - Likelihood (L): {formula['likelihood_L']}\n")
                f.write(f"  - Mitigation (Mi): {round(formula['mitigation_Mi'], 2)}\n")
                f.write(f"  - Final Calculation: {formula['rrs_calculation']}\n\n")
                
                # Likelihood details
                likelihood = formula['likelihood_details']
                f.write("LIKELIHOOD CALCULATION DETAILS:\n")
                f.write(f"  - Max Port Impact: {likelihood['port_max_impact']}\n")
                f.write(f"  - Max Vulnerability Impact: {likelihood['vuln_max_impact']}\n")
                f.write(f"  - Admin Panel Impact: {likelihood['admin_impact']}\n")
                f.write(f"  - Exploit Factor (B): {likelihood['exploit_factor_B']}\n")
                f.write(f"  - Max Category Impact: {likelihood['max_category_impact']}\n")
                f.write(f"  - Raw Likelihood (0-10): {likelihood['raw_likelihood_1_10']}\n")
                f.write("\n" + "-" * 60 + "\n\n")
        
        # Save summary report
        # report_filename = 'rrs_detailed_report.txt'
        # with open(report_filename, 'w', encoding='utf-8') as f:
        #     f.write("RANSOMWARE RISK SCORE (RRS) DETAILED REPORT\n")
        #     f.write("=" * 50 + "\n\n")
        #     f.write(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        #     f.write(f"Total URLs analyzed: {len(results)}\n\n")
        #     
        #     # Risk level summary
        #     risk_counts = {}
        #     for result in results:
        #         level = result['risk_level']
        #         risk_counts[level] = risk_counts.get(level, 0) + 1
        #     
        #     f.write("RISK LEVEL SUMMARY:\n")
        #     f.write("-" * 20 + "\n")
        #     for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        #         count = risk_counts.get(level, 0)
        #         f.write(f"{level}: {count} URLs\n")
        #     f.write("\n")
        
        print(f"\nResults saved to:")
        print(f"- {csv_filename} (CSV format)")
        print(f"- {calc_filename} (Detailed calculations)")
        # print(f"- {report_filename} (Summary report)")
        print(f"Total URLs with risk: {len(results)}")

    def _get_risk_level(self, rrs: float) -> str:
        """Return risk level string based on RRS score."""
        if rrs >= 8.0:
            return "CRITICAL"
        elif rrs >= 6.0:
            return "HIGH"
        elif rrs >= 3.0:
            return "MEDIUM"
        elif rrs > 0.0:
            return "LOW"
        else:
            return "NONE"

def main():
    parser = argparse.ArgumentParser(description="Calculate Ransomware Risk Score (RRS) for URLs.")
    parser.add_argument("-c", "--csv", type=str, default="rrs_results.csv", help="Output CSV file for RRS results")
    parser.add_argument("-t", "--txt", type=str, default="rrs_calculation_breakdown.txt", help="Output TXT file for detailed calculations")
    args = parser.parse_args()

    calculator = RRSCalculator()
    results = calculator.process_all_urls(output_csv=args.csv, output_txt=args.txt)

if __name__ == "__main__":
    main()