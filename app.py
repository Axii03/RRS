from flask import Flask, request, jsonify, send_from_directory, send_file
import subprocess
import os
import json
import logging
import time
import threading
from datetime import datetime

app = Flask(__name__, static_folder='static')
app.logger.setLevel(logging.INFO)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('process.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

scan_progress = {
    'status': 'idle',
    'step': '',
    'progress': 0,
    'message': '',
    'results': [],
    'estimated_time': 0,
    'elapsed_time': 0
}

scan_estimates = {}

@app.route('/')
def index():
    try:
        return send_file('main.html')
    except Exception as e:
        logger.error(f'Error serving main.html: {e}')
        return jsonify({'error': 'Could not load main.html'}), 500

@app.route('/static/<path:filename>')
def static_files(filename):
    try:
        return send_from_directory(app.static_folder, filename)
    except Exception as e:
        logger.error(f'Error serving static file {filename}: {e}')
        return jsonify({'error': f'Could not load static file: {filename}'}), 500

@app.route('/scan', methods=['GET'])
def scan():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'status': 'error', 'message': 'Domain required'}), 400

    # Check if scan is already running
    if scan_progress['status'] == 'running':
        return jsonify({
            'status': 'running', 
            'message': 'Scan already in progress',
            'progress': scan_progress['progress'],
            'step': scan_progress['step']
        })

    # Start scan in background thread
    thread = threading.Thread(target=run_scan_pipeline, args=(domain,))
    thread.daemon = True
    thread.start()

    return jsonify({
        'status': 'started', 
        'message': f'Ransomware vulnerability scan started for {domain}',
        'domain': domain
    })

@app.route('/scan/progress', methods=['GET'])
def get_scan_progress():
    return jsonify(scan_progress)

@app.route('/scan/results', methods=['GET'])
def get_scan_results():
    try:
        if os.path.exists('url_risk_data.json'):
            with open('url_risk_data.json', 'r', encoding='utf-8') as f:
                results = json.load(f)
            return jsonify({
                'status': 'success',
                'results': results,
                'total_count': len(results)
            })
        else:
            return jsonify({
                'status': 'no_results',
                'message': 'No results available',
                'results': []
            })
    except Exception as e:
        logger.error(f'Error loading results: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500
@app.route('/download/breakdown', methods=['GET'])
def download_breakdown():
    """Download the RRS calculation breakdown file"""
    try:
        breakdown_file = 'rrs_calculation_breakdown.txt'
        if os.path.exists(breakdown_file):
            return send_file(
                breakdown_file,
                as_attachment=True,
                download_name='rrs_calculation_breakdown.txt',
                mimetype='text/plain'
            )
        else:
            return jsonify({'error': 'Calculation breakdown not available'}), 404
    except Exception as e:
        logger.error(f'Error downloading breakdown: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/download/csv', methods=['GET'])
def download_csv():
    """Download the RRS results CSV file"""
    try:
        csv_file = 'rrs_results.csv'
        if os.path.exists(csv_file):
            return send_file(
                csv_file,
                as_attachment=True,
                download_name='rrs_results.csv',
                mimetype='text/csv'
            )
        else:
            return jsonify({'error': 'CSV results not available'}), 404
    except Exception as e:
        logger.error(f'Error downloading CSV: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/download/cve', methods=['GET'])
def download_cve():
    """Download the CVE scan results CSV file"""
    try:
        cve_file = 'cve_scan_results.csv'
        if os.path.exists(cve_file):
            return send_file(
                cve_file,
                as_attachment=True,
                download_name='cve_scan_results.csv',
                mimetype='text/csv'
            )
        else:
            return jsonify({'error': 'CVE results not available'}), 404
    except Exception as e:
        logger.error(f'Error downloading CVE results: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/vulnerability_reports')
def list_vulnerability_reports():
    """List all available vulnerability reports"""
    try:
        reports_dir = 'vulnerability_reports'
        if not os.path.exists(reports_dir):
            return jsonify({'reports': []})
        
        reports = []
        for filename in os.listdir(reports_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(reports_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    reports.append({
                        'filename': filename,
                        'url': report_data.get('url', 'Unknown'),
                        'rrs_score': report_data.get('rrs_score', 0),
                        'risk_level': report_data.get('risk_level', 'Unknown'),
                        'scan_timestamp': report_data.get('scan_timestamp', 'Unknown')
                    })
                except Exception as e:
                    logger.warning(f'Error reading report {filename}: {e}')
        
        # Sort by RRS score (highest first)
        reports.sort(key=lambda x: x['rrs_score'], reverse=True)
        
        return jsonify({'reports': reports})
        
    except Exception as e:
        logger.error(f'Error listing vulnerability reports: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/vulnerability_reports/<filename>')
def get_vulnerability_report(filename):
    """Get specific vulnerability report"""
    try:
        reports_dir = 'vulnerability_reports'
        filepath = os.path.join(reports_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Report not found'}), 404
        
        with open(filepath, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return jsonify(report_data)
        
    except Exception as e:
        logger.error(f'Error loading vulnerability report: {e}')
        return jsonify({'error': str(e)}), 500

def estimate_scan_time(domain):
    """Estimate total scan time based on domain complexity"""
    base_time = 60
    
    try:
        result = subprocess.run(
            ['python', 'sub.py', domain],
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        subdomain_count = 0
        if os.path.exists('active_subdomains_urls.txt'):
            with open('active_subdomains_urls.txt', 'r') as f:
                subdomain_count = len(f.readlines())
        
        # Estimate based on subdomain count
        if subdomain_count <= 10:
            estimated_time = 300  # 5 minutes
        elif subdomain_count <= 50:
            estimated_time = 900  # 15 minutes
        elif subdomain_count <= 100:
            estimated_time = 1800  # 30 minutes
        else:
            estimated_time = 3600  # 60 minutes
        
        return estimated_time, subdomain_count
        
    except Exception as e:
        logger.warning(f'Could not estimate scan time: {e}')
        return 1800, 0  # Default to 30 minutes

def update_progress(step, progress, message):
    """Update scan progress"""
    global scan_progress
    scan_progress.update({
        'step': step,
        'progress': progress,
        'message': message
    })
    logger.info(f'Progress: {progress}% - {step} - {message}')

def cleanup_old_files():
    files_to_clean = [
        'all_subdomains.txt',
        'active_subdomains_urls.txt',
        'scan_results.csv',
        'scan_results_output.txt',
        'nmap_scan_results.txt',
        'exposed_admin_panels.txt',
        'cve_scan_results.csv',
        'exploit_summary.json',
        'exploit_results.json',
        'rrs_results.csv',
        'rrs_calculation_breakdown.txt',
        'url_risk_data.json'
    ]
    
    for file in files_to_clean:
        try:
            if os.path.exists(file):
                os.remove(file)
                logger.info(f'Cleaned up old file: {file}')
        except Exception as e:
            logger.warning(f'Could not remove file {file}: {e}')

def run_script_without_timeout(script_name, args=None):
    try:
        cmd = ['python', script_name]
        if args:
            cmd.extend(args)
        
        logger.info(f'Executing: {" ".join(cmd)}')
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True,
            encoding='utf-8'
        )
        
        if result.stdout:
            logger.info(f'{script_name} stdout: {result.stdout}')
        if result.stderr:
            logger.warning(f'{script_name} stderr: {result.stderr}')
        
        if result.returncode != 0:
            logger.error(f'{script_name} failed with return code {result.returncode}')
            return False, f'{script_name} failed: {result.stderr}'
        
        return True, f'{script_name} completed successfully'
        
    except Exception as e:
        error_msg = f'{script_name} execution error: {str(e)}'
        logger.error(error_msg)
        return False, error_msg

def count_file_lines(filename):
    """Count lines in a file"""
    try:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                return len(f.readlines())
        return 0
    except:
        return 0

def run_scan_pipeline(domain):
    """Run the complete vulnerability scanning pipeline without timeout restrictions"""
    global scan_progress
    
    try:
        scan_progress['status'] = 'running'
        start_time = time.time()
        
        update_progress('cleanup', 5, 'Cleaning up old files...')
        cleanup_old_files()
        
        update_progress('subdomain_discovery', 10, 'Discovering subdomains...')
        success, message = run_script_without_timeout('sub.py', [domain])
        if not success:
            scan_progress.update({'status': 'error', 'message': message})
            return
        subdomain_count = count_file_lines('active_subdomains_urls.txt')
        if subdomain_count == 0:
            error_msg = 'No active subdomains found'
            scan_progress.update({'status': 'error', 'message': error_msg})
            return
        
        # Update progress with subdomain count
        update_progress('subdomain_discovery', 15, f'Found {subdomain_count} active subdomains')
        
        update_progress('port_scanning', 25, f'Scanning ports on {subdomain_count} hosts...')
        success, message = run_script_without_timeout('port.py')
        if not success:
            logger.warning(f'Port scanning warning: {message}')
        
        update_progress('technology_scanning', 40, 'Analyzing technologies and security features...')
        success, message = run_script_without_timeout('other.py')
        if not success:
            scan_progress.update({'status': 'error', 'message': message})
            return
        
        update_progress('admin_panel_detection', 55, 'Checking for exposed admin panels...')
        success, message = run_script_without_timeout('check_admin_panel.py')
        if not success:
            logger.warning(f'Admin panel detection warning: {message}')
        
        update_progress('vulnerability_analysis', 70, 'Analyzing vulnerabilities (this may take a while)...')
        success, message = run_script_without_timeout('cve.py')
        if not success:
            logger.warning(f'CVE analysis warning: {message}')

        update_progress('exploit_check', 80, 'Checking for public exploits...')
        success, message = run_script_without_timeout(
            'cve_exploit_checker.py', 
            ["-i", "cve_scan_results.csv", "-o", "exploit_results.json"]
        )
        if not success:
            logger.warning(f'Exploit check warning: {message}')
            # Continue even if exploit check fails partially

        update_progress('risk_calculation', 90, 'Calculating ransomware risk scores...')
        success, message = run_script_without_timeout('RRS.py')
        if not success:
            scan_progress.update({'status': 'error', 'message': message})
            return
        
        update_progress('finalizing', 95, 'Finalizing results...')
        
        try:
            with open('url_risk_data.json', 'r', encoding='utf-8') as f:
                results = json.load(f)
            
            elapsed_time = time.time() - start_time
            
            scan_progress.update({
                'status': 'completed',
                'step': 'complete',
                'progress': 100,
                'message': f'Scan completed successfully. Found {len(results)} URLs with significant risk.',
                'results': results,
                'execution_time': round(elapsed_time, 2),
                'elapsed_time': round(elapsed_time, 2),
                'completion_time': datetime.now().isoformat(),
                'subdomain_count': subdomain_count
            })
            
            logger.info(f'Scan completed successfully for {domain} in {elapsed_time/60:.1f} minutes. Found {len(results)} high-risk URLs.')
            
        except FileNotFoundError:
            elapsed_time = time.time() - start_time
            scan_progress.update({
                'status': 'completed',
                'step': 'complete', 
                'progress': 100,
                'message': 'Scan completed but no significant risks were found.',
                'results': [],
                'execution_time': round(elapsed_time, 2),
                'elapsed_time': round(elapsed_time, 2),
                'completion_time': datetime.now().isoformat(),
                'subdomain_count': subdomain_count
            })
            
            logger.info(f'Scan completed for {domain} in {elapsed_time/60:.1f} minutes with no significant risks found.')
        
    except Exception as e:
        error_msg = f'Scan pipeline error: {str(e)}'
        logger.error(error_msg)
        elapsed_time = time.time() - start_time if 'start_time' in locals() else 0
        scan_progress.update({
            'status': 'error',
            'message': error_msg,
            'execution_time': round(elapsed_time, 2),
            'elapsed_time': round(elapsed_time, 2)
        })

@app.route('/scan/stop', methods=['POST'])
def stop_scan():
    """Stop current scan"""
    global scan_progress
    scan_progress.update({
        'status': 'stopped',
        'message': 'Scan stopped by user'
    })
    return jsonify({'status': 'stopped', 'message': 'Scan stopped'})

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.3'
    })

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('vulnerability_reports', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("=" * 60)
    print("Ransomware Vulnerability Risk Assessment Tool v1.0.3")
    print("=" * 60)
    print("Starting Flask application...")
    print("Access the web interface at: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)