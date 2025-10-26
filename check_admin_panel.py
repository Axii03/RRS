import argparse
import requests
import re
import urllib.parse
import urllib3
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

HIGH_PRIORITY_PATHS = [
    '/admin', '/wp-admin', '/administrator', '/phpmyadmin', '/cpanel',
    '/admin/login', '/wp-login.php', '/login'
]

MEDIUM_PRIORITY_PATHS = [
    '/adminpanel', '/backend', '/dashboard', '/admin_area', '/controlpanel',
    '/admin.php', '/admin.html', '/manage', '/panel'
]

LOW_PRIORITY_PATHS = [
    '/admin1', '/admin2', '/configuration', '/config', '/setup',
    '/webadmin', '/manager', '/console', '/control'
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}


def is_ipv4(hostname: str) -> bool:
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))


def check_url_fast(url: str, path: str, timeout: float = 5.0):
    """Check a single URL+path quickly for admin-panel indicators.

    Returns a dict with info on match or None.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return None

        clean_url = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            clean_url += f":{parsed.port}"

        if not path.startswith('/'):
            path = '/' + path
        test_url = clean_url + path

        verify_ssl = not (parsed.scheme == 'https' and is_ipv4(parsed.hostname))

        response = requests.get(test_url, headers=HEADERS, allow_redirects=True, verify=verify_ssl, timeout=timeout)

        if response.status_code != 200:
            return None

        content_lower = response.text.lower()

        score = 0
        matched_keywords = []

        critical_keywords = [
            'type="password"', "type='password'", 'input type="password"',
            'name="password"', 'id="password"', 'password field',
            'authentication required', 'please log in', 'please sign in'
        ]
        for keyword in critical_keywords:
            if re.search(keyword, content_lower):
                score += 5
                matched_keywords.append(keyword)
                break

        strong_keywords = [
            'admin panel', 'administration panel', 'control panel',
            'administrator login', 'admin login', 'admin area', 'management console'
        ]
        for keyword in strong_keywords:
            if keyword in content_lower:
                score += 3
                matched_keywords.append(keyword)
                break

        moderate_keywords = ['username', 'email address', 'log in', 'sign in', 'signin', 'login', 'authenticate']
        moderate_count = sum(1 for kw in moderate_keywords if kw in content_lower)
        if moderate_count >= 2:
            score += 2
            matched_keywords.append(f"{moderate_count} login terms")

        title = ''
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            title_high_priority = ['admin', 'administrator', 'login', 'dashboard', 'control panel', 'cms', 'backend']
            title_matches = sum(1 for kw in title_high_priority if kw in title.lower())
            if title_matches >= 1:
                score += 2
                matched_keywords.append(f"title:{title_matches}")

        path_keywords = ['admin', 'login', 'panel', 'dashboard', 'manage', 'backend', 'wp-admin', 'phpmyadmin']
        path_matches = sum(1 for kw in path_keywords if kw in path.lower())
        if path_matches >= 1:
            score += 1
            matched_keywords.append(f"path:{path_matches}")

        # Form patterns
        if '<form' in content_lower:
            form_patterns = [r'<form[^>]*method=["\']post["\']', r'<form[^>]*action[^>]*(login|signin|auth|admin)']
            for pattern in form_patterns:
                if re.search(pattern, content_lower):
                    score += 1
                    matched_keywords.append('form_pattern')
                    break

        # Tech indicators
        tech_indicators = {
            'wordpress': ['wp-login', 'wordpress', 'wp-admin'],
            'joomla': ['joomla', 'administrator', 'com_login'],
            'drupal': ['drupal', 'user/login', 'user-login'],
            'phpmyadmin': ['phpmyadmin', 'pma_username', 'pma_password'],
            'cpanel': ['cpanel', 'whm', 'webmail']
        }
        for tech, inds in tech_indicators.items():
            if any(ind in content_lower or ind in path.lower() for ind in inds):
                score += 2
                matched_keywords.append(f"tech:{tech}")
                break

        # Thresholds
        if score >= 7:
            priority = 'HIGH'
        elif score >= 4:
            priority = 'MEDIUM'
        elif score >= 2:
            priority = 'LOW'
        else:
            return None

        return {
            'url': test_url,
            'title': title[:200] if title else 'No title',
            'score': score,
            'priority': priority,
            'status_code': response.status_code,
            'keywords': ', '.join(matched_keywords[:6])
        }

    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return None
    except Exception as e:
        logger.debug(f"Error checking {url}{path}: {e}")
        return None


def check_single_url_tiered(url: str):
    for path in HIGH_PRIORITY_PATHS:
        result = check_url_fast(url, path, timeout=5)
        if result:
            result['tier'] = 'HIGH'
            return result

    for path in MEDIUM_PRIORITY_PATHS:
        result = check_url_fast(url, path, timeout=4)
        if result:
            result['tier'] = 'MEDIUM'
            return result

    for path in LOW_PRIORITY_PATHS:
        result = check_url_fast(url, path, timeout=3)
        if result:
            result['tier'] = 'LOW'
            return result

    return None


def load_urls_from_file(filename: str):
    urls = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ',' in line:
                    url = line.split(',')[0].strip()
                else:
                    url = line
                if not url.startswith(('http://', 'https://')):
                    urls.append('https://' + url)
                else:
                    urls.append(url)
        unique_urls = list(dict.fromkeys(urls))
        logger.info(f"Loaded {len(unique_urls)} unique URLs from {filename}")
        return unique_urls
    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
        print(f"[!] File not found: {filename}")
        return []
    except Exception as e:
        logger.error(f"Error reading file {filename}: {e}")
        print(f"[!] Error reading file: {e}")
        return []


def check_admin_panels(input_file: str, output_file: str = 'exposed_admin_panels.txt'):
    print('[+] Starting optimized admin panel detection...')
    urls = load_urls_from_file(input_file)
    if not urls:
        print('[!] No URLs to check')
        return

    found_panels = []
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=60) as executor:
            futures = {executor.submit(check_single_url_tiered, url): url for url in urls}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                url = futures[future]
                try:
                    result = future.result()
                    if result:
                        found_panels.append(result)
                        print(f"[+] Admin panel found: {result['url']} (Tier: {result['tier']}, Score: {result['score']})")
                except Exception as e:
                    logger.debug(f"Error processing {url}: {e}")

                if completed % 25 == 0:
                    elapsed = time.time() - start_time
                    progress = (completed / len(urls)) * 100
                    rate = completed / elapsed if elapsed > 0 else 0
                    print(f"[*] Progress: {completed}/{len(urls)} ({progress:.1f}%) - Found: {len(found_panels)} - Rate: {rate:.1f} URLs/sec")

    except KeyboardInterrupt:
        print('\n[!] Scan interrupted by user')
    except Exception as e:
        logger.error(f"Error during scanning: {e}")
        print(f"[!] Error during scanning: {e}")

    # Save results
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            for panel in found_panels:
                parsed = urllib.parse.urlparse(panel['url'])
                base_domain = parsed.hostname or panel['url']
                if parsed.port:
                    base_domain += f":{parsed.port}"
                out.write(f"{panel['url']},{base_domain}\n")

        print(f"\n[+] Found {len(found_panels)} admin panels (1 per URL max)")
        print(f"[+] Results saved to {output_file}")

        if found_panels:
            print('\n[+] Admin Panel Summary:')
            tiers = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for p in found_panels:
                tiers[p.get('tier', 'LOW')] = tiers.get(p.get('tier', 'LOW'), 0) + 1
            print(f"  HIGH: {tiers['HIGH']}  MEDIUM: {tiers['MEDIUM']}  LOW: {tiers['LOW']}")
    except Exception as e:
        logger.error(f"Error saving results: {e}")
        print(f"[!] Error saving results: {e}")


def main():
    parser = argparse.ArgumentParser(description="Check for exposed admin panels with tiered priority.")
    parser.add_argument('-i', '--input', type=str, default='active_subdomains_urls.txt', help='Input file with subdomain URLs')
    parser.add_argument('-o', '--output', type=str, default='exposed_admin_panels.txt', help='Output file for found admin panels')
    args = parser.parse_args()

    start = time.time()
    check_admin_panels(args.input, args.output)
    elapsed = time.time() - start
    print(f"\n[+] Total scan time: {elapsed/60:.1f} minutes ({elapsed:.1f} seconds)")


if __name__ == '__main__':
    main()