#!/usr/bin/env python3
"""
Stealthy URL Status Checker - Red Team Edition
Features:
- Multi-threaded scanning
- User-agent rotation
- Proxy chaining
- SSL verification control
- Verbose progress reporting
- Anti-blocking techniques
- CSV output with full diagnostics
"""

import requests
import urllib3
import concurrent.futures
import argparse
import random
import time
from urllib.parse import urlparse
from datetime import datetime
import csv
import socket
from itertools import cycle

# Global configuration
VERIFY_SSL = False
VERBOSE = False

# Execution parameters
DEFAULT_THREADS = 15
TIMEOUT = 12
RETRIES = 2
DELAY_RANGE = (1, 4)

# Built-in user agents (updated 2024)
DEFAULT_USER_AGENTS = [
    # Desktop browsers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    
    # Mobile devices
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    
    # Search engines
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    
    # Legacy systems
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    
    # Embedded systems
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
]

# Proxy configuration
PROXIES = []
try:
    with open('proxies.txt') as f:
        PROXIES = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    pass

proxy_pool = cycle(PROXIES) if PROXIES else None

def get_random_headers():
    """Generate randomized headers for each request"""
    return {
        'User-Agent': random.choice(DEFAULT_USER_AGENTS),
        'Accept': random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        ]),
        'Accept-Language': random.choice(['en-US,en;q=0.9', 'es-ES,es;q=0.8']),
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': random.choice(['keep-alive', 'close']),
        'Cache-Control': random.choice(['max-age=0', 'no-cache'])
    }

def get_proxy():
    """Rotate through proxy list"""
    return next(proxy_pool) if proxy_pool else None

def check_url(url):
    """Execute request with anti-detection measures"""
    global VERIFY_SSL
    
    result = {
        'url': url,
        'status': None,
        'error': None,
        'ip': None,
        'attempts': 0,
        'proxy': None,
        'user_agent': None,
        'timestamp': datetime.now().isoformat()
    }

    for attempt in range(RETRIES + 1):
        try:
            time.sleep(random.uniform(*DELAY_RANGE))
            headers = get_random_headers()
            proxy = get_proxy()
            proxies = {'http': proxy, 'https': proxy} if proxy else None
            
            # Validate and normalize URL
            parsed = urlparse(url)
            if not parsed.scheme:
                url = f'http://{url}'
                parsed = urlparse(url)
            
            # DNS resolution
            domain = parsed.netloc
            result['ip'] = socket.gethostbyname(domain)
            
            # Make request
            response = requests.head(
                url,
                headers=headers,
                proxies=proxies,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=VERIFY_SSL
            )
            
            # Record successful result
            result.update({
                'status': response.status_code,
                'attempts': attempt + 1,
                'proxy': proxy,
                'user_agent': headers['User-Agent']
            })
            return result

        except (requests.exceptions.RequestException, socket.gaierror) as e:
            result['error'] = str(e)
            result['attempts'] = attempt + 1
            time.sleep(2 ** attempt)  # Exponential backoff
            continue

    return result

def process_urls(urls, output_file, max_threads):
    """Manage scanning process with progress tracking"""
    global VERBOSE
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_url, url): url for url in urls}
        total = len(futures)
        processed = 0
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=[
                'timestamp', 'url', 'status', 'error', 
                'ip', 'attempts', 'proxy', 'user_agent'
            ])
            writer.writeheader()

            for future in concurrent.futures.as_completed(futures):
                processed += 1
                try:
                    result = future.result()
                    writer.writerow(result)
                    
                    # Verbose output
                    if VERBOSE:
                        status = result['status'] or 'ERR'
                        output = [
                            f"[{processed}/{total}] {result['url']}",
                            f"Status: {status}",
                            f"IP: {result['ip']}",
                            f"Attempts: {result['attempts']}"
                        ]
                        
                        if result['proxy']:
                            output.append(f"Proxy: {result['proxy']}")
                        if result['error']:
                            output.append(f"Error: {result['error']}")
                            
                        print(" → ".join(output))
                    
                    time.sleep(random.uniform(0.1, 0.5))
                except Exception as e:
                    print(f'Error processing future: {str(e)}')

def main():
    global VERIFY_SSL, PROXIES, DELAY_RANGE, VERBOSE
    
    parser = argparse.ArgumentParser(
        description='Stealthy URL Status Checker',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-i', '--input', required=True,
                       help='Input file containing URLs (one per line)')
    parser.add_argument('-o', '--output', default='results.csv',
                       help='Output CSV file')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS,
                       help='Number of concurrent threads')
    parser.add_argument('-p', '--proxies', default='proxies.txt',
                       help='File containing proxy servers')
    parser.add_argument('-d', '--delay', type=float, nargs=2, 
                       default=DELAY_RANGE, metavar=('MIN', 'MAX'),
                       help='Delay range between requests in seconds')
    parser.add_argument('--verify-ssl', action='store_true',
                       help='Enable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()

    # Configure global settings
    VERIFY_SSL = args.verify_ssl
    VERBOSE = args.verbose
    DELAY_RANGE = args.delay

    # Suppress SSL warnings if verification disabled
    if not VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Load proxies
    try:
        with open(args.proxies) as f:
            PROXIES = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        if args.proxies != 'proxies.txt':
            print(f"Warning: Proxy file '{args.proxies}' not found")

    # Load and deduplicate URLs
    with open(args.input, 'r') as f:
        urls = list(set(line.strip() for line in f if line.strip()))

    # Print startup banner
    if VERBOSE:
        print(f"""\n[ Stealth URL Scanner ]
Targets: {len(urls)}
Threads: {args.threads}
Proxies: {len(PROXIES) if PROXIES else 'None'}
SSL Verification: {'Enabled' if VERIFY_SSL else 'Disabled'}
Delay Range: {DELAY_RANGE[0]} - {DELAY_RANGE[1]} seconds
----------------------------------------""")

    # Start scanning
    process_urls(urls, args.output, args.threads)

    if VERBOSE:
        print("\n[+] Scan completed successfully")
        print(f"[+] Results saved to: {args.output}")

if __name__ == '__main__':
    main()