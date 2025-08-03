Cerberus XSS
Cerberus XSS by Sudeepa Wanigarathne is an advanced XSS testing tool for pentesters and bug bounty hunters. It features web crawling, WAF bypass, DOM-based XSS detection, and blind XSS logging. With a rich terminal UI, it offers interactive menus, progress bars, and detailed reports. Ethically test with permission only.
Features

Web Crawling: Spiders target websites to identify forms and parameters.
Payload Injection: Tests a wide range of XSS payloads, including encoded and obfuscated variants.
WAF Bypass: Uses case variation, comment injection, whitespace, and nested encoding to evade Web Application Firewalls.
DOM-based XSS Detection: Identifies potential DOM sinks for client-side vulnerabilities.
Blind XSS: Logs callback payloads for blind XSS testing.
Rich UI: Colorful output, progress bars, and interactive menus using the rich library.
Session Persistence: Saves scan progress for resumption.
Proxy Support: Integrates with tools like Burp Suite.

Installation
Cerberus XSS is designed for Kali Linux and uses a Python virtual environment.

Update Kali Linux:
sudo apt update && sudo apt upgrade -y


Install Prerequisites:
sudo apt install python3 python3-pip python3-venv -y


Clone the Repository:
git clone https://github.com/your-username/cerberus_xss.git
cd cerberus_xss


Set Up Virtual Environment:
python3 -m venv venv
source venv/bin/activate


Install Dependencies:
pip install -r requirements.txt



Usage
Run the tool in interactive or command-line mode.

Interactive Mode:
python cerberus_xss.py

Follow the prompts to configure the scan.

Command-Line Mode:
python cerberus_xss.py http://example.com --output report.json --rate-limit 0.5 --depth 3 --proxy http://127.0.0.1:8080


--output: Output report file (default: cerberus_xss_report.json).
--rate-limit: Seconds between requests (default: 1).
--depth: Maximum crawling depth (default: 2).
--proxy: Proxy for requests (e.g., Burp Suite).



See docs/usage.md for detailed instructions.
Ethical Use

Permission Required: Only test websites with explicit permission. Unauthorized testing is illegal.
Blind XSS: Replace your-callback-server.com in the script with your own callback server.
Rate Limiting: Adjust --rate-limit to avoid overwhelming servers.

Example Output
╔════════════════════════════════════════════════════╗
║                                                    ║
║      Cerberus XSS - Advanced Penetration Tool      ║
║          Author: Sudeepa Wanigarathne             ║
║                                                    ║
║       </>  Injecting Security, Ethically  -->      ║
║                                                    ║
╚════════════════════════════════════════════════════╝
Welcome to Cerberus XSS by Sudeepa Wanigarathne
Do you have permission to test this target? [Y/n]: y
Enter target URL [http://example.com]: http://test.com
...
[!] Target http://test.com is VULNERABLE to XSS!
┌──────────────────────────────┬──────────────────────────────┬────────────────────┬──────────┬──────────────────────────────┐
│ URL                          │ Payload                      │ Context            │ Severity │ PoC                          │
├──────────────────────────────┼──────────────────────────────┼────────────────────┼──────────┼──────────────────────────────┤
│ http://test.com/search?...   │ <script>alert('XSS')</script>│ JavaScript Context │ High     │ http://test.com/search?...   │
└──────────────────────────────┴──────────────────────────────┴────────────────────┴──────────┴──────────────────────────────┘

Contributing
Contributions are welcome! Please submit pull requests or open issues on GitHub.
License
This project is licensed under the MIT License. See LICENSE for details.
Disclaimer
Cerberus XSS is for ethical security testing only. The author is not responsible for misuse.
