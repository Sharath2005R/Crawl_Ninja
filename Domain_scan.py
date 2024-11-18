import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import signal
import sys
import subprocess


class Scanner:
    def __init__(self, url, ignore_url=None, choice=None, output_file=None):
        self.target_url = url
        self.target_links = []
        
        # Ensure ignore_url is a list, even if it's provided as a string
        self.ignore_url = [ignore_url] if isinstance(ignore_url, str) else (ignore_url if ignore_url else [])
        
        self.session = requests.Session()
        self.crawling_phase = True  # Flag to track the phase of the program
        self.choice = int(choice) if choice else 0
        
        self.output_file = output_file  # File to store results

        # Set up signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        if self.crawling_phase:
            print("\n[!] Ctrl+C detected. Stopping the crawling process and moving to form scanning...")
            self.crawling_phase = False  # Stop crawling and move to form scanning
        else:
            print("\n[!] Ctrl+C detected during form scanning. Exiting the program.")
            sys.exit(0)  # Exit immediately during form scanning

    def log_to_file(self, message):
        """
        Helper function to log results to a file if output_file is set.
        """
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(message + "\n")

    def extract_links(self, url):
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', response.text)
    
    def discover_subdomains(self):
        """
        Uses Subfinder to discover subdomains of the target URL.
        """
        print(f"\n[+] Discovering subdomains for {self.target_url}...\n")
        
        # Call Subfinder with subprocess
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target_url, "-silent"], 
                capture_output=True, 
                text=True
            )

            print("Subfinder Output:")
            print(result.stdout)  # Print the raw output from Subfinder
            
            if result.returncode != 0:
                print(f"Subfinder error: {result.stderr}")

            # Capture and split the result to get subdomains
            subdomains = result.stdout.splitlines()
            self.subdomains.extend(subdomains)

            # Print and store the discovered subdomains
            for subdomain in subdomains:
                # Prepend 'https://' to each subdomain
                full_url = f"https://{subdomain}"  # Or use 'http://' if preferred
                print(f"[+] Discovered subdomain: {full_url}")
                self.target_links.append(full_url)
                self.log_to_file(f"[+] Discovered subdomain: {full_url}")

        except Exception as e:
            print(f"Error running Subfinder: {e}")

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        if not self.crawling_phase:  # Stop crawling if the phase is set to form scanning
            return
        href_links = self.extract_links(url)
        for link in href_links:
            absolute_link = urljoin(url, link)

            if '#' in absolute_link:
                absolute_link = absolute_link.split('#')[0]

            if absolute_link not in self.target_links and self.target_url in absolute_link and absolute_link not in self.ignore_url:
                self.target_links.append(absolute_link)
                print(f"[+] Discovered link: {absolute_link}")
                self.log_to_file(f"[+] Discovered link: {absolute_link}")
                self.crawl(absolute_link)

    def extract_form(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, "html.parser")
        return parsed_html.find_all("form")

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method", "get").lower()

        input_list = form.find_all("input")
        post_data = {}
        for input_tag in input_list:
            input_name = input_tag.get("name")
            input_type = input_tag.get('type')
            input_value = input_tag.get("value", "")

            if input_type == "text":
                input_value = value
            if input_name:
                post_data[input_name] = input_value

        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        if self.choice == 1 or self.choice == 2:
            print("\n[+] Starting scan on target links...\n")
            self.crawling_phase = False  # Set the phase to form scanning when starting the scanner
            for link in self.target_links:
                forms = self.extract_form(link)

                for form in forms:
                    if self.choice == 1:  # XSS testing
                        print(f"[+] Testing XSS injection in {link}")
                        vuln_form = self.test_xss_payload_inform(form, link)
                        if vuln_form:
                            message = f"\n\n[!!] XSS discovered in form at URL: {link}\n{self.get_form_details(form)}"
                            print(message)
                            self.log_to_file(message)
                    elif self.choice == 2:  # SQL Injection testing
                        print(f"[+] Testing Sql injection in {link}")
                    
                        vuln_form = self.test_sql_injection_inform(form, link)
                        if vuln_form:
                            message = f"\n\n[!!] SQL Injection discovered in form at URL: {link}\n{self.get_form_details(form)}"
                            print(message)
                            self.log_to_file(message)

        # Check XSS in URLs with parameters
            for link in self.target_links:
                if "=" in link:
                    if self.choice == 1:  # XSS testing
                        print(f"[+] Testing URL for XSS: {link}")
                        vuln_url = self.test_xss_payload_inurl(link)
                        if vuln_url:
                            message = f"\n\n[!!] XSS discovered in URL: {link}"
                            print(message)
                            self.log_to_file(message)
                    elif self.choice == 2:  # SQL Injection testing
                        print(f"[+] Testing URL for SQL Injection: {link}")
                        vuln_url = self.test_sql_injection_inurl(link)
                        if vuln_url:
                            message = f"\n\n[!!] SQL Injection discovered in URL: {link}"
                            print(message)
                            self.log_to_file(message)
                    
    def get_form_details(self, form):
        """
        Beautifies and returns the form details for the vulnerable form.
        """
        form_details = []
        form_details.append(f"Action: {form.get('action')}")
        form_details.append(f"Method: {form.get('method', 'get').upper()}")
        form_details.append("Inputs:")
        for input_tag in form.find_all("input"):
            input_name = input_tag.get("name")
            input_type = input_tag.get("type")
            input_value = input_tag.get("value", "")
            form_details.append(f" - {input_name} ({input_type}) = {input_value}")
        return "\n".join(form_details)

    def test_xss_payload_inurl(self, url):
        xss_test_script = "<scRIpt>alert('hacked')</scripT>"
        xss_test_url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(xss_test_url)

        if xss_test_script in response.text:
            return True
        return False

    def test_xss_payload_inform(self, form, url):
        xss_test_script = "<scRIpt>alert('hacked')</scripT>"
        response = self.submit_form(form, xss_test_script, url)

        if xss_test_script in response.text:
            return True
        return False

    def test_sql_injection_inform(self, form, url):
        errors = {"quoted string not properly terminated", 
                  "unclosed quotation mark after the character string",  
                  "you have an error in your sql syntax;"}
        for c in "\"'": 
            response = self.submit_form(form, c, url)
            for error in errors:
                if error in response.content.decode().lower():
                    return True
        return False

    def test_sql_injection_inurl(self, url):    
        errors = {"quoted string not properly terminated", 
                  "unclosed quotation mark after the character string",  
                  "you have an error in your sql syntax;"}
        for c in "\"'": 
            sql_test_url = url.replace("=", "=" + c)
            response = self.session.get(sql_test_url)
            for error in errors:
                if error in response.content.decode().lower():
                    return True
        return False
