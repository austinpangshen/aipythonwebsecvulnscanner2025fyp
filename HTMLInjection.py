import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

class HTMLInjectionScanner:

    def __init__(self):
        self.session = requests.Session()

        self.payloads = [
            "<h1>INJECTED</h1>",
            "\"><h1>INJECTED</h1>",
            "</title><h1>INJECTED</h1>"
        ]

    def scan_url(self, url):
        results = []

        print(f"\nScanning: {url}")

        parsed = urlparse(url)

        # Extract parameters
        params = parse_qs(parsed.query)

        if not params:
            print("No parameters found.")
            return results

        for param in params:
            print(f"\nTesting parameter: {param}")

            for payload in self.payloads:

                test_params = params.copy()
                test_params[param] = [payload]

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

                try:
                    response = self.session.get(test_url, timeout=5)
                    response_text = response.text

                    results.append({
                        "payload": payload,
                        "response": response_text,
                        "url": test_url,
                        "type": "html"
                    })

                    if self.detect_xss(response_text, payload):
                        print("HTML injection FOUND")
                        print("URL:", test_url)
                        print("Payload:", payload)

                except Exception as e:
                    print(f"Request error: {e}")

        if not results:
            print("No HTML injection detected.")

        return results
    

    def detect_xss(self, html, payload):
        return payload in html
    
    def scan_form(self, form):
        results = []

        print(f"\n[Form Scan] {form['url']}")

        # Build full URL
        target_url = urljoin(form["url"], form["action"])
        method = form["method"].upper()

        # Extract input names
        input_names = []
        for input_field in form["inputs"]:
            name = input_field.get("name")
            if name:
                input_names.append(name)

        if not input_names:
            print("No usable inputs found.")
            return results

        for param in input_names:
            print(f"\nTesting input: {param}")

            for payload in self.payloads:

                # Build data
                data = {name: "test" for name in input_names}
                data[param] = payload

                print(f"Injecting payload: {payload}")

                try:
                    if method == "GET":
                        response = self.session.get(target_url, params=data, timeout=5)
                    else:
                        response = self.session.post(target_url, data=data, timeout=5)

                    response_text = response.text

                    results.append({
                        "payload": payload,
                        "response": response_text,
                        "url": target_url,
                        "type": "xss"
                    })

                    if self.detect_xss(response_text, payload):
                        print("🚨 HTML Injection FOUND")
                        print("URL:", target_url)
                        print("Payload:", payload)

                except Exception as e:
                    print(f"Request error: {e}")

                

        return results
    
if __name__ == "__main__":

    scanner = HTMLInjectionScanner()

    target = input(
        "Enter URL with parameter (example: http://testphp.vulnweb.com/search.php?test=1): "
    )

    scanner.scan_url(target)