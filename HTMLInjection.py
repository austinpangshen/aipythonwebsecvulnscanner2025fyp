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

        print(f"\n[Scanning URL] {url}")

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            print("[INFO] No query parameters detected.")
            return results

        for param in params:
            print(f"\n[Testing Parameter] {param}")

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

                print(f"[Payload] {payload}")

                try:
                    response = self.session.get(test_url, timeout=5)
                    response_text = response.text

                    results.append({
                        "payload": payload,
                        "url": test_url,
                        "type": "html_injection"
                    })

                    if self.detect_html_injection(response_text):
                        print("⚠️ [VULNERABLE] HTML Injection detected")
                        print(f"→ URL: {test_url}")
                        print(f"→ Parameter: {param}")
                        print(f"→ Payload: {payload}")

                except Exception as e:
                    print(f"[ERROR] Request failed: {e}")

        if not results:
            print("[INFO] No injection points tested.")

        return results

    def detect_html_injection(self, html):
        return "INJECTED" in html

    def scan_form(self, form):
        results = []

        print(f"\n[Scanning Form] {form['url']}")

        target_url = urljoin(form["url"], form["action"])
        method = form["method"].upper()

        input_names = []
        for input_field in form["inputs"]:
            name = input_field.get("name")
            if name:
                input_names.append(name)

        if not input_names:
            print("[INFO] No usable input fields found.")
            return results

        for param in input_names:
            print(f"\n[Testing Input] {param}")

            for payload in self.payloads:

                data = {name: "test" for name in input_names}
                data[param] = payload

                print(f"[Payload] {payload}")

                try:
                    if method == "GET":
                        response = self.session.get(target_url, params=data, timeout=5)
                    else:
                        response = self.session.post(target_url, data=data, timeout=5)

                    response_text = response.text

                    results.append({
                        "payload": payload,
                        "url": target_url,
                        "type": "html_injection",
                        "param": param
                    })

                    if self.detect_html_injection(response_text):
                        print("⚠️ [VULNERABLE] HTML Injection detected (Form)")
                        print(f"→ URL: {target_url}")
                        print(f"→ Input: {param}")
                        print(f"→ Payload: {payload}")

                except Exception as e:
                    print(f"[ERROR] Request failed: {e}")

        return results


if __name__ == "__main__":

    scanner = HTMLInjectionScanner()

    target = input(
        "Enter URL with parameter (example: http://testphp.vulnweb.com/search.php?test=1): "
    )

    scanner.scan_url(target)