import requests
import time

class SSRFScanner:

    def __init__(self, session=None):
        self.session = session or requests.Session()

        
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254"
        ]

    #response analysis
    def analyze_response(self, response):

        indicators = []
        is_vulnerable = False

        text = response.text.lower()

        # success case
        if response.status_code == 200 and len(text) > 0:
            indicators.append("Non-empty response")

            if "root:" in text or "aws" in text:
                indicators.append("Sensitive data detected")
                is_vulnerable = True

        # error-based detection
        if response.status_code in [500, 502, 503]:
            indicators.append("Server error")
            is_vulnerable = True

        # timeout behavior
        if response.elapsed.total_seconds() > 5:
            indicators.append("Slow response")
            is_vulnerable = True

        # connection errors
        errors = [
            "connection refused",
            "failed to connect",
            "timeout"
        ]

        for err in errors:
            if err in text:
                indicators.append(err)
                is_vulnerable = True

        return is_vulnerable, indicators

    # =========================
    # URL SCAN
    # =========================
    def scan_url(self, url):

        results = []

        if "?" not in url:
            return results

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params:

            for payload in self.payloads:

                test_params = params.copy()
                test_params[param] = payload

                new_query = urlencode(test_params, doseq=True)

                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self.session.get(test_url, timeout=5)

                    is_vuln, indicators = self.analyze_response(response)

                    if is_vuln:
                        print("🚨 SSRF DETECTED")

                        results.append({
                            "type": "ssrf",
                            "url": test_url,
                            "payload": payload,
                            "evidence": indicators,
                            "response": response.text[:200]
                        })

                except Exception:
                    continue

                time.sleep(0.3)

        return results

    # =========================
    # FORM SCAN
    # =========================
    def scan_form(self, form):

        results = []

        from urllib.parse import urljoin

        target_url = urljoin(form["url"], form["action"])
        method = form["method"].upper()

        inputs = [i.get("name") for i in form["inputs"] if i.get("name")]

        for param in inputs:

            for payload in self.payloads:

                data = {name: "test" for name in inputs}
                data[param] = payload

                try:
                    if method == "POST":
                        response = self.session.post(target_url, data=data, timeout=5)
                    else:
                        response = self.session.get(target_url, params=data, timeout=5)

                    is_vuln, indicators = self.analyze_response(response)

                    if is_vuln:
                        print("🚨 SSRF FORM DETECTED")

                        results.append({
                            "type": "ssrf",
                            "url": target_url,
                            "payload": payload,
                            "evidence": indicators,
                            "response": response.text[:200]
                        })

                except Exception:
                    continue

        return results
    
if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("python ssrf.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    scanner = SSRFScanner()

    results = scanner.scan_url(target_url)

    if results:

        print("\n=== SSRF Findings ===")

        for r in results:

            print("\n🚨 SSRF DETECTED")
            print(f"Payload: {r['payload']}")
            print(f"URL: {r['url']}")
            print(f"Evidence: {r['evidence']}")
            print(f"Response Snippet:\n{r['response']}")

    else:
        print("\nNo SSRF vulnerabilities detected.")