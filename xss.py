import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import joblib
import pandas as pd
from feature_extractor import FeatureExtractor

class SimpleXSSScanner:

    def __init__(self):
        self.session = requests.Session()
        self.model = joblib.load("model.pkl")
        self.le = joblib.load("label_encoder.pkl")
        self.extractor = FeatureExtractor()

        self.payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]

    def _get_confidence(self, payload, response_text, baselinetext):
        """Run ML model and return (verdict, confidence_float)"""
        try:
            features_dict = self.extractor.extract(payload, response_text, baselinetext)
            df = pd.DataFrame([features_dict])
            df = df.drop(columns=["payload", "label", "is_reflected"], errors="ignore")

            expected_features = [
                "payload_length", "special_chars", "response_length",
                "length_diff", "has_script", "has_event", "has_js_protocol",
                "has_h1", "has_basic_html", "has_html_tag", "error_detected"
            ]
            df = df[expected_features]

            pred = self.model.predict(df)
            probs = self.model.predict_proba(df)[0]
            label = self.le.inverse_transform(pred)[0]
            confidence = probs[list(self.le.classes_).index(label)]

            if confidence > 0.7:
                verdict = "High"
            elif confidence > 0.5:
                verdict = "Medium"
            else:
                verdict = "Low"

            return verdict, round(confidence * 100, 1)

        except Exception as e:
            print(f"[ML Error] {e}")
            return "Medium", 50.0

    def detect_xss(self, html, payload):
        return payload in html

    def scan_url(self, url, baselinetext=None):
        results = []
        print(f"\nScanning: {url}")

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            print("No parameters found.")
            return results

        for param in params:
            print(f"\nTesting parameter: {param}")
            confirmed_payloads = []
            verdict = "Low"
            confidence = 0.0

            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                print(f"Injecting: {payload}")

                try:
                    response = self.session.get(test_url, timeout=5)
                    response_text = response.text

                    if self.detect_xss(response_text, payload):
                        print("🚨 XSS FOUND")
                        confirmed_payloads.append(payload)
                        verdict, confidence = self._get_confidence(payload, response_text, baselinetext)

                except Exception as e:
                    print(f"Request error: {e}")

            # One result per parameter, grouped payloads
            if confirmed_payloads:
                # Build the base URL without params for display
                base_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, "", parsed.fragment
                ))
                results.append({
                    "url": base_url,
                    "parameter": param,
                    "payloads": confirmed_payloads,
                    "confidence": confidence,
                    "verdict": verdict,
                    "evidence": f"Payload reflected unescaped in HTTP response body for parameter '{param}'",
                    "type": "xss"
                })

        return results

    def scan_form(self, form, baselinetext):
        results = []
        print(f"\n[Form Scan] {form['url']}")

        target_url = urljoin(form["url"], form["action"])
        method = form["method"].upper()

        input_names = [f.get("name") for f in form["inputs"] if f.get("name")]

        if not input_names:
            print("No usable inputs found.")
            return results

        for param in input_names:
            print(f"\nTesting input: {param}")
            confirmed_payloads = []
            verdict = "Low"
            confidence = 0.0

            for payload in self.payloads:
                data = {name: "test" for name in input_names}
                data[param] = payload

                print(f"Injecting: {payload}")

                try:
                    if method == "GET":
                        response = self.session.get(target_url, params=data, timeout=5)
                    else:
                        response = self.session.post(target_url, data=data, timeout=5)

                    response_text = response.text

                    if self.detect_xss(response_text, payload):
                        print("🚨 XSS FOUND")
                        confirmed_payloads.append(payload)
                        verdict, confidence = self._get_confidence(payload, response_text, baselinetext)

                except Exception as e:
                    print(f"Request error: {e}")

            if confirmed_payloads:
                results.append({
                    "url": target_url,
                    "parameter": param,
                    "payloads": confirmed_payloads,
                    "confidence": confidence,
                    "verdict": verdict,
                    "evidence": f"Payload reflected unescaped in HTTP response body for form input '{param}'",
                    "type": "xss"
                })

        return results


if __name__ == "__main__":
    scanner = SimpleXSSScanner()
    target = input("Enter URL with parameter: ")
    scanner.scan_url(target)