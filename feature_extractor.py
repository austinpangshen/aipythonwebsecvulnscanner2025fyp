import re

class FeatureExtractor:
    def __init__(self):
        self.error_keywords = ["error", "sql", "warning", "exception"]

    def extract(self, payload, response_text, baseline_text=None):
        features = {}

        payload_lower = payload.lower()
        response_lower = response_text.lower()

        # =========================
        # PAYLOAD FEATURES
        # =========================
        features["payload"] = payload
        features["payload_length"] = len(payload)

        features["special_chars"] = len(re.findall(r"[<>'\"=/]", payload))

        
        # --- XSS indicators ---
        features["has_script"] = int(bool(re.search(r"<\s*script", payload_lower)))

        features["has_event"] = int(bool(re.search(r"on\w+\s*=", payload_lower)))
        # matches onerror=, onload=, etc.

        features["has_js_protocol"] = int("javascript:" in payload_lower)

        # --- HTML injection indicators ---
        features["has_h1"] = int("<h1" in payload_lower)

        features["has_basic_html"] = int(
            any(tag in payload_lower for tag in ["<p", "<b", "<i"])
        )

        # --- Generic tag presence (fallback) ---
        features["has_html_tag"] = int(bool(re.search(r"<[a-z]+\b", payload_lower)))

        # =========================
        # RESPONSE FEATURES
        # =========================
        features["response_length"] = len(response_text)

        features["is_reflected"] = int(payload in response_text)

        features["error_detected"] = int(
            any(word in response_lower for word in self.error_keywords)
        )

        # =========================
        # BASELINE COMPARISON
        # =========================
        if baseline_text:
            features["length_diff"] = len(response_text) - len(baseline_text)
        else:
            features["length_diff"] = 0

        # =========================
        # LABEL (placeholder)
        # =========================
        features["label"] = 0

        return features