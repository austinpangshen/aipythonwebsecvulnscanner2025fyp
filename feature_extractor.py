import re


class FeatureExtractor:
    def __init__(self):
        self.error_keywords = ["error", "sql", "warning", "exception"]

    def extract(self, payload, response_text, baseline_text=None):
        features = {}

        # --- Payload features ---
        features["payload"] = payload
        features["payload_length"] = len(payload)

        features["special_chars"] = len(re.findall(r"[<>'\"=/]", payload))

        # --- Response features ---
        features["response_length"] = len(response_text)

        features["is_reflected"] = int(payload in response_text)

        # Error detection
        features["error_detected"] = int(
            any(word in response_text.lower() for word in self.error_keywords)
        )

        # --- Baseline comparison ---
        if baseline_text:
            features["length_diff"] = len(response_text) - len(baseline_text)
        else:
            features["length_diff"] = 0

        # --- Label placeholder (you can overwrite later) ---
        features["label"] = 0

        return features