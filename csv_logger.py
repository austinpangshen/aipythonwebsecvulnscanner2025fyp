import csv
import os


class CSVLogger:
    def __init__(self, filename):
        self.filename = filename

        self.headers = [
            "payload",
            "payload_length",
            "special_chars",
            "is_reflected",
            "response_length",
            "error_detected",
            "length_diff",
            "label"
        ]

        # Create file with header if not exists
        if not os.path.exists(self.filename):
            with open(self.filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.headers)
                writer.writeheader()

    def log(self, feature_dict):
        with open(self.filename, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            writer.writerow(feature_dict)