import csv
import os


class CSVLogger:
    def __init__(self, filename):
        
        # Target directory
        target_dir = r"C:\Users\Austin\FYP New"

        # Ensure directory exists
        os.makedirs(target_dir, exist_ok=True)

        # Join directory + filename
        self.filename = os.path.join(target_dir, filename)

        print("[DEBUG] CSV will be saved at:", self.filename)

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
            print("[DEBUG] Creating new CSV file...")
            with open(self.filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.headers)
                writer.writeheader()

    def log(self, feature_dict):
        print("[DEBUG] Writing row to CSV...")

        with open(self.filename, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            writer.writerow(feature_dict)