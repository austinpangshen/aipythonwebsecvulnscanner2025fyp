import csv
import os


# =========================
# SAFE COLUMN FINDER
# =========================
def find_column(headers, target):
    for h in headers:
        if h.strip().lower() == target.lower():
            return h
    return None


# =========================
# LABEL FUNCTION (INTENT + RESULT)
# =========================
def label_row(payload, is_reflected, error_detected):
    payload = payload.lower()

    # If not reflected → attack failed → benign
    if int(is_reflected) == 0:
        return "benign"

    # If reflected → determine type
    if any(x in payload for x in [
        "<script", "onerror", "onload",
        "javascript:", "alert(", "prompt(", "confirm("
    ]):
        return "xss"

    elif "<" in payload and ">" in payload:
        return "html_injection"

    return "benign"


# =========================
# MAIN FIXER
# =========================
def relabel_csv(input_file, output_file=None):
    if output_file is None:
        output_file = input_file  # overwrite

    rows = []

    with open(input_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames

        # 🔍 auto-detect columns
        payload_col = find_column(headers, "payload")
        reflect_col = find_column(headers, "is_reflected")
        error_col = find_column(headers, "error_detected")

        if not payload_col:
            print("[ERROR] 'payload' column not found.")
            return

        if not reflect_col:
            print("[ERROR] 'is_reflected' column not found.")
            return

        print(f"[DEBUG] Using columns:")
        print(f" payload → {payload_col}")
        print(f" is_reflected → {reflect_col}")
        print(f" error_detected → {error_col}")

        for row in reader:
            payload = row.get(payload_col, "")
            is_reflected = row.get(reflect_col, 0)
            error_detected = row.get(error_col, 0) if error_col else 0

            # ✅ Apply new labeling logic
            row["label"] = label_row(payload, is_reflected, error_detected)

            rows.append(row)

    # Ensure label column exists in header
    if "label" not in headers:
        headers.append("label")

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[SUCCESS] Labels updated in: {output_file}")


# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    filename = input("Enter CSV filename (e.g. dataset.csv): ").strip()

    if not os.path.exists(filename):
        print("[ERROR] File not found.")
    else:
        relabel_csv(filename)