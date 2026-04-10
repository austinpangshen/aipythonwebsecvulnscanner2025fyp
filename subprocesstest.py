import subprocess
import os

def run_sqlmap(url):
    print(f"\n[SQLMap] Scanning: {url}")

    sqlmap_path = os.path.join("sqlmap-master", "sqlmap-master", "sqlmap.py")

    print(f"[DEBUG] Path: {sqlmap_path}")
    print(f"[DEBUG] Exists: {os.path.exists(sqlmap_path)}")

    command = [
        "python", sqlmap_path,
        "-u", url,
        "--batch",
        "--level", "1",
        "--risk", "1",
        "--flush-session"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        print("\n=== STDOUT ===\n")
        print(result.stdout)

        print("\n=== STDERR ===\n")
        print(result.stderr)

        if "is vulnerable" in result.stdout.lower():
            print("⚠️ [VULNERABLE] SQL Injection detected!")

    except Exception as e:
        print(f"[ERROR] {e}")


def menu():
    while True:
        print("\n=== SQLMap Scanner Menu ===")
        print("1. Scan a URL")
        print("2. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            url = input("Enter target URL (with parameters): ").strip()

            if "?" not in url:
                print("[WARNING] URL has no parameters. SQLMap may not work properly.")

            run_sqlmap(url)

        elif choice == "2":
            print("Exiting...")
            break

        else:
            print("[ERROR] Invalid choice. Try again.")


if __name__ == "__main__":
    menu()