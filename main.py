#usual methods
from crawler import WebCrawler
from testlogin import test_login_form, is_login_form
from xss import SimpleXSSScanner
from unsafehttpmethods import UnsafeHTTPMethodScanner
from xxe import XXEScanner
from HTMLInjection import HTMLInjectionScanner
from csrf import CSRFScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webtech import WebTech

#sqlmap
import os
import subprocess

#csv
from feature_extractor import FeatureExtractor
from csv_logger import CSVLogger

import requests

def inject_payload(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for key in query:
        query[key] = payload  # replace value

    new_query = urlencode(query, doseq=True)

    return urlunparse(parsed._replace(query=new_query))

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


def run_scan(target):

    wt = WebTech()
    wt.timeout = 100
    fingerprint = wt.start_from_url(target)

    print(fingerprint)

    crawler = WebCrawler(target, max_pages=10)
    results = crawler.crawl()
    if not results["links"]:
        print("[!] No links found, using target as test URL")
        results["links"].append(target + "?test=")

    print("\n=== Crawl Results ===")
    print(f"Pages found: {results['total_pages']}")
    print(f"Forms found: {results['total_forms']}")
    print(f"Links found: {len(results['links'])}")
    print(f"Interesting directories found: {results['interesting_urls']}")

    run_sqlmap(target)

    # =========================
    # INIT FEATURE SYSTEM
    # =========================
    extractor = FeatureExtractor()
    logger = CSVLogger("dataset.csv")
    print("[DEBUG] CSV logger initialized")

    # baseline request (VERY IMPORTANT)
    try:
        baseline = requests.get(target).text
    except:
        baseline = ""

    # =========================
    # LOGIN TESTING
    # =========================
    print("\n=== Login Form Testing ===")

    for form in results["forms"]:

        if is_login_form(form):
            print("Login form found!")
            test_login_form(crawler.session, form)

    # =========================
    # XSS TESTING + DATASET
    # =========================
    print("\n=== XSS URL Testing ===")

    xss_scanner = SimpleXSSScanner()
    all_xss_results = []
    formxssresults = []

    for link in results["links"]:
        if "?" in link:
            scan_results = xss_scanner.scan_url(link)
            if scan_results:
                all_xss_results.extend(scan_results)

    for forms in results["forms"]:
        formxssresults = xss_scanner.scan_form(forms)

        for r in formxssresults:
            print(f" {r['payload']}")

    ##HTML injection
    print("\n=== HTML URL Testing ===")

    htmlscanner = HTMLInjectionScanner()
    all_html_results = []
    formhtmlresults = []

    for link in results["links"]:
        if "?" in link:
            scan_results = htmlscanner.scan_url(link)
            if scan_results:
                all_html_results.extend(scan_results)
    
    print(f"[INFO] Total HTML results: {len(all_html_results)}")

    for forms in results["forms"]:
        formhtmlresults = htmlscanner.scan_form(forms)
        if formhtmlresults:
            all_html_results.extend(formhtmlresults)


    # =========================
    # FEATURE EXTRACTION + CSV LOGGING
    # =========================
    print("\n=== Feature Extraction & Logging ===")
    all_results = []

    all_results.extend(all_xss_results)
    all_results.extend(all_html_results)

    for r in all_results:

        payload = r["payload"]
        response = r["response"]

        # ✅ Extract features using YOUR extractor
        feature_dict = extractor.extract(payload, response, baseline)

        # ✅ Log ONE row at a time (matches your CSVLogger)
        logger.log(feature_dict)


    # =========================
    # HTTP METHOD SCAN
    # =========================
    http_scanner = UnsafeHTTPMethodScanner()
    http_scanner.scan_target(target)

    # =========================
    # XXE SCAN
    # =========================
    xxe_scanner = XXEScanner(crawler.session)
    xxe_results = xxe_scanner.scan(results)

    if not xxe_results:
        print("No XXE vulnerabilities detected (target may not process XML input)")

    # =========================
    # CSRF TESTING
    # =========================
    print("\n=== CSRF Testing ===")

    csrf_scanner = CSRFScanner(crawler.session, results)
    csrf_results = csrf_scanner.scan()

    if not csrf_results:
        print("No CSRF vulnerabilities detected")
    else:
        print(f"Found {len(csrf_results)} CSRF vulnerabilities\n")

        for i, vuln in enumerate(csrf_results, 1):
            print(f"{i}. [{vuln['subtype']}]")
            print(f"   URL: {vuln['url']}")
            print(f"   Method: {vuln['method']}")
            print(f"   Evidence: {vuln['evidence']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Impact: {vuln['impact']}")
            print("-" * 50)

        # =========================
    # FINAL RETURN (IMPORTANT)
    # =========================
    return {
        "links": results.get("links", []),
        "xss": all_xss_results,
        "html": all_html_results,
        "csrf": csrf_results
    }


if __name__ == "__main__":
    target = input("Enter a target: ")
    run_scan(target)