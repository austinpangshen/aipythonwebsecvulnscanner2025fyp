from crawler import WebCrawler
from testlogin import test_login_form, is_login_form
from xss import SimpleXSSScanner
from unsafehttpmethods import UnsafeHTTPMethodScanner
from xxe import XXEScanner
from csrf import CSRFScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from HTMLInjection import HTMLInjectionScanner

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


def main():

    target = input("Enter target URL: ")

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

    print("\n=== XSS URL Testing ===")

    xss_scanner = SimpleXSSScanner()
    all_xss_results = []
    formxssresults = []

    for link in results["links"]:
        if "?" in link:
            scan_results = xss_scanner.scan_url(link)
            if scan_results:
                all_xss_results.extend(scan_results)
    
    print(scan_results)

    """for forms in results["forms"]:
        formxssresults = xss_scanner.scan_form(forms)"""

        

    # =========================
    # FEATURE EXTRACTION + CSV LOGGING
    # =========================
    print("\n=== Feature Extraction & Logging ===")

    vulns = []

    for r in all_xss_results:

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


if __name__ == "__main__":
    main()