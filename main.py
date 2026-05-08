#usual methods
from crawler import WebCrawler
from testlogin import test_login_form, is_login_form
from xss import SimpleXSSScanner
from unsafehttpmethods import UnsafeHTTPMethodScanner
from xxe import XXEScanner
from HTMLInjection import HTMLInjectionScanner
from csrf import CSRFScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from webtech import WebTech
from ssrf import SSRFScanner
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import jsonify

#sqlmap
import os
import subprocess

#model for ml
from ml_model import train_model

#csv
from feature_extractor import FeatureExtractor
from csv_logger import CSVLogger

import requests

def deduplicate(findings):
    seen = set()
    unique = []
    for item in findings:
        key = (item.get("url"), item.get("parameter"))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique

def inject_payload(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for key in query:
        query[key] = payload  

    new_query = urlencode(query, doseq=True)

    return urlunparse(parsed._replace(query=new_query))

def run_sqlmap(url, cookies=None):
    if isinstance(url, dict):
        base = urljoin(url.get("url", ""), url.get("action", ""))
        inputs = {i["name"]: i.get("value", "test") for i in url.get("inputs", []) if i.get("name")}
        url = base + ("?" + urlencode(inputs) if inputs else "")

    if not url or not url.startswith("http"):
        return {"url": str(url), "output": "Invalid URL skipped", "vulnerable": False, "authenticated": False}

    sqlmap_path = os.path.join("sqlmap-master", "sqlmap-master", "sqlmap.py")

    if not os.path.exists(sqlmap_path):
        return {"url": url, "output": f"SQLMap not found at: {sqlmap_path}", "vulnerable": False, "authenticated": False}

    output_dir = os.path.join("sqlmap_output")
    os.makedirs(output_dir, exist_ok=True)

    command = [
        "python", sqlmap_path,
        "-u", url,
        "--batch",
        "--level", "1",
        "--risk", "1",
        "--flush-session",
        "--output-dir", output_dir
    ]

    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        if cookie_str:
            command += ["--cookie", cookie_str]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        # SQLMap stdout + stderr combined
        full_output = result.stdout or ""
        if result.stderr:
            full_output += result.stderr

        # If stdout is empty, try reading from the log file SQLMap writes
        if not full_output.strip():
            from urllib.parse import urlparse as _urlparse
            hostname = _urlparse(url).hostname or "target"
            log_path = os.path.join(output_dir, hostname, "log")
            if os.path.exists(log_path):
                with open(log_path, "r", errors="ignore") as f:
                    full_output = f.read()

        if not full_output.strip():
            full_output = "SQLMap ran but produced no output. The target may have blocked the scan or no parameters were found."

        is_vulnerable = "is vulnerable" in full_output.lower()

        return {
            "url": url,
            "output": full_output,
            "vulnerable": is_vulnerable,
            "authenticated": bool(cookies)
        }

    except subprocess.TimeoutExpired:
        return {"url": url, "output": "SQLMap timed out after 120 seconds.", "vulnerable": False, "authenticated": False}
    except Exception as e:
        return {"url": url, "output": f"Error running SQLMap: {str(e)}", "vulnerable": False, "authenticated": False}

def run_scan(target):
    from flaskui import scan_progress
    loggerswitch = False

    scan_progress["percent"] = 0
    #
    if not os.path.exists("model.pkl"):
        train_model()
    
    scan_progress["percent"] = 5
    scan_progress["status"] = "Detecting technologies..."

    wt = WebTech()
    wt.timeout = 100
    fingerprint = wt.start_from_url(target)
    print(fingerprint)

    webtech_results = {
        "technologies": [],
        "headers": [],
        "raw": str(fingerprint)
    }

    raw = str(fingerprint)
    lines = raw.split("\n")

    for line in lines:
        line = line.strip()

        # Detect technologies
        if line.startswith("-"):
            webtech_results["technologies"].append(line.replace("-", "").strip())

        # Detect headers
        elif "Allow:" in line:
            value = line.split("Allow:")[-1].strip()
            webtech_results["headers"].append(value)

    scan_progress["percent"] = 15
    scan_progress["status"] = "Crawling website..."

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
    scan_progress["percent"] = 30
    scan_progress["status"] = "Running SQLMap..."

    all_sqlmap_results = []
    all_sqlmap_results = run_sqlmap(target)
    
    print("\n=== Login Form Testing ===")

    for form in results["forms"]:

        if is_login_form(form):
            print("Login form found!")
            test_login_form(crawler.session, form)

    # =========================
    # XSS TESTING + DATASET
    # =========================
    print("\n=== XSS URL Testing ===")
    scan_progress["percent"] = 50
    scan_progress["status"] = "Scanning XSS..."

    xss_scanner = SimpleXSSScanner()
    all_xss_results = []
    formxssresults = []

    for link in results["links"]:
        if "?" in link:
            scan_results = xss_scanner.scan_url(link, baseline)
            if scan_results:
                all_xss_results.extend(scan_results)

    for forms in results["forms"]:
        formxssresults = xss_scanner.scan_form(forms, baseline)
        if formxssresults:
                all_xss_results.extend(formxssresults)

    ##HTML injection
    print("\n=== HTML URL Testing ===")

    htmlscanner = HTMLInjectionScanner()
    all_html_results = []
    formhtmlresults = []

    for link in results["links"]:
        if "?" in link:
            scan_results = htmlscanner.scan_url(link, baseline)
            if scan_results:
                all_html_results.extend(scan_results)

    for forms in results["forms"]:
        formhtmlresults = htmlscanner.scan_form(forms, baseline)
        if formhtmlresults:
            all_html_results.extend(formhtmlresults)

    # FEATURE EXTRACTION + CSV LOGGING
    if loggerswitch == True:
        print("\n=== Feature Extraction & Logging ===")
        all_results = []

        all_results.extend(all_xss_results)
        all_results.extend(all_html_results)

        for r in all_results:

            payload = r["payload"]
            response = r["response"]

            # ✅ Extract features using YOUR extractor
            feature_dict = extractor.extract(payload, response, baseline)
            logger.log(feature_dict)

    print("\n=== SSRF Testing ===")
    scan_progress["percent"] = 70 
    scan_progress["status"] = "Scanning SSRF..."

    ssrf_scanner = SSRFScanner(crawler.session)
    all_ssrf_results = []

    # URL testing
    for link in results["links"]:
        if "?" in link:
            scan_results = ssrf_scanner.scan_url(link)
            if scan_results:
                all_ssrf_results.extend(scan_results)

    # Form testing
    for form in results["forms"]:
        form_results = ssrf_scanner.scan_form(form)
        if form_results:
            all_ssrf_results.extend(form_results)


    # =========================
    # HTTP METHOD SCAN
    # =========================
    scan_progress["percent"] = 70
    scan_progress["status"] = "HTTP Method Testing..."
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
    scan_progress["percent"] = 90
    scan_progress["status"] = "CSRF Testing..."

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
        "xss": deduplicate(all_xss_results),
        "html": deduplicate(all_html_results),
        "csrf": csrf_results,
        "ssrf": all_ssrf_results,
        "xxe": xxe_results,
        "webtech": webtech_results,
        "sqlmap": all_sqlmap_results
    }


if __name__ == "__main__":
    target = input("Enter a target: ")
    run_scan(target)