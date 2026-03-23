from crawler import WebCrawler
from testlogin import test_login_form, is_login_form
from xss import SimpleXSSScanner
from unsafehttpmethods import UnsafeHTTPMethodScanner
from xxe import XXEScanner
from csrf import CSRFScanner


# NEW IMPORTS
from feature_extractor import FeatureExtractor
from csv_logger import CSVLogger


def main():

    target = input("Enter target URL: ")

    crawler = WebCrawler(target, max_pages=10)

    results = crawler.crawl()

    print("\n=== Crawl Results ===")
    print(f"Pages found: {results['total_pages']}")
    print(f"Forms found: {results['total_forms']}")
    print(f"Links found: {len(results['links'])}")
    print(f"Interesting directories found: {results['interesting_urls']}")


    # LOGIN TESTING
    print("\n=== Login Form Testing ===")

    for form in results["forms"]:
        if is_login_form(form):
            print("Login form found!")
            test_login_form(crawler.session, form)

    # XSS TESTING
    print("\n=== XSS URL Testing ===")

    xss_scanner = SimpleXSSScanner()

    for link in results["links"]:
        if "?" in link:   # only scan URLs with parameters
            xss_scanner.scan_url(link)
        
    # HTTP method scan
    http_scanner = UnsafeHTTPMethodScanner()
    http_scanner.scan_target(target)
    
    xxe_scanner = XXEScanner(crawler.session)
    xxe_results = xxe_scanner.scan(results)

    if not xxe_results:
        print("No XXE vulnerabilities detected (target may not process XML input)")

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