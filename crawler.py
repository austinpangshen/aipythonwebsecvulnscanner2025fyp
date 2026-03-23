import requests
from bs4 import BeautifulSoup
from collections import deque
import logging
from urllib.parse import urljoin, urlparse, parse_qs
import time

def normalize_url(url):
        """Normalize URL for consistent processing"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

def is_same_domain(url1, url2):
        """Check if two URLs belong to same domain"""
        return urlparse(url1).netloc == urlparse(url2).netloc


def add_delay():
        """Add delay between requests"""
        time.sleep(1)

def extract_links(soup, base_url):
        """Extract all links from page"""
        links = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if is_same_domain(full_url, base_url):
                links.add(full_url)
        return list(links)

def extract_forms(soup):
        """Extract all forms from BeautifulSoup object"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }

            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', '')
                }
                if input_data['name']:  # Only add if name exists
                    form_data['inputs'].append(input_data)

            forms.append(form_data)
        return forms

class WebCrawler:
    def __init__(self, target_url, max_pages=50):
        self.target_url = normalize_url(target_url)
        self.max_pages = max_pages
        self.visited_urls = set()
        self.found_forms = []
        self.found_links = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0'
        })
        self.interesting_keywords = [
            "admin",
            "login",
            "dashboard",
            "panel",
            "portal",
            "manage",
            "config",
            "setup",
            "backup",
            "phpmyadmin"
        ]

        self.interesting_urls = []

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def crawl(self):
        """Main crawling function"""
        self.logger.info(f"Starting crawl of {self.target_url}")

        url_queue = deque([self.target_url])

        while url_queue and len(self.visited_urls) < self.max_pages:
            current_url = url_queue.popleft()

            if current_url in self.visited_urls:
                continue

            try:
                self.logger.info(f"Crawling: {current_url}")
                response = self._make_request(current_url)

                if response and response.status_code == 200:
                    self.visited_urls.add(current_url)
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract forms
                    forms = extract_forms(soup)
                    for form in forms:
                        form['url'] = current_url
                        self.found_forms.append(form)

                    # Extract links for further crawling
                    links = extract_links(soup, current_url)
                    for link in links:
                        if link not in self.visited_urls:
                            url_queue.append(link)

                            if link not in self.found_links:
                                self.found_links.append(link)

                            # Detect interesting directories
                            parsed_path = urlparse(link).path.lower()

                            for keyword in self.interesting_keywords:
                                if keyword in parsed_path:
                                    if link not in self.interesting_urls:
                                        self.interesting_urls.append(link)

                add_delay()

            except Exception as e:
                self.logger.error(f"Error crawling {current_url}: {str(e)}")
                continue

        self.logger.info(f"Crawl completed. Found {len(self.visited_urls)} pages, {len(self.found_forms)} forms")
        return self.get_results()

    def _make_request(self, url):
        """Make HTTP request with error handling"""
        try:
            response = self.session.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False  # For testing purposes
            )
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            return None

    def get_results(self):
        """Get crawling results"""
        return {
            'target_url': self.target_url,
            'visited_urls': list(self.visited_urls),
            'forms': self.found_forms,
            'links': self.found_links,
            'interesting_urls': self.interesting_urls,
            'total_pages': len(self.visited_urls),
            'total_forms': len(self.found_forms)
        }


# Simple CLI test for Phase 1
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python crawler.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    crawler = WebCrawler(target, max_pages=10)
    results = crawler.crawl()

    print(f"\n=== Crawl Results for {target} ===")
    print(f"Pages found: {results['total_pages']}")
    print(f"Forms found: {results['total_forms']}")
    print(f"Links found: {len(results['links'])}")

    print("\n=== Forms Found ===")
    for i, form in enumerate(results['forms'], 1):
        print(f"Form {i}:")
        print(f"  URL: {form['url']}")
        print(f"  Method: {form['method']}")
        print(f"  Action: {form['action']}")
        print(f"  Inputs: {len(form['inputs'])}")
        for inp in form['inputs']:
            print(f"    - {inp['name']} ({inp['type']})")
        print()