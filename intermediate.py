from crawler import WebCrawler


def run_crawler(target_url, max_pages=10):
    """
    Run the web crawler and return results
    """

    crawler = WebCrawler(target_url, max_pages=max_pages)
    results = crawler.crawl()

    return results

