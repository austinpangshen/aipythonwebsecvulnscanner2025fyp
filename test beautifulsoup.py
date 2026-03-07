import requests
from bs4 import BeautifulSoup

url = "https://www.google.com"
headers = {'User-Agent': 'Mozilla/5.0'} # Pretend to be a browser

try:
    # 1. Get the raw HTML
    response = requests.get(url, headers=headers)
    
    # 2. Turn the messy HTML into a "Soup" object
    # We use 'html.parser' which comes built-in with Python
    soup = BeautifulSoup(response.text, 'html.parser')

    print("--- Google Page Info ---")
    
    # 3. Extract the Title tag
    print(f"Page Title: {soup.title.string}")

    # 4. Find the Google Logo (Searching for an <img> tag)
    logo = soup.find('img')
    if logo and logo.get('alt'):
        print(f"Logo Description (Alt text): {logo.get('alt')}")

    # 5. Find all links (<a> tags)
    links = soup.find_all('a')
    print(f"\nFound {len(links)} links on the page. Here are the first 5:")
    
    for link in links[:5]:
        text = link.text.strip() or "No Text"
        href = link.get('href')
        print(f"- {text}: {href}")

except Exception as e:
    print(f"An error occurred: {e}")