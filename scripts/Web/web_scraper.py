################ Scrape email Addresses ###################
'''
import requests
from bs4 import BeautifulSoup
import re

url = "https://example.com"

def scrape_emails(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    emails = re.findall(r'\S+@\S+', soup.get_text())
    return set(emails)

email_set = scrape_emails(url)
for email in email_set:
    print("[+] Found Email: " + email)
'''
