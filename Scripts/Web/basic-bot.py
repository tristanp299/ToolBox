import requests
from bs4 import BeautifulSoup

def get_info(url):
    # Get the HTML content of the URL
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all the email addresses on the page and return them as a list
    emails = [a['href'] for a in soup.find_all('a', href=True) if '@' in a['href']]
    
    # Find all the phone numbers on the page and return them as a list
    phones = []
    for tag in soup.find_all():
        text = tag.get_text(strip=True)
        if any(c.isdigit() for c in text):
            # Check if there are digits in the text and assume it's a phone number
            phones.append(''.join(char for char in text if char.isdigit()))
    
    return emails, phones
emails, phones = get_info('https://en.wikipedia.org/wiki/Joe_Biden')
print(f'Emails found: {emails}')
print(f'Phone numbers found: {phones}')
