import os
import requests
import argparse
import time
import base64
from typing import List, Dict, Optional, Tuple

# Configure logging
import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Search GitHub for keywords in code, issues, PRs, and commits.'
    )
    parser.add_argument('-o', '--organization', default='', 
                       help='GitHub organization name (optional)')
    parser.add_argument('-k', '--keywords', required=True, nargs='+',
                       help='Keywords to search for (space-separated)')
    parser.add_argument('-l', '--language', default='',
                       help='Programming language to search in (default: all)')
    parser.add_argument('-t', '--token', default=os.getenv('GITHUB_TOKEN'),
                       help='GitHub token (default: from GITHUB_TOKEN env var)')
    parser.add_argument('--case-sensitive', action='store_true',
                       help='Perform case-sensitive search')
    parser.add_argument('--max-retries', type=int, default=3,
                       help='Max retries for API requests (default: 3)')
    parser.add_argument('--wildcard', action='store_true',
                       help='Append wildcard (*) to each keyword for partial matches')
    return parser.parse_args()

def create_search_query(keywords: List[str], org: str, language: str, wildcard: bool) -> str:
    """Create a GitHub API search query string."""
    if wildcard:
        keyword_query = '+'.join([f'{keyword}*' for keyword in keywords])
    else:
        keyword_query = '+'.join([f'"{keyword}"' for keyword in keywords])
    
    org_filter = f' org:{org}' if org else ''
    language_filter = f' language:{language}' if language else ''
    return f'{keyword_query}{org_filter}{language_filter}'

def fetch_github_paginated(url: str, headers: Dict[str, str], max_retries: int = 3) -> List[Dict]:
    """Fetch paginated results from GitHub API with retry logic."""
    items = []
    retries = 0
    while url and retries < max_retries:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Check rate limits
            if int(response.headers.get('X-RateLimit-Remaining', 1)) < 1:
                reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
                sleep_time = max(reset_time - time.time(), 0) + 10
                logger.warning(f'Rate limit exceeded. Sleeping for {sleep_time:.1f} seconds')
                time.sleep(sleep_time)
                continue
                
            data = response.json()
            items.extend(data.get('items', []))
            
            # Handle pagination
            if 'next' in response.links:
                url = response.links['next']['url']
            else:
                url = ''
            
            retries = 0  # Reset retry counter after successful request
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            retries += 1
            if retries < max_retries:
                sleep_time = 2 ** retries
                logger.info(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
    
    return items

def fetch_code_content(url: str, headers: Dict[str, str]) -> Optional[str]:
    """Fetch and decode base64-encoded code content."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        content_b64 = response.json().get('content', '')
        return base64.b64decode(content_b64).decode('utf-8', errors='ignore')
    except (requests.exceptions.RequestException, KeyError, UnicodeDecodeError) as e:
        logger.error(f"Failed to fetch code content: {str(e)}")
        return None

def extract_context(snippet: str, keyword: str, case_sensitive: bool, num_lines: int = 5) -> List[Tuple[str, int]]:
    """Extract context around keyword matches."""
    context_snippets = []
    lines = snippet.split('\n')
    search_func = str.__contains__ if case_sensitive else lambda s, k: k.lower() in s.lower()
    
    for i, line in enumerate(lines):
        if search_func(line, keyword):
            start = max(0, i - num_lines)
            end = min(len(lines), i + num_lines + 1)
            context = '\n'.join(lines[start:end])
            context_snippets.append((context, i+1))
    return context_snippets

def find_matched_keywords(content: str, keywords: List[str], case_sensitive: bool) -> List[str]:
    """Identify which keywords are present in the content."""
    matched = []
    for keyword in keywords:
        if case_sensitive:
            if keyword in content:
                matched.append(keyword)
        else:
            if keyword.lower() in content.lower():
                matched.append(keyword)
    return matched

def search_github(args: argparse.Namespace) -> Dict[str, List]:
    """Main search function handling all GitHub search operations."""
    headers = {
        'Authorization': f'token {args.token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'GitHub-Scraper/1.0'
    }
    
    # Construct search queries
    base_query = create_search_query(args.keywords, args.organization, args.language, args.wildcard)
    
    search_endpoints = {
        'code': f'https://api.github.com/search/code?q={base_query}+in:file',
        'issues': f'https://api.github.com/search/issues?q={base_query}+type:issue',
        'prs': f'https://api.github.com/search/issues?q={base_query}+type:pr',
        'commits': f'https://api.github.com/search/commits?q={base_query}'
    }
    
    results = {}
    
    # Search all endpoints
    for category, url in search_endpoints.items():
        logger.info(f"Searching {category}...")
        items = fetch_github_paginated(url, headers, args.max_retries)
        
        if category == 'code':
            code_results = []
            for item in items:
                content = fetch_code_content(item['url'], headers)
                if content:
                    html_url = item['html_url']
                    for keyword in args.keywords:
                        contexts = extract_context(content, keyword, args.case_sensitive)
                        for ctx, line_num in contexts:
                            code_results.append({
                                'keyword': keyword,
                                'context': ctx,
                                'url': html_url,
                                'line': line_num
                            })
            results['code'] = code_results
        else:
            category_results = []
            for item in items:
                if category in ['issues', 'prs']:
                    content = (item.get('title', '') or '') + '\n' + (item.get('body', '') or '')
                    html_url = item['html_url']
                else:  # commits
                    content = (item['commit'].get('message', '') or '')
                    html_url = item['html_url']
                
                matched_keywords = find_matched_keywords(content, args.keywords, args.case_sensitive)
                if matched_keywords:
                    category_results.append({
                        'content': content,
                        'url': html_url,
                        'keywords': matched_keywords
                    })
            results[category] = category_results
    
    return results

def format_output(result: Dict, category: str) -> str:
    """Format individual result entry for output."""
    output = []
    if category == 'code':
        output.append(f"Keyword: {result['keyword']}")
        output.append(f"Line: {result['line']}")
        output.append(f"URL: {result['url']}")
        output.append("Context:")
        output.append(result['context'])
    else:
        output.append(f"Matched Keywords: {', '.join(result['keywords'])}")
        output.append(f"URL: {result['url']}")
        output.append("Content:")
        output.append(result['content'][:500] + ('...' if len(result['content']) > 500 else ''))
    return '\n'.join(output)

def main():
    args = parse_arguments()
    if not args.token:
        logger.error("GitHub token required. Use --token or set GITHUB_TOKEN environment variable.")
        return
    
    results = search_github(args)
    
    # Print results
    for category, items in results.items():
        print(f"\n{'='*40}")
        print(f"{category.upper()} RESULTS ({len(items)} found):")
        print('='*40)
        for idx, item in enumerate(items[:10], 1):
            print(f"\nResult #{idx}:")
            print(format_output(item, category))
            print('-'*40)

if __name__ == '__main__':
    main()