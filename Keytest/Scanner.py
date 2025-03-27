import requests
import os
import time
import csv
import threading
import concurrent.futures
from datetime import datetime
from dotenv import load_dotenv

# Load GitHub tokens from .env file
load_dotenv()
GITHUB_TOKENS = [os.getenv(f"GITHUB_TOKEN_{i}") for i in range(1, 11)]
GITHUB_TOKENS = [token for token in GITHUB_TOKENS if token]  # Remove empty keys

if not GITHUB_TOKENS:
    raise ValueError("❌ No GitHub tokens found in .env file!")

# Create headers for API keys
HEADERS_LIST = [
    {
        "User-Agent": "APIKeyScanner/1.0",
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}",
    }
    for token in GITHUB_TOKENS
]

# Queries to scan
QUERIES = [
    'path:.ini sk- OR OPENAI',
    'path:.config sk- OR OPENAI',
    'path:.conf sk- OR OPENAI',
    'path:.cfg sk- OR OPENAI',
    'path:.key sk- OR OPENAI',
    'sk- OPENAI',
    'path:.env sk- OPENAI'
]
# Ensure API key rotation is thread-safe
token_lock = threading.Lock()

def check_rate_limit(headers):
    """Check API rate limit and wait if needed."""
    url = "https://api.github.com/rate_limit"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"⚠️ Rate limit check failed: {response.json()}")
        return 0, datetime.now()
    
    data = response.json()
    remaining = data['rate']['remaining']
    reset_time = datetime.fromtimestamp(data['rate']['reset'])
    
    if remaining == 0:
        wait_time = (reset_time - datetime.now()).total_seconds()
        print(f"⏳ API rate limit exceeded! Waiting {int(wait_time)} seconds...")
        time.sleep(wait_time + 1)
    
    return remaining, reset_time

def fetch_all_pages(query, headers):
    """Fetch all available pages of results for a query."""
    base_url = "https://api.github.com/search/code"
    per_page = 100  
    max_pages = 10  
    results = []
    
    for page in range(1, max_pages + 1):
        params = {'q': query, 'per_page': per_page, 'page': page}
        response = requests.get(base_url, params=params, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            items = data.get('items', [])
            if not items:
                break  
            
            for item in items:
                repo_name = item['repository']['full_name']
                file_path = item['path']
                file_url = item['html_url']
                results.append([repo_name, file_path, file_url])
            
            time.sleep(2)  # Prevent hitting secondary rate limits
        
        elif response.status_code == 403:
            print("\n❌ Rate Limit Exceeded! Waiting before retrying...")
            remaining, reset_time = check_rate_limit(headers)
            continue  # Retry with the same key after waiting

        else:
            print(f"\n❌ Error {response.status_code}: {response.json()}")
            break

    return results

def scan_github(query, headers, key_index):
    """Run a GitHub query using a specific API key."""
    print(f"\n🔍 Searching '{query}' with API key {key_index + 1}")

    results = fetch_all_pages(query, headers)
    print(f"✅ Found {len(results)} results for '{query}' with API key {key_index + 1}")

    if results:
        save_to_csv(results, f"results_key_{key_index + 1}.csv")
    
    return results

def save_to_csv(data, filename):
    """Save results to a CSV file."""
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Repository", "File Path", "File URL"])
        writer.writerows(data)
    print(f"\n📂 Results saved to {filename}")

def main():
    print(f"🚀 Starting GitHub Scanner with {len(GITHUB_TOKENS)} API keys...\n")

    # Check rate limits before starting
    for headers in HEADERS_LIST:
        check_rate_limit(headers)

    # Assign each query to an API key in a round-robin fashion
    assignments = []
    for i, query in enumerate(QUERIES):
        key_index = i % len(GITHUB_TOKENS)  # Evenly distribute queries
        assignments.append((query, key_index))

    # Print key assignments before running
    print("\n🔄 API Key Assignments:")
    for query, key_index in assignments:
        print(f"   - API Key {key_index + 1} → Query: {query}")

    print("\n⏳ Starting searches...\n")

    # Run queries in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(GITHUB_TOKENS)) as executor:
        futures = []
        for query, key_index in assignments:
            headers = HEADERS_LIST[key_index]
            futures.append(executor.submit(scan_github, query, headers, key_index))
        
        concurrent.futures.wait(futures)  # Wait for all threads to complete

    print("\n✅ Scan completed")

if __name__ == "__main__":
    main()
