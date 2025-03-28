import os
import re
import csv
import base64
import requests
import threading
from queue import Queue
from typing import List, Dict
import time
import concurrent.futures
import logging
from dotenv import load_dotenv

# Load GitHub tokens from .env file
load_dotenv()
GITHUB_TOKENS = [os.getenv(f"GITHUB_TOKEN_{i}") for i in range(1, 21)]
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

class GitHubAPIKeyScanner:
    def __init__(self, max_workers: int = 10):
        """
        Initialize the GitHub API Key Scanner with multithreading support
        
        :param max_workers: Maximum number of concurrent threads
        """
        # Comprehensive key patterns
        self.key_patterns = {
            'openai_sk': r'sk-[a-zA-Z0-9]{48}',
            'openai_proj_sk': r'sk-proj-[a-zA-Z0-9]{35}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{48}-[a-zA-Z0-9]{16}-[a-zA-Z0-9]{11}_[a-zA-Z0-9]{25}_[a-zA-Z0-9]{2}',
            'aws_access_key': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
            'aws_secret_key': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
            'stripe_api_key': r'sk_[live|test]_[0-9a-zA-Z]{24}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'slack_token': r'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
            'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'generic_api_key': r'(?i)(api[_]?key\s*[:=]\s*[\'"][a-zA-Z0-9_\-]+[\'"])',
            'secret_key_pattern': r'(?i)(secret[_]?key\s*[:=]\s*[\'"][a-zA-Z0-9_\-]+[\'"])'
        }
        
        self.file_filters = [
            '.ini', '.config', '.conf', '.cfg', '.key', '.env', 
            '.yaml', '.yml', '.toml', '.properties', '.json', 
            'credentials', 'secrets'
        ]
        
        # Multithreading setup
        self.max_workers = max_workers
        self.results_lock = threading.Lock()
        self.token_lock = threading.Lock()
        self.current_token_index = 0
        
        # Logging setup
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def get_next_headers(self):
        """Get the next available headers in a round-robin fashion"""
        with self.token_lock:
            headers = HEADERS_LIST[self.current_token_index]
            self.current_token_index = (self.current_token_index + 1) % len(HEADERS_LIST)
            return headers

    def search_repositories(self, query: str, max_results: int = 1000) -> List[Dict]:
        """
        Search GitHub repositories
        
        :param query: Search query
        :param max_results: Maximum number of results to return
        :return: List of repository details
        """
        url = 'https://api.github.com/search/repositories'
        params = {
            'q': query,
            'sort': 'stars',
            'order': 'desc',
            'per_page': min(max_results, 100)
        }
        
        try:
            headers = self.get_next_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json().get('items', [])
        except requests.RequestException as e:
            self.logger.error(f"Error searching repositories: {e}")
            return []

    def search_code_in_repo(self, repo_full_name: str, file_extension: str) -> List[Dict]:
        """
        Search code in a specific repository
        
        :param repo_full_name: Full name of the repository
        :param file_extension: File extension to search
        :return: List of code search results
        """
        url = 'https://api.github.com/search/code'
        params = {
            'q': f'extension:{file_extension} repo:{repo_full_name}',
            'per_page': 100
        }
        
        try:
            headers = self.get_next_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json().get('items', [])
        except requests.RequestException as e:
            self.logger.error(f"Error searching code in {repo_full_name}: {e}")
            return []

    def fetch_file_content(self, repo_full_name: str, file_path: str) -> str:
        """
        Fetch content of a specific file
        
        :param repo_full_name: Full name of the repository
        :param file_path: Path to the file
        :return: File content as string
        """
        url = f'https://api.github.com/repos/{repo_full_name}/contents/{file_path}'
        
        try:
            headers = self.get_next_headers()
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            content = response.json().get('content', '')
            
            return base64.b64decode(content).decode('utf-8', errors='ignore')
        except requests.RequestException as e:
            self.logger.error(f"Error fetching file content from {repo_full_name}/{file_path}: {e}")
            return ''

    def extract_api_keys(self, content: str) -> Dict[str, List[str]]:
        """
        Extract API keys from content
        
        :param content: File content to search
        :return: Dictionary of key types and found keys
        """
        found_keys = {}
        for key_type, pattern in self.key_patterns.items():
            keys = re.findall(pattern, content, re.IGNORECASE)
            if keys:
                found_keys[key_type] = list(set(keys))
        return found_keys

    def process_repository(self, repo: Dict, master_output_file: str):
        """
        Process a single repository
        
        :param repo: Repository details
        :param master_output_file: Path to master output CSV
        """
        try:
            # Scan through different file types
            for file_ext in self.file_filters:
                code_results = self.search_code_in_repo(repo['full_name'], file_ext)
                
                for code_item in code_results:
                    # Fetch file content
                    file_content = self.fetch_file_content(repo['full_name'], code_item['path'])
                    
                    # Extract API keys
                    api_keys = self.extract_api_keys(file_content)
                    
                    # Write results to master CSV
                    if api_keys:
                        with self.results_lock:
                            with open(master_output_file, 'a', newline='', encoding='utf-8') as master_csvfile:
                                master_csv_writer = csv.writer(master_csvfile)
                                for key_type, keys in api_keys.items():
                                    for key in keys:
                                        master_csv_writer.writerow([
                                            repo['full_name'], 
                                            code_item['path'], 
                                            key_type, 
                                            key
                                        ])
                        
                        self.logger.info(f"Found keys in {repo['full_name']} - {code_item['path']}")
                    
                    # Respect GitHub API rate limits
                    time.sleep(0.5)
        
        except Exception as e:
            self.logger.error(f"Error processing repo {repo['full_name']}: {e}")

    def scan_repositories(self, search_query: str = '', max_repos: int = 1000):
        """
        Scan public repositories with multithreading
        
        :param search_query: Initial repository search query
        :param max_repos: Maximum number of repositories to scan
        """
        # Create output directory
        os.makedirs('github_key_scan_results', exist_ok=True)
        
        # Master output file
        master_output_file = 'github_key_scan_results/all_keys_master.csv'
        
        # Write CSV headers
        with open(master_output_file, 'w', newline='', encoding='utf-8') as master_csvfile:
            master_csv_writer = csv.writer(master_csvfile)
            master_csv_writer.writerow(['Repository', 'File Path', 'Key Type', 'API Key'])
        
        # Default search query if none provided
        if not search_query:
            search_query = 'filename:.env OR filename:config OR filename:credentials OR filename:secrets'
        
        # Search repositories
        repos = self.search_repositories(search_query, max_repos)
        
        self.logger.info(f"Found {len(repos)} repositories to scan")
        
        # Use ThreadPoolExecutor for concurrent processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create a list of futures
            futures = [
                executor.submit(self.process_repository, repo, master_output_file) 
                for repo in repos
            ]
            
            # Wait for all futures to complete
            concurrent.futures.wait(futures)

def main():
    # Create scanner with 10 concurrent workers
    scanner = GitHubAPIKeyScanner(max_workers=10)
    
    # Broad search across all languages
    scanner.scan_repositories(max_repos=500)  # Adjust max_repos as needed

if __name__ == '__main__':
    main()