#!/usr/bin/env python3

import json
import re
import sys
import argparse
from typing import Dict, List, Set
from pathlib import Path
import ipaddress
import logging
from datetime import datetime
import base64

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('file_analyzer.log'),
        logging.StreamHandler()
    ]
)

class FileAnalyzer:
    def __init__(self):
        # Regular expressions for different types of data
        self.patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
            'hash': r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b',
            'api_key': r'(?i)(?:api[_-]?key|secret)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            # New patterns for sensitive information
            'username': r'(?i)(?:username|user|login)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'password': r'(?i)(?:password|pass|pwd)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'public_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PUBLIC KEY-----',
            'aws_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'base64_encoded': r'[A-Za-z0-9+/=]{40,}',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'social_security': r'\b\d{3}-\d{2}-\d{4}\b',
            'database_connection': r'(?i)(?:mysql|postgresql|mongodb|sqlserver)://[^:\s]+:[^@\s]+@[^:\s]+:\d+',
            'access_token': r'(?i)(?:access[_-]?token|bearer[_-]?token)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'refresh_token': r'(?i)(?:refresh[_-]?token)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'oauth_token': r'(?i)(?:oauth[_-]?token)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'session_id': r'(?i)(?:session[_-]?id|sid)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'cookie': r'(?i)(?:cookie|session)[=:]\s*[\'"]([^\'"]+)[\'"]'
        }
        
        # Initialize results dictionary with new categories
        self.results: Dict[str, Set[str]] = {
            'ipv4': set(),
            'ipv6': set(),
            'email': set(),
            'domain': set(),
            'url': set(),
            'hash': set(),
            'api_key': set(),
            'jwt': set(),
            'username': set(),
            'password': set(),
            'private_key': set(),
            'public_key': set(),
            'aws_key': set(),
            'base64_encoded': set(),
            'credit_card': set(),
            'social_security': set(),
            'database_connection': set(),
            'access_token': set(),
            'refresh_token': set(),
            'oauth_token': set(),
            'session_id': set(),
            'cookie': set()
        }

    def validate_ipv4(self, ip: str) -> bool:
        """Validate if a string is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def is_valid_base64(self, string: str) -> bool:
        """Validate if a string is valid base64 encoded."""
        try:
            # Add padding if necessary
            padding = 4 - (len(string) % 4)
            if padding != 4:
                string += '=' * padding
            # Try to decode
            base64.b64decode(string)
            return True
        except Exception:
            return False

    def analyze_file(self, file_path: str) -> None:
        """Analyze the content of a file and extract relevant information."""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                return

            # Read file content based on file type
            if file_path.suffix.lower() == '.json':
                with open(file_path, 'r') as f:
                    content = json.dumps(json.load(f))
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

            # Extract information using regex patterns
            for data_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    value = match.group(0)
                    # Apply additional validation based on data type
                    if data_type == 'ipv4' and not self.validate_ipv4(value):
                        continue
                    if data_type == 'base64_encoded' and not self.is_valid_base64(value):
                        continue
                    self.results[data_type].add(value)

        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")

    def print_results(self) -> None:
        """Print the extracted information in a formatted way."""
        print("\n=== File Analysis Results ===\n")
        
        # Define categories for better organization
        categories = {
            'Network Information': ['ipv4', 'ipv6', 'domain', 'url'],
            'Authentication': ['username', 'password', 'jwt', 'access_token', 'refresh_token', 'oauth_token'],
            'API & Keys': ['api_key', 'aws_key'],
            'Cryptography': ['private_key', 'public_key', 'hash'],
            'Sensitive Data': ['credit_card', 'social_security', 'email'],
            'Session Management': ['session_id', 'cookie'],
            'Database': ['database_connection'],
            'Encoded Data': ['base64_encoded']
        }

        for category, data_types in categories.items():
            print(f"\n{category}:")
            for data_type in data_types:
                values = self.results[data_type]
                if values:
                    print(f"  {data_type.upper()} ({len(values)} found):")
                    for value in sorted(values):
                        print(f"    - {value}")

def main():
    parser = argparse.ArgumentParser(description='Analyze files for cybersecurity purposes')
    parser.add_argument('file_path', help='Path to the file to analyze')
    args = parser.parse_args()

    analyzer = FileAnalyzer()
    analyzer.analyze_file(args.file_path)
    analyzer.print_results()

if __name__ == "__main__":
    main() 