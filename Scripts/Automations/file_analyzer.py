#!/usr/bin/env python3
#Author: Tristan Pereira
#Date: 2025-03-28
#Purpose: Analyze files for cybersecurity purposes
#Usage: python3 file_analyzer.py <file_path>

# Import necessary libraries
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
import math

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
            'hash': r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}|\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})\b',
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
            'cookie': r'(?i)(?:cookie|session)[=:]\s*[\'"]([^\'"]+)[\'"]',
            # New API-related patterns
            'api_endpoint': r'(?i)(?:https?://[^/\s]+)?/(?:api|rest|graphql|v\d+)/[^\s"\']+',
            'api_method': r'(?i)(?:\'|"|\b)(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)(?:\'|"|\b)',
            'content_type': r'(?i)(?:Content-Type|content-type)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'api_version': r'(?i)(?:v\d+(?:\.\d+)*|\bversion[=:]\s*[\'"]([^\'"]+)[\'"])',
            'api_parameter': r'(?i)(?:[?&][^=\s]+=[^&\s]+)',
            'authorization_header': r'(?i)(?:Authorization|auth)[=:]\s*[\'"]([^\'"]+)[\'"]',
            'rate_limit': r'(?i)(?:rate[_-]?limit|x-rate-limit)[=:]\s*[\'"]?(\d+)[\'"]?',
            'api_key_param': r'(?i)(?:api_key|apikey|key)=([^&\s]+)',
            'curl_command': r'(?i)curl\s+(?:-X\s+(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+)?[\'"]?https?://[^\s\'">]+',
            'webhook_url': r'(?i)(?:webhook|callback)[=:]\s*[\'"]?https?://[^\s\'"]+[\'"]?',
            'http_status_code': r'(?i)(?:status|code)[=:]\s*[\'"]?(\d{3})[\'"]?',
            # OpenAPI/Swagger detection
            'openapi_schema': r'(?i)(?:\"openapi\"\s*:\s*\"[^\"]*)|(swagger\s*:\s*\"[^\"]*)',
            
            # GraphQL patterns
            'graphql_query': r'(?i)(?:query\s+\w+\s*\{[^}]*\}|mutation\s+\w+\s*\{[^}]*\})',
            'graphql_schema': r'(?i)(?:type\s+\w+\s*\{[^}]*\}|input\s+\w+\s*\{[^}]*\}|interface\s+\w+\s*\{[^}]*\})',
            
            # REST resource patterns
            'rest_resource': r'(?i)(?:\/[a-zA-Z0-9_-]+(?:\/\{[a-zA-Z0-9_-]+\})?(?:\/[a-zA-Z0-9_-]+)*)',
            
            # API response patterns
            'xml_response': r'(?i)(?:<\?xml[^>]+>|<[a-zA-Z0-9_:]+\s+xmlns)',
            
            # Error handling patterns
            'error_pattern': r'(?i)(?:\"error\"\s*:\s*\{|\"errors\"\s*:\s*\[|\<error>|\<errors>)',
            'http_error': r'(?i)(?:[45]\d{2}\s+[A-Za-z\s]+)',
            
            # API authentication schemes
            'oauth_flow': r'(?i)(?:oauth2|authorization_code|client_credentials|password|implicit)',
            'api_auth_scheme': r'(?i)(?:bearer|basic|digest|apikey|oauth|jwt)\s+auth',
            
            # API request headers
            'request_header': r'(?i)(?:[A-Za-z0-9-]+:\s*[^\n]+)',
            
            # Request body identification
            'request_body_json': r'(?i)(?:body\s*:\s*\{[^}]*\}|data\s*:\s*\{[^}]*\})',
            'form_data': r'(?i)(?:FormData|multipart\/form-data|application\/x-www-form-urlencoded)',
            
            # API parameter types
            'path_parameter': r'(?i)(?:\{[a-zA-Z0-9_-]+\})',
            'query_parameter': r'(?i)(?:\?(?:[a-zA-Z0-9_-]+=[^&\s]+)(?:&[a-zA-Z0-9_-]+=[^&\s]+)*)',
            
            # API documentation patterns
            'api_doc_comment': r'(?i)(?:\/\*\*[\s\S]*?\*\/|\/\/\/.*$|#\s+@api)',
            
            # Webhook patterns
            'webhook_event': r'(?i)(?:\"event\"\s*:\s*\"[^\"]+\"|event=[^&\s]+)',
            
            # Rate limiting and pagination
            'pagination': r'(?i)(?:page=\d+|limit=\d+|offset=\d+|per_page=\d+)',
            'rate_limit_header': r'(?i)(?:X-RateLimit-Limit|X-RateLimit-Remaining|X-RateLimit-Reset)',
            
            # New pattern for successful JSON requests
            'successful_json_request': r'(?i)(?:\{\s*\"(?:success|status|ok|result)\"\s*:\s*(?:true|\"success\"|\"ok\"|1)|\{\s*\"data\"\s*:|\{\s*\"[^\"]+\"\s*:\s*\{[^}]+\}\s*,\s*\"status\"\s*:\s*(?:200|201|\"success\"|\"ok\"))',
            
            # New pattern for failed JSON requests
            'failed_json_request': r'(?i)(?:\{\s*\"(?:error|errors|status)\"\s*:\s*(?:false|\"failed\"|\"error\"|0|\{)|\{\s*\"message\"\s*:\s*\"[^\"]*error[^\"]*\")',
        }
        
        # Add hash identification patterns
        self.hash_patterns = {
            'MD5': (r'^[a-fA-F0-9]{32}$', 32),
            'SHA-1': (r'^[a-fA-F0-9]{40}$', 40),
            'SHA-256': (r'^[a-fA-F0-9]{64}$', 64),
            'SHA-512': (r'^[a-fA-F0-9]{128}$', 128),
            'NTLM': (r'^[a-fA-F0-9]{32}$', 32),
            'MySQL4': (r'^[a-fA-F0-9]{16}$', 16),
            'MySQL5': (r'^[a-fA-F0-9]{40}$', 40),
            'BCrypt': (r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$', None),
            'RIPEMD-160': (r'^[a-fA-F0-9]{40}$', 40)
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
            'cookie': set(),
            'api_endpoint': set(),
            'api_method': set(),
            'content_type': set(),
            'api_version': set(),
            'api_parameter': set(),
            'authorization_header': set(),
            'rate_limit': set(),
            'api_key_param': set(),
            'curl_command': set(),
            'webhook_url': set(),
            'http_status_code': set(),
            'openapi_schema': set(),
            'graphql_query': set(),
            'graphql_schema': set(),
            'rest_resource': set(),
            'xml_response': set(),
            'error_pattern': set(),
            'http_error': set(),
            'oauth_flow': set(),
            'api_auth_scheme': set(),
            'request_header': set(),
            'request_body_json': set(),
            'form_data': set(),
            'path_parameter': set(),
            'query_parameter': set(),
            'api_doc_comment': set(),
            'webhook_event': set(),
            'pagination': set(),
            'rate_limit_header': set(),
            'api_framework': set(),
            'successful_json_request': set(),
            'failed_json_request': set(),
            'api_request_examples': set(),
        }
        
        # API structure correlation data
        self.api_structure = {}

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

    def calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string to help identify randomness.
        Higher entropy suggests more randomness, which is typical of hashes.
        
        Args:
            string (str): The string to analyze
            
        Returns:
            float: The calculated entropy value
        """
        freq_dict = {}
        for c in string:
            freq_dict[c] = freq_dict.get(c, 0) + 1
            
        length = len(string)
        entropy = 0
        for freq in freq_dict.values():
            probability = freq / length
            entropy -= probability * math.log2(probability)
            
        return entropy

    def identify_hash(self, hash_value: str) -> str:
        """
        Advanced hash identification using pattern matching and entropy analysis.
        
        Args:
            hash_value (str): The hash string to identify
            
        Returns:
            str: Identified hash type(s) or 'Unknown'
        """
        # Clean the hash value
        hash_value = hash_value.strip()
        
        # Calculate entropy
        entropy = self.calculate_entropy(hash_value)
        
        # Store potential matches
        potential_matches = []
        
        # Check against known patterns
        for hash_type, (pattern, length) in self.hash_patterns.items():
            if length and len(hash_value) != length:
                continue
                
            if re.match(pattern, hash_value):
                if hash_type == 'MD5':
                    if entropy > 3.0:
                        potential_matches.append(hash_type)
                elif hash_type == 'BCrypt':
                    potential_matches = ['BCrypt']
                    break
                else:
                    potential_matches.append(hash_type)
        
        # Additional checks for specific hash types
        if len(hash_value) == 32:
            if all(c in '0123456789abcdef' for c in hash_value.lower()):
                if hash_value.lower().startswith('aad3b435'):
                    potential_matches = ['NTLM (Empty Password)']
                elif entropy < 2.5:
                    potential_matches.append('NTLM')
        
        return '/'.join(potential_matches) if potential_matches else 'Unknown'

    def extract_api_structure(self, content: str) -> None:
        """
        Extract and correlate API endpoints with their methods, parameters, and response types.
        
        Args:
            content (str): The file content to analyze
        """
        # Look for OpenAPI/Swagger schemas first
        openapi_match = re.search(r'(?i)"swagger"\s*:\s*"([^"]+)"|"openapi"\s*:\s*"([^"]+)"', content)
        if openapi_match:
            self.results['openapi_schema'].add(f"OpenAPI/Swagger detected: {openapi_match.group(1) or openapi_match.group(2)}")
            # Advanced OpenAPI extraction would be done here
        
        # Extract API endpoints and correlate with methods
        endpoints = {}
        
        # Find all potential API endpoints
        endpoint_matches = re.finditer(self.patterns['api_endpoint'], content)
        for match in endpoint_matches:
            endpoint = match.group(0)
            
            # Try to find methods associated with this endpoint
            context_window = content[max(0, match.start() - 100):min(len(content), match.end() + 100)]
            
            # Look for HTTP methods near the endpoint
            method_matches = re.finditer(self.patterns['api_method'], context_window)
            methods = [m.group(0).strip('"\'') for m in method_matches]
            
            # Look for parameters
            params = []
            param_matches = re.finditer(self.patterns['api_parameter'], context_window)
            params.extend([p.group(0) for p in param_matches])
            
            path_param_matches = re.finditer(self.patterns['path_parameter'], endpoint)
            params.extend([p.group(0) for p in path_param_matches])
            
            # Look for content types
            content_type_matches = re.finditer(self.patterns['content_type'], context_window)
            content_types = [ct.group(0) for ct in content_type_matches]
            
            # Store the correlated information
            if endpoint not in endpoints:
                endpoints[endpoint] = {
                    'methods': set(methods),
                    'parameters': set(params),
                    'content_types': set(content_types)
                }
            else:
                endpoints[endpoint]['methods'].update(methods)
                endpoints[endpoint]['parameters'].update(params)
                endpoints[endpoint]['content_types'].update(content_types)
        
        # Store the API structure for later use
        self.api_structure = endpoints
    
    def detect_api_frameworks(self, content: str) -> None:
        """
        Detect common API frameworks and patterns.
        
        Args:
            content (str): The file content to analyze
        """
        frameworks = []
        
        # REST API detection
        if re.search(r'(?i)rest[ful]?[\s_-]?api', content):
            frameworks.append('REST API')
        
        # GraphQL detection
        if re.search(r'(?i)(?:graphql|query\s+\{|mutation\s+\{)', content):
            frameworks.append('GraphQL')
        
        # SOAP detection
        if re.search(r'(?i)(?:<soap:|<\/soap:|soap:Envelope)', content):
            frameworks.append('SOAP')
        
        # gRPC detection
        if re.search(r'(?i)(?:grpc\.|\bproto3\b)', content):
            frameworks.append('gRPC')
        
        # Store detected frameworks
        if frameworks:  # Only try to add if we found frameworks
            # Ensure the key exists before adding to it
            if 'api_framework' not in self.results:
                self.results['api_framework'] = set()
                
            # Add each framework
            for framework in frameworks:
                self.results['api_framework'].add(framework)
    
    def extract_api_responses(self, content: str) -> None:
        """
        Extract and categorize API responses by success/failure status.
        
        Args:
            content (str): The file content to analyze
        """
        # Find JSON success patterns
        success_matches = re.finditer(self.patterns['successful_json_request'], content)
        for match in success_matches:
            # Extract a reasonable chunk of the JSON response (not just the matching part)
            start_pos = match.start()
            
            # Try to find the end of this JSON object
            brace_count = 0
            end_pos = start_pos
            
            # Find opening brace
            while start_pos < len(content) and content[start_pos] != '{':
                start_pos += 1
            
            # Find matching closing brace
            for i in range(start_pos, min(start_pos + 500, len(content))):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            # Extract a reasonable sample of the JSON
            json_sample = content[start_pos:end_pos]
            if len(json_sample) > 200:
                json_sample = json_sample[:197] + "..."
            
            self.results['successful_json_request'].add(json_sample)
        
        # Find JSON error patterns
        error_matches = re.finditer(self.patterns['failed_json_request'], content)
        for match in error_matches:
            # Similar extraction logic as above
            start_pos = match.start()
            
            while start_pos < len(content) and content[start_pos] != '{':
                start_pos += 1
            
            brace_count = 0
            end_pos = start_pos
            
            for i in range(start_pos, min(start_pos + 500, len(content))):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            json_sample = content[start_pos:end_pos]
            if len(json_sample) > 200:
                json_sample = json_sample[:197] + "..."
            
            self.results['failed_json_request'].add(json_sample)
    
    def extract_complete_api_requests(self, content: str) -> None:
        """
        Extract complete API requests including method, endpoint, headers, and payload.
        This helps users understand how to construct successful API requests.
        Only extracts requests that appear to be successful based on context.
        
        Args:
            content (str): The file content to analyze
        """
        # Initialize request examples collection if it doesn't exist
        self.results['api_request_examples'] = self.results.get('api_request_examples', set())
        
        # Look for patterns that might indicate complete API requests
        request_patterns = [
            # cURL command pattern
            r'(?i)curl\s+(?:-X\s+)?(?P<method>GET|POST|PUT|DELETE|PATCH)\s+["\']?(?P<url>https?://[^\s"\']+)["\']?(?P<options>(?:\s+-H\s+["\'][^"\']+["\']|\s+--header\s+["\'][^"\']+["\']|\s+-d\s+["\'].*?["\']|\s+--data\s+["\'].*?["\']|\s+--data-raw\s+["\'](.+?)["\']|\s+-F\s+["\'].*?["\'])*)',
            
            # JavaScript fetch/axios pattern
            r'(?i)(?:fetch|axios)(?:\.[a-zA-Z]+)?\(\s*["\'](?P<url>https?://[^\s"\']+)["\'](?:\s*,\s*\{(?P<options>.*?)\})?\s*\)',
            
            # Python requests pattern
            r'(?i)requests\.(?P<method>get|post|put|delete|patch)\(\s*["\'](?P<url>https?://[^\s"\']+)["\'](?:\s*,\s*(?P<options>.*?))?\s*\)',
            
            # Postman/insomnia-style documentation
            r'(?i)(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<url>https?://[^\s"\']+)[\s\n]+(?P<headers>(?:[A-Za-z0-9-]+:\s*[^\n]+[\n])+)(?:[\n\s]*(?P<body>\{.*?\}))?',
        ]
        
        # Define success indicators - patterns that suggest a request was successful
        success_indicators = [
            # HTTP success status codes
            r'(?i)(?:status(?:_code)?|code)\s*(?::|=|==)\s*(?:200|201|202|204|2\d{2})',
            # JSON success fields
            r'(?i)(?:"status"\s*:\s*(?:200|201|"success"|"ok"))',
            r'(?i)(?:"success"\s*:\s*(?:true|1))',
            r'(?i)(?:"ok"\s*:\s*(?:true|1))',
            # Success message patterns
            r'(?i)(?:"message"\s*:\s*"[^"]*(?:success|succeeded)[^"]*")',
            # Common success comments/logs
            r'(?i)(?:\/\/\s*success|#\s*success|console\.log\("[^"]*success[^"]*"\))',
            # Return data without errors
            r'(?i)(?:"data"\s*:\s*\{[^}]+\})(?![^}]*"error")',
            # Explicit validation of successful response
            r'(?i)(?:assert(?:Equal)?\([^)]*(?:200|201|(?:true|success))[^)]*\))',
        ]
        
        for pattern in request_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                try:
                    # First check if this request has evidence of success
                    # Examine context after the request (where the response would be)
                    context_window = content[match.start():min(len(content), match.end() + 500)]
                    success_found = False
                    
                    # Look for success indicators in the context window
                    for indicator in success_indicators:
                        if re.search(indicator, context_window):
                            success_found = True
                            break
                    
                    # Skip this request if no success indicators were found
                    if not success_found:
                        continue
                    
                    # Extract basic components
                    method = match.group('method').upper() if 'method' in match.groupdict() else "GET"
                    url = match.group('url')
                    
                    # Build request example
                    example = f"{method} {url}"
                    
                    # Process options/headers
                    if 'options' in match.groupdict() and match.group('options'):
                        options = match.group('options')
                        
                        # Extract headers
                        headers = []
                        header_matches = re.finditer(r'-H\s+["\']([^"\']+)["\']|--header\s+["\']([^"\']+)["\']', options)
                        for h_match in header_matches:
                            header = h_match.group(1) or h_match.group(2)
                            # Sanitize sensitive headers
                            if re.search(r'(?i)authorization|api[-_]?key|token|secret', header):
                                header = re.sub(r'(?i)(\b(?:authorization|api[-_]?key|token|secret)[^:]*:).*', r'\1 [REDACTED]', header)
                            headers.append(header)
                        
                        if headers:
                            example += "\nHeaders:"
                            for header in headers:
                                example += f"\n  {header}"
                        
                        # Extract body content if possible
                        body_match = re.search(r'-d\s+["\'](.+?)["\']|--data\s+["\'](.+?)["\']|--data-raw\s+["\'](.+?)["\']|body\s*:\s*(\{.+?\})|data\s*:\s*(\{.+?\})', options, re.DOTALL)
                        if body_match:
                            body = next((g for g in body_match.groups() if g), "")
                            if body:
                                # Truncate long bodies
                                if len(body) > 300:
                                    body = body[:297] + "..."
                                example += f"\nBody:\n  {body}"
                    
                    # For Postman/insomnia pattern
                    if 'headers' in match.groupdict() and match.group('headers'):
                        headers = match.group('headers').strip().split('\n')
                        example += "\nHeaders:"
                        for header in headers:
                            # Sanitize sensitive headers
                            if re.search(r'(?i)authorization|api[-_]?key|token|secret', header):
                                header = re.sub(r'(?i)(\b(?:authorization|api[-_]?key|token|secret)[^:]*:).*', r'\1 [REDACTED]', header)
                            if header.strip():
                                example += f"\n  {header.strip()}"
                    
                    if 'body' in match.groupdict() and match.group('body'):
                        body = match.group('body')
                        if len(body) > 300:
                            body = body[:297] + "..."
                        example += f"\nBody:\n  {body}"
                    
                    # Add explicit success note
                    example += "\nStatus: SUCCESSFUL REQUEST"
                    
                    # Store the example
                    self.results['api_request_examples'].add(example)
                    
                except Exception as e:
                    # Don't crash if something goes wrong with one example
                    logging.warning(f"Error processing API request example: {str(e)}")
    
    def analyze_file(self, file_path: str) -> None:
        """Analyze the content of a file and extract relevant information."""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                return

            # Read file content based on file type
            if file_path.suffix.lower() == '.json':
                try:
                    # Try to parse as JSON first
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        json_content = json.load(f)
                        content = json.dumps(json_content)
                except json.JSONDecodeError as json_err:
                    # If JSON parsing fails, read as plain text
                    logging.warning(f"File {file_path} has invalid JSON syntax at {json_err}. Processing as text.")
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

            # Extract information using regex patterns
            for data_type, pattern in self.patterns.items():
                # Skip the JSON response patterns as we'll handle them separately
                if data_type in ['successful_json_request', 'failed_json_request']:
                    continue
                
                matches = re.finditer(pattern, content)
                for match in matches:
                    value = match.group(0)
                    # Apply additional validation based on data type
                    if data_type == 'ipv4' and not self.validate_ipv4(value):
                        continue
                    if data_type == 'base64_encoded' and not self.is_valid_base64(value):
                        continue
                    if data_type == 'hash':
                        hash_type = self.identify_hash(value)
                        confidence = self.calculate_entropy(value)
                        value = f"{value} (Type: {hash_type}, Entropy: {confidence:.2f})"
                    self.results[data_type].add(value)

            # Add advanced API analysis
            self.extract_api_structure(content)
            self.detect_api_frameworks(content)
            self.extract_api_responses(content)
            self.extract_complete_api_requests(content)
            
            # Perform additional analysis for API specification files
            if file_path.name.lower() in ('swagger.json', 'openapi.json', 'swagger.yaml', 'openapi.yaml', 'api-docs.json'):
                logging.info(f"Detected potential API specification file: {file_path}")
                # Here you could add specific OpenAPI/Swagger parsing logic

        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")

    def print_results(self, markdown_format=False) -> None:
        """
        Print the extracted information in a formatted way.
        
        Args:
            markdown_format (bool): If True, output will be wrapped in triple backticks for markdown
        """
        # Start markdown output if requested
        if markdown_format:
            print("```")
        
        print("\n=== File Analysis Results ===\n")
        
        # Define categories for better organization
        categories = {
            'Network Information': ['ipv4', 'ipv6', 'domain', 'url'],
            'Authentication': ['username', 'password', 'jwt', 'access_token', 'refresh_token', 'oauth_token'],
            'API & Keys': ['api_key', 'aws_key', 'api_key_param'],
            'Cryptography': ['private_key', 'public_key', 'hash'],
            'Sensitive Data': ['credit_card', 'social_security', 'email'],
            'Session Management': ['session_id', 'cookie'],
            'Database': ['database_connection'],
            'Encoded Data': ['base64_encoded'],
            'API Information': ['api_endpoint', 'api_method', 'content_type', 'api_version', 
                               'api_parameter', 'authorization_header', 'rate_limit', 
                               'api_key_param', 'curl_command', 'webhook_url', 'http_status_code'],
            'API Request Examples': ['api_request_examples'],
            'API Responses': ['successful_json_request', 'failed_json_request'],
            'API Frameworks': ['api_framework', 'openapi_schema', 'graphql_query', 'graphql_schema'],
            'API Structure': ['rest_resource', 'path_parameter', 'query_parameter', 
                             'xml_response', 'request_header', 
                             'request_body_json', 'form_data'],
            'API Security': ['api_auth_scheme', 'oauth_flow'],
            'API Error Handling': ['error_pattern', 'http_error'],
            'API Documentation': ['api_doc_comment'],
            'API Advanced Features': ['webhook_event', 'pagination', 'rate_limit_header'],
        }

        for category, data_types in categories.items():
            print(f"\n{category}:")
            for data_type in data_types:
                values = self.results[data_type]
                if values:
                    print(f"  {data_type.upper()} ({len(values)} found):")
                    for value in sorted(values):
                        print(f"    - {value}")

        # Print correlated API structure if available
        if self.api_structure:
            print("\nCorrelated API Structure:")
            for endpoint, details in self.api_structure.items():
                print(f"  ENDPOINT: {endpoint}")
                
                if details['methods']:
                    print(f"    Methods: {', '.join(details['methods'])}")
                
                if details['parameters']:
                    print(f"    Parameters: {', '.join(details['parameters'])}")
                
                if details['content_types']:
                    print(f"    Content Types: {', '.join(details['content_types'])}")
                
                print("")  # Empty line for readability
        
        # Add warning disclaimer
        print("\n" + "="*80)
        print("WARNING DISCLAIMER:")
        print("-"*80)
        print("This analysis is based on pattern matching and may not be exhaustive.")
        print("Some API endpoints, credentials, or sensitive data might not be detected.")
        print("Successful API request examples are based on contextual clues and might be incomplete.")
        print("For critical security analysis, always perform manual verification.")
        print("="*80)
        
        # End markdown output if requested
        if markdown_format:
            print("```")

def main():
    parser = argparse.ArgumentParser(description='Analyze files for cybersecurity purposes')
    parser.add_argument('file_path', help='Path to the file to analyze')
    parser.add_argument('--md', action='store_true', help='Output in markdown format (wrapped in triple backticks)')
    args = parser.parse_args()

    analyzer = FileAnalyzer()
    analyzer.analyze_file(args.file_path)
    analyzer.print_results(markdown_format=args.md)

if __name__ == "__main__":
    main() 