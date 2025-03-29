#!/usr/bin/env python3
#Author: Tristan Pereira
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
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
import mmap
import ast
import astroid
from radon.complexity import cc_visit
from radon.metrics import h_visit

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
            'domain_keywords': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
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
            'domain_keywords': set(),
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
            'code_complexity': set(),
            'security_smells': set(),
            'code_quality': set(),
            'high_entropy_strings': set(),
            'commented_code': set(),
            'network_protocols': set(),
            'network_security_issues': set(),
            'network_ports': set(),
            'network_hosts': set(),
            'network_endpoints': set(),
            'software_versions': set(),
        }
        
        # API structure correlation data
        self.api_structure = {}
        
        # Add machine learning models for advanced pattern detection
        self.ml_models = self._initialize_ml_models()
        
        # Add NLP capabilities for semantic analysis
        self.nlp_engine = self._initialize_nlp_engine()
        
        # Add binary file analysis capabilities
        self.binary_analyzers = {
            'pe': self._analyze_pe_file,
            'elf': self._analyze_elf_file,
            'macho': self._analyze_macho_file
        }

    def _initialize_ml_models(self):
        """
        Initialize machine learning models for pattern detection using scikit-learn.
        
        This uses lightweight scikit-learn models for credential detection and 
        pattern recognition instead of TensorFlow, making it easier to install
        and run on most systems.
        
        Returns:
            dict: Dictionary of scikit-learn models for different detection tasks
        """
        models = {}
        try:
            # Import scikit-learn dependencies
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.ensemble import IsolationForest, RandomForestClassifier
            from sklearn.model_selection import train_test_split
            import joblib
            
            # Check if we have pre-trained models
            model_path = Path(__file__).parent / "models"
            if model_path.exists():
                # Try to load pre-trained models if they exist
                credential_model_path = model_path / "credential_detector.joblib"
                if credential_model_path.exists():
                    models['credential_detector'] = joblib.load(credential_model_path)
                    models['credential_vectorizer'] = joblib.load(model_path / "credential_vectorizer.joblib")
                
                api_model_path = model_path / "api_pattern.joblib"
                if api_model_path.exists():
                    models['api_pattern'] = joblib.load(api_model_path)
                    models['api_vectorizer'] = joblib.load(model_path / "api_vectorizer.joblib")
            
            # If we don't have pre-trained models, initialize new ones for runtime training
            if 'credential_detector' not in models:
                # For credential detection: Isolation Forest for anomaly detection
                # This can detect unusual strings that might be credentials
                models['credential_vectorizer'] = TfidfVectorizer(
                    analyzer='char', ngram_range=(2, 5), max_features=100
                )
                models['credential_detector'] = IsolationForest(
                    n_estimators=100, contamination=0.1, random_state=42
                )
                
            if 'api_pattern' not in models:
                # For API pattern recognition: Random Forest classifier
                models['api_vectorizer'] = TfidfVectorizer(
                    analyzer='word', ngram_range=(1, 3), max_features=100
                )
                models['api_pattern'] = RandomForestClassifier(
                    n_estimators=50, random_state=42
                )
            
            # Store some example patterns for training if needed
            models['example_credentials'] = [
                "password123", "api_key_12345", "secret_token_xyz", 
                "Bearer abc123def456", "AKIA1234567890ABCDEF"
            ]
            models['example_non_credentials'] = [
                "normal text", "hello world", "function name", 
                "variable", "import library"
            ]
                
            models['example_api_patterns'] = [
                "/api/v1/users", "GET /data", "POST /auth/login",
                "api.example.com/v2/resources", "/graphql?query="
            ]
            models['example_non_api_patterns'] = [
                "/static/images", "/css/styles.css", "/home/user",
                "file.txt", "document.html"
            ]
            
            logging.info(f"Initialized scikit-learn models for pattern detection")
            return models
            
        except ImportError:
            logging.warning("scikit-learn not available. Install with: pip install scikit-learn joblib")
            return {}
        except Exception as e:
            logging.error(f"Error initializing ML models: {str(e)}")
            return {}
    
    def _initialize_nlp_engine(self):
        """
        Initialize NLP engine for semantic analysis of text content.
        
        This enables understanding context and meaning beyond pattern matching,
        helping to identify sensitive information based on surrounding text.
        
        Returns:
            object: NLP engine instance or None if not available
        """
        try:
            # Only import if available to make this feature optional
            import spacy
            return spacy.load("en_core_web_sm")
        except ImportError:
            logging.warning("Spacy not available. Semantic analysis disabled.")
            return None
        except Exception as e:
            logging.error(f"Error initializing NLP engine: {str(e)}")
            return None
            
    def _analyze_pe_file(self, file_path):
        """
        Analyze Windows PE (Portable Executable) binary files.
        
        Extracts embedded strings, resources, imports/exports, certificates,
        and identifies potential malicious indicators.
        
        Args:
            file_path (Path): Path to the PE file
            
        Returns:
            dict: Analysis results
        """
        try:
            import pefile
            pe = pefile.PE(str(file_path))
            
            results = {
                'imports': [],
                'exports': [],
                'sections': [],
                'resources': [],
                'certificates': []
            }
            
            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            results['imports'].append(f"{entry.dll.decode()}.{imp.name.decode()}")
            
            # Extract sections
            for section in pe.sections:
                results['sections'].append({
                    'name': section.Name.decode().rstrip('\x00'),
                    'size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                })
            
            return results
        except ImportError:
            logging.warning("pefile not available. PE analysis disabled.")
            return {}
        except Exception as e:
            logging.error(f"Error analyzing PE file: {str(e)}")
            return {}

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
    
    def _analyze_code_structure(self, file_path, content):
        """
        Perform advanced code structure analysis to identify security smells and code quality issues.
        
        Args:
            file_path (Path): Path to the file
            content (str): Content of the file
        """
        file_ext = file_path.suffix.lower()
        
        # Python code analysis
        if file_ext == '.py':
            self._analyze_python_code(content)
        
        # JavaScript/TypeScript analysis
        elif file_ext in ['.js', '.jsx', '.ts', '.tsx']:
            self._analyze_js_code(content)
        
        # Java analysis
        elif file_ext in ['.java']:
            self._analyze_java_code(content)
        
        # Generic code analysis for any language
        self._analyze_generic_code(content)
    
    def _analyze_python_code(self, content):
        """
        Analyze Python code for security issues and complexity.
        
        Args:
            content (str): Python code content
        """
        try:
            # Parse the code
            tree = ast.parse(content)
            
            # Security smell detection
            security_patterns = {
                'Hardcoded Secret': re.compile(r'(?:password|secret|key|token)\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
                'Shell Injection': re.compile(r'(?:os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\(', re.IGNORECASE),
                'SQL Injection': re.compile(r'(?:execute|executemany)\s*\(\s*[f\'"]', re.IGNORECASE),
                'Pickle Usage': re.compile(r'pickle\.(?:load|loads)', re.IGNORECASE),
                'Temp File': re.compile(r'(?:tempfile\.mk(?:stemp|temp)|open\s*\(\s*[\'"]\/tmp\/)', re.IGNORECASE),
                'Assert Usage': re.compile(r'\bassert\b', re.IGNORECASE),
                'HTTP Without TLS': re.compile(r'http:\/\/(?!localhost|127\.0\.0\.1)', re.IGNORECASE),
            }
            
            # Check for security patterns
            for smell_name, pattern in security_patterns.items():
                matches = pattern.finditer(content)
                for match in matches:
                    line_no = content[:match.start()].count('\n') + 1
                    context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                    finding = f"{smell_name} (line {line_no}): {context}"
                    self.results['security_smells'].add(finding)
            
            # Complexity analysis using radon
            try:
                # Calculate cyclomatic complexity
                complexities = cc_visit(content)
                for item in complexities:
                    if item.complexity > 10:  # Threshold for high complexity
                        self.results['code_complexity'].add(
                            f"High complexity ({item.complexity}) in {item.name} at line {item.lineno}"
                        )
                
                # Calculate maintainability index
                h_visit_result = h_visit(content)
                if h_visit_result.mi < 65:  # Low maintainability threshold
                    self.results['code_quality'].add(
                        f"Low maintainability index: {h_visit_result.mi:.2f}/100"
                    )
            except Exception as e:
                logging.warning(f"Error calculating code metrics: {str(e)}")
            
            # AST-based analysis
            class SecurityVisitor(ast.NodeVisitor):
                def __init__(self, analyzer):
                    self.analyzer = analyzer
                    
                def visit_Import(self, node):
                    # Check for dangerous imports
                    dangerous_modules = ['pickle', 'marshal', 'shelve', 'dill']
                    for name in node.names:
                        if name.name in dangerous_modules:
                            line_no = node.lineno
                            self.analyzer.results['security_smells'].add(
                                f"Dangerous module import: {name.name} (line {line_no})"
                            )
                    self.generic_visit(node)
                    
                def visit_Call(self, node):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
                        line_no = node.lineno
                        self.analyzer.results['security_smells'].add(
                            f"Dangerous function call: {node.func.id} (line {line_no})"
                        )
                    self.generic_visit(node)
                
                def visit_BinOp(self, node):
                    # String formatting with % operator for SQL can be risky
                    if isinstance(node.op, ast.Mod) and any(s in content[node.lineno] for s in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                        line_no = node.lineno
                        self.analyzer.results['security_smells'].add(
                            f"Potential SQL injection with string formatting (line {line_no})"
                        )
                    self.generic_visit(node)
            
            # Apply AST visitor
            visitor = SecurityVisitor(self)
            visitor.visit(tree)
            
        except SyntaxError as e:
            self.results['code_quality'].add(f"Python syntax error: {str(e)}")
        except Exception as e:
            logging.error(f"Error analyzing Python code: {str(e)}")
    
    def _analyze_js_code(self, content):
        """
        Analyze JavaScript/TypeScript code for security issues.
        
        Args:
            content (str): JavaScript code content
        """
        # Similar to Python analysis but with JavaScript-specific patterns
        security_patterns = {
            'Eval Usage': re.compile(r'\beval\s*\(', re.IGNORECASE),
            'Document Write': re.compile(r'document\.write\s*\(', re.IGNORECASE),
            'innerHtml Assignment': re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
            'DOM-based XSS': re.compile(r'(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer))', re.IGNORECASE),
            'DOM Storage Usage': re.compile(r'(?:localStorage|sessionStorage)\.', re.IGNORECASE),
            'Hardcoded JWT': re.compile(r'[\'"]eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*[\'"]', re.IGNORECASE),
            'Protocol-relative URL': re.compile(r'[\'"]\/\/\w+', re.IGNORECASE),
            'HTTP Without TLS': re.compile(r'http:\/\/(?!localhost|127\.0\.0\.1)', re.IGNORECASE),
        }
        
        # Check for security patterns
        for smell_name, pattern in security_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                finding = f"{smell_name} (line {line_no}): {context}"
                self.results['security_smells'].add(finding)
    
    def _analyze_java_code(self, content):
        """
        Analyze Java code for security issues.
        
        Args:
            content (str): Java code content
        """
        security_patterns = {
            'Hardcoded Password': re.compile(r'(?:password|pwd|passwd)\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
            'SQL Injection': re.compile(r'(?:executeQuery|executeUpdate|prepareStatement)\s*\(\s*[\'"].*\+', re.IGNORECASE),
            'Command Injection': re.compile(r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)', re.IGNORECASE),
            'XXE Vulnerability': re.compile(r'(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)', re.IGNORECASE),
            'Crypto Issues': re.compile(r'(?:MD5|DES|AES/ECB)', re.IGNORECASE),
            'Random Predictable': re.compile(r'new\s+Random\s*\(\s*\)', re.IGNORECASE),
            'Trust All Certificates': re.compile(r'TrustAllCerts|X509TrustManager', re.IGNORECASE),
        }
        
        # Check for security patterns
        for smell_name, pattern in security_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                finding = f"{smell_name} (line {line_no}): {context}"
                self.results['security_smells'].add(finding)
    
    def _analyze_generic_code(self, content):
        """
        Perform language-agnostic code analysis.
        
        Args:
            content (str): Code content
        """
        # Check for entropy in strings - high entropy strings might be secrets
        string_pattern = re.compile(r'[\'"]([^\'"]{16,})[\'"]')
        strings = string_pattern.finditer(content)
        
        for match in strings:
            string_value = match.group(1)
            entropy = self.calculate_entropy(string_value)
            
            # High entropy strings might be secrets, tokens, or keys
            if entropy > 4.0 and len(string_value) >= 16:
                line_no = content[:match.start()].count('\n') + 1
                self.results.setdefault('high_entropy_strings', set()).add(
                    f"High entropy string (entropy: {entropy:.2f}) at line {line_no}: {string_value[:10]}..."
                )
        
        # Check for commented-out code (might contain security issues)
        comment_patterns = [
            re.compile(r'\/\/.*\b(?:if|for|while|switch|return)\b.*\{'),  # JavaScript/Java/C/C++
            re.compile(r'#.*\b(?:if|for|while|def|return)\b.*:'),  # Python
            re.compile(r'<!--.*\b(?:if|for|while|function)\b.*-->'),  # HTML
        ]
        
        for pattern in comment_patterns:
            matches = pattern.finditer(content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                self.results.setdefault('commented_code', set()).add(
                    f"Commented-out code at line {line_no}"
                )
    
    def analyze_file(self, file_path: str) -> None:
        """Analyze the content of a file and extract relevant information."""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                return

            # Determine file type
            file_type = self._detect_file_type(file_path)
            logging.info(f"Detected file type: {file_type}")
            
            # Use appropriate analysis method based on file type
            if file_type in ['binary', 'executable']:
                self._analyze_binary_file(file_path)
            else:
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
            
            # Add network traffic analysis
            self._analyze_network_patterns(content)
            
            # Detect software versions
            software_versions = self._detect_software_versions(content)
            
            # Perform additional analysis for API specification files
            if file_path.name.lower() in ('swagger.json', 'openapi.json', 'swagger.yaml', 'openapi.yaml', 'api-docs.json'):
                logging.info(f"Detected potential API specification file: {file_path}")
                # Here you could add specific OpenAPI/Swagger parsing logic

            # Apply ML-based detection if available
            if self.ml_models and 'credential_detector' in self.ml_models:
                self._apply_ml_detection(content)
            
            # Apply semantic analysis if NLP engine is available
            if self.nlp_engine:
                self._apply_semantic_analysis(content)

            # Perform code structure analysis for text files
            if file_type == "text":
                self._analyze_code_structure(file_path, content)

            # Analyze network patterns
            self._analyze_network_patterns(content)

            # Detect software versions
            self._detect_software_versions(content)

        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")

    def _detect_file_type(self, file_path: Path) -> str:
        """
        Detect file type using magic numbers and file extensions.
        
        Args:
            file_path (Path): Path to the file
            
        Returns:
            str: Detected file type
        """
        try:
            import magic
            file_type = magic.from_file(str(file_path))
            
            # Categorize the file type
            if "PE32" in file_type or "PE32+" in file_type:
                return "executable"
            elif "ELF" in file_type:
                return "executable"
            elif "Mach-O" in file_type:
                return "executable"
            elif any(x in file_type for x in ["text", "JSON", "XML", "ASCII"]):
                return "text"
            elif "data" in file_type or "binary" in file_type:
                return "binary"
            else:
                return file_type
        except ImportError:
            # Fallback to extension-based detection
            suffix = file_path.suffix.lower()
            if suffix in ['.exe', '.dll', '.sys', '.so', '.dylib']:
                return "executable"
            elif suffix in ['.txt', '.json', '.xml', '.html', '.js', '.py', '.java', '.c', '.cpp']:
                return "text"
            else:
                return "unknown"
                
    def _apply_ml_detection(self, content: str) -> None:
        """
        Apply scikit-learn models to detect patterns beyond regex capabilities.
        
        This method uses trained ML models to identify potential credentials
        and API patterns that might be missed by regular expressions.
        
        Args:
            content (str): Content to analyze
        """
        if not self.ml_models:
            return
        
        try:
            # Split content into lines and chunks for analysis
            lines = content.splitlines()
            chunks = []
            
            # Create smaller chunks for analysis (sliding window)
            for i in range(len(lines)):
                chunk = " ".join(lines[max(0, i-2):min(len(lines), i+3)])
                if len(chunk) > 10:  # Only analyze non-trivial chunks
                    chunks.append(chunk)
            
            # If we have too few chunks, just use the whole content
            if len(chunks) < 5:
                chunks = [content]
            
            # === Credential Detection ===
            if 'credential_detector' in self.ml_models and 'credential_vectorizer' in self.ml_models:
                detector = self.ml_models['credential_detector']
                vectorizer = self.ml_models['credential_vectorizer']
                
                # First-time training if needed (will be quick with few examples)
                if not hasattr(detector, 'fitted_') or not detector.fitted_:
                    # Combine examples and fit vectorizer
                    examples = self.ml_models['example_credentials'] + self.ml_models['example_non_credentials']
                    X = vectorizer.fit_transform(examples)
                    # Train the model (anomaly detection)
                    detector.fit(X)
                
                # Extract potential credentials (strings that look like passwords, tokens)
                potential_credentials = []
                credential_pattern = re.compile(r'[\'"]([^\'"]{8,})[\'"]')
                
                for chunk in chunks:
                    for match in credential_pattern.finditer(chunk):
                        cred = match.group(1)
                        if len(cred) >= 8 and len(cred) <= 100:
                            potential_credentials.append((cred, chunk, match.start()))
                
                # Analyze each potential credential
                for cred, context, pos in potential_credentials:
                    # Skip if it's a common word or already detected
                    if cred.lower() in ['password', 'username', 'false', 'true', 'null']:
                        continue
                    
                    # Convert to feature vector
                    X = vectorizer.transform([cred])
                    
                    # Predict (-1 for anomalies = potential credentials, 1 for normal)
                    prediction = detector.predict(X)[0]
                    score = detector.decision_function(X)[0]
                    
                    # If it's detected as a potential credential
                    if prediction == -1 or score < -0.2:
                        entropy = self.calculate_entropy(cred)
                        if entropy > 3.0:  # Higher entropy suggests randomness = potential secret
                            finding = f"Potential credential detected (ML): '{cred}' (entropy: {entropy:.2f})"
                            # Store in ML findings
                            self.results.setdefault('ml_credential_findings', set()).add(finding)
            
            # === API Pattern Detection ===
            if 'api_pattern' in self.ml_models and 'api_vectorizer' in self.ml_models:
                classifier = self.ml_models['api_pattern']
                vectorizer = self.ml_models['api_vectorizer']
                
                # First-time training if needed
                if not hasattr(classifier, 'classes_'):
                    # Prepare training data
                    examples = (
                        [(p, 1) for p in self.ml_models['example_api_patterns']] + 
                        [(p, 0) for p in self.ml_models['example_non_api_patterns']]
                    )
                    X = [ex[0] for ex in examples]
                    y = [ex[1] for ex in examples]
                    
                    # Fit vectorizer and train classifier
                    X_vec = vectorizer.fit_transform(X)
                    classifier.fit(X_vec, y)
                
                # Extract potential API patterns
                api_pattern = re.compile(r'\/[\w\-\.\/]+(?:\?[\w=&]+)?')
                potential_apis = []
                
                for chunk in chunks:
                    for match in api_pattern.finditer(chunk):
                        api = match.group(0)
                        if 5 <= len(api) <= 100:  # Reasonable API path length
                            potential_apis.append((api, chunk))
                            
                # Analyze each potential API endpoint
                for api, context in potential_apis:
                    # Skip if already detected by regex
                    if any(api in existing for existing in self.results['api_endpoint']):
                        continue
                    
                    # Vectorize and predict
                    X = vectorizer.transform([api])
                    prediction = classifier.predict(X)[0]
                    
                    # If classified as API endpoint with reasonable confidence
                    if prediction == 1:
                        # Check if it has common API path components
                        if re.search(r'\/(?:v\d+|api|rest|graphql|data|auth|users|resources)', api, re.IGNORECASE):
                            finding = f"Potential API endpoint (ML): {api}"
                            self.results.setdefault('ml_api_findings', set()).add(finding)
                            
        except Exception as e:
            logging.error(f"Error in ML detection: {str(e)}")
        
    def _apply_semantic_analysis(self, content: str) -> None:
        """
        Apply NLP to understand context and semantic meaning.
        
        Args:
            content (str): Content to analyze
        """
        doc = self.nlp_engine(content)
        
        # Extract entities that might be sensitive
        for ent in doc.ents:
            if ent.label_ in ["PERSON", "ORG", "GPE"]:
                self.results.setdefault("semantic_entities", set()).add(f"{ent.text} ({ent.label_})")
                
        # Identify sentences that might contain sensitive information
        sensitive_keywords = ["password", "secret", "key", "credential", "token", "private"]
        for sent in doc.sents:
            if any(keyword in sent.text.lower() for keyword in sensitive_keywords):
                self.results.setdefault("sensitive_contexts", set()).add(sent.text.strip())

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
            'Network Information': ['ipv4', 'ipv6', 'domain_keywords', 'url'],
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
            'Code Complexity': ['code_complexity'],
            'Security Smells': ['security_smells'],
            'Code Quality': ['code_quality'],
            'High Entropy Strings': ['high_entropy_strings'],
            'Commented Code': ['commented_code'],
            'Network': ['network_protocols', 'network_security_issues', 'network_ports', 'network_hosts', 'network_endpoints'],
            'Software': ['software_versions'],
            'ML Detection': ['ml_credential_findings', 'ml_api_findings'],
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

    def analyze_file_parallel(self, file_path: str) -> None:
        """
        Analyze a file using parallel processing for large files.
        
        This method splits the file into chunks and processes them in parallel,
        significantly improving performance for large files.
        
        Args:
            file_path (str): Path to the file to analyze
        """
        file_path = Path(file_path)
        file_size = file_path.stat().st_size
        
        # Only use parallel processing for large files
        if file_size < 10 * 1024 * 1024:  # 10MB
            return self.analyze_file(file_path)
            
        # Determine optimal chunk size and number of workers
        chunk_size = max(1024 * 1024, file_size // multiprocessing.cpu_count())  # At least 1MB
        num_chunks = math.ceil(file_size / chunk_size)
        
        logging.info(f"Processing large file ({file_size/1024/1024:.2f} MB) in {num_chunks} chunks")
        
        # Process chunks in parallel
        with ProcessPoolExecutor() as executor:
            futures = []
            
            for i in range(num_chunks):
                start_pos = i * chunk_size
                end_pos = min(start_pos + chunk_size, file_size)
                futures.append(executor.submit(self._process_file_chunk, file_path, start_pos, end_pos))
                
            # Collect results
            for future in as_completed(futures):
                try:
                    chunk_results = future.result()
                    self._merge_chunk_results(chunk_results)
                except Exception as e:
                    logging.error(f"Error processing chunk: {str(e)}")
    
    def _process_file_chunk(self, file_path: Path, start_pos: int, end_pos: int) -> dict:
        """
        Process a chunk of a file.
        
        Args:
            file_path (Path): Path to the file
            start_pos (int): Starting position in file
            end_pos (int): Ending position in file
            
        Returns:
            dict: Results for this chunk
        """
        chunk_results = {key: set() for key in self.results.keys()}
        
        with open(file_path, 'rb') as f:
            # Use memory mapping for efficient access
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                # Extend chunk to include complete lines
                # Move start_pos to the beginning of a line
                if start_pos > 0:
                    while start_pos > 0 and mm[start_pos-1:start_pos] != b'\n':
                        start_pos -= 1
                
                # Move end_pos to the end of a line
                while end_pos < len(mm) and mm[end_pos-1:end_pos] != b'\n':
                    end_pos += 1
                
                chunk_data = mm[start_pos:end_pos].decode('utf-8', errors='ignore')
                
                # Process the chunk with normal pattern detection
                for data_type, pattern in self.patterns.items():
                    matches = re.finditer(pattern, chunk_data)
                    for match in matches:
                        value = match.group(0)
                        # Apply validation (simplified for example)
                        chunk_results[data_type].add(value)
        
        return chunk_results
    
    def _merge_chunk_results(self, chunk_results: dict) -> None:
        """
        Merge results from a chunk into the main results.
        
        Args:
            chunk_results (dict): Results from a chunk
        """
        for key, values in chunk_results.items():
            if key in self.results:
                self.results[key].update(values)
            else:
                self.results[key] = values

    def _analyze_network_patterns(self, content):
        """
        Analyze content for network communication patterns and security issues.
        
        This function scans the file content for evidence of network protocols, insecure 
        communication patterns, and potential network security vulnerabilities.
        
        Args:
            content (str): File content to analyze
        """
        # Initialize result categories if they don't already exist
        self.results.setdefault('network_protocols', set())
        self.results.setdefault('network_security_issues', set())
        
        # Network protocol patterns - these help us identify what communication protocols are used
        # Each regex is designed to match specific code patterns indicating protocol usage
        protocol_patterns = {
            'HTTP': r'(?i)(?:http\.(?:get|post|put|delete)|fetch\(|XMLHttpRequest|axios)',
            'HTTPS': r'(?i)https:\/\/',
            'FTP': r'(?i)(?:ftp:\/\/|ftps:\/\/|\bftp\s+(?:open|get|put))',
            'SSH': r'(?i)(?:ssh\s+|ssh2_connect|new\s+SSH|JSch)',
            'SMTP': r'(?i)(?:smtp\s+|mail\s+send|createTransport|sendmail|new\s+SmtpClient)',
            'DNS': r'(?i)(?:dns\s+lookup|resolv|nslookup|dig\s+)',
            'MQTT': r'(?i)(?:mqtt\s+|MQTTClient|mqtt\.connect)',
            'WebSocket': r'(?i)(?:new\s+WebSocket|createWebSocketClient|websocket\.connect)',
            'gRPC': r'(?i)(?:grpc\.(?:Server|Client)|new\s+ServerBuilder)',
            'GraphQL': r'(?i)(?:graphql\s+|ApolloClient|gql`)',
            'TCP/IP': r'(?i)(?:socket\.|Socket\(|createServer|listen\(\d+|bind\(\d+|connect\(\d+)',
            'UDP': r'(?i)(?:dgram\.|DatagramSocket|UdpClient)',
            'ICMP': r'(?i)(?:ping\s+|ICMP|IcmpClient)',
            'SNMP': r'(?i)(?:snmp\s+|SnmpClient|createSnmpSession)',
            'LDAP': r'(?i)(?:ldap\s+|LdapClient|createLdapConnection)',
        }
        
        # Network security issues - these patterns help identify potential security vulnerabilities
        # Each regex matches code that might indicate an insecure implementation
        security_patterns = {
            'Clear Text Credentials': r'(?i)(?:auth=|user:pass@|username=\w+&password=)',
            'Insecure Protocol': r'(?i)(?:ftp:\/\/|telnet:\/\/|http:\/\/(?!localhost|127\.0\.0\.1))',
            'Hardcoded IP': r'\b(?:PUBLIC_IP|SERVER_ADDR|API_HOST)\s*=\s*[\'"](?:\d{1,3}\.){3}\d{1,3}[\'"]',
            'Open Port': r'(?i)(?:listen\(\s*\d+|port\s*=\s*\d+|\.connect\(\s*(?:["\']\w+["\']\s*,\s*)?\d+\))',
            'Weak TLS': r'(?i)(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|\bRC4\b|\bDES\b|MD5WithRSA|allowAllHostnames)',
            'Certificate Validation Disabled': r'(?i)(?:verify=False|CERT_NONE|InsecureRequestWarning|rejectUnauthorized:\s*false|trustAllCerts)',
            'Proxy Settings': r'(?i)(?:proxy\s*=|http_proxy|https_proxy|\.setProxy|\.proxy\()',
            'CORS Misconfiguration': r'(?i)(?:Access-Control-Allow-Origin:\s*\*|cors\({.*?origin:\s*[\'"]?\*[\'"]?)',
            'Unencrypted Socket': r'(?i)(?:new\s+Socket|socket\.|createServer)(?![^\n]*SSL|[^\n]*TLS)',
            'Server-Side Request Forgery': r'(?i)(?:\.open\([\'"]GET[\'"],\s*(?:url|req|request))',
            'DNS Rebinding': r'(?i)(?:allowLocal\s*:|allowAny\s*:|\*\.localhost)',
            'WebSockets Insecure': r'(?i)(?:ws:\/\/|new\s+WebSocket\([\'"]ws:\/\/)',
        }
        
        # Port and host extraction patterns - to find specific network configurations
        port_pattern = re.compile(r'(?:^|\s)(?:PORT|port)\s*(?:=|:)\s*(\d+)', re.IGNORECASE)
        host_pattern = re.compile(r'(?:^|\s)(?:HOST|host|SERVER|server)\s*(?:=|:)\s*[\'"]([\w\.\-]+)[\'"]', re.IGNORECASE)
        
        # Identify protocols used in the code
        # We'll loop through each pattern and check if it appears in the content
        for protocol, pattern in protocol_patterns.items():
            if re.search(pattern, content):
                # If we find a match, add it to our results
                self.results['network_protocols'].add(protocol)
                logging.info(f"Detected network protocol: {protocol}")
        
        # Identify potential security issues
        # We'll find all matches and extract contextual information for each one
        for issue, pattern in security_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # Calculate line number for better context
                line_no = content[:match.start()].count('\n') + 1
                
                # Extract surrounding context to help understand the finding
                # This grabs 20 characters before and after the match for context
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                
                # Add the finding to our results with context information
                finding = f"{issue} (line {line_no}): {context}"
                self.results['network_security_issues'].add(finding)
                logging.info(f"Detected network security issue: {issue} at line {line_no}")
        
        # Extract ports and hosts for additional network information
        # This helps identify specific network configurations
        ports = set()
        hosts = set()
        
        # Find all port configurations
        port_matches = port_pattern.finditer(content)
        for match in port_matches:
            port = match.group(1)
            # Check if the port is in a common range
            port_number = int(port)
            if 0 <= port_number <= 65535:  # Valid port range
                ports.add(port)
                
                # Flag potentially sensitive ports
                if port_number in [21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 27017]:
                    self.results['network_security_issues'].add(
                        f"Potentially sensitive port used: {port} (common for {self._get_port_service(port_number)})"
                    )
        
        # Find all host configurations
        host_matches = host_pattern.finditer(content)
        for match in host_matches:
            host = match.group(1)
            hosts.add(host)
            
            # Check if the host is hardcoded to a specific IP (not localhost)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) and not host.startswith(('127.', '192.168.', '10.')):
                self.results['network_security_issues'].add(
                    f"Hardcoded non-local IP address: {host}"
                )
        
        # If we found any ports or hosts, add them to the results
        if ports:
            self.results.setdefault('network_ports', set()).update(ports)
        if hosts:
            self.results.setdefault('network_hosts', set()).update(hosts)
        
        # Analyze network traffic patterns by correlating hosts and ports
        # This helps understand the complete network communication architecture
        if hosts and ports:
            for host in hosts:
                for port in ports:
                    if re.search(rf'{re.escape(host)}.*?{port}|{port}.*?{re.escape(host)}', content, re.DOTALL):
                        self.results.setdefault('network_endpoints', set()).add(f"{host}:{port}")

    def _get_port_service(self, port):
        """
        Get common service name for a port number.
        
        This helper function translates port numbers into human-readable service names
        to make the findings more understandable.
        
        Args:
            port (int): Port number
            
        Returns:
            str: Common service name for that port
        """
        # Map of common ports to their typical services
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alternate",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown Service")

    def _detect_software_versions(self, content):
        """
        Detect software versions mentioned in the content.
        
        This function scans for version strings of common libraries, frameworks, and tools
        to help identify outdated or vulnerable software versions. This information is crucial
        for vulnerability assessment.
        
        Args:
            content (str): File content to analyze
            
        Returns:
            dict: Detected software and their versions
        """
        # Dictionary to store detected software versions
        detected_versions = {}
        
        # Common libraries and their version patterns
        # Each regex is designed to match a specific library/framework version string pattern
        lib_patterns = {
            'jquery': r'(?:jquery[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'bootstrap': r'(?:bootstrap[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'react': r'(?:react[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'vue': r'(?:vue[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'angular': r'(?:angular[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'lodash': r'(?:lodash[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'express': r'(?:express[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'django': r'(?:django[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'flask': r'(?:flask[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'spring': r'(?:spring[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'tensorflow': r'(?:tensorflow[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'pytorch': r'(?:pytorch[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'openssl': r'(?:openssl[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)',
            'nginx': r'(?:nginx[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'apache': r'(?:apache[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'php': r'(?:php[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'node.js': r'(?:node[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'python': r'(?:python[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'java': r'(?:java[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'dotnet': r'(?:\.net[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'wordpress': r'(?:wordpress[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'drupal': r'(?:drupal[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'joomla': r'(?:joomla[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            # Additional software patterns
            'laravel': r'(?:laravel[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'symfony': r'(?:symfony[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'spring-boot': r'(?:spring-boot[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'rails': r'(?:rails[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'jquery-ui': r'(?:jquery-ui[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'moment': r'(?:moment[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'axios': r'(?:axios[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'webpack': r'(?:webpack[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'babel': r'(?:babel[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'eslint': r'(?:eslint[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'jest': r'(?:jest[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'mocha': r'(?:mocha[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'cypress': r'(?:cypress[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'next.js': r'(?:next[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'nuxt.js': r'(?:nuxt[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'gatsby': r'(?:gatsby[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'redux': r'(?:redux[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'vuex': r'(?:vuex[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'mobx': r'(?:mobx[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'sass': r'(?:sass[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'less': r'(?:less[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'tailwindcss': r'(?:tailwindcss[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'bulma': r'(?:bulma[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'foundation': r'(?:foundation[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'material-ui': r'(?:material-ui[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'ant-design': r'(?:antd[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'chakra-ui': r'(?:chakra[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        }
        
        # Generic version pattern to catch version declarations that don't match the specific library patterns
        # This helps identify other software versions that might not be in our predefined list
        generic_version_pattern = r'(?i)(?:version|ver\.?)\s*[=:]\s*[\'"]([0-9]+(?:\.[0-9]+)+)[\'"]'
        
        # Package manager file patterns - these help identify version info from common dependency files
        package_file_patterns = {
            'package.json': r'"([\w\-@/]+)":\s*"([~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\.]+)?)"',
            'requirements.txt': r'([\w\-]+)(?:={1,2}|>=|<=|>|<|~=)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'composer.json': r'"([\w\-/]+)":\s*"([~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\.]+)?)"',
            'build.gradle': r'([\w\-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'pom.xml': r'<([\w\-\.]+)>[0-9]+\.[0-9]+(?:\.[0-9]+)?</\1>',
        }
        
        # Look for versions using the specific library patterns
        # This is our first pass to find common libraries with known patterns
        for lib, pattern in lib_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                ver = match.group(1)
                
                # Store the version info
                if lib not in detected_versions or self._is_newer_version(ver, detected_versions[lib]):
                    detected_versions[lib] = ver
                    logging.info(f"Detected {lib} version: {ver}")
        
        # Look for generic version declarations
        # This is our second pass to catch other version declarations
        generic_matches = re.finditer(generic_version_pattern, content)
        for match in generic_matches:
            ver = match.group(1)
            
            # Try to identify the software from surrounding context
            context_start = max(0, match.start() - 50)
            context_end = min(len(content), match.end() + 50)
            context = content[context_start:context_end]
            
            # Check if any known library name appears in the context
            for lib in lib_patterns.keys():
                if lib.lower() in context.lower() and lib not in detected_versions:
                    detected_versions[lib] = ver
                    logging.info(f"Detected potential {lib} version: {ver} from context")
                    break
        
        # Check for package manager files content
        # This helps identify dependencies declared in package manager files
        for file_type, pattern in package_file_patterns.items():
            if file_type.lower() in content.lower() or re.search(r'\b' + re.escape(file_type) + r'\b', content):
                matches = re.finditer(pattern, content)
                for match in matches:
                    package_name = match.group(1)
                    package_version = match.group(2)
                    
                    # Clean up version strings with special characters
                    if package_version.startswith(('~', '^')):
                        package_version = package_version[1:]
                    
                    # Standardize the package name
                    clean_name = package_name.split('/')[-1].lower()
                    
                    # Add to our findings
                    if clean_name not in detected_versions:
                        detected_versions[clean_name] = package_version
                        logging.info(f"Detected {clean_name} version: {package_version} from {file_type}-like content")
        
        # Store result in the class for later use in vulnerability checking
        self.results.setdefault('software_versions', set())
        for software, version in detected_versions.items():
            self.results['software_versions'].add(f"{software}: {version}")
        
        return detected_versions

    def _is_newer_version(self, version1, version2):
        """
        Compare two version strings to determine if version1 is newer than version2.
        
        This helper function supports the software version detection by comparing
        version numbers to identify the most recent version in the file.
        
        Args:
            version1 (str): First version string
            version2 (str): Second version string
            
        Returns:
            bool: True if version1 is newer than version2, False otherwise
        """
        try:
            # Split version parts and convert to integers for comparison
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Compare each part
            for i in range(max(len(v1_parts), len(v2_parts))):
                # Get part or default to 0 if index is out of range
                v1_part = v1_parts[i] if i < len(v1_parts) else 0
                v2_part = v2_parts[i] if i < len(v2_parts) else 0
                
                # Compare parts
                if v1_part > v2_part:
                    return True
                elif v1_part < v2_part:
                    return False
                
            # All parts are equal
            return False
        except Exception:
            # If comparison fails, assume version1 is not newer
            return False

    def _analyze_elf_file(self, file_path):
        """
        Analyze ELF (Executable and Linkable Format) binary files commonly used on Linux.
        
        This method extracts important information from ELF binaries like sections,
        symbols, dynamic dependencies, and security features.
        
        Args:
            file_path (Path): Path to the ELF file
        
        Returns:
            dict: Analysis results
        """
        try:
            # Check if pyelftools is available
            try:
                from elftools.elf.elffile import ELFFile
                from elftools.elf.sections import SymbolTableSection
                from elftools.elf.dynamic import DynamicSection
            except ImportError:
                logging.warning("pyelftools not available. ELF analysis disabled.")
                return {"error": "pyelftools library not available"}
        
            results = {
                'sections': [],
                'symbols': [],
                'libraries': [],
                'security_features': []
            }
        
            with open(file_path, 'rb') as f:
                # Parse the ELF file
                elf = ELFFile(f)
                
                # Get basic information
                results['elf_type'] = elf.header['e_type']
                results['machine'] = elf.header['e_machine']
                results['entry_point'] = hex(elf.header['e_entry'])
                
                # Extract sections
                for section in elf.iter_sections():
                    section_info = {
                        'name': section.name,
                        'size': section['sh_size'],
                        'type': section['sh_type']
                    }
                    results['sections'].append(section_info)
                    
                    # Check for symbol tables
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol.name:
                                results['symbols'].append(symbol.name)
                    
                    # Check for dynamic sections to find libraries
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                results['libraries'].append(tag.needed)
                
                # Check for security features
                # 1. NX (No-Execute) protection
                if elf.header.e_flags & 0x4:
                    results['security_features'].append('NX (No-Execute) enabled')
                
                # 2. Check for RELRO
                dynamic = elf.get_section_by_name('.dynamic')
                if dynamic:
                    relro = False
                    bind_now = False
                    for tag in dynamic.iter_tags():
                        if tag.entry.d_tag == 'DT_FLAGS':
                            if tag.entry.d_val & 0x8:  # DF_BIND_NOW
                                bind_now = True
                        if tag.entry.d_tag == 'DT_FLAGS_1':
                            if tag.entry.d_val & 0x8:  # DF_1_NOW
                                bind_now = True
                            if tag.entry.d_val & 0x10000:  # DF_1_PIE
                                results['security_features'].append('PIE (Position Independent Executable)')
                
                    if '.relro' in [s.name for s in elf.iter_sections()]:
                        relro = True
                    
                    if relro and bind_now:
                        results['security_features'].append('Full RELRO')
                    elif relro:
                        results['security_features'].append('Partial RELRO')
                
                # 3. Check for PIE
                if elf.header['e_type'] == 'ET_DYN':
                    results['security_features'].append('PIE (Position Independent Executable)')
                
                # 4. Check for canaries
                if any('__stack_chk_fail' in sym for sym in results['symbols']):
                    results['security_features'].append('Stack canaries')
            
            return results
        except ImportError:
            logging.warning("pyelftools not available. ELF analysis disabled.")
            return {}
        except Exception as e:
            logging.error(f"Error analyzing ELF file: {str(e)}")
            return {"error": str(e)}

    def _analyze_macho_file(self, file_path):
        """
        Analyze Mach-O binary files used on macOS and iOS.
        
        This method extracts important information from Mach-O binaries like
        load commands, symbols, linked libraries and security features.
        
        Args:
            file_path (Path): Path to the Mach-O file
        
        Returns:
            dict: Analysis results
        """
        try:
            # Check if macholib is available
            try:
                import macholib.MachO
            except ImportError:
                logging.warning("macholib not available. Mach-O analysis disabled.")
                return {"error": "macholib library not available"}
        
            results = {
                'load_commands': [],
                'libraries': [],
                'symbols': [],
                'security_features': []
            }
        
            # Parse the Mach-O file
            macho = macholib.MachO.MachO(str(file_path))
        
            # Analyze each header (fat binaries can have multiple)
            for header in macho.headers:
                # Get CPU type
                results['cpu_type'] = header.header.cputype
            
                # Extract load commands
                for cmd in header.commands:
                    cmd_type = cmd[0].cmd
                    results['load_commands'].append(cmd_type)
                    
                    # Extract linked libraries
                    if cmd_type == macholib.MachO.LC_LOAD_DYLIB:
                        lib_path = cmd[2].decode('utf-8') if hasattr(cmd[2], 'decode') else cmd[2]
                        results['libraries'].append(lib_path)
                
                # Check for security features
                # 1. Check for PIE
                if any(cmd[0].cmd == macholib.MachO.LC_MAIN for cmd in header.commands):
                    results['security_features'].append('PIE (Position Independent Executable)')
                
                # 2. Check for stack canary
                if any('___stack_chk_fail' in cmd[2] if len(cmd) > 2 and hasattr(cmd[2], '__contains__') else False
                    for cmd in header.commands):
                    results['security_features'].append('Stack canary')
                
                # 3. Check for ARC (Automatic Reference Counting)
                if any('_objc_release' in cmd[2] if len(cmd) > 2 and hasattr(cmd[2], '__contains__') else False
                    for cmd in header.commands):
                    results['security_features'].append('ARC (Automatic Reference Counting)')
                
                # 4. Check for code signing
                if any(cmd[0].cmd == macholib.MachO.LC_CODE_SIGNATURE for cmd in header.commands):
                    results['security_features'].append('Code signing')
            
            return results
        except ImportError:
            logging.warning("macholib not available. Mach-O analysis disabled.")
            return {}
        except Exception as e:
            logging.error(f"Error analyzing Mach-O file: {str(e)}")
            return {"error": str(e)}

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