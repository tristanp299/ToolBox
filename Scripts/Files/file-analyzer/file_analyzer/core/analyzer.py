#!/usr/bin/env python3
# Core analyzer class

import re
import logging
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
import multiprocessing
import math
from concurrent.futures import ProcessPoolExecutor, as_completed
import mmap

from ..plugins.plugin_registry import PluginRegistry
from ..utils.file_utils import read_file_content, detect_file_type, calculate_entropy
from ..core.patterns import get_patterns, get_hash_patterns


class FileAnalyzer:
    """
    Core file analyzer class.
    
    This class coordinates the analysis of files using various plugins
    and provides a central interface for result collection and processing.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the file analyzer with optional configuration.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        self._setup_logging()
        
        # Get regex patterns for different types of data
        self.patterns = get_patterns()
        self.hash_patterns = get_hash_patterns()
        
        # Initialize results dictionary
        self.results = self._initialize_results()
        
        # API structure correlation data
        self.api_structure = {}
        
        # Initialize plugin registry
        self.plugin_registry = PluginRegistry()
        
        # Load plugins
        self._load_plugins()
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        log_level = self.config.get('log_level', logging.INFO)
        log_file = self.config.get('log_file', 'file_analyzer.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def _initialize_results(self) -> Dict[str, Set[str]]:
        """
        Initialize the results dictionary with empty sets for all categories.
        
        Returns:
            Empty results dictionary
        """
        results = {}
        
        # Initialize with all pattern keys
        for key in self.patterns.keys():
            results[key] = set()
        
        # Add additional result categories
        additional_categories = [
            'api_framework', 'code_complexity', 'security_smells', 'code_quality',
            'high_entropy_strings', 'commented_code', 'network_protocols',
            'network_security_issues', 'network_ports', 'network_hosts',
            'network_endpoints', 'software_versions', 'ml_credential_findings',
            'ml_api_findings'
        ]
        
        for category in additional_categories:
            results[category] = set()
        
        return results
    
    def _load_plugins(self) -> None:
        """Load and register all plugins."""
        try:
            # Discover built-in plugins
            self.plugin_registry.discover_plugins()
            
            # Load additional plugins from custom directories if specified
            custom_plugin_dirs = self.config.get('plugin_dirs', [])
            for plugin_dir in custom_plugin_dirs:
                if Path(plugin_dir).exists():
                    self.plugin_registry.discover_plugins(plugin_dir)
            
            logging.info(f"Loaded {sum(len(plugins) for plugins in self.plugin_registry.plugins.values())} plugins")
        except Exception as e:
            logging.error(f"Error loading plugins: {str(e)}")
    
    def analyze_file(self, file_path: str) -> Dict[str, Set[str]]:
        """
        Analyze a file and extract relevant information.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of analysis results
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                return self.results

            # Determine file type
            file_type = detect_file_type(file_path)
            logging.info(f"Detected file type: {file_type}")
            
            # Check file size to determine processing method
            file_size = file_path.stat().st_size
            
            if file_size > 10 * 1024 * 1024:  # 10MB
                # For large files, use parallel processing
                self.analyze_file_parallel(file_path)
            else:
                # For smaller files, use standard processing
                content, is_binary = read_file_content(file_path)
                
                # Process the file with built-in pattern matching
                self._process_patterns(content)
                
                # Process with registered plugins
                applicable_plugins = self.plugin_registry.get_plugins_for_file(file_path, file_type, content)
                
                for plugin in applicable_plugins:
                    try:
                        logging.info(f"Applying {plugin.name} plugin")
                        plugin.analyze(file_path, file_type, content, self.results)
                    except Exception as e:
                        logging.error(f"Error in plugin {plugin.name}: {str(e)}")
            
            return self.results

        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")
            return self.results
    
    def _process_patterns(self, content: str) -> None:
        """
        Process the content with built-in regex patterns.
        
        Args:
            content: The file content to analyze
        """
        # Extract information using regex patterns
        for data_type, pattern in self.patterns.items():
            # Skip the JSON response patterns as they're handled by plugins
            if data_type in ['successful_json_request', 'failed_json_request']:
                continue
            
            matches = re.finditer(pattern, content)
            for match in matches:
                value = match.group(0)
                
                # Apply additional validation based on data type
                if data_type == 'ipv4':
                    from ipaddress import IPv4Address, AddressValueError
                    try:
                        IPv4Address(value)
                        self.results[data_type].add(value)
                    except AddressValueError:
                        continue
                        
                elif data_type == 'base64_encoded':
                    from ..utils.file_utils import is_valid_base64
                    if is_valid_base64(value):
                        self.results[data_type].add(value)
                        
                elif data_type == 'hash':
                    hash_type = self._identify_hash(value)
                    confidence = calculate_entropy(value)
                    value = f"{value} (Type: {hash_type}, Entropy: {confidence:.2f})"
                    self.results[data_type].add(value)
                    
                else:
                    # Default case - just add the value
                    self.results[data_type].add(value)
    
    def _identify_hash(self, hash_value: str) -> str:
        """
        Advanced hash identification using pattern matching and entropy analysis.
        
        Args:
            hash_value: The hash string to identify
            
        Returns:
            Identified hash type(s) or 'Unknown'
        """
        # Clean the hash value
        hash_value = hash_value.strip()
        
        # Calculate entropy
        entropy = calculate_entropy(hash_value)
        
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
    
    def analyze_file_parallel(self, file_path: Path) -> None:
        """
        Analyze a file using parallel processing for large files.
        
        This method splits the file into chunks and processes them in parallel,
        significantly improving performance for large files.
        
        Args:
            file_path: Path to the file to analyze
        """
        file_size = file_path.stat().st_size
        
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
    
    def _process_file_chunk(self, file_path: Path, start_pos: int, end_pos: int) -> Dict[str, Set[str]]:
        """
        Process a chunk of a file.
        
        Args:
            file_path: Path to the file
            start_pos: Starting position in file
            end_pos: Ending position in file
            
        Returns:
            Results for this chunk
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
                    if data_type in ['successful_json_request', 'failed_json_request']:
                        continue
                        
                    matches = re.finditer(pattern, chunk_data)
                    for match in matches:
                        value = match.group(0)
                        # Apply validation (simplified for example)
                        chunk_results[data_type].add(value)
        
        return chunk_results
    
    def _merge_chunk_results(self, chunk_results: Dict[str, Set[str]]) -> None:
        """
        Merge results from a chunk into the main results.
        
        Args:
            chunk_results: Results from a chunk
        """
        for key, values in chunk_results.items():
            if key in self.results:
                self.results[key].update(values)
            else:
                self.results[key] = values
    
    def get_results(self) -> Dict[str, Set[str]]:
        """
        Get the analysis results.
        
        Returns:
            Copy of the results dictionary
        """
        return {k: v.copy() for k, v in self.results.items()}
    
    def get_api_structure(self) -> Dict:
        """
        Get the API structure information.
        
        Returns:
            The API structure dictionary
        """
        return self.api_structure.copy()
    
    def reset_results(self) -> None:
        """Reset the results to an empty state."""
        self.results = self._initialize_results()
        self.api_structure = {} 