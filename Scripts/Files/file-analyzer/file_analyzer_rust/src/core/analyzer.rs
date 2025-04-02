/// Core file analyzer implementation
///
/// This file contains the implementation of the FileAnalyzer which coordinates
/// the analysis of files, applying various detection techniques.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;

use log::{debug, info, warn, error};
use anyhow::Result;
use regex::Regex;
use rayon::prelude::*;
use serde_json::Value;
use memmap2::Mmap;

use crate::core::patterns;
use crate::utils::file_utils::{self, FileType, read_file_content, get_file_metadata};

/// Error when memory limit is exceeded during analysis
#[derive(Debug, thiserror::Error)]
#[error("Memory limit exceeded during analysis")]
pub struct MemoryLimitExceeded;

/// Error when operation timeout is reached
#[derive(Debug, thiserror::Error)]
#[error("Operation timed out after {duration:?}")]
pub struct TimeoutExceeded {
    duration: Duration,
}

/// Core file analyzer structure
pub struct FileAnalyzer {
    /// Configuration options
    config: Value,
    
    /// Regex patterns for different types of data
    patterns: HashMap<String, HashMap<String, String>>,
    
    /// Compiled regex patterns (optimization)
    compiled_patterns: HashMap<String, Regex>,
    
    /// Analysis results organized by category
    results: HashMap<String, HashSet<String>>,
    
    /// Timeout duration for analysis operations
    timeout: Duration,
    
    /// Optional memory limit in bytes
    memory_limit: Option<usize>,
}

impl FileAnalyzer {
    /// Create a new FileAnalyzer instance
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration options as a JSON value
    /// * `patterns` - HashMap of regex patterns for detection
    /// * `timeout_seconds` - Timeout duration in seconds per file
    /// * `memory_limit_mb` - Optional memory limit in megabytes
    ///
    /// # Returns
    ///
    /// A new FileAnalyzer instance
    pub fn new(
        config: &Value,
        patterns: &HashMap<String, HashMap<String, String>>,
        timeout_seconds: u64,
        memory_limit_mb: Option<usize>,
    ) -> Self {
        // Convert memory limit from MB to bytes if provided
        let memory_limit = memory_limit_mb.map(|mb| mb * 1024 * 1024);
        
        // Create empty results structure
        let results = Self::initialize_results();
        
        // Precompile patterns for efficiency
        let compiled_patterns = Self::compile_patterns(&patterns["general"]);

        Self {
            config: config.clone(),
            patterns: patterns.clone(),
            compiled_patterns,
            results,
            timeout: Duration::from_secs(timeout_seconds),
            memory_limit,
        }
    }
    
    /// Initialize the results dictionary with empty sets for all categories
    ///
    /// # Returns
    ///
    /// Empty results dictionary
    fn initialize_results() -> HashMap<String, HashSet<String>> {
        let mut results = HashMap::new();
        
        // Standard categories
        let categories = [
            "ipv4", "ipv6", "email", "domain_keywords", "url", "hash", "api_key", "jwt",
            "username", "password", "private_key", "public_key", "aws_key", "base64_encoded",
            "credit_card", "social_security", "database_connection", "access_token",
            "refresh_token", "oauth_token", "session_id", "cookie", "api_endpoint",
            "api_method", "content_type", "api_version", "api_parameter",
            "authorization_header", "rate_limit", "api_key_param", "curl_command",
            "webhook_url", "http_status_code", "openapi_schema", "graphql_query",
            "graphql_schema", "rest_resource", "xml_response", "error_pattern",
            "http_error", "oauth_flow", "api_auth_scheme", "code_quality",
            "high_entropy_strings", "commented_code", "network_protocols",
            "network_security_issues", "network_ports", "network_hosts",
            "network_endpoints", "software_versions", "runtime_errors", "file_metadata",
        ];
        
        for category in categories.iter() {
            results.insert(category.to_string(), HashSet::new());
        }
        
        results
    }
    
    /// Reset the results to an empty state
    pub fn reset_results(&mut self) {
        self.results = Self::initialize_results();
    }
    
    /// Compile regular expressions for better performance
    ///
    /// # Arguments
    ///
    /// * `patterns` - HashMap of pattern name to regex string
    ///
    /// # Returns
    ///
    /// HashMap of compiled regex patterns
    fn compile_patterns(patterns: &HashMap<String, String>) -> HashMap<String, Regex> {
        let mut compiled = HashMap::new();
        
        for (name, pattern) in patterns {
            match Regex::new(pattern) {
                Ok(regex) => { compiled.insert(name.clone(), regex); },
                Err(e) => {
                    error!("Error compiling pattern for {}: {}", name, e);
                    // Skip this pattern
                }
            }
        }
        
        compiled
    }
    
    /// Analyze a file and extract relevant information
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to analyze
    ///
    /// # Returns
    ///
    /// Analysis results organized by category
    pub fn analyze_file(&mut self, file_path: &Path) -> Result<Vec<(String, HashSet<String>)>> {
        info!("Analyzing file: {}", file_path.display());
        
        // Record start time for timeout tracking
        let start_time = Instant::now();
        
        // Create a cancellation flag for timeout
        let timeout_flag = Arc::new(AtomicBool::new(false));
        let timeout_flag_clone = timeout_flag.clone();
        
        // Spawn timeout thread
        let timeout_duration = self.timeout;
        thread::spawn(move || {
            thread::sleep(timeout_duration);
            timeout_flag_clone.store(true, Ordering::SeqCst);
        });
        
        // Check if file exists
        if !file_path.exists() {
            error!("File not found: {}", file_path.display());
            self.results.get_mut("runtime_errors")
                .unwrap()
                .insert(format!("File not found: {}", file_path.display()));
            return Ok(self.results_as_vec());
        }
        
        // Add file metadata
        self.add_file_metadata(file_path)?;
        
        // Determine file type
        let file_type = file_utils::detect_file_type(file_path);
        info!("Detected file type: {:?}", file_type);
        
        // Get file size for processing strategy
        let file_size = std::fs::metadata(file_path)?.len() as usize;
        
        // Choose analysis method based on file size
        let max_standard_size = 10 * 1024 * 1024; // 10MB threshold for standard processing
        
        if let Some(limit) = self.memory_limit {
            if file_size > limit {
                warn!("File size ({} bytes) exceeds memory limit, using chunked processing", file_size);
                self.chunked_analyze(file_path, file_type)?;
            } else if file_size > max_standard_size {
                info!("Using memory-mapped analysis for large file ({} bytes)", file_size);
                self.analyze_file_mmap(file_path, file_type)?;
            } else {
                // Standard processing for smaller files
                let file_content = read_file_content(file_path)?;
                self.process_patterns(&file_content.content)?;
            }
        } else {
            // No memory limit specified
            if file_size > max_standard_size {
                info!("Using memory-mapped analysis for large file ({} bytes)", file_size);
                self.analyze_file_mmap(file_path, file_type)?;
            } else {
                // Standard processing for smaller files
                let file_content = read_file_content(file_path)?;
                self.process_patterns(&file_content.content)?;
            }
        }
        
        // Check for timeout
        if timeout_flag.load(Ordering::SeqCst) {
            warn!("Analysis timed out for {}", file_path.display());
            self.results.get_mut("runtime_errors")
                .unwrap()
                .insert(format!("Analysis timed out after {:?}", self.timeout));
        }
        
        let elapsed = start_time.elapsed();
        info!("Analysis completed in {:?}", elapsed);
        
        Ok(self.results_as_vec())
    }
    
    /// Convert results hashmap to a vector of (category, values) tuples
    ///
    /// # Returns
    ///
    /// Vector representation of results
    fn results_as_vec(&self) -> Vec<(String, HashSet<String>)> {
        self.results
            .iter()
            .map(|(category, values)| (category.clone(), values.clone()))
            .collect()
    }
    
    /// Add file metadata to results
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    fn add_file_metadata(&mut self, file_path: &Path) -> Result<()> {
        let metadata = get_file_metadata(file_path)?;
        
        for (key, value) in metadata {
            self.results
                .get_mut("file_metadata")
                .unwrap()
                .insert(format!("{}: {}", key, value));
        }
        
        Ok(())
    }
    
    /// Process file content with all defined regex patterns
    ///
    /// # Arguments
    ///
    /// * `content` - File content to analyze
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    fn process_patterns(&mut self, content: &str) -> Result<()> {
        // Apply each compiled pattern
        for (data_type, compiled_pattern) in &self.compiled_patterns.clone() {
            // Skip JSON response patterns as they require special handling
            if data_type == "successful_json_request" || data_type == "failed_json_request" {
                continue;
            }
            
            // Find all matches
            for cap in compiled_pattern.find_iter(content) {
                let value = cap.as_str();
                
                // Apply additional validation based on data type
                match data_type.as_str() {
                    "ipv4" => {
                        if patterns::is_valid_ipv4(value) {
                            if let Some(set) = self.results.get_mut("ipv4") {
                                set.insert(value.to_string());
                            }
                        }
                    },
                    "base64_encoded" => {
                        if patterns::is_valid_base64(value) {
                            if let Some(set) = self.results.get_mut("base64_encoded") {
                                set.insert(value.to_string());
                            }
                        }
                    },
                    "hash" => {
                        let hash_type = patterns::identify_hash(value);
                        let confidence = patterns::calculate_entropy(value);
                        let enriched_value = format!("{} (Type: {}, Entropy: {:.2})", value, hash_type, confidence);
                        
                        if let Some(set) = self.results.get_mut("hash") {
                            set.insert(enriched_value);
                        }
                    },
                    _ => {
                        // Default case - just add the value
                        if let Some(set) = self.results.get_mut(data_type) {
                            set.insert(value.to_string());
                        }
                    }
                }
            }
        }
        
        // Look for high-entropy strings
        self.detect_high_entropy_strings(content);
        
        Ok(())
    }
    
    /// Detect high-entropy strings which may be secrets or encryption keys
    ///
    /// # Arguments
    ///
    /// * `content` - Content to analyze for high-entropy strings
    fn detect_high_entropy_strings(&mut self, content: &str) {
        // Define entropy threshold for high-entropy strings
        const ENTROPY_THRESHOLD: f64 = 4.5;
        
        // Split content into words (non-whitespace sequences)
        let words: Vec<&str> = content.split_whitespace().collect();
        
        for word in words {
            // Skip short strings (less than 8 chars)
            if word.len() < 8 {
                continue;
            }
            
            // Only check strings that look like they might be secrets
            // (alphanumeric with possible symbols but not regular text)
            let is_potential_secret = word.chars().all(|c| c.is_alphanumeric() || "!@#$%^&*()-_=+[]{}|;:,.<>?/".contains(c));
            
            if is_potential_secret {
                let entropy = patterns::calculate_entropy(word);
                
                if entropy > ENTROPY_THRESHOLD {
                    if let Some(set) = self.results.get_mut("high_entropy_strings") {
                        set.insert(format!("{} (Entropy: {:.2})", word, entropy));
                    }
                }
            }
        }
    }
    
    /// Analyze a large file using memory mapping for efficiency
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to analyze
    /// * `file_type` - Detected file type
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    fn analyze_file_mmap(&mut self, file_path: &Path, _file_type: FileType) -> Result<()> {
        // Open the file
        let file = File::open(file_path)?;
        
        // Create a memory map for efficient access
        let mmap = unsafe { Mmap::map(&file)? };
        
        // Convert to string (for text processing)
        let content = match std::str::from_utf8(&mmap) {
            Ok(content) => content,
            Err(_) => {
                // File might be binary, use lossy conversion
                let content = String::from_utf8_lossy(&mmap);
                self.process_patterns(&content)?;
                return Ok(());
            }
        };
        
        // Process the content with pattern detection
        self.process_patterns(content)?;
        
        Ok(())
    }
    
    /// Analyze a very large file in manageable chunks to avoid memory issues
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to analyze
    /// * `file_type` - Detected file type
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    fn chunked_analyze(&mut self, file_path: &Path, _file_type: FileType) -> Result<()> {
        const CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5MB chunks
        
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut chunk_num = 1;
        let mut buffer = Vec::with_capacity(CHUNK_SIZE);
        
        loop {
            // Read a chunk
            buffer.clear();
            let bytes_read = reader.by_ref().take(CHUNK_SIZE as u64).read_to_end(&mut buffer)?;
            if bytes_read == 0 {
                break; // End of file
            }
            
            // Convert to string for processing
            let content = String::from_utf8_lossy(&buffer);
            
            debug!("Processing chunk {} of file {}", chunk_num, file_path.display());
            
            // Process patterns in this chunk
            self.process_patterns(&content)?;
            
            // Next chunk
            chunk_num += 1;
        }
        
        Ok(())
    }
    
    /// Analyze a file in parallel chunks for large files
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to analyze
    /// * `file_type` - Detected file type
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    fn analyze_file_parallel(&mut self, file_path: &Path, _file_type: FileType) -> Result<()> {
        const CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5MB per chunk
        
        // Get file size
        let file_size = std::fs::metadata(file_path)?.len() as usize;
        let num_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE; // Ceiling division
        
        // Shared results that all threads will update
        let shared_results = Arc::new(Mutex::new(HashMap::new()));
        
        // Initialize result sets
        for key in self.results.keys() {
            shared_results.lock().unwrap().insert(key.clone(), HashSet::new());
        }
        
        // Process chunks in parallel
        (0..num_chunks).into_par_iter().for_each(|chunk_idx| {
            let start_pos = chunk_idx * CHUNK_SIZE;
            let end_pos = std::cmp::min((chunk_idx + 1) * CHUNK_SIZE, file_size);
            
            // Process this chunk
            match self.process_file_chunk(file_path, start_pos, end_pos) {
                Ok(chunk_results) => {
                    // Merge chunk results into shared results
                    let mut results = shared_results.lock().unwrap();
                    for (key, values) in chunk_results {
                        if let Some(set) = results.get_mut(&key) {
                            set.extend(values);
                        }
                    }
                }
                Err(e) => {
                    error!("Error processing chunk {}: {}", chunk_idx, e);
                    
                    // Add error to runtime_errors
                    if let Ok(mut results) = shared_results.lock() {
                        if let Some(set) = results.get_mut("runtime_errors") {
                            set.insert(format!("Chunk processing error: {}", e));
                        }
                    }
                }
            }
        });
        
        // Update main results with all findings from shared results
        for (key, values) in shared_results.lock().unwrap().iter() {
            if let Some(set) = self.results.get_mut(key) {
                set.extend(values.iter().cloned());
            }
        }
        
        Ok(())
    }
    
    /// Process a single chunk of a file
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file
    /// * `start_pos` - Starting position in the file
    /// * `end_pos` - Ending position in the file
    ///
    /// # Returns
    ///
    /// Results for this chunk
    fn process_file_chunk(&self, file_path: &Path, start_pos: usize, end_pos: usize) 
        -> Result<HashMap<String, HashSet<String>>> {
        
        // Initialize results for this chunk
        let mut chunk_results = HashMap::new();
        for key in self.results.keys() {
            chunk_results.insert(key.clone(), HashSet::new());
        }
        
        // Open the file
        let mut file = File::open(file_path)?;
        
        // Seek to the start position
        file.seek(SeekFrom::Start(start_pos as u64))?;
        
        // Read the chunk
        let mut buffer = vec![0; end_pos - start_pos];
        file.read_exact(&mut buffer)?;
        
        // Convert to string for pattern processing
        let content = String::from_utf8_lossy(&buffer);
        
        // Apply patterns to this chunk
        for (data_type, compiled_pattern) in &self.compiled_patterns {
            // Skip some patterns that need special handling
            if data_type == "successful_json_request" || data_type == "failed_json_request" {
                continue;
            }
            
            // Find all matches
            for cap in compiled_pattern.find_iter(&content) {
                let value = cap.as_str().to_string();
                
                // Store the match in chunk results
                if let Some(set) = chunk_results.get_mut(data_type) {
                    set.insert(value);
                }
            }
        }
        
        Ok(chunk_results)
    }
    
    /// Get the analysis results
    ///
    /// # Returns
    ///
    /// Reference to the results dictionary
    pub fn get_results(&self) -> &HashMap<String, HashSet<String>> {
        &self.results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_initialize_results() {
        let results = FileAnalyzer::initialize_results();
        assert!(results.contains_key("ipv4"));
        assert!(results.contains_key("hash"));
        assert!(results.contains_key("file_metadata"));
        assert!(results["ipv4"].is_empty());
    }
    
    #[test]
    fn test_validate_ipv4() {
        let mut analyzer = FileAnalyzer::new(
            &serde_json::json!({}),
            &patterns::load_patterns(),
            300,
            None
        );
        
        // Valid IPv4
        analyzer.validate_ipv4("192.168.1.1");
        assert!(analyzer.results["ipv4"].contains("192.168.1.1"));
        
        // Invalid IPv4
        analyzer.validate_ipv4("999.999.999.999");
        assert!(!analyzer.results["ipv4"].contains("999.999.999.999"));
    }
} 