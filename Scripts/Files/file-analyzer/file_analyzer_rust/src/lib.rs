/// File Analyzer - A comprehensive file analysis tool for cybersecurity
///
/// This library provides functionality to analyze files for security-relevant information,
/// including credentials, API endpoints, network information, and other sensitive data.

// Re-export core modules
pub mod core;
pub mod utils;

// Re-export main analyzer types for convenience
pub use crate::core::analyzer::FileAnalyzer;
pub use crate::core::patterns::load_patterns;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Analyze a single file and return the results
///
/// This is a convenience function for simple use cases.
///
/// # Arguments
///
/// * `file_path` - Path to the file to analyze
/// * `timeout_seconds` - Timeout in seconds (0 for no timeout)
///
/// # Returns
///
/// Results of the analysis as a vector of (category, values) tuples
pub fn analyze_file<P: AsRef<std::path::Path>>(
    file_path: P,
    timeout_seconds: u64,
) -> anyhow::Result<Vec<(String, std::collections::HashSet<String>)>> {
    // Initialize analyzer with default settings
    let patterns = load_patterns();
    let config = serde_json::json!({});
    let timeout = if timeout_seconds > 0 { timeout_seconds } else { 300 };
    
    let mut analyzer = FileAnalyzer::new(&config, &patterns, timeout, None);
    
    // Analyze the file
    analyzer.analyze_file(file_path.as_ref())
}

/// Library configuration and utilities
pub mod config {
    use serde_json::Value;
    
    /// Create default configuration
    pub fn default_config() -> Value {
        serde_json::json!({
            "timeout": 300,
            "memory_limit": null,
            "log_level": "info",
            "log_file": "file_analyzer.log"
        })
    }
}

/// Command-line application functionality
pub mod app {
    use crate::core::analyzer::FileAnalyzer;
    use crate::core::patterns::load_patterns;
    use std::path::Path;
    
    /// Run the analyzer on multiple files
    ///
    /// # Arguments
    ///
    /// * `file_paths` - Paths to files to analyze
    /// * `config` - Configuration options
    ///
    /// # Returns
    ///
    /// Results for all files
    pub fn run_analyzer<P: AsRef<Path>>(
        file_paths: &[P],
        config: &serde_json::Value,
        timeout_seconds: u64,
        memory_limit_mb: Option<usize>,
    ) -> anyhow::Result<Vec<(String, Vec<(String, std::collections::HashSet<String>)>)>> {
        let patterns = load_patterns();
        let mut results = Vec::new();
        
        for file_path in file_paths {
            let mut analyzer = FileAnalyzer::new(config, &patterns, timeout_seconds, memory_limit_mb);
            let file_results = analyzer.analyze_file(file_path.as_ref())?;
            let path_str = file_path.as_ref().to_string_lossy().to_string();
            results.push((path_str, file_results));
        }
        
        Ok(results)
    }
} 