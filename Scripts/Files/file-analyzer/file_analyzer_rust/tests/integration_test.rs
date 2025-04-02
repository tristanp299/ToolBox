/// Integration tests for the file analyzer
///
/// These tests verify that the main functionality of the file analyzer works correctly,
/// including pattern detection and result generation.

use std::path::Path;
use std::collections::HashSet;
use serde_json::Value;

use file_analyzer::core::analyzer::FileAnalyzer;
use file_analyzer::core::patterns::load_patterns;

#[test]
fn test_analyze_test_file() {
    // Initialize the analyzer
    let patterns = load_patterns();
    let config = serde_json::json!({});
    let mut analyzer = FileAnalyzer::new(&config, &patterns, 60, None);
    
    // Analyze the test file
    let test_file = Path::new("tests/test_data.txt");
    let results = analyzer.analyze_file(test_file).expect("Failed to analyze test file");
    
    // Convert results to a more easily testable format
    let results_map: std::collections::HashMap<_, _> = results.into_iter().collect();
    
    // Test that we found some common patterns
    assert!(results_map.contains_key("ipv4"));
    assert!(results_map.contains_key("email"));
    assert!(results_map.contains_key("url"));
    assert!(results_map.contains_key("api_key"));
    assert!(results_map.contains_key("hash"));
    
    // Verify specific findings
    if let Some(ipv4_set) = results_map.get("ipv4") {
        assert!(ipv4_set.contains("192.168.1.1"));
        assert!(ipv4_set.contains("10.0.0.1"));
    } else {
        panic!("No IPv4 addresses found");
    }
    
    if let Some(email_set) = results_map.get("email") {
        assert!(email_set.contains("test@example.com"));
        assert!(email_set.contains("support@company.org"));
    } else {
        panic!("No email addresses found");
    }
    
    if let Some(jwt_set) = results_map.get("jwt") {
        assert!(jwt_set.iter().any(|s| s.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")));
    } else {
        panic!("No JWT tokens found");
    }
    
    // Verify that we found the credit card number
    if let Some(cc_set) = results_map.get("credit_card") {
        assert!(cc_set.contains("4111-1111-1111-1111") || cc_set.contains("4111111111111111"));
    } else {
        panic!("No credit card numbers found");
    }
    
    // Verify that we found the social security number
    if let Some(ssn_set) = results_map.get("social_security") {
        assert!(ssn_set.contains("123-45-6789"));
    } else {
        panic!("No social security numbers found");
    }
    
    // Verify that we found some API endpoints
    if let Some(api_set) = results_map.get("api_endpoint") {
        assert!(api_set.iter().any(|s| s.contains("/v1/users/")));
    } else {
        panic!("No API endpoints found");
    }
    
    // Verify high entropy strings
    if let Some(entropy_set) = results_map.get("high_entropy_strings") {
        assert!(!entropy_set.is_empty(), "No high entropy strings found");
    }
}

#[test]
fn test_empty_file() {
    // Create a temporary empty file
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let empty_file_path = temp_dir.path().join("empty.txt");
    std::fs::write(&empty_file_path, "").expect("Failed to write empty file");
    
    // Initialize analyzer
    let patterns = load_patterns();
    let config = serde_json::json!({});
    let mut analyzer = FileAnalyzer::new(&config, &patterns, 60, None);
    
    // Analyze the empty file
    let results = analyzer.analyze_file(&empty_file_path).expect("Failed to analyze empty file");
    
    // Verify that no patterns were found
    for (category, values) in &results {
        if category != "file_metadata" && category != "runtime_errors" {
            assert!(values.is_empty(), "Category {} should be empty for empty file", category);
        }
    }
} 