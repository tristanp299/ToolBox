/// Simple example demonstrating how to use the File Analyzer library

use anyhow::Result;
use file_analyzer::analyze_file;
use std::path::Path;

fn main() -> Result<()> {
    // Path to file for analysis
    let file_path = "examples/sample_data.txt";
    
    // Create sample file
    std::fs::write(
        file_path,
        r#"This is a simple example file with sensitive data:
API key: api_key="2a4e6c8f0b2d4d6a8c0e2f4a6c8e0f2a"
A secret password: password="TopSecret123!"
IP address: 192.168.1.100
Email: admin@example.com
"#,
    )?;
    
    println!("Analyzing file: {}", file_path);
    
    // Analyze the file (default timeout of 60 seconds)
    let results = analyze_file(Path::new(file_path), 60)?;
    
    // Display results
    for (category, values) in results {
        if !values.is_empty() {
            println!("\n{} ({} found):", category, values.len());
            for value in values {
                println!("  - {}", value);
            }
        }
    }
    
    Ok(())
} 