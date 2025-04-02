/// Output formatter for analysis results
///
/// This module handles formatting and exporting analysis results in various formats,
/// including console output, JSON, HTML, and CSV.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use anyhow::{Result, Context};
use colored::Colorize;
use handlebars::Handlebars;
use serde_json::{self, json, Value};

/// Format analysis results for console output
///
/// # Arguments
///
/// * `results` - Analysis results organized by category
/// * `use_markdown` - Whether to format output with markdown triple backticks
///
/// # Returns
///
/// Formatted string for console output
pub fn format_results(
    results: &[(String, HashSet<String>)],
    use_markdown: &bool,
) -> String {
    let mut output = String::new();
    
    // Start markdown code block if requested
    if *use_markdown {
        output.push_str("```\n");
    }
    
    // Group results by category for better organization
    let categories = [
        ("File Information", vec!["file_metadata"]),
        ("Network Information", vec!["ipv4", "ipv6", "domain_keywords", "url", "network_protocols", 
                                     "network_security_issues", "network_ports", "network_hosts", 
                                     "network_endpoints"]),
        ("API and Authentication", vec!["api_key", "api_endpoint", "api_method", "api_parameter", 
                                        "api_version", "authorization_header", "api_key_param",
                                        "jwt", "access_token", "refresh_token", "oauth_token", 
                                        "http_status_code"]),
        ("Credentials and Sensitive Data", vec!["username", "password", "private_key", "public_key", 
                                                "aws_key", "database_connection", "session_id", 
                                                "cookie", "high_entropy_strings"]),
        ("Encoded and Hashed Data", vec!["hash", "base64_encoded"]),
        ("Software and Versions", vec!["software_versions"]),
        ("Code Issues", vec!["code_quality", "commented_code"]),
        ("Errors", vec!["runtime_errors"]),
    ];
    
    // Store results in a hashmap for easy lookup
    let results_map: HashMap<_, _> = results.iter().cloned().collect();
    
    // Process each category group
    for (group_name, categories_in_group) in categories.iter() {
        let mut group_has_results = false;
        let mut group_output = String::new();
        
        // Check if any category in this group has results
        for category in categories_in_group {
            if let Some(values) = results_map.get(*category) {
                if !values.is_empty() {
                    group_has_results = true;
                    
                    // Format category name
                    let formatted_category = category.replace('_', " ");
                    let title = formatted_category.chars()
                        .enumerate()
                        .map(|(i, c)| if i == 0 || formatted_category.chars().nth(i-1) == Some(' ') {
                            c.to_uppercase().next().unwrap_or(c)
                        } else {
                            c
                        })
                        .collect::<String>();
                    
                    group_output.push_str(&format!("  {}: {}\n", title.cyan().bold(), values.len()));
                    
                    // Add each value with indentation
                    let mut sorted_values: Vec<_> = values.iter().collect();
                    sorted_values.sort();
                    
                    for value in sorted_values {
                        group_output.push_str(&format!("    - {}\n", value));
                    }
                    
                    group_output.push('\n');
                }
            }
        }
        
        // Add group to output if it has results
        if group_has_results {
            output.push_str(&format!("{}\n", group_name.yellow().bold()));
            output.push_str(&group_output);
        }
    }
    
    // End markdown code block if requested
    if *use_markdown {
        output.push_str("```\n");
    }
    
    // If no results found, add a message
    if output.is_empty() {
        output = if *use_markdown {
            "```\nNo findings detected.\n```\n".to_string()
        } else {
            "No findings detected.\n".to_string()
        };
    }
    
    output
}

/// Export results to a JSON file
///
/// # Arguments
///
/// * `results` - Analysis results organized by category
/// * `output_path` - Path where the JSON file will be written
///
/// # Returns
///
/// Result indicating success or failure
pub fn export_results_json(
    results: &[(String, HashSet<String>)],
    output_path: &Path,
) -> Result<()> {
    // Convert results to a serializable format
    let mut json_output = serde_json::Map::new();
    
    for (category, values) in results {
        let values_vec: Vec<_> = values.iter().cloned().collect();
        json_output.insert(category.clone(), json!(values_vec));
    }
    
    // Write to file
    let file = File::create(output_path)
        .context(format!("Failed to create JSON output file: {}", output_path.display()))?;
    
    serde_json::to_writer_pretty(file, &json_output)
        .context("Failed to write JSON data")?;
    
    Ok(())
}

/// Create an HTML report from analysis results
///
/// # Arguments
///
/// * `results` - Analysis results organized by category
/// * `output_path` - Path where the HTML file will be written
///
/// # Returns
///
/// Result indicating success or failure
pub fn create_html_report(
    results: &[(String, HashSet<String>)],
    output_path: &Path,
) -> Result<()> {
    // Register the Handlebars template engine
    let mut handlebars = Handlebars::new();
    
    // Register the template
    const HTML_TEMPLATE: &str = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>File Analysis Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            h1 {
                color: #2c3e50;
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
            }
            h2 {
                color: #2980b9;
                margin-top: 30px;
            }
            h3 {
                color: #3498db;
                margin-top: 20px;
            }
            .category {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .findings {
                list-style-type: none;
                padding-left: 20px;
            }
            .findings li {
                padding: 5px 0;
                border-bottom: 1px solid #eee;
            }
            .findings li:last-child {
                border-bottom: none;
            }
            .category-count {
                background-color: #3498db;
                color: white;
                border-radius: 20px;
                padding: 2px 8px;
                font-size: 0.8em;
                margin-left: 10px;
            }
            .timestamp {
                color: #7f8c8d;
                font-size: 0.9em;
                margin-bottom: 30px;
            }
            .summary {
                background-color: #e8f4f8;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 30px;
            }
            .group {
                margin-bottom: 40px;
            }
        </style>
    </head>
    <body>
        <h1>File Analysis Report</h1>
        <div class="timestamp">Generated on: {{timestamp}}</div>
        
        <div class="summary">
            <h2>Analysis Summary</h2>
            <p>Total findings: {{total_findings}}</p>
            <p>Categories with findings: {{categories_with_findings}}</p>
        </div>
        
        {{#each groups}}
        <div class="group">
            <h2>{{name}}</h2>
            
            {{#each categories}}
            {{#if values.length}}
            <div class="category">
                <h3>{{name}} <span class="category-count">{{values.length}}</span></h3>
                <ul class="findings">
                    {{#each values}}
                    <li>{{this}}</li>
                    {{/each}}
                </ul>
            </div>
            {{/if}}
            {{/each}}
        </div>
        {{/each}}
    </body>
    </html>
    "#;
    
    handlebars.register_template_string("report", HTML_TEMPLATE)
        .context("Failed to register HTML template")?;
    
    // Convert results to a serializable format for the template
    let results_map: HashMap<_, _> = results.iter().cloned().collect();
    
    // Define category groups for the report
    let groups = [
        ("File Information", vec!["file_metadata"]),
        ("Network Information", vec!["ipv4", "ipv6", "domain_keywords", "url", "network_protocols", 
                                     "network_security_issues", "network_ports", "network_hosts", 
                                     "network_endpoints"]),
        ("API and Authentication", vec!["api_key", "api_endpoint", "api_method", "api_parameter", 
                                        "api_version", "authorization_header", "api_key_param",
                                        "jwt", "access_token", "refresh_token", "oauth_token", 
                                        "http_status_code"]),
        ("Credentials and Sensitive Data", vec!["username", "password", "private_key", "public_key", 
                                                "aws_key", "database_connection", "session_id", 
                                                "cookie", "high_entropy_strings"]),
        ("Encoded and Hashed Data", vec!["hash", "base64_encoded"]),
        ("Software and Versions", vec!["software_versions"]),
        ("Code Issues", vec!["code_quality", "commented_code"]),
        ("Errors", vec!["runtime_errors"]),
    ];
    
    // Prepare the template data
    let mut template_data = serde_json::Map::new();
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    template_data.insert("timestamp".to_string(), json!(timestamp));
    
    // Calculate total findings and categories with findings
    let total_findings: usize = results_map.values().map(|v| v.len()).sum();
    let categories_with_findings = results_map.values().filter(|v| !v.is_empty()).count();
    
    template_data.insert("total_findings".to_string(), json!(total_findings));
    template_data.insert("categories_with_findings".to_string(), json!(categories_with_findings));
    
    // Prepare groups data
    let mut groups_data = Vec::new();
    
    for (group_name, categories_in_group) in groups.iter() {
        let mut group = serde_json::Map::new();
        group.insert("name".to_string(), json!(group_name));
        
        let mut categories_data = Vec::new();
        
        for &category in categories_in_group {
            let mut category_data = serde_json::Map::new();
            
            // Format category name for display
            let formatted_category = category.replace('_', " ");
            let title = formatted_category.chars()
                .enumerate()
                .map(|(i, c)| if i == 0 || formatted_category.chars().nth(i-1) == Some(' ') {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c
                })
                .collect::<String>();
            
            category_data.insert("name".to_string(), json!(title));
            
            // Add values if they exist
            if let Some(values) = results_map.get(category) {
                let mut sorted_values: Vec<_> = values.iter().cloned().collect();
                sorted_values.sort();
                category_data.insert("values".to_string(), json!(sorted_values));
            } else {
                category_data.insert("values".to_string(), json!(Vec::<String>::new()));
            }
            
            categories_data.push(Value::Object(category_data));
        }
        
        group.insert("categories".to_string(), json!(categories_data));
        groups_data.push(Value::Object(group));
    }
    
    template_data.insert("groups".to_string(), json!(groups_data));
    
    // Render the template
    let html = handlebars.render("report", &template_data)
        .context("Failed to render HTML template")?;
    
    // Write to file
    let mut file = File::create(output_path)
        .context(format!("Failed to create HTML output file: {}", output_path.display()))?;
    
    file.write_all(html.as_bytes())
        .context("Failed to write HTML data")?;
    
    Ok(())
}

/// Create a CSV report from analysis results
///
/// # Arguments
///
/// * `results` - Analysis results organized by category
/// * `output_path` - Path where the CSV file will be written
///
/// # Returns
///
/// Result indicating success or failure
pub fn create_csv_report(
    results: &[(String, HashSet<String>)],
    output_path: &Path,
) -> Result<()> {
    // Create a CSV writer
    let file = File::create(output_path)
        .context(format!("Failed to create CSV output file: {}", output_path.display()))?;
    
    let mut writer = csv::Writer::from_writer(file);
    
    // Write header
    writer.write_record(&["Category", "Finding"])
        .context("Failed to write CSV header")?;
    
    // Write all findings
    for (category, values) in results {
        // Format category name for display
        let formatted_category = category.replace('_', " ");
        let title = formatted_category.chars()
            .enumerate()
            .map(|(i, c)| if i == 0 || formatted_category.chars().nth(i-1) == Some(' ') {
                c.to_uppercase().next().unwrap_or(c)
            } else {
                c
            })
            .collect::<String>();
        
        for value in values {
            writer.write_record(&[&title, value])
                .context("Failed to write CSV record")?;
        }
    }
    
    // Flush the writer to ensure all data is written
    writer.flush().context("Failed to flush CSV writer")?;
    
    Ok(())
}

/// Create a summary of findings for multiple files
///
/// # Arguments
///
/// * `all_results` - Results for multiple files
///
/// # Returns
///
/// Summary string
pub fn create_summary(
    all_results: &[(String, Vec<(String, HashSet<String>)>)],
) -> String {
    let mut output = String::new();
    
    output.push_str(&format!("{}\n\n", "Analysis Summary".yellow().bold()));
    
    // Total files analyzed
    output.push_str(&format!("Files analyzed: {}\n", all_results.len()));
    
    // Calculate total findings across all files
    let total_findings: usize = all_results
        .iter()
        .map(|(_, results)| {
            results.iter().map(|(_, values)| values.len()).sum::<usize>()
        })
        .sum();
    
    output.push_str(&format!("Total findings: {}\n\n", total_findings));
    
    // Count findings by category across all files
    let mut category_counts: HashMap<String, usize> = HashMap::new();
    
    for (_, results) in all_results {
        for (category, values) in results {
            if !values.is_empty() {
                *category_counts.entry(category.clone()).or_insert(0) += values.len();
            }
        }
    }
    
    // Show top categories
    if !category_counts.is_empty() {
        output.push_str(&format!("{}\n", "Top Finding Categories".cyan().bold()));
        
        let mut categories: Vec<_> = category_counts.iter().collect();
        categories.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
        
        for (i, (category, count)) in categories.iter().take(10).enumerate() {
            let formatted_category = category.replace('_', " ");
            let title = formatted_category.chars()
                .enumerate()
                .map(|(i, c)| if i == 0 || formatted_category.chars().nth(i-1) == Some(' ') {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c
                })
                .collect::<String>();
            
            output.push_str(&format!("{}. {}: {}\n", i+1, title, count));
        }
    }
    
    output
} 