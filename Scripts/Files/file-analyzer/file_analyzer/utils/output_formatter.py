#!/usr/bin/env python3
# Output formatting utilities

from typing import Dict, Set, Any, List, Optional
import json

def format_results(results: Dict[str, Set[str]], api_structure: Optional[Dict] = None, 
                   markdown_format: bool = False, colors: Optional[Dict] = None) -> str:
    """
    Format analysis results for display.
    
    Args:
        results: Dictionary of result categories and their values
        api_structure: API structure correlation data (optional)
        markdown_format: Whether to format for markdown
        colors: Dictionary of color functions (optional)
        
    Returns:
        Formatted string of results
    """
    output = []
    
    # Use colors if provided, otherwise create no-op functions
    if colors is None:
        colors = {k: lambda x: x for k in ["red", "green", "yellow", "blue", "magenta", "cyan"]}
    
    # Start markdown output if requested
    if markdown_format:
        output.append("```")
    
    output.append("\n=== File Analysis Results ===\n")
    
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
        category_output = []
        category_output.append(f"\n{colors['cyan'](category)}:")
        
        for data_type in data_types:
            if data_type in results and results[data_type]:
                values = results[data_type]
                category_output.append(f"  {colors['green'](data_type.upper())} ({len(values)} found):")
                for value in sorted(values):
                    # Apply yellow color to potential security issues
                    if data_type in ['security_smells', 'network_security_issues', 'high_entropy_strings']:
                        category_output.append(f"    - {colors['yellow'](value)}")
                    else:
                        category_output.append(f"    - {value}")
        
        # Only add the category if it has content
        if len(category_output) > 1:
            output.extend(category_output)

    # Print correlated API structure if available
    if api_structure:
        output.append("\n" + colors['cyan']("Correlated API Structure:"))
        for endpoint, details in api_structure.items():
            output.append(f"  {colors['magenta']('ENDPOINT:')} {endpoint}")
            
            if details.get('methods'):
                output.append(f"    Methods: {', '.join(details['methods'])}")
            
            if details.get('parameters'):
                output.append(f"    Parameters: {', '.join(details['parameters'])}")
            
            if details.get('content_types'):
                output.append(f"    Content Types: {', '.join(details['content_types'])}")
            
            output.append("")  # Empty line for readability
    
    # Add warning disclaimer
    output.append("\n" + "="*80)
    output.append(colors['yellow']("WARNING DISCLAIMER:"))
    output.append("-"*80)
    output.append("This analysis is based on pattern matching and may not be exhaustive.")
    output.append("Some API endpoints, credentials, or sensitive data might not be detected.")
    output.append("Successful API request examples are based on contextual clues and might be incomplete.")
    output.append("For critical security analysis, always perform manual verification.")
    output.append("="*80)
    
    # End markdown output if requested
    if markdown_format:
        output.append("```")
    
    return "\n".join(output)

def export_results_json(results: Dict[str, Set[str]], output_file: str) -> None:
    """
    Export analysis results to a JSON file.
    
    Args:
        results: Dictionary of result categories and their values
        output_file: Path to save the JSON file
    """
    # Convert sets to lists for JSON serialization
    json_results = {}
    for key, value in results.items():
        json_results[key] = list(value)
    
    with open(output_file, 'w') as f:
        json.dump(json_results, f, indent=2)
    
    print(f"Results exported to {output_file}")

def create_html_report(results: Dict[str, Set[str]], api_structure: Optional[Dict] = None, 
                      output_file: str = "file_analysis_report.html") -> None:
    """
    Create an HTML report from the analysis results.
    
    Args:
        results: Dictionary of result categories and their values
        api_structure: API structure correlation data (optional)
        output_file: Path to save the HTML report
    """
    # Define categories for better organization (same as in format_results)
    categories = {
        'Network Information': ['ipv4', 'ipv6', 'domain_keywords', 'url'],
        'Authentication': ['username', 'password', 'jwt', 'access_token', 'refresh_token', 'oauth_token'],
        'API & Keys': ['api_key', 'aws_key', 'api_key_param'],
        'Cryptography': ['private_key', 'public_key', 'hash'],
        # ... (copy from format_results)
    }
    
    # Start building HTML content
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2 { color: #333; }
            .category { margin-top: 20px; border-bottom: 1px solid #ddd; }
            .datatype { margin-left: 20px; margin-top: 10px; }
            .value { margin-left: 40px; margin-bottom: 5px; }
            .security-issue { color: #e74c3c; }
            .disclaimer { background-color: #fcf8e3; padding: 15px; border: 1px solid #faebcc; border-radius: 4px; margin-top: 30px; }
            .endpoint { background-color: #eef; padding: 10px; margin: 10px 0; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>File Analysis Report</h1>
    """
    
    # Add each category and its findings
    for category, data_types in categories.items():
        category_has_content = False
        
        # Check if this category has any content
        for data_type in data_types:
            if data_type in results and results[data_type]:
                category_has_content = True
                break
                
        if not category_has_content:
            continue
            
        html_content += f'<div class="category"><h2>{category}</h2>'
        
        for data_type in data_types:
            if data_type in results and results[data_type]:
                values = results[data_type]
                html_content += f'<div class="datatype"><h3>{data_type.upper()} ({len(values)} found)</h3>'
                
                for value in sorted(values):
                    # Add special class for security issues
                    if data_type in ['security_smells', 'network_security_issues', 'high_entropy_strings']:
                        html_content += f'<div class="value security-issue">{value}</div>'
                    else:
                        html_content += f'<div class="value">{value}</div>'
                        
                html_content += '</div>'  # Close datatype div
        
        html_content += '</div>'  # Close category div
    
    # Add API structure if available
    if api_structure:
        html_content += '<div class="category"><h2>Correlated API Structure</h2>'
        
        for endpoint, details in api_structure.items():
            html_content += f'<div class="endpoint"><h3>ENDPOINT: {endpoint}</h3>'
            
            if details.get('methods'):
                html_content += f'<p><strong>Methods:</strong> {", ".join(details["methods"])}</p>'
            
            if details.get('parameters'):
                html_content += f'<p><strong>Parameters:</strong> {", ".join(details["parameters"])}</p>'
            
            if details.get('content_types'):
                html_content += f'<p><strong>Content Types:</strong> {", ".join(details["content_types"])}</p>'
                
            html_content += '</div>'  # Close endpoint div
            
        html_content += '</div>'  # Close category div
    
    # Add disclaimer
    html_content += """
        <div class="disclaimer">
            <h3>WARNING DISCLAIMER:</h3>
            <p>This analysis is based on pattern matching and may not be exhaustive.</p>
            <p>Some API endpoints, credentials, or sensitive data might not be detected.</p>
            <p>Successful API request examples are based on contextual clues and might be incomplete.</p>
            <p>For critical security analysis, always perform manual verification.</p>
        </div>
    </body>
    </html>
    """
    
    # Write the HTML file
    with open(output_file, 'w') as f:
        f.write(html_content)
        
    print(f"HTML report created at {output_file}") 