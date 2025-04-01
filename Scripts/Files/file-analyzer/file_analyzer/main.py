#!/usr/bin/env python3
# Main entry point for the file analyzer

import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from .core.analyzer import FileAnalyzer
from .utils.dependency_checker import check_dependencies, generate_requirements_file, setup_colored_output
from .utils.output_formatter import format_results, export_results_json, create_html_report


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Analyze files for cybersecurity purposes')
    parser.add_argument('file_path', nargs='?', help='Path to the file to analyze')
    parser.add_argument('--md', action='store_true', help='Output in markdown format (wrapped in triple backticks)')
    parser.add_argument('--skip-checks', action='store_true', help='Skip dependency checks (for advanced users)')
    parser.add_argument('--requirements', action='store_true', help='Generate requirements.txt file and exit')
    parser.add_argument('--version', action='store_true', help='Show version information and exit')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--html', help='Export results to HTML report')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--plugin-dir', action='append', help='Additional plugin directory')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                         default='INFO', help='Set logging level')
    parser.add_argument('--log-file', default='file_analyzer.log', help='Log file path')
    
    return parser.parse_args()


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file if provided.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config = {}
    
    if config_path:
        import json
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            logging.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
    
    return config


def main():
    """Main entry point function."""
    args = parse_arguments()
    
    # Show version info if requested
    if args.version:
        print("File Analyzer v1.0.0")
        print("Author: Tristan Pereira")
        print("A comprehensive file analysis tool for cybersecurity")
        sys.exit(0)
    
    # Generate requirements file if requested
    if args.requirements:
        generate_requirements_file()
        sys.exit(0)
    
    # Check dependencies unless explicitly skipped
    if not args.skip_checks:
        if not check_dependencies():
            sys.exit(1)
    
    # Set up colored output
    colors = setup_colored_output()
    
    # We need a file path to analyze
    if not args.file_path:
        print(colors["red"]("Error: No file specified for analysis"))
        print(f"Usage: python -m file_analyzer <file_path>")
        print(f"Run with --help for more options")
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Apply command line configurations
    config['log_level'] = getattr(logging, args.log_level.upper())
    config['log_file'] = args.log_file
    if args.plugin_dir:
        config['plugin_dirs'] = args.plugin_dir
    
    # Initialize analyzer with configuration
    analyzer = FileAnalyzer(config)
    
    # Create a progress bar for the analysis process if tqdm is available
    try:
        from tqdm import tqdm
        with tqdm(total=100, desc="Analyzing file", unit="%") as progress_bar:
            # Update progress bar after initialization
            progress_bar.update(10)
            
            # Analyze the file
            analyzer.analyze_file(args.file_path)
            
            # Update progress bar after main analysis
            progress_bar.update(80)
            
            # Get results
            results = analyzer.get_results()
            api_structure = analyzer.get_api_structure()
            
            # Format and print results
            formatted_results = format_results(results, api_structure, args.md, colors)
            print(formatted_results)
            
            # Export to JSON if requested
            if args.json:
                export_results_json(results, args.json)
            
            # Create HTML report if requested
            if args.html:
                create_html_report(results, api_structure, args.html)
            
            # Complete the progress bar
            progress_bar.update(10)
    except ImportError:
        # Fall back to regular execution if tqdm is not available
        analyzer.analyze_file(args.file_path)
        
        # Get results
        results = analyzer.get_results()
        api_structure = analyzer.get_api_structure()
        
        # Format and print results
        formatted_results = format_results(results, api_structure, args.md, colors)
        print(formatted_results)
        
        # Export to JSON if requested
        if args.json:
            export_results_json(results, args.json)
        
        # Create HTML report if requested
        if args.html:
            create_html_report(results, api_structure, args.html)


if __name__ == "__main__":
    main()
