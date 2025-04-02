/// File Analyzer - A comprehensive file analysis tool for cybersecurity
/// This tool analyzes files to extract security-relevant information
///
/// The main entry point for the file analyzer application. It parses command-line
/// arguments and coordinates the analysis process.

use anyhow::{Result, anyhow};
use clap::{Parser, ArgGroup, ArgAction};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use log::{info, warn, error, LevelFilter};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// Import modules
mod core;
mod utils;

use crate::core::analyzer::FileAnalyzer;
use crate::core::patterns::load_patterns;
use crate::utils::file_utils;
use crate::utils::output_formatter;

/// Command line argument structure
#[derive(Parser, Debug)]
#[command(
    name = "file_analyzer",
    author = "RUSTSEC Team",
    version = "0.1.0",
    about = "A comprehensive file analysis tool for cybersecurity",
    long_about = "This tool analyzes files to extract security-relevant information such as:
- API endpoints and authentication details
- Network information (IPs, domains, URLs)
- Sensitive data (credentials, tokens, keys)
- Code quality and security issues
- And much more!"
)]
#[command(group(
    ArgGroup::new("input")
        .required(true)
        .args(["file_paths", "dir"]),
))]
struct Args {
    /// Path(s) to the file(s) to analyze
    #[arg(name = "file_paths")]
    file_paths: Vec<String>,

    /// Analyze all files in directory (recursively)
    #[arg(long = "dir")]
    dir: Option<String>,

    /// Exclude file pattern (glob syntax, can be used multiple times)
    #[arg(long = "exclude", action = ArgAction::Append)]
    exclude: Option<Vec<String>>,

    /// Include only file pattern (glob syntax, can be used multiple times)
    #[arg(long = "include", action = ArgAction::Append)]
    include: Option<Vec<String>>,

    /// Maximum file size to analyze in MB (default: 50)
    #[arg(long = "max-size", default_value = "50")]
    max_size: usize,

    /// Maximum number of files to analyze (default: 1000)
    #[arg(long = "max-files", default_value = "1000")]
    max_files: usize,

    /// Output in markdown format (wrapped in triple backticks)
    #[arg(long = "md", action = ArgAction::SetTrue)]
    md: bool,

    /// Export results to JSON file
    #[arg(long = "json")]
    json: Option<String>,

    /// Export results to HTML report
    #[arg(long = "html")]
    html: Option<String>,

    /// Export results to CSV file
    #[arg(long = "csv")]
    csv: Option<String>,

    /// Directory to store all output files
    #[arg(long = "output-dir")]
    output_dir: Option<String>,

    /// Suppress terminal output
    #[arg(long = "quiet", action = ArgAction::SetTrue)]
    quiet: bool,

    /// Show only summary information
    #[arg(long = "summary-only", action = ArgAction::SetTrue)]
    summary_only: bool,

    /// Path to configuration file
    #[arg(long = "config")]
    config: Option<String>,

    /// Number of parallel workers (0=auto, default: auto)
    #[arg(long = "parallel", default_value = "0")]
    parallel: usize,

    /// Analysis timeout in seconds per file (default: 300)
    #[arg(long = "timeout", default_value = "300")]
    timeout: u64,

    /// Memory limit in MB (default: auto)
    #[arg(long = "memory-limit")]
    memory_limit: Option<usize>,

    /// Set logging level (default: INFO)
    #[arg(long = "log-level", default_value = "info")]
    log_level: LevelFilter,

    /// Log file path (default: file_analyzer.log)
    #[arg(long = "log-file", default_value = "file_analyzer.log")]
    log_file: String,
}

/// Main entry point function
fn main() -> Result<()> {
    // Record the start time
    let start_time = Instant::now();

    // Parse command line arguments
    let args = Args::parse();

    // Set up logging
    let _ = setup_logging(&args);

    // Load configuration
    let config = load_config(&args.config)?;

    // Get files to analyze
    let files_to_analyze = get_files_to_analyze(&args)?;

    if files_to_analyze.is_empty() {
        eprintln!("{}", "Error: No files specified or found for analysis".red());
        eprintln!("Run with --help for usage information");
        process::exit(1);
    }

    // Analyze all files
    let all_results = analyze_files(&files_to_analyze, &config, &args)?;

    // Export results if requested
    export_all_results(&all_results, &args)?;

    // Print results to console if not in quiet mode
    if !args.quiet {
        // Calculate total findings
        let total_findings: usize = all_results
            .iter()
            .map(|(_, results)| {
                results.iter().map(|(_, values)| values.len()).sum::<usize>()
            })
            .sum();

        // Print summary
        let elapsed_time = start_time.elapsed();
        println!("\n{}", "Analysis Complete".bold());
        println!("{} {}", "Files analyzed:".green(), all_results.len());
        println!("{} {}", "Total findings:".green(), total_findings);
        println!(
            "{} {:.2} seconds",
            "Time elapsed:".green(),
            elapsed_time.as_secs_f64()
        );

        // Print detailed results for each file
        if !args.summary_only {
            for (file_path_str, results) in &all_results {
                println!("\n{}", "=".repeat(80).bold());
                println!("{} {}", "Results for:".cyan(), file_path_str);
                println!("{}", "=".repeat(80).bold());

                // Format and print results
                let formatted_results = output_formatter::format_results(results, &args.md);
                println!("{}", formatted_results);
            }
        }
    }

    Ok(())
}

/// Set up logging with file and console output
fn setup_logging(args: &Args) -> Result<()> {
    // Configure logging
    let mut builder = env_logger::Builder::new();
    
    // Set log level from arguments
    builder.filter_level(args.log_level);
    
    // Set format
    builder.format(|buf, record| {
        use std::io::Write;
        use chrono::Local;
        writeln!(
            buf,
            "{} - {} - {} - {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.target(),
            record.args()
        )
    });
    
    // Add file output
    if let Ok(file) = File::create(&args.log_file) {
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }
    
    // Initialize logger
    builder.init();
    
    Ok(())
}

/// Load configuration from file if provided
fn load_config(config_path: &Option<String>) -> Result<serde_json::Value> {
    let config = match config_path {
        Some(path) => {
            let path = Path::new(path);
            if !path.exists() {
                error!("Configuration file not found: {}", path.display());
                serde_json::Value::Object(serde_json::Map::new())
            } else {
                let config_str = std::fs::read_to_string(path)?;
                match serde_json::from_str(&config_str) {
                    Ok(config) => {
                        info!("Loaded configuration from {}", path.display());
                        config
                    }
                    Err(e) => {
                        error!("Invalid JSON in configuration file: {}", e);
                        serde_json::Value::Object(serde_json::Map::new())
                    }
                }
            }
        }
        None => serde_json::Value::Object(serde_json::Map::new()),
    };

    Ok(config)
}

/// Get list of files to analyze based on command line arguments
fn get_files_to_analyze(args: &Args) -> Result<Vec<PathBuf>> {
    let mut files_to_analyze = Vec::new();
    let max_files = args.max_files;
    let max_size_bytes = args.max_size * 1024 * 1024; // Convert MB to bytes

    // Process individual files
    if !args.file_paths.is_empty() {
        for file_path in &args.file_paths {
            let path = PathBuf::from(file_path);
            if path.exists() {
                if path.is_file() {
                    match path.metadata() {
                        Ok(metadata) => {
                            if metadata.len() <= max_size_bytes as u64 {
                                files_to_analyze.push(path);
                            } else {
                                warn!(
                                    "Skipping {}: exceeds maximum file size ({:.2} MB)",
                                    path.display(),
                                    metadata.len() as f64 / 1024.0 / 1024.0
                                );
                            }
                        }
                        Err(e) => error!("Error reading metadata for {}: {}", path.display(), e),
                    }
                } else {
                    warn!("Skipping {}: not a file", path.display());
                }
            } else {
                error!("File not found: {}", path.display());
            }
        }
    }

    // Process directory recursively
    if let Some(dir_path) = &args.dir {
        let dir_path = PathBuf::from(dir_path);
        if !dir_path.exists() || !dir_path.is_dir() {
            error!("Directory not found: {}", dir_path.display());
        } else {
            // Create include/exclude patterns
            let include_patterns = args.include.clone().unwrap_or_else(|| vec!["*".to_string()]);
            let exclude_patterns = args.exclude.clone().unwrap_or_default();

            use walkdir::WalkDir;
            for entry in WalkDir::new(&dir_path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                // Check if we've reached the maximum number of files
                if files_to_analyze.len() >= max_files {
                    warn!("Reached maximum file limit ({})", max_files);
                    break;
                }

                let file_path = entry.path();
                if file_path.is_file() {
                    match file_path.metadata() {
                        Ok(metadata) => {
                            if metadata.len() > max_size_bytes as u64 {
                                continue;
                            }

                            // Check include/exclude patterns
                            let file_name = file_path.to_string_lossy();
                            let include_match = include_patterns
                                .iter()
                                .any(|pattern| glob_match(&file_name, pattern));
                            let exclude_match = exclude_patterns
                                .iter()
                                .any(|pattern| glob_match(&file_name, pattern));

                            if include_match && !exclude_match {
                                files_to_analyze.push(file_path.to_path_buf());
                            }
                        }
                        Err(e) => error!("Error reading metadata for {}: {}", file_path.display(), e),
                    }
                }
            }
        }
    }

    Ok(files_to_analyze)
}

/// Simple glob pattern matching
fn glob_match(text: &str, pattern: &str) -> bool {
    // This is a very simple implementation - in a real app, you might
    // want to use the 'glob' crate for proper glob matching
    let pattern = pattern.replace("*", ".*").replace("?", ".");
    let re = regex::Regex::new(&format!("^{}$", pattern)).unwrap_or_else(|_| {
        regex::Regex::new(".*").unwrap() // Fallback to match everything on error
    });
    re.is_match(text)
}

/// Analyze multiple files with progress tracking
fn analyze_files(
    files: &[PathBuf],
    config: &serde_json::Value,
    args: &Args,
) -> Result<Vec<(String, Vec<(String, HashSet<String>)>)>> {
    let total_files = files.len();
    let results = Arc::new(Mutex::new(Vec::new()));

    // Determine number of workers for parallel processing
    let num_workers = if args.parallel == 0 {
        // Use available parallelism (number of logical CPU cores)
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        args.parallel
    };

    if !args.quiet {
        println!(
            "\n{} {} files with {} workers...",
            "Analyzing".bold(),
            total_files,
            num_workers
        );
    }

    if total_files == 0 {
        return Ok(Vec::new());
    }

    // Load patterns (only once to avoid redundant initialization)
    let patterns = load_patterns();

    // Set up progress bar if not in quiet mode
    let progress_bar = if !args.quiet {
        let pb = ProgressBar::new(total_files as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Create a local thread pool instead of using the global one
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_workers)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build thread pool: {}", e))?;

    // Process files in parallel using the local pool
    pool.install(|| {
        files.par_iter().for_each(|file_path| {
            let file_path_string = file_path.to_string_lossy().to_string();
            
            // Create analyzer instance with shared patterns
            let mut analyzer = FileAnalyzer::new(config, &patterns, args.timeout, args.memory_limit);
            
            match analyzer.analyze_file(file_path) {
                Ok(file_results) => {
                    // Lock results and add this file's analysis
                    if let Ok(mut all_results) = results.lock() {
                        all_results.push((file_path_string, file_results));
                    }
                }
                Err(e) => {
                    error!("Error analyzing {}: {}", file_path.display(), e);
                    // Add error to results
                    if let Ok(mut all_results) = results.lock() {
                        let mut error_results = Vec::new();
                        let mut error_set = HashSet::new();
                        error_set.insert(format!("Error: {}", e));
                        error_results.push(("error".to_string(), error_set));
                        all_results.push((file_path_string, error_results));
                    }
                }
            }
            
            // Update progress bar
            if let Some(pb) = &progress_bar {
                pb.inc(1);
            }
        });
    });

    // Finish progress bar
    if let Some(pb) = progress_bar {
        pb.finish_with_message("Analysis complete");
    }

    // Retrieve results
    let all_results = Arc::try_unwrap(results)
        .expect("Failed to retrieve analysis results")
        .into_inner()
        .expect("Failed to unlock results mutex");

    Ok(all_results)
}

/// Export results for all analyzed files based on command line arguments
fn export_all_results(
    all_results: &[(String, Vec<(String, HashSet<String>)>)],
    args: &Args,
) -> Result<()> {
    // Create output directory if specified
    if let Some(output_dir) = &args.output_dir {
        std::fs::create_dir_all(output_dir)?;
    }

    // Process each file's results
    for (file_path_str, results) in all_results {
        let file_path = Path::new(file_path_str);

        // Generate output paths
        if let Some(json_path) = &args.json {
            let json_path = if all_results.len() > 1 {
                generate_output_path(args, file_path, ".json")
            } else {
                PathBuf::from(json_path)
            };
            output_formatter::export_results_json(results, &json_path)?;
        }

        if let Some(html_path) = &args.html {
            let html_path = if all_results.len() > 1 {
                generate_output_path(args, file_path, ".html")
            } else {
                PathBuf::from(html_path)
            };
            output_formatter::create_html_report(results, &html_path)?;
        }

        if let Some(csv_path) = &args.csv {
            let csv_path = if all_results.len() > 1 {
                generate_output_path(args, file_path, ".csv")
            } else {
                PathBuf::from(csv_path)
            };
            output_formatter::create_csv_report(results, &csv_path)?;
        }
    }

    Ok(())
}

/// Generate output file path based on input file and output directory
fn generate_output_path(args: &Args, file_path: &Path, extension: &str) -> PathBuf {
    if let Some(output_dir) = &args.output_dir {
        let file_stem = file_path.file_stem().unwrap_or_default();
        let output_filename = format!("{}_analysis{}", file_stem.to_string_lossy(), extension);
        PathBuf::from(output_dir).join(output_filename)
    } else {
        let file_stem = file_path.file_stem().unwrap_or_default();
        let output_filename = format!("{}_analysis{}", file_stem.to_string_lossy(), extension);
        PathBuf::from(output_filename)
    }
} 