/// File handling utilities
///
/// This module provides utility functions for reading files, detecting file types,
/// calculating entropy, and handling file content.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use log::warn;
use anyhow::{Result, Context};
use std::collections::HashMap;
use base64::Engine;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Represents the type of a file based on analysis
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileType {
    /// Plain text file (e.g., source code, config files)
    Text,
    /// Binary executable file (ELF, PE, Mach-O)
    Executable,
    /// Binary data file (non-executable)
    Binary,
    /// JSON file
    Json,
    /// XML file
    Xml,
    /// HTML file
    Html,
    /// Image file
    Image,
    /// Document file (e.g., PDF, DOC)
    Document,
    /// Archive file (e.g., ZIP, TAR)
    Archive,
    /// Unknown file type
    Unknown,
}

/// Result of reading a file's content
#[derive(Debug)]
pub struct FileContent {
    /// The content of the file as a string
    pub content: String,
    /// Whether the file appears to be binary
    pub is_binary: bool,
    /// Additional metadata about the file
    pub metadata: HashMap<String, String>,
}

/// Read the content of a file with proper error handling.
///
/// # Arguments
///
/// * `file_path` - Path to the file
///
/// # Returns
///
/// A result containing the file content and metadata
pub fn read_file_content(file_path: &Path) -> Result<FileContent> {
    // Initialize empty metadata
    let mut metadata = HashMap::new();
    
    // Read file metadata
    if let Ok(meta) = fs::metadata(file_path) {
        metadata.insert("size".to_string(), meta.len().to_string());
        metadata.insert("modified".to_string(), format!("{:?}", meta.modified()?));
    }
    
    // First, try to read as text
    match fs::read_to_string(file_path) {
        Ok(content) => {
            // Check if content is valid UTF-8
            let is_binary = content.chars().any(|c| c.is_control() && !c.is_whitespace());
            
            // Special handling for JSON files
            if let Some(extension) = file_path.extension() {
                if extension.to_string_lossy().to_lowercase() == "json" {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(json_content) => {
                            let formatted_json = serde_json::to_string(&json_content)?;
                            return Ok(FileContent {
                                content: formatted_json,
                                is_binary: false,
                                metadata,
                            });
                        }
                        Err(e) => {
                            warn!("File {} has invalid JSON syntax: {}", file_path.display(), e);
                            // Continue with the content as is
                        }
                    }
                }
            }
            
            Ok(FileContent {
                content,
                is_binary,
                metadata,
            })
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::InvalidData {
                // If we hit decoding errors, it might be binary
                let mut buffer = Vec::new();
                let mut file = File::open(file_path)?;
                file.read_to_end(&mut buffer)
                    .context(format!("Failed to read binary file: {}", file_path.display()))?;
                
                metadata.insert("binary".to_string(), "true".to_string());
                let hex_content = hex::encode(&buffer);
                
                Ok(FileContent {
                    content: hex_content,
                    is_binary: true,
                    metadata,
                })
            } else {
                Err(e.into())
            }
        }
    }
}

/// Detect file type using file extensions and content analysis.
///
/// # Arguments
///
/// * `file_path` - Path to the file
///
/// # Returns
///
/// The detected file type
pub fn detect_file_type(file_path: &Path) -> FileType {
    // First, check extension
    if let Some(extension) = file_path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        
        match ext.as_str() {
            // Executables
            "exe" | "dll" | "so" | "dylib" | "bin" => return FileType::Executable,
            
            // Text-based formats
            "txt" | "md" | "log" | "cfg" | "conf" => return FileType::Text,
            "c" | "cpp" | "h" | "hpp" | "rs" | "py" | "js" | "ts" | "java" | "go" | "rb" | "php" | "sh" | "pl" | "cs" => return FileType::Text,
            
            // Web formats
            "html" | "htm" => return FileType::Html,
            "xml" | "svg" => return FileType::Xml,
            "json" => return FileType::Json,
            
            // Images
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" => return FileType::Image,
            
            // Documents
            "pdf" | "doc" | "docx" | "odt" | "rtf" => return FileType::Document,
            
            // Archives
            "zip" | "tar" | "gz" | "xz" | "bz2" | "7z" | "rar" => return FileType::Archive,
            
            _ => {} // Fall through to content-based detection
        }
    }
    
    // If extension doesn't provide a definitive answer, try to read the file
    if let Ok(file_content) = read_file_content(file_path) {
        if file_content.is_binary {
            // Try to identify binary file type by checking magic numbers
            let content = file_content.content;
            
            // This is a very basic implementation - in a real app, you would
            // use library like `content_inspector` or check file signatures (magic numbers)
            if content.starts_with("7f454c46") {  // ELF header in hex
                return FileType::Executable;
            } else if content.starts_with("4d5a") {  // MZ header for PE files
                return FileType::Executable;
            } else if content.starts_with("cafebabe") || content.starts_with("feedface") {  // Mach-O headers
                return FileType::Executable;
            } else if content.starts_with("504b0304") {  // PK header for ZIP
                return FileType::Archive;
            } else if content.starts_with("89504e47") {  // PNG signature
                return FileType::Image;
            } else if content.starts_with("25504446") {  // PDF signature
                return FileType::Document;
            }
            
            return FileType::Binary;
        } else {
            // For text content, try to determine based on content
            let content = &file_content.content;
            
            if content.trim_start().starts_with("{") && content.trim_end().ends_with("}") {
                return FileType::Json;
            } else if content.trim_start().starts_with("<") && (
                   content.contains("<!DOCTYPE html>") 
                || content.contains("<html") 
                || content.contains("<body")
            ) {
                return FileType::Html;
            } else if content.trim_start().starts_with("<") && (
                   content.contains("<?xml") 
                || content.contains("<root>")
                || content.contains("xmlns")
            ) {
                return FileType::Xml;
            }
            
            return FileType::Text;
        }
    }
    
    // Default to Unknown if we couldn't determine
    FileType::Unknown
}

/// Calculate Shannon entropy of a string to help identify randomness.
/// Higher entropy suggests more randomness, which is typical of hashes.
///
/// # Arguments
///
/// * `string` - The string to analyze
///
/// # Returns
///
/// The calculated entropy value
pub fn calculate_entropy(string: &str) -> f64 {
    if string.is_empty() {
        return 0.0;
    }
    
    let mut freq_map = HashMap::new();
    let length = string.len() as f64;
    
    for c in string.chars() {
        *freq_map.entry(c).or_insert(0) += 1;
    }
    
    let mut entropy = 0.0;
    for count in freq_map.values() {
        let probability = *count as f64 / length;
        entropy -= probability * probability.log2();
    }
    
    entropy
}

/// Check if a string is valid base64 encoded.
///
/// # Arguments
///
/// * `string` - String to check
///
/// # Returns
///
/// True if valid base64, False otherwise
pub fn is_valid_base64(string: &str) -> bool {
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    
    // Base64 strings should have a length that is a multiple of 4
    if string.len() % 4 != 0 {
        return false;
    }
    
    // Check if all characters are valid base64 characters
    if !string.chars().all(|c| charset.contains(c)) {
        return false;
    }
    
    // Try to decode
    match base64::engine::general_purpose::STANDARD.decode(string) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Get file metadata for a given path.
///
/// # Arguments
///
/// * `file_path` - Path to the file
///
/// # Returns
///
/// A hashmap containing file metadata
pub fn get_file_metadata(file_path: &Path) -> Result<HashMap<String, String>> {
    let mut metadata_map = HashMap::new();
    
    // Basic file info
    metadata_map.insert("file_name".to_string(), file_path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string()));
    
    if let Ok(metadata) = fs::metadata(file_path) {
        metadata_map.insert("file_size".to_string(), metadata.len().to_string());
        
        // Add timestamps
        if let Ok(created) = metadata.created() {
            metadata_map.insert("created".to_string(), 
                                format!("{:?}", created));
        }
        
        if let Ok(modified) = metadata.modified() {
            metadata_map.insert("modified".to_string(), 
                               format!("{:?}", modified));
        }
        
        if let Ok(accessed) = metadata.accessed() {
            metadata_map.insert("accessed".to_string(), 
                               format!("{:?}", accessed));
        }
        
        // File mode/permissions
        #[cfg(unix)]
        metadata_map.insert("permissions".to_string(), 
                          format!("{:o}", metadata.permissions().mode()));
        #[cfg(not(unix))]
        metadata_map.insert("permissions".to_string(), 
                          "unknown".to_string());
        
        // Add file type
        if metadata.is_file() {
            metadata_map.insert("type".to_string(), "file".to_string());
        } else if metadata.is_dir() {
            metadata_map.insert("type".to_string(), "directory".to_string());
        } else if metadata.is_symlink() {
            metadata_map.insert("type".to_string(), "symlink".to_string());
        }
    }
    
    Ok(metadata_map)
} 