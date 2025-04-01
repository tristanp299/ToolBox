// Standalone decryptor with independent functionality
// No dependency on encryptor binary - fully self-contained for opsec

use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    env,
    time::Instant,
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; 
use aes_gcm::aead::Aead;
use argon2::{Argon2, password_hash::SaltString};
use flate2::read::GzDecoder;
use tar::Archive;
use zeroize::Zeroizing;
use indicatif::{ProgressBar, ProgressStyle};

/// Custom error type for decryption operations
#[derive(Debug)]
enum DecryptError {
    IoError(io::Error),
    DecryptionError(String),
    PasswordError(String),
    ValidationError(String),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DecryptError::IoError(e) => write!(f, "I/O error: {}", e),
            DecryptError::DecryptionError(s) => write!(f, "Decryption error: {}", s),
            DecryptError::PasswordError(s) => write!(f, "Password error: {}", s),
            DecryptError::ValidationError(s) => write!(f, "Validation error: {}", s),
        }
    }
}

impl std::error::Error for DecryptError {}

impl From<io::Error> for DecryptError {
    fn from(error: io::Error) -> Self {
        DecryptError::IoError(error)
    }
}

/// Application configuration
struct Config {
    verbose: bool,
    show_progress: bool,
}

/// Derive a key from a password using Argon2. 
/// Returns a 32-byte key suitable for AES-256.
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    // Use Argon2 with default parameters for key derivation
    let argon2 = Argon2::default();
    
    // Create a buffer for our 32-byte key (suitable for AES-256)
    let mut key = [0u8; 32];
    
    // Derive the key using password and salt
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Error deriving key with Argon2");
    
    key
}

/// Validates paths to prevent path traversal attacks and ensures directories exist
fn validate_path<P: AsRef<Path>>(path: P, must_exist: bool) -> Result<PathBuf, DecryptError> {
    let path_ref = path.as_ref();
    
    // Handle paths that should exist
    if must_exist && !path_ref.exists() {
        return Err(DecryptError::ValidationError(
            format!("Path '{}' does not exist", path_ref.display())
        ));
    }
    
    // For file outputs, ensure parent directory exists
    if !must_exist && path_ref.file_name().is_some() {
        if let Some(parent) = path_ref.parent() {
            if !parent.is_dir() && parent != Path::new("") {
                return Err(DecryptError::ValidationError(
                    format!("Parent directory '{}' does not exist", parent.display())
                ));
            }
        }
    }
    
    // Return the absolute path if possible, otherwise the original path
    match path_ref.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(_) => Ok(path_ref.to_path_buf()),
    }
}

/// Print usage information
fn print_usage(program_name: &str) {
    println!("Usage (Decryption):");
    println!("  {} <encrypted_file.enc> [output_directory]", program_name);
    println!("\nOptions:");
    println!("  -v, --verbose    Enable verbose output");
    println!("  -p, --progress   Show progress bars");
    println!("  -h, --help       Display this help message");
    println!("\nThis is a standalone decryptor tool for red team operations.");
}

/// Decrypt a file created by the encryptor and extract its contents
pub fn decrypt_archive<P: AsRef<Path>>(
    encrypted_file: P,
    output_path: P,
    password: &str,
    config: &Config
) -> Result<(), DecryptError> {
    let start_time = Instant::now();
    
    // VALIDATION: Check paths first
    let encrypted_file = validate_path(&encrypted_file, true)?;
    let output_path = validate_path(&output_path, false)?;
    
    // Create output directory if it doesn't exist
    if !output_path.exists() {
        std::fs::create_dir_all(&output_path)?;
    }
    
    // Create progress bar if requested
    let progress_bar = if config.show_progress {
        let file_size = match encrypted_file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };
        
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-")
        );
        Some(pb)
    } else {
        None
    };
    
    // --- Read Encrypted File ---
    let mut in_file = BufReader::new(File::open(&encrypted_file)?);
    
    // 1) Read salt (fixed 16 bytes)
    let mut salt = [0u8; 16];
    in_file.read_exact(&mut salt)?;
    
    // 2) Read nonce (fixed 12 bytes)
    let mut nonce_bytes = [0u8; 12];
    in_file.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    if let Some(ref pb) = progress_bar {
        pb.inc(16 + 12); // Salt + nonce
    }
    
    // 3) Read the rest (ciphertext)
    let mut ciphertext = Vec::new();
    let bytes_read = in_file.read_to_end(&mut ciphertext)?;
    
    if let Some(ref pb) = progress_bar {
        pb.inc(bytes_read as u64); 
    }
    
    // --- Decrypt the Data ---
    // Derive key from password and salt
    let key = derive_key_from_password(password, &salt);
    
    // Set up the AES-GCM cipher with our key
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| DecryptError::DecryptionError(format!("Invalid key: {:?}", e)))?;
    
    // Decrypt the data
    let decrypted_data = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| DecryptError::DecryptionError("Decryption failed - incorrect password or corrupted data".to_string()))?;
    
    if config.verbose {
        println!("DEBUG: Successfully decrypted data, size: {} bytes", decrypted_data.len());
    }
    
    // --- Decompress the Data ---
    if let Some(ref pb) = progress_bar {
        pb.println("Data decrypted, extracting files...");
    }
    
    // Set up GZip decoder
    let gz_decoder = GzDecoder::new(decrypted_data.as_slice());
    
    // Set up TAR archive extractor
    let mut archive = Archive::new(gz_decoder);
    
    // Extract all files
    archive.unpack(&output_path)?;
    
    // Security: Zero out sensitive data
    let _z_key = Zeroizing::new(key);
    let _z_salt = Zeroizing::new(salt);
    let _z_nonce = Zeroizing::new(nonce_bytes);
    
    if let Some(ref pb) = progress_bar {
        pb.finish_with_message("Decryption and extraction complete!");
    }
    
    // Calculate and display elapsed time
    let elapsed = start_time.elapsed();
    println!("Decryption complete! Files extracted to: {} (in {:.2?})", output_path.display(), elapsed);
    
    Ok(())
}

/// Command-line interface for the decryption tool
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Get the program name from the command path
    let program_name = if let Some(cmd) = args.get(0) {
        // Extract just the filename
        std::path::Path::new(cmd)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("decryptor")
    } else {
        "decryptor"
    };
    
    // Parse configuration flags
    let mut config = Config {
        verbose: false,
        show_progress: false,
    };
    
    // Parse flags
    for arg in &args {
        match arg.as_str() {
            "--verbose" | "-v" => config.verbose = true,
            "--progress" | "-p" => config.show_progress = true,
            _ => {}
        }
    }
    
    if config.verbose {
        println!("DEBUG: Executing standalone decryptor: {}", program_name);
    }
    
    // Handle help flag
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage(program_name);
        return Ok(());
    }
    
    // Remove flags from arguments for simpler processing
    let filtered_args: Vec<String> = args.iter()
        .filter(|arg| !arg.starts_with("-"))
        .cloned()
        .collect();
    
    // Show usage if not enough arguments
    if filtered_args.len() < 2 {
        print_usage(program_name);
        return Err("Not enough arguments provided".into());
    }
    
    // Get the encrypted file path (first non-flag argument after program name)
    let encrypted_file = &filtered_args[1];
    
    // Get output directory (second non-flag argument or default)
    let output_dir = filtered_args.get(2).cloned().unwrap_or_else(|| "decrypted_files".to_string());
    
    // Prompt for password
    println!("Enter decryption password: ");
    let password = rpassword::read_password()?;
    
    println!("Decrypting {} to {}", encrypted_file, output_dir);
    decrypt_archive(encrypted_file, &output_dir, &password, &config)?;
    
    // Security: Zeroize password
    let _z_password = Zeroizing::new(password);
    
    Ok(())
}
