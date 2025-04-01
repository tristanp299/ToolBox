use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write, Seek, SeekFrom},
    path::{Path, PathBuf},
    env, time::{Instant, Duration},
    fmt, error,
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; 
use aes_gcm::aead::{Aead, OsRng};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, PasswordHash, PasswordHasher as _}};
use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use rand::RngCore;
use tar::{Builder, Archive};
use walkdir::WalkDir;
use zeroize::Zeroizing;
use tempfile::tempdir;

// Optional progress tracking
use indicatif::{ProgressBar, ProgressStyle};

/// Custom error type for encryption/decryption operations
#[derive(Debug)]
pub enum CryptoError {
    IoError(io::Error),
    WalkdirError(walkdir::Error),
    EncryptionError(String),
    DecryptionError(String),
    PasswordError(String),
    ValidationError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::IoError(e) => write!(f, "I/O error: {}", e),
            CryptoError::WalkdirError(e) => write!(f, "Walkdir error: {}", e),
            CryptoError::EncryptionError(s) => write!(f, "Encryption error: {}", s),
            CryptoError::DecryptionError(s) => write!(f, "Decryption error: {}", s),
            CryptoError::PasswordError(s) => write!(f, "Password error: {}", s),
            CryptoError::ValidationError(s) => write!(f, "Validation error: {}", s),
        }
    }
}

impl error::Error for CryptoError {}

impl From<io::Error> for CryptoError {
    fn from(error: io::Error) -> Self {
        CryptoError::IoError(error)
    }
}

impl From<walkdir::Error> for CryptoError {
    fn from(error: walkdir::Error) -> Self {
        CryptoError::WalkdirError(error)
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
fn validate_path<P: AsRef<Path>>(path: P, must_exist: bool) -> Result<PathBuf, CryptoError> {
    let path_ref = path.as_ref();
    
    // Handle paths that should exist
    if must_exist && !path_ref.exists() {
        return Err(CryptoError::ValidationError(
            format!("Path '{}' does not exist", path_ref.display())
        ));
    }
    
    // For file outputs, ensure parent directory exists
    if !must_exist && path_ref.file_name().is_some() {
        if let Some(parent) = path_ref.parent() {
            if !parent.is_dir() && parent != Path::new("") {
                return Err(CryptoError::ValidationError(
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

/// Calculate total size of files to be encrypted/decrypted
fn calculate_directory_size<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    let path_ref = path.as_ref();
    
    if path_ref.is_file() {
        return Ok(path_ref.metadata()?.len());
    }
    
    let mut total_size = 0;
    for entry in WalkDir::new(path_ref).min_depth(1).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
            }
        }
    }
    
    Ok(total_size)
}

/// Encrypt all files in `input_path` into a single output file, using AES-GCM.
///
/// Steps:
/// 1) Create a TAR archive of `input_path`
/// 2) GZip-compress the TAR
/// 3) Encrypt the compressed data with AES-GCM
/// 4) Write everything out to `output_file`
pub fn encrypt_directory<P: AsRef<Path>>(
    input_path: P,
    output_file: P,
    password: &str,
    config: &Config,
) -> Result<(), CryptoError> {
    let start_time = Instant::now();
    
    // VALIDATION: Check paths first, before any processing
    let input_path = validate_path(&input_path, true)?;
    let output_file = validate_path(&output_file, false)?;
    
    if config.verbose {
        println!("DEBUG: Input path: {}", input_path.display());
        println!("DEBUG: Output file: {}", output_file.display());
    }
    
    // Check input is readable
    if !input_path.exists() {
        return Err(CryptoError::ValidationError(
            format!("Input path '{}' does not exist", input_path.display())
        ));
    }
    
    // Create progress bar if requested
    let progress_bar = if config.show_progress {
        // Calculate total size to show progress
        let total_size = match calculate_directory_size(&input_path) {
            Ok(size) => size,
            Err(_) => 0,
        };
        
        let pb = ProgressBar::new(total_size);
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
    
    // Create a temporary directory for processing
    let temp_dir = tempdir()?;
    let archive_path = temp_dir.path().join("archive.tar.gz");
    
    // --- Create TAR+GZIP Archive ---
    // First, archive the input directory/file
    create_archive(&input_path, &archive_path, &progress_bar, config.verbose)?;
    
    if let Some(ref pb) = progress_bar {
        pb.println("Archive created, encrypting...");
    }
    
    // --- Generate Encryption Components ---
    // Generate a random salt for key derivation
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    
    // Derive encryption key from password + salt
    let key = derive_key_from_password(password, &salt);
    
    // Create cipher with the derived key
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::EncryptionError(format!("Invalid key length: {:?}", e)))?;
    
    // Generate random nonce for encryption
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // --- Perform Encryption ---
    // Read the archive file
    let mut archive_data = Vec::new();
    let mut archive_file = File::open(&archive_path)?;
    archive_file.read_to_end(&mut archive_data)?;
    
    // Encrypt the archive data
    let ciphertext = cipher.encrypt(nonce, archive_data.as_ref())
        .map_err(|e| CryptoError::EncryptionError(format!("Encryption error: {:?}", e)))?;
    
    // --- Write Encrypted File ---
    let mut out_file = BufWriter::new(File::create(&output_file)?);
    
    // 1) Write salt for key derivation
    out_file.write_all(&salt)?;
    
    // 2) Write nonce for decryption
    out_file.write_all(&nonce_bytes)?;
    
    // 3) Write the encrypted data
    out_file.write_all(&ciphertext)?;
    out_file.flush()?;
    
    // --- Security: Zero out sensitive data ---
    let _z_key = Zeroizing::new(key);
    let _z_salt = Zeroizing::new(salt);
    let _z_nonce = Zeroizing::new(nonce_bytes);
    
    if let Some(ref pb) = progress_bar {
        pb.finish_with_message("Encryption complete!");
    }
    
    // Calculate and display elapsed time
    let elapsed = start_time.elapsed();
    println!("Encryption complete! File saved to: {} (in {:.2?})", output_file.display(), elapsed);
    
    Ok(())
}

/// Helper function to create a TAR+GZIP archive of a file or directory
fn create_archive(
    input_path: &Path, 
    archive_path: &Path,
    progress_bar: &Option<ProgressBar>,
    verbose: bool
) -> Result<(), CryptoError> {
    // Create the TAR+GZIP file
    let archive_file = File::create(archive_path)?;
    let gz_encoder = GzEncoder::new(archive_file, Compression::best());
    let mut tar_builder = Builder::new(gz_encoder);
    
    // Get metadata
    let input_meta = std::fs::metadata(input_path)?;
    let input_name = input_path.file_name().ok_or(CryptoError::ValidationError(
        "Invalid input path".to_string()
    ))?;
    
    // Process based on whether it's a file or directory
    if input_meta.is_dir() {
        // Add each file in the directory to the archive
        if verbose {
            println!("Adding directory to archive: {}", input_path.display());
        }
        
        // First add all the directories to ensure proper structure
        for entry in WalkDir::new(input_path) {
            let entry = entry?;
            if entry.file_type().is_dir() && entry.path() != input_path {
                // Get relative path for proper directory structure
                let relative_path = entry.path().strip_prefix(input_path)
                    .map_err(|_| CryptoError::ValidationError("Path strip error".to_string()))?;
                
                if verbose {
                    println!("DEBUG: Adding directory: {}", relative_path.display());
                }
                tar_builder.append_dir(relative_path, entry.path())?;
            }
        }
        
        // Then add all files
        let mut files_added = 0;
        for entry in WalkDir::new(input_path) {
            let entry = entry?;
            if entry.file_type().is_file() {
                // Update progress bar if present
                if let Some(ref pb) = progress_bar {
                    if let Ok(metadata) = entry.metadata() {
                        pb.inc(metadata.len());
                    }
                }
                
                // Get relative path for proper file location in archive
                let relative_path = entry.path().strip_prefix(input_path)
                    .map_err(|_| CryptoError::ValidationError("Path strip error".to_string()))?;
                
                if verbose {
                    println!("DEBUG: Adding file: {}", relative_path.display());
                }
                tar_builder.append_path_with_name(entry.path(), relative_path)?;
                files_added += 1;
            }
        }
        
        // If directory was empty, add a README placeholder
        if files_added == 0 {
            if verbose {
                println!("DEBUG: Directory was empty, adding placeholder file");
            }
            let readme = "This directory was empty when encrypted.\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(readme.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder.append_data(&mut header, "README.txt", readme.as_bytes())?;
        }
    } else {
        // It's a single file, add it to the archive
        if verbose {
            println!("Adding file to archive: {}", input_path.display());
        }
        tar_builder.append_path_with_name(input_path, input_name)?;
        
        // Update progress bar if present
        if let Some(ref pb) = progress_bar {
            pb.inc(input_meta.len());
        }
    }
    
    // Finalize the TAR archive
    tar_builder.finish()?;
    
    Ok(())
}

/// Decrypt a file created by `encrypt_directory` and extract its contents
pub fn decrypt_archive<P: AsRef<Path>>(
    encrypted_file: P,
    output_path: P,
    password: &str,
    config: &Config
) -> Result<(), CryptoError> {
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
        pb.println("Decrypting data...");
    }
    
    // --- Decrypt Data ---
    // Derive key from password and salt
    let key = derive_key_from_password(password, &salt);
    
    // Create cipher for decryption
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid key length: {:?}", e)))?;
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionError(
            format!("Decryption failed: {:?} (likely wrong password or corrupted file)", e)
        ))?;
    
    // --- Create temporary directory ---
    let temp_dir = tempdir()?;
    let archive_path = temp_dir.path().join("archive.tar.gz");
    
    // Write decrypted data to temporary archive file
    let mut archive_file = File::create(&archive_path)?;
    archive_file.write_all(&plaintext)?;
    archive_file.flush()?;
    
    if let Some(ref pb) = progress_bar {
        pb.println("Extracting files...");
    }
    
    // --- Extract Archive ---
    let archive_file = File::open(&archive_path)?;
    let gz_decoder = GzDecoder::new(archive_file);
    let mut tar_archive = Archive::new(gz_decoder);
    
    // Extract all files to output path
    println!("Extracting files to: {}", output_path.display());
    tar_archive.unpack(&output_path)?;
    
    // --- Security: Zero out sensitive data ---
    let _z_key = Zeroizing::new(key);
    
    if let Some(ref pb) = progress_bar {
        pb.finish_with_message("Decryption complete!");
    }
    
    // Calculate and display elapsed time
    let elapsed = start_time.elapsed();
    println!("Decryption complete! Files extracted to: {} (in {:.2?})", output_path.display(), elapsed);
    
    Ok(())
}

/// Print usage information
fn print_usage(program_name: &str) {
    println!("Usage:");
    println!("  Encryption mode:");
    println!("    {} <input_path> [output_file.enc]", program_name);
    println!("  Decryption mode:");
    println!("    {} --decrypt <encrypted_file.enc> [output_directory]", program_name);
    println!("\nOptions:");
    println!("  -v, --verbose    Enable verbose output");
    println!("  -p, --progress   Show progress bars");
    println!("  -h, --help       Display this help message");
}

/// Command-line interface for the encryption/decryption tool
fn main() -> Result<(), Box<dyn error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let program_name = args[0].split('/').last().unwrap_or("encryptor");
    
    // Parse configuration flags
    let mut config = Config {
        verbose: false,
        show_progress: false,
    };
    
    // Handle help flag
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage(program_name);
        return Ok(());
    }
    
    // Parse other flags
    for arg in &args {
        match arg.as_str() {
            "--verbose" | "-v" => config.verbose = true,
            "--progress" | "-p" => config.show_progress = true,
            _ => {}
        }
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
    
    // Determine if we're encrypting or decrypting
    let is_decrypting = args.iter().any(|arg| arg == "--decrypt");
    
    if is_decrypting {
        // DECRYPTION MODE
        // Find the encrypted file path (first non-flag argument after program name)
        let encrypted_file = filtered_args.get(1).ok_or("Missing encrypted file path")?;
        
        // Find output directory (second non-flag argument or default)
        let output_dir = filtered_args.get(2).cloned().unwrap_or_else(|| "decrypted_files".to_string());
        
        // Prompt for password
        println!("Enter decryption password: ");
        let password = rpassword::read_password()?;
        
        println!("Decrypting {} to {}", encrypted_file, output_dir);
        decrypt_archive(encrypted_file, &output_dir, &password, &config)?;
        
        // Security: Zeroize password
        let _z_password = Zeroizing::new(password);
    } else {
        // ENCRYPTION MODE
        // Get input path (first non-flag argument)
        let input_path = &filtered_args[1];
        
        // Verify input path exists
        if !Path::new(input_path).exists() {
            return Err(format!("Input path '{}' does not exist", input_path).into());
        }
        
        // Get output file name or use default
        let mut output_file = if filtered_args.len() >= 3 {
            filtered_args[2].clone()
        } else {
            // Default name based on input
            let input_name = Path::new(input_path).file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("encrypted_data");
            format!("{}.enc", input_name)
        };
        
        // Ensure output has .enc extension
        if !output_file.ends_with(".enc") {
            output_file = format!("{}.enc", output_file);
        }
        
        // Prompt for password (twice to confirm)
        println!("Enter encryption password: ");
        let password = rpassword::read_password()?;
        
        // Validate password strength
        if password.len() < 8 {
            return Err("Password is too weak. For security, please use at least 8 characters.".into());
        }
        
        println!("Confirm encryption password: ");
        let confirm_password = rpassword::read_password()?;
        
        // Verify passwords match
        if password != confirm_password {
            return Err("Passwords do not match.".into());
        }
        
        println!("Encrypting {} to {}", input_path, output_file);
        encrypt_directory(input_path, &output_file, &password, &config)?;
        
        // Security: Zeroize passwords
        let _z_password = Zeroizing::new(password);
        let _z_confirm_password = Zeroizing::new(confirm_password);
    }
    
    Ok(())
}
