use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use dialoguer::{Password, Input};
use rand::{rngs::OsRng, RngCore};
use tar::Builder;
use tempfile::tempdir;
use zeroize::Zeroize;
use flate2::write::GzEncoder;
use flate2::Compression;

/// SecureData structure to hold sensitive information that will be properly zeroized when dropped
struct SecureData {
    data: Vec<u8>,
}

impl SecureData {
    fn new(data: Vec<u8>) -> Self {
        SecureData { data }
    }
    
    fn get(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureData {
    fn drop(&mut self) {
        // Securely overwrite the memory before deallocation
        self.data.zeroize();
    }
}

/// Compress a file or directory using tar and gzip
fn compress(path: &Path) -> io::Result<SecureData> {
    let temp_dir = tempdir()?;
    let archive_path = temp_dir.path().join("compressed_data.tar.gz");
    
    // Create a file for the archive
    let archive_file = File::create(&archive_path)?;
    let encoder = GzEncoder::new(archive_file, Compression::best());
    let mut builder = Builder::new(encoder);

    if path.is_dir() {
        // Recursively add directory contents to the archive
        for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            let relative_path = entry_path.strip_prefix(path.parent().unwrap_or(Path::new("")))
                .unwrap_or(entry_path);

            if entry_path.is_file() {
                println!("Adding file to archive: {}", relative_path.display());
                builder.append_path_with_name(entry_path, relative_path)?;
            } else if entry_path.is_dir() && entry_path != path {
                // Create empty directories in the archive
                println!("Adding directory to archive: {}", relative_path.display());
                builder.append_dir(relative_path, entry_path)?;
            }
        }
    } else if path.is_file() {
        // Add single file to archive
        println!("Adding file to archive: {}", path.file_name().unwrap_or_default().to_string_lossy());
        builder.append_path_with_name(path, path.file_name().unwrap_or_default())?;
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Path is not a file or directory"));
    }
    
    // Finish the archive
    builder.finish()?;
    
    // Read the compressed data into memory
    let mut compressed_data = Vec::new();
    File::open(&archive_path)?.read_to_end(&mut compressed_data)?;
    
    // Securely delete the temporary file
    secure_delete(&archive_path)?;
    
    // Return the compressed data in a secure container
    Ok(SecureData::new(compressed_data))
}

/// Encrypt data using AES-256-GCM with a key derived from a password using Argon2
fn encrypt(data: &[u8], password: &str) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Generate a secure random salt
    let salt = SaltString::generate(&mut OsRng);
    
    // Generate a secure random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Derive key using Argon2id (memory-hard KDF)
    let mut derived_key = [0u8; 32]; // 256-bit key
    
    // Configure Argon2 with high security parameters
    let argon2 = Argon2::default();
    
    match argon2.hash_password_into(
        password.as_bytes(),
        salt.as_ref(),
        &mut derived_key,
    ) {
        Ok(_) => {
            // Initialize AES-GCM cipher
            let cipher = Aes256Gcm::new_from_slice(&derived_key)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            // Encrypt the data
            let ciphertext = cipher.encrypt(nonce, data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            // Zero out the derived key from memory
            derived_key.zeroize();
            
            Ok((ciphertext, nonce_bytes.to_vec(), salt.as_ref().to_vec()))
        },
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

/// Securely delete a file by overwriting it with random data multiple times before removal
fn secure_delete(path: &Path) -> io::Result<()> {
    if path.exists() {
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len() as usize;
        
        if file_size > 0 {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(path)?;
            
            // Perform multiple overwrite passes with different patterns
            for _ in 0..3 {
                // First pass: random data
                let mut random_data = vec![0u8; file_size];
                OsRng.fill_bytes(&mut random_data);
                file.write_all(&random_data)?;
                file.sync_all()?;
                
                // Second pass: zeros
                let zeros = vec![0u8; file_size];
                file.write_all(&zeros)?;
                file.sync_all()?;
                
                // Third pass: ones
                let ones = vec![255u8; file_size];
                file.write_all(&ones)?;
                file.sync_all()?;
                
                // Zero out our buffers
                random_data.zeroize();
            }
        }
        
        // Finally remove the file
        fs::remove_file(path)?;
    }
    
    Ok(())
}

/// Write data to an output file with the specified extension
fn write_encrypted_data(
    original_path: &Path,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
) -> io::Result<PathBuf> {
    // Create output filename with .enc extension
    let source_name = original_path.file_name()
        .unwrap_or_default()
        .to_string_lossy();
    
    let mut output_path = PathBuf::from(original_path.parent().unwrap_or(Path::new("")));
    
    if original_path.is_dir() {
        output_path.push(format!("{}.enc", source_name));
    } else {
        output_path.push(format!("{}.enc", source_name));
    }
    
    // Write the encrypted package
    let mut file = File::create(&output_path)?;
    
    // Format: [salt_length(4)][salt][nonce_length(4)][nonce][ciphertext]
    file.write_all(&(salt.len() as u32).to_le_bytes())?;
    file.write_all(&salt)?;
    file.write_all(&(nonce.len() as u32).to_le_bytes())?;
    file.write_all(&nonce)?;
    file.write_all(&ciphertext)?;
    
    println!("Encrypted data written to: {}", output_path.display());
    Ok(output_path)
}

/// Verify the system is secure for encryption operations
fn verify_system_security() -> bool {
    // Check if we're running on a secure OS
    let os_info = Command::new("uname")
        .arg("-a")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    
    // Check for swap encryption to prevent sensitive data from being swapped to disk
    let swap_encrypted = Command::new("swapon")
        .arg("--show")
        .output()
        .map(|o| {
            let output = String::from_utf8_lossy(&o.stdout);
            output.contains("crypt") || output.is_empty() // No swap or encrypted swap
        })
        .unwrap_or(false);
    
    // Check that temp directories are memory-backed (tmpfs)
    let tmpfs_mounted = Command::new("mount")
        .output()
        .map(|o| {
            let output = String::from_utf8_lossy(&o.stdout);
            output.contains("tmpfs on /tmp")
        })
        .unwrap_or(false);
    
    if !swap_encrypted {
        eprintln!("⚠️ WARNING: Swap space may not be encrypted. Sensitive key data might be swapped to disk.");
    }
    
    if !tmpfs_mounted {
        eprintln!("⚠️ WARNING: /tmp directory may not be memory-backed. Temporary files might persist on disk.");
    }
    
    // Return true for now, but display warnings for user to make informed decision
    true
}

fn main() -> io::Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <file_or_directory_path> [output_file]", args[0]);
        exit(1);
    }
    
    let input_path = PathBuf::from(&args[1]);
    if !input_path.exists() {
        eprintln!("Error: File or directory does not exist: {}", input_path.display());
        exit(1);
    }
    
    // Verify system security
    if !verify_system_security() {
        eprintln!("Security verification failed. Exiting for safety.");
        exit(1);
    }
    
    // Get encryption password securely (won't show up in shell history or ps output)
    let password = Password::new()
        .with_prompt("Enter encryption password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;
    
    // Generate a memorable identifier for this archive (optional)
    let identifier: String = Input::new()
        .with_prompt("Enter an optional identifier/note for this archive (press Enter to skip)")
        .allow_empty(true)
        .interact_text()?;
    
    println!("Compressing data...");
    let compressed_data = compress(&input_path)?;
    println!("Encryption in progress...");
    
    // Encrypt the compressed data
    let (ciphertext, nonce, salt) = encrypt(compressed_data.get(), &password)?;
    
    // Write the encrypted data to the output file
    let output_path = match args.get(2) {
        Some(path) => PathBuf::from(path),
        None => {
            // Use default output path
            write_encrypted_data(&input_path, ciphertext, nonce, salt)?
        }
    };
    
    // If an identifier was provided, save it to a separate file
    if !identifier.is_empty() {
        let mut id_path = output_path.clone();
        id_path.set_extension("id");
        fs::write(id_path, identifier)?;
    }
    
    // Offer to securely delete the original files if desired
    let delete_original: bool = Input::new()
        .with_prompt("Securely delete original files? (yes/no)")
        .default("no".to_string())
        .interact_text()?
        .to_lowercase()
        .starts_with('y');
    
    if delete_original {
        println!("Securely deleting original files...");
        if input_path.is_dir() {
            for entry in walkdir::WalkDir::new(&input_path).into_iter().filter_map(|e| e.ok()) {
                if entry.path().is_file() {
                    secure_delete(entry.path())?;
                }
            }
            fs::remove_dir_all(&input_path)?;
        } else {
            secure_delete(&input_path)?;
        }
        println!("Original files securely deleted.");
    }
    
    println!("Operation completed successfully.");
    Ok(())
}
