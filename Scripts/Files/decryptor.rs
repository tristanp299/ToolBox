use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::exit;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use dialoguer::Password;
use flate2::read::GzDecoder;
use tar::Archive;
use tempfile::tempdir;
use zeroize::Zeroize;

/// Decrypt data using AES-256-GCM with a key derived from a password using Argon2
fn decrypt(
    ciphertext: &[u8], 
    nonce_bytes: &[u8], 
    salt: &[u8],
    password: &str
) -> io::Result<Vec<u8>> {
    // Derive key using Argon2id
    let mut derived_key = [0u8; 32]; // 256-bit key
    
    // Configure Argon2 with same parameters as encryption
    let argon2 = Argon2::default();
    
    match argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut derived_key,
    ) {
        Ok(_) => {
            // Initialize AES-GCM cipher
            let cipher = Aes256Gcm::new_from_slice(&derived_key)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            // Convert nonce bytes to Nonce type
            let nonce = Nonce::from_slice(nonce_bytes);
            
            // Decrypt the data
            let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|e| {
                    eprintln!("Decryption failed: Incorrect password or corrupted data");
                    io::Error::new(io::ErrorKind::Other, e)
                })?;
            
            // Zero out the derived key from memory
            derived_key.zeroize();
            
            Ok(plaintext)
        },
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

/// Extract a tar.gz archive to the specified directory
fn extract_archive(archive_data: &[u8], output_dir: &Path) -> io::Result<()> {
    // Create GzDecoder from archive data
    let gz = GzDecoder::new(archive_data);
    
    // Create tar Archive from GzDecoder
    let mut archive = Archive::new(gz);
    
    // Extract all files
    println!("Extracting files to: {}", output_dir.display());
    archive.unpack(output_dir)?;
    
    Ok(())
}

/// Read an encrypted file and parse its components
fn read_encrypted_file(file_path: &Path) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut file = File::open(file_path)?;
    
    // Read the salt length
    let mut salt_len_bytes = [0u8; 4];
    file.read_exact(&mut salt_len_bytes)?;
    let salt_len = u32::from_le_bytes(salt_len_bytes) as usize;
    
    // Read the salt
    let mut salt = vec![0u8; salt_len];
    file.read_exact(&mut salt)?;
    
    // Read the nonce length
    let mut nonce_len_bytes = [0u8; 4];
    file.read_exact(&mut nonce_len_bytes)?;
    let nonce_len = u32::from_le_bytes(nonce_len_bytes) as usize;
    
    // Read the nonce
    let mut nonce = vec![0u8; nonce_len];
    file.read_exact(&mut nonce)?;
    
    // Read the ciphertext (all remaining bytes)
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;
    
    Ok((ciphertext, nonce, salt))
}

/// Check if an identifier file exists for this encrypted file
fn check_for_identifier(encrypted_file_path: &Path) -> Option<String> {
    let mut id_path = encrypted_file_path.to_path_buf();
    id_path.set_extension("id");
    
    if id_path.exists() {
        match fs::read_to_string(&id_path) {
            Ok(content) => {
                println!("📝 Found identifier for this archive: {}", content);
                Some(content)
            },
            Err(_) => None,
        }
    } else {
        None
    }
}

fn main() -> io::Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <encrypted_file> [output_directory]", args[0]);
        exit(1);
    }
    
    let input_path = PathBuf::from(&args[1]);
    if !input_path.exists() {
        eprintln!("Error: File does not exist: {}", input_path.display());
        exit(1);
    }
    
    // Check if this file has an identifier note
    check_for_identifier(&input_path);
    
    // Read the encrypted file and parse its components
    println!("Reading encrypted file...");
    let (ciphertext, nonce, salt) = read_encrypted_file(&input_path)?;
    
    // Get the decryption password securely
    let password = Password::new()
        .with_prompt("Enter decryption password")
        .interact()?;
    
    // Decrypt the data
    println!("Decrypting data...");
    let decrypted_data = decrypt(&ciphertext, &nonce, &salt, &password)?;
    
    // Determine the output directory
    let output_dir = if args.len() >= 3 {
        PathBuf::from(&args[2])
    } else {
        // Create a directory based on the input filename, without the .enc extension
        let mut output_name = input_path.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        // If the output name ends with .tar.gz, remove that too
        if output_name.ends_with(".tar.gz") {
            output_name = output_name[..output_name.len() - 7].to_string();
        }
        
        let mut dir = input_path.parent().unwrap_or(Path::new("")).to_path_buf();
        dir.push(format!("{}_extracted", output_name));
        dir
    };
    
    // Create the output directory if it doesn't exist
    fs::create_dir_all(&output_dir)?;
    
    // Extract the decrypted archive
    extract_archive(&decrypted_data, &output_dir)?;
    
    println!("✅ Decryption and extraction completed successfully!");
    println!("📂 Files extracted to: {}", output_dir.display());
    Ok(())
} 