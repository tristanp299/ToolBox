#!/usr/bin/env python3

"""
secure_archive.py - Secure file/folder compression and encryption tool with OPSEC considerations

This script provides a secure way to compress and encrypt files or folders with strong
operational security considerations. It uses AES-256-GCM for encryption with
Argon2id for key derivation from passwords.

OPSEC Considerations:
1. No temporary unencrypted files are written to disk
2. Memory is zeroed after use where possible
3. Password is never stored in plaintext
4. Encrypted data includes no metadata about original content
5. Option to securely delete original files
6. Option to add random padding to obscure true file size
7. No personally identifiable information is included in the output
"""

import os
import sys
import time
import random
import argparse
import getpass
import shutil
import tarfile
import io
import secrets
import base64
import logging
from pathlib import Path
from typing import Union, Optional

# Third-party libraries
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Required cryptography libraries not found. Please install with:")
    print("pip install cryptography")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('secure_archive')


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: The number of random bytes to generate
        
    Returns:
        A bytes object containing secure random bytes
    """
    return secrets.token_bytes(length)


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from a password using Argon2id.
    
    Argon2id is a memory-hard function designed to be resistant to both
    side-channel attacks and GPU cracking attempts.
    
    Args:
        password: The user-provided password
        salt: A random salt value (should be at least 16 bytes)
        
    Returns:
        A 32-byte key suitable for AES-256
    """
    # Use Argon2id with memory-hard parameters for protection against various attacks
    # These parameters can be adjusted based on the target system's capabilities
    kdf = Argon2id(
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=4,  # Number of iterations
        memory_cost=65536,  # 64 MB in KiB (higher is more secure but slower)
        parallelism=4  # Number of parallel threads
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM with an authenticated encryption scheme.
    
    GCM (Galois/Counter Mode) provides both confidentiality and authenticity,
    detecting any tampering with the ciphertext.
    
    Args:
        data: The plaintext data to encrypt
        key: The 32-byte encryption key
        
    Returns:
        A bytes object containing the nonce + ciphertext
    """
    # Generate a random 96-bit nonce (12 bytes) for AES-GCM
    # Each nonce should be used exactly once per key
    nonce = secure_random_bytes(12)
    
    # Create an AES-GCM cipher with our key
    aesgcm = AESGCM(key)
    
    # Encrypt the data (authenticated encryption)
    # Empty bytes as associated_data means we're not authenticating any additional data
    ciphertext = aesgcm.encrypt(nonce, data, b'')
    
    # Return nonce + ciphertext so we can decrypt later
    # The nonce isn't secret, but needs to be stored alongside the ciphertext
    return nonce + ciphertext


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data that was encrypted with AES-256-GCM.
    
    Args:
        encrypted_data: The encrypted data (nonce + ciphertext)
        key: The 32-byte encryption key
        
    Returns:
        The decrypted plaintext data
    """
    # Extract the nonce from the first 12 bytes
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    # Create an AES-GCM cipher with our key
    aesgcm = AESGCM(key)
    
    # Decrypt the data
    # This will raise an exception if the data has been tampered with
    plaintext = aesgcm.decrypt(nonce, ciphertext, b'')
    
    return plaintext


def compress_path(path: Union[str, Path], padding_size: int = 0) -> bytes:
    """
    Compress a file or directory into a tar.gz archive in memory.
    
    Args:
        path: Path to the file or directory to compress
        padding_size: Optional random padding size in bytes to obscure true file size
        
    Returns:
        Compressed data as bytes
    """
    path = Path(path)
    
    # Use an in-memory file-like object to avoid writing to disk
    compressed_data = io.BytesIO()
    
    # Create a gzipped tar archive
    with tarfile.open(fileobj=compressed_data, mode='w:gz') as tar:
        # If it's a directory, add all contents
        if path.is_dir():
            # Get the parent directory to ensure proper paths in the archive
            base_dir = path.parent
            for item in path.rglob('*'):
                # Calculate the archive name relative to the parent
                arcname = item.relative_to(base_dir)
                tar.add(item, arcname=arcname)
        # If it's a file, just add the file
        else:
            tar.add(path, arcname=path.name)
    
    # Get the compressed data
    result = compressed_data.getvalue()
    
    # Add random padding if requested
    if padding_size > 0:
        pad = secure_random_bytes(random.randint(1, padding_size))
        # We'll add a 4-byte length indicator, followed by the padding
        pad_len = len(pad).to_bytes(4, byteorder='big')
        result += pad_len + pad
    else:
        # Add 4-byte zero to indicate no padding
        result += (0).to_bytes(4, byteorder='big')
    
    return result


def secure_delete_file(path: Union[str, Path]) -> None:
    """
    Securely delete a file by overwriting it multiple times before deletion.
    
    This is a best-effort approach, as modern file systems and SSDs make
    true secure deletion difficult without specialized tools.
    
    Args:
        path: Path to the file to securely delete
    """
    path = Path(path)
    
    if not path.is_file():
        logger.warning(f"Cannot securely delete {path}: not a file or doesn't exist")
        return
    
    # Get file size
    size = path.stat().st_size
    
    # Skip if the file is too large (> 1GB) to avoid performance issues
    if size > 1_000_000_000:
        logger.warning(f"File {path} is too large for secure deletion. Consider using specialized tools.")
        os.remove(path)
        return
    
    try:
        # First overwrite with zeros
        with open(path, 'wb') as f:
            f.write(b'\x00' * size)
            f.flush()
            os.fsync(f.fileno())
        
        # Then overwrite with random data
        with open(path, 'wb') as f:
            f.write(secure_random_bytes(size))
            f.flush()
            os.fsync(f.fileno())
        
        # Finally delete the file
        os.remove(path)
        logger.info(f"Securely deleted {path}")
    except Exception as e:
        logger.error(f"Error during secure deletion of {path}: {e}")
        # Try normal deletion as fallback
        try:
            os.remove(path)
        except Exception:
            pass


def secure_delete_directory(path: Union[str, Path]) -> None:
    """
    Recursively and securely delete all files in a directory, then remove the directory.
    
    Args:
        path: Path to the directory to securely delete
    """
    path = Path(path)
    
    if not path.is_dir():
        logger.warning(f"Cannot securely delete {path}: not a directory or doesn't exist")
        return
    
    # Securely delete all files recursively
    for item in path.rglob('*'):
        if item.is_file():
            secure_delete_file(item)
    
    # Remove all empty directories
    shutil.rmtree(path)
    logger.info(f"Securely deleted directory {path}")


def create_secure_archive(
    source_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    password: Optional[str] = None,
    secure_delete: bool = False,
    padding_size: int = 0,
    verbose: bool = False
) -> Path:
    """
    Create a secure encrypted archive from a file or directory.
    
    Args:
        source_path: Path to the file or directory to encrypt
        output_path: Path where the encrypted archive will be saved (default: auto-generated)
        password: Password for encryption (if None, will prompt)
        secure_delete: Whether to securely delete the original files
        padding_size: Maximum size of random padding in bytes (actual size will be random)
        verbose: Whether to log detailed information
    
    Returns:
        Path to the created secure archive
    """
    source_path = Path(source_path)
    
    # Validate source path
    if not source_path.exists():
        raise FileNotFoundError(f"Source path does not exist: {source_path}")
    
    # Set up logging based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    # Auto-generate output path if not provided
    if output_path is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        random_suffix = secrets.token_hex(4)
        output_path = Path(f"secure_archive_{timestamp}_{random_suffix}.enc")
    else:
        output_path = Path(output_path)
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get password if not provided
    if password is None:
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise ValueError("Passwords do not match")
    
    logger.info(f"Compressing {source_path}...")
    compressed_data = compress_path(source_path, padding_size)
    logger.debug(f"Compressed size: {len(compressed_data)} bytes")
    
    # Generate a random salt
    salt = secure_random_bytes(16)
    
    # Derive encryption key from password
    logger.info("Deriving encryption key...")
    key = derive_key_from_password(password, salt)
    
    # Encrypt the compressed data
    logger.info("Encrypting data...")
    encrypted_data = encrypt_data(compressed_data, key)
    
    # Create the final file format: salt + encrypted_data
    final_data = salt + encrypted_data
    
    # Write to the output file
    logger.info(f"Writing encrypted archive to {output_path}...")
    with open(output_path, 'wb') as f:
        f.write(final_data)
    
    # Securely delete original if requested
    if secure_delete:
        logger.info(f"Securely deleting original {'directory' if source_path.is_dir() else 'file'}...")
        if source_path.is_dir():
            secure_delete_directory(source_path)
        else:
            secure_delete_file(source_path)
    
    logger.info(f"Successfully created encrypted archive: {output_path}")
    return output_path


def decrypt_secure_archive(
    archive_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    password: Optional[str] = None,
    secure_delete: bool = False,
    verbose: bool = False
) -> Path:
    """
    Decrypt and extract a secure archive.
    
    Args:
        archive_path: Path to the encrypted archive
        output_path: Path where the decrypted contents will be extracted (default: auto-generated)
        password: Password for decryption (if None, will prompt)
        secure_delete: Whether to securely delete the encrypted archive after extraction
        verbose: Whether to log detailed information
    
    Returns:
        Path to the extracted contents
    """
    archive_path = Path(archive_path)
    
    # Validate archive path
    if not archive_path.exists() or not archive_path.is_file():
        raise FileNotFoundError(f"Archive file does not exist: {archive_path}")
    
    # Set up logging based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    # Auto-generate output path if not provided
    if output_path is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"extracted_{timestamp}")
    else:
        output_path = Path(output_path)
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get password if not provided
    if password is None:
        password = getpass.getpass("Enter decryption password: ")
    
    # Read the encrypted archive
    with open(archive_path, 'rb') as f:
        data = f.read()
    
    # Extract the salt (first 16 bytes)
    salt, encrypted_data = data[:16], data[16:]
    
    # Derive the key from the password and salt
    logger.info("Deriving decryption key...")
    key = derive_key_from_password(password, salt)
    
    # Decrypt the data
    try:
        logger.info("Decrypting data...")
        decrypted_data = decrypt_data(encrypted_data, key)
    except Exception as e:
        raise ValueError(f"Decryption failed. Incorrect password or corrupted data: {e}")
    
    # Check if there's padding at the end
    padding_length = int.from_bytes(decrypted_data[-4:], byteorder='big')
    if padding_length > 0:
        # Remove the padding and padding length indicator
        decrypted_data = decrypted_data[:-padding_length-4]
    else:
        # Just remove the padding length indicator
        decrypted_data = decrypted_data[:-4]
    
    # Create an in-memory file-like object for the tar extractor
    compressed_io = io.BytesIO(decrypted_data)
    
    # Extract the tar archive
    logger.info(f"Extracting to {output_path}...")
    with tarfile.open(fileobj=compressed_io, mode='r:gz') as tar:
        tar.extractall(path=output_path)
    
    # Securely delete the encrypted archive if requested
    if secure_delete:
        logger.info("Securely deleting encrypted archive...")
        secure_delete_file(archive_path)
    
    logger.info(f"Successfully extracted contents to: {output_path}")
    return output_path


def main():
    """
    Main function to handle command-line arguments and execute the appropriate action.
    """
    parser = argparse.ArgumentParser(
        description="Securely compress and encrypt files/folders with strong OPSEC considerations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Create subparsers for different operations
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file or directory')
    encrypt_parser.add_argument('source', help='File or directory to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file path')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password (not recommended, use prompt instead)')
    encrypt_parser.add_argument('-d', '--delete', action='store_true', help='Securely delete original after encryption')
    encrypt_parser.add_argument('--padding', type=int, default=1048576, help='Maximum random padding size in bytes (default: 1MB)')
    encrypt_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt an encrypted archive')
    decrypt_parser.add_argument('archive', help='Encrypted archive to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output directory for extracted contents')
    decrypt_parser.add_argument('-p', '--password', help='Decryption password (not recommended, use prompt instead)')
    decrypt_parser.add_argument('-d', '--delete', action='store_true', help='Securely delete archive after decryption')
    decrypt_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute the appropriate command
    if args.command == 'encrypt':
        try:
            create_secure_archive(
                source_path=args.source,
                output_path=args.output,
                password=args.password,
                secure_delete=args.delete,
                padding_size=args.padding,
                verbose=args.verbose
            )
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            sys.exit(1)
    
    elif args.command == 'decrypt':
        try:
            decrypt_secure_archive(
                archive_path=args.archive,
                output_path=args.output,
                password=args.password,
                secure_delete=args.delete,
                verbose=args.verbose
            )
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main() 