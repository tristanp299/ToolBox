# 🔒 Secure File Encryptor/Decryptor

A high-security tool for compressing and encrypting files and directories with strong operational security (opsec) considerations specifically designed for red team operations.

## 🛡️ Security Features

- **AES-256-GCM Authenticated Encryption** - Military-grade encryption with authentication to protect against tampering
- **Argon2id Key Derivation** - Memory-hard password hashing resistant to specialized hardware attacks
- **Secure Memory Handling** - Sensitive data like encryption keys are zeroed in memory when no longer needed
- **Secure File Deletion** - Multi-pass overwriting of files before deletion to prevent recovery
- **System Security Checks** - Verification of system security features like encrypted swap and memory-backed temp directories
- **Secure Password Entry** - Passwords are entered securely and never appear in command line history or process listings
- **File Format Obfuscation** - Compressed before encryption to hide file signatures and reduce data patterns

## 🛠️ Prerequisites

- Rust toolchain (Cargo, rustc)
- Linux-based operating system (for secure file deletion)

## 📦 Installation & Building

### Independent Binaries for Red Team Operations

This project now uses completely independent binaries for encryption and decryption:

- `encryptor` - A standalone binary for encryption operations
- `decryptor` - A separate standalone binary for decryption operations

Each binary operates independently, providing several operational security advantages:
- **Smaller Footprints**: Each binary is more focused and potentially smaller
- **Reduced Detection**: Smaller, single-purpose binaries are less likely to trigger detection
- **Operational Flexibility**: You can deploy only the functionality you need
- **Compartmentalization**: If one binary is discovered, the other may remain undetected
- **Different Signatures**: Each binary has a different signature, making detection harder

Build options:

```bash
# Normal build (creates both binaries)
./build.sh

# Build minimal-sized binaries (using UPX compression if available)
./build.sh --minimal

# Clean build artifacts (keeps final binaries)
./build.sh --clean

# Full cleanup (removes all generated files including binaries)
./build.sh --full-clean
```

The build script:
1. Creates completely separate binaries with no dependencies between them
2. Applies binary hardening techniques (stripping symbols)
3. Optionally compresses binaries for minimal size with the `--minimal` flag
4. Stores build artifacts in a separate `build/` directory for a clean workspace

### Manual Build with Cargo

Alternatively, you can build directly with cargo:

```bash
cargo build --release
```

The binaries will be located in `target/release/`.

## 🚀 Usage

### Encryption

```bash
./encryptor <file_or_directory_path> [output_file]
```

Example:
```bash
./encryptor ~/Documents/loot
```

### Decryption

```bash
./decryptor <encrypted_file> [output_directory]
```

Example:
```bash
./decryptor loot.enc ~/exfil
```

## 🔒 Operational Security Recommendations

### Before Using This Tool

1. **Secure Operating Environment**
   - Use a secure operating system like Tails, Whonix, or a hardened Linux distribution
   - Consider using a live boot system for maximum security
   - Disconnect from the internet during encryption/decryption operations

2. **Memory Protection**
   - Ensure swap is either disabled or encrypted
   - Use memory-backed tmpfs for temporary files

3. **Password Security**
   - Use a strong, unique password (16+ characters with high entropy)
   - Consider using a password manager or diceware for generating passwords
   - Never reuse encryption passwords

### After Using This Tool

1. **Secure Original Data**
   - Use the secure deletion option to remove original files if no longer needed
   - Alternatively, use external secure deletion tools for extra assurance

2. **Clean Up**
   - Close all applications that might have accessed the sensitive files
   - Consider rebooting after handling particularly sensitive data

3. **Transfer Security**
   - When transferring encrypted files, use secure channels
   - Consider using a different system for encryption vs. transfer

## ⚠️ Warnings and Limitations

- **Password Recovery**: There is NO WAY to recover your data if you forget the password
- **System Security**: This tool provides warnings but cannot guarantee total system security
- **Legal Considerations**: Understand the legal implications of encryption in your jurisdiction

## 🔍 Technical Details

### File Format

Encrypted files use the following format:
```
[salt_length(4 bytes)][salt][nonce_length(4 bytes)][nonce][ciphertext]
```

### Encryption Process

1. Files/directories are compressed using tar+gzip
2. Compressed data is encrypted with AES-256-GCM
3. Encryption key is derived from password using Argon2id
4. Metadata (salt, nonce) is prepended to the encrypted data

## 🧰 Advanced Usage

### Identifiers

You can add an optional identifier/note to your archive during encryption. This can be useful for remembering the contents without decrypting.

### Secure Deletion Options

The tool offers secure deletion with multiple-pass overwriting to prevent forensic recovery.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔍 Red Team Operational Considerations

### Size Optimization

When using these tools during a red team operation, you may want to minimize file size:

```bash
# Build minimal-sized binaries
./build.sh --minimal
```

This will apply UPX compression if available, significantly reducing binary size.

### Independent Operation

Each binary can be deployed independently:

- Deploy only the encryptor to target systems for data exfiltration
- Keep the decryptor on your control system for data recovery
- Avoid unnecessary tools on target systems

### OPSEC Best Practices

- Rename the binaries to blend in with the target environment
- Consider embedding these tools in other legitimate binaries
- Use memory-only execution when possible
- Securely delete these tools after use 