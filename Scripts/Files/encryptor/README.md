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

This project uses completely independent binaries for encryption and decryption:

- `encryptor` - A standalone binary for encryption operations
- `decryptor` - A separate standalone binary for decryption operations

Each binary operates independently, providing several operational security advantages:
- **Smaller Footprints**: Each binary is more focused and potentially smaller
- **Reduced Detection**: Smaller, single-purpose binaries are less likely to trigger detection
- **Operational Flexibility**: You can deploy only the functionality you need
- **Compartmentalization**: If one binary is discovered, the other may remain undetected
- **Different Signatures**: Each binary has a different signature, making detection harder

### Advanced Build Options

The build script offers several options optimized for red team operations:

```bash
# Standard build
./build.sh

# Build minimal-sized binaries with UPX compression
./build.sh --minimal

# Build extremely small binaries (extreme compression)
./build.sh --ultra-minimal

# Build fully static binaries (no external dependencies)
./build.sh --static

# Combine options for maximum portability and minimal size
./build.sh --static --ultra-minimal

# Clean build artifacts (keeps final binaries)
./build.sh --clean

# Full cleanup (removes all generated files including binaries)
./build.sh --full-clean
```

#### Size Optimization Comparison

| Build Option | Encryptor Size | Decryptor Size | Notes |
|--------------|----------------|----------------|-------|
| Standard     | ~800KB         | ~700KB         | Default build |
| --minimal    | ~300KB         | ~250KB         | UPX compression |
| --ultra-minimal | ~200KB      | ~150KB         | Extreme compression, slower startup |
| --static     | ~900KB         | ~800KB         | No external dependencies |
| --static --minimal | ~350KB   | ~300KB         | Portable & compressed |

The build script:
1. Creates completely separate binaries with no dependencies between them
2. Applies binary hardening techniques (stripping symbols)
3. Optionally creates fully static binaries that will work on any compatible Linux system
4. Optionally compresses binaries for minimal size with the `--minimal` or `--ultra-minimal` flags
5. Stores build artifacts in a separate `build/` directory for a clean workspace

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

## 🔒 Advantages Over Standard Encryption Tools

This tool provides several critical advantages over standard encryption tools like zip, 7-zip, or gpg for red team operations:

### Security Advantages

- **Military-Grade Encryption**: Uses AES-256-GCM authenticated encryption, which provides both confidentiality and integrity verification, unlike zip's standard encryption
- **Advanced Key Derivation**: Implements Argon2id (winner of the Password Hashing Competition), which is memory-hard and resistant to specialized hardware attacks, unlike zip's simpler PBKDF2 approach
- **Secure Memory Handling**: Actively zeroes sensitive data (passwords, keys) in memory when no longer needed, a feature missing from most standard tools
- **Custom Format**: Custom encrypted format is less recognizable than common formats that might be flagged by security tools

### Operational Security for Red Teams

- **Zero Dependencies**: Fully self-contained, static binaries with no external dependencies, eliminating the need for standard tools to be installed on target systems
- **Low Visibility**: Much smaller signatures and resource usage compared to deploying full encryption suites
- **Countermeasure Resistance**: Does not create standard file signatures or formats that might trigger Data Loss Prevention (DLP) or endpoint security tools
- **Secure Deletion**: Includes secure file deletion capabilities to remove originals without leaving forensic traces
- **Custom Control**: Full control over the encryption process, file format, and operational characteristics

### Deployment Advantages

- **Minimal Footprint**: UPX compression reduces binary size dramatically compared to standard tools (often 10x smaller)
- **Separate Tools**: Independent encryption and decryption tools allow deploying only what's needed for each phase of operation
- **Built for Automation**: Designed to be easily scriptable and integrated into broader red team toolkits
- **Cross-Platform**: Works on various Linux systems without requiring additional libraries

### Practical Superiority

- **Designed for Speed**: Optimized for encrypting data quickly during time-sensitive operations
- **Better Password Security**: Takes extra measures to protect password entry and handling
- **Harder Attribution**: Custom tools are more difficult to attribute than using standard tools with known signatures
- **Feature Selection**: Includes only needed features, avoiding the bloat of multi-purpose tools

While tools like zip, gpg, or 7-zip offer convenience for everyday use, this purpose-built encryption tool provides superior security and operational advantages for sensitive red team operations where stealth, control, and security are paramount.

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

When using these tools during a red team operation, you can optimize for your specific scenario:

- **Minimal size**: Use `./build.sh --ultra-minimal` for the smallest possible binaries
- **Maximum portability**: Use `./build.sh --static` for binaries that work on any compatible Linux system
- **Balanced approach**: Use `./build.sh --static --minimal` for a good balance of size and portability

### Extreme Portability

The `--static` build option creates fully self-contained binaries with no external dependencies. This means:

- Will work on virtually any Linux system without installing additional libraries
- Can be deployed to air-gapped or restricted environments
- No risk of dependency issues or version conflicts
- More reliable execution in unpredictable environments

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