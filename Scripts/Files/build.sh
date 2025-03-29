#!/bin/bash

# Build script for secure_encryptor tools
# This script builds the encryption and decryption tools with maximum security settings

# Color formatting for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting secure encryptor build process...${NC}"

# Check if Rust and Cargo are installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust and Cargo are required but not installed.${NC}"
    echo -e "Please install Rust from https://rustup.rs/ and try again."
    exit 1
fi

# Create directory structure if it doesn't exist
mkdir -p src
mkdir -p target/release

# Copy source files to src directory
echo -e "Preparing source files..."
cp encryptor.rs src/main.rs
cp Cargo.toml ./

# Check if we're in a secure environment
echo -e "Checking system security..."
if cat /proc/swaps | grep -q "partition"; then
    echo -e "${YELLOW}⚠️  WARNING: Swap space detected. Consider disabling swap or enabling encrypted swap.${NC}"
fi

if ! mount | grep -q "tmpfs on /tmp"; then
    echo -e "${YELLOW}⚠️  WARNING: /tmp directory may not be memory-backed. Temporary files might persist on disk.${NC}"
fi

# Build the encryptor in release mode
echo -e "Building encryptor..."
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Encryptor built successfully!${NC}"
    cp target/release/secure_encryptor ./encryptor
    chmod +x ./encryptor
else
    echo -e "${RED}Encryptor build failed!${NC}"
    exit 1
fi

# Now build the decryptor
echo -e "Preparing decryptor source files..."
cp decryptor.rs src/main.rs

# Modify Cargo.toml to change the binary name
sed -i 's/name = "secure_encryptor"/name = "secure_decryptor"/' Cargo.toml

# Build the decryptor in release mode
echo -e "Building decryptor..."
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Decryptor built successfully!${NC}"
    cp target/release/secure_decryptor ./decryptor
    chmod +x ./decryptor
else
    echo -e "${RED}Decryptor build failed!${NC}"
    exit 1
fi

# Provide usage instructions
echo -e "\n${GREEN}=== Build Completed Successfully ===${NC}"
echo -e "\nTo encrypt files/folders:"
echo -e "  ${YELLOW}./encryptor <file_or_directory_path> [output_file]${NC}"
echo -e "\nTo decrypt files:"
echo -e "  ${YELLOW}./decryptor <encrypted_file> [output_directory]${NC}"
echo -e "\nFor more information, please read the README.md file."

# Cleanup
echo -e "\nCleaning up build files..."
# Keep the final binaries but remove intermediate files
chmod +x encryptor decryptor

echo -e "${GREEN}Done!${NC}" 