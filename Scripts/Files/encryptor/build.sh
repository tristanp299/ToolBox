#!/bin/bash

# Build script for secure encryptor/decryptor tools
# This script builds completely independent binaries for encryption and decryption
# with maximum security and operational security for red team operations

# Color formatting for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Define directories
BUILD_DIR="./build"
RELEASE_DIR="$BUILD_DIR/release"
OUTPUT_DIR="$BUILD_DIR/bin"
SRC_DIR="./src"

echo -e "${YELLOW}Starting secure encryptor/decryptor build process...${NC}"

# Parse command line arguments
CLEAN_ONLY=false
FULL_CLEAN=false
MINIMAL=false

for arg in "$@"; do
  case $arg in
    --clean)
      CLEAN_ONLY=true
      shift
      ;;
    --full-clean)
      FULL_CLEAN=true
      shift
      ;;
    --minimal)
      MINIMAL=true
      shift
      ;;
  esac
done

# Function to clean build artifacts
clean_build() {
  echo -e "Cleaning build artifacts..."
  
  # Clean cargo build
  cargo clean
  
  # Remove build directories but preserve source
  rm -rf "$BUILD_DIR"
  
  echo -e "${GREEN}Build files cleaned.${NC}"
  
  if [ "$FULL_CLEAN" = true ]; then
    echo -e "Performing full cleanup (removing binaries)..."
    rm -f ./encryptor ./decryptor
    echo -e "${GREEN}Full cleanup completed.${NC}"
  fi
}

# Clean up if requested
if [ "$CLEAN_ONLY" = true ] || [ "$FULL_CLEAN" = true ]; then
  clean_build
  exit 0
fi

# Check if Rust and Cargo are installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust and Cargo are required but not installed.${NC}"
    echo -e "Please install Rust from https://rustup.rs/ and try again."
    exit 1
fi

# Clean previous builds to ensure we're starting fresh
clean_build

# Create directory structure
echo -e "Creating build directory structure..."
mkdir -p "$SRC_DIR"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$RELEASE_DIR"

# Copy source files to src directory
echo -e "Preparing source files..."

# Make sure the main source file is in place
if [ ! -f "$SRC_DIR/main.rs" ]; then
    cp -v encryptor.rs "$SRC_DIR/main.rs"
fi

# Make sure decryptor source is in place
if [ ! -f "$SRC_DIR/decryptor.rs" ]; then
    cp -v decryptor.rs "$SRC_DIR/decryptor.rs"
fi

# Check if we're in a secure environment
echo -e "Checking system security..."
if cat /proc/swaps | grep -q "partition"; then
    echo -e "${YELLOW}⚠️  WARNING: Swap space detected. Consider disabling swap or enabling encrypted swap.${NC}"
fi

if ! mount | grep -q "tmpfs on /tmp"; then
    echo -e "${YELLOW}⚠️  WARNING: /tmp directory may not be memory-backed. Temporary files might persist on disk.${NC}"
fi

# Build both binaries
echo -e "Building independent encryptor and decryptor binaries..."
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    
    # Create the output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Copy the built binaries to our output directory
    cp target/release/encryptor "$OUTPUT_DIR/encryptor"
    cp target/release/decryptor "$OUTPUT_DIR/decryptor"
    
    # Copy to main directory for convenience
    cp "$OUTPUT_DIR/encryptor" ./encryptor
    cp "$OUTPUT_DIR/decryptor" ./decryptor
    
    # Make executable
    chmod +x ./encryptor ./decryptor "$OUTPUT_DIR/encryptor" "$OUTPUT_DIR/decryptor"
    
    # Apply strip to make binaries smaller and harder to reverse-engineer
    echo -e "Stripping debug symbols and applying binary hardening..."
    strip -s ./encryptor ./decryptor
    
    # Check if we should apply additional hardening (not available on all systems)
    if command -v upx &> /dev/null && [ "$MINIMAL" = true ]; then
        echo -e "Applying UPX compression to reduce binary size..."
        upx --best --ultra-brute ./encryptor ./decryptor 2>/dev/null || echo -e "${YELLOW}UPX compression failed, continuing without it.${NC}"
    fi
    
    echo -e "${GREEN}Binaries built and hardened successfully!${NC}"
    
    # Show binary sizes
    enc_size=$(du -h ./encryptor | cut -f1)
    dec_size=$(du -h ./decryptor | cut -f1)
    echo -e "Encryptor size: ${YELLOW}$enc_size${NC}"
    echo -e "Decryptor size: ${YELLOW}$dec_size${NC}"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# No need for file_encryptor.sh since its functionality is in encryptor
if [ -f "file_encryptor.sh" ]; then
    echo -e "${YELLOW}Removing obsolete file_encryptor.sh (functionality now in encryptor binary)${NC}"
    rm -f file_encryptor.sh
fi

# Move build artifacts to build directory
echo -e "Organizing build artifacts..."
if [ -d "target" ]; then
    # Move target directory to build folder
    mv target "$BUILD_DIR/"
fi

# Provide usage instructions
echo -e "\n${GREEN}=== Build Completed Successfully ===${NC}"
echo -e "\nTo encrypt files/folders:"
echo -e "  ${YELLOW}./encryptor <file_or_directory_path> [output_file]${NC}"
echo -e "\nTo decrypt files:"
echo -e "  ${YELLOW}./decryptor <encrypted_file> [output_directory]${NC}"
echo -e "\nFor more options:"
echo -e "  ${YELLOW}./encryptor --help${NC}"
echo -e "  ${YELLOW}./decryptor --help${NC}"
echo -e "\nTo clean build files:"
echo -e "  ${YELLOW}./build.sh --clean${NC}"
echo -e "\nTo remove all generated files including binaries:"
echo -e "  ${YELLOW}./build.sh --full-clean${NC}"
echo -e "\nTo build minimal size binaries (using UPX if available):"
echo -e "  ${YELLOW}./build.sh --minimal${NC}"
echo -e "\nFor more information, please read the README.md file."

echo -e "${GREEN}Done!${NC}" 