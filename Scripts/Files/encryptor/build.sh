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

# Clean previous builds to ensure we're starting fresh
echo -e "Cleaning previous builds..."
cargo clean

# Create directory structure if it doesn't exist
mkdir -p src
mkdir -p target/release

# Copy source files to src directory
echo -e "Preparing source files..."
# Use our updated encryptor.rs for both tools (they share the same codebase)
cp -v encryptor.rs src/main.rs
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
    # The binary name might be secure_decryptor based on Cargo.toml
    if [ -f "target/release/secure_decryptor" ]; then
        cp target/release/secure_decryptor ./encryptor
    else
        cp target/release/secure_encryptor ./encryptor
    fi
    chmod +x ./encryptor
else
    echo -e "${RED}Encryptor build failed!${NC}"
    exit 1
fi

# Now build the decryptor - use the same binary with a different name
echo -e "Preparing decryptor files..."

# Copy the encryptor binary to decryptor_bin
# The binary could be named secure_encryptor or secure_decryptor based on Cargo.toml
if [ -f "target/release/secure_decryptor" ]; then
    cp target/release/secure_decryptor ./decryptor_bin
else
    cp target/release/secure_encryptor ./decryptor_bin
fi

# Create a simpler decryptor wrapper that directly calls the encryptor
echo -e "Creating decryptor wrapper..."

# Create a streamlined wrapper script that calls encryptor directly
cat > decryptor << 'EOF'
#!/bin/bash
# Streamlined wrapper script that calls encryptor with --decrypt flag

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Call the encryptor directly with --decrypt flag
"$SCRIPT_DIR/encryptor" --decrypt "$@"
EOF

# Make the wrapper script executable
chmod +x decryptor

# No need for file_encryptor.sh since its functionality is in encryptor
if [ -f "file_encryptor.sh" ]; then
    echo -e "${YELLOW}Removing obsolete file_encryptor.sh (functionality now in encryptor binary)${NC}"
    rm -f file_encryptor.sh
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