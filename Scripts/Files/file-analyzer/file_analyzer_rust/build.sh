#!/bin/bash

# ---------------------------------------------------------------
# Build script for file_analyzer_rust
# 
# This script builds the File Analyzer tool with various options
# for optimal performance and security in red team operations
# ---------------------------------------------------------------

# Color formatting for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Define directories
BUILD_DIR="./build"
RELEASE_DIR="$BUILD_DIR/release"
OUTPUT_DIR="$BUILD_DIR/bin"
SRC_DIR="./src"

# Function to show usage information
show_help() {
  echo -e "${BLUE}File Analyzer Build Script Usage:${NC}"
  echo -e "  ${YELLOW}./build.sh${NC}                Build the File Analyzer tool (release mode)"
  echo -e "  ${YELLOW}./build.sh --help${NC}         Show this help message"
  echo -e "  ${YELLOW}./build.sh --clean${NC}        Clean build files only"
  echo -e "  ${YELLOW}./build.sh --full-clean${NC}   Remove all generated files including binaries"
  echo -e "  ${YELLOW}./build.sh --minimal${NC}      Build minimal size binary with UPX compression"
  echo -e "  ${YELLOW}./build.sh --ultra-minimal${NC} Build extremely small binary (slower startup)"
  echo -e "  ${YELLOW}./build.sh --static${NC}       Build fully static binary (no external dependencies)"
  echo -e "  ${YELLOW}./build.sh --docker-static${NC} Build fully static binary using Docker (recommended)"
}

echo -e "${YELLOW}Starting File Analyzer build process...${NC}"

# Parse command line arguments
CLEAN_ONLY=false
FULL_CLEAN=false
MINIMAL=false
ULTRA_MINIMAL=false
STATIC=false
HELP=false
DOCKER_BUILD=false

for arg in "$@"; do
  case $arg in
    --help|-h)
      HELP=true
      shift
      ;;
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
    --ultra-minimal)
      ULTRA_MINIMAL=true
      MINIMAL=true
      shift
      ;;
    --static)
      STATIC=true
      shift
      ;;
    --docker-static)
      DOCKER_BUILD=true
      shift
      ;;
  esac
done

# Show help if requested
if [ "$HELP" = true ]; then
  show_help
  exit 0
fi

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
    rm -f ./file_analyzer
    echo -e "${GREEN}Full cleanup completed.${NC}"
  fi
}

# Function to build with Docker
docker_static_build() {
  echo -e "${GREEN}Building static File Analyzer using Docker...${NC}"
  
  # Check if Docker is installed
  if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed. Please install Docker first.${NC}"
    echo -e "You can install Docker by following instructions at: https://docs.docker.com/get-docker/"
    exit 1
  fi
  
  # Create directory structure
  mkdir -p "$OUTPUT_DIR"
  
  # Build the Docker image
  echo -e "${YELLOW}Building Docker image...${NC}"
  docker build -t file-analyzer .
  
  if [ $? -ne 0 ]; then
    echo -e "${RED}Docker build failed!${NC}"
    exit 1
  fi
  
  echo -e "${GREEN}Docker image built successfully. Extracting binary...${NC}"
  
  # Create a container from the image but don't run it
  CONTAINER_ID=$(docker create file-analyzer)
  
  # Create bin directory if it doesn't exist
  mkdir -p ./bin
  
  # Copy the built binary from the container
  docker cp $CONTAINER_ID:/file_analyzer ./bin/file_analyzer
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Static binary extracted successfully${NC}"
    docker rm $CONTAINER_ID > /dev/null
  else
    echo -e "${RED}Failed to extract binary from Docker container${NC}"
    docker rm $CONTAINER_ID > /dev/null
    exit 1
  fi
  
  # Copy to main directory for convenience
  cp ./bin/file_analyzer ./file_analyzer
  
  # Make executable
  chmod +x ./file_analyzer ./bin/file_analyzer
  
  # Show binary size
  bin_size=$(du -h ./file_analyzer | cut -f1)
  echo -e "File Analyzer static binary size: ${YELLOW}$bin_size${NC}"
  
  # Run file command to verify binary type
  echo -e "\n${BLUE}Binary information:${NC}"
  file ./file_analyzer
  
  echo -e "${GREEN}Static binary build completed successfully!${NC}"
}

# Clean up if requested
if [ "$CLEAN_ONLY" = true ] || [ "$FULL_CLEAN" = true ]; then
  clean_build
  exit 0
fi

# If Docker build is requested, use Docker
if [ "$DOCKER_BUILD" = true ]; then
  docker_static_build
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
mkdir -p "$OUTPUT_DIR"
mkdir -p "$RELEASE_DIR"

# Check if we're in a secure environment
echo -e "Checking system security..."
if cat /proc/swaps | grep -q "partition"; then
    echo -e "${YELLOW}⚠️  WARNING: Swap space detected. Consider disabling swap or enabling encrypted swap.${NC}"
    echo -e "${YELLOW}              This helps prevent sensitive data from being written to disk.${NC}"
fi

if ! mount | grep -q "tmpfs on /tmp"; then
    echo -e "${YELLOW}⚠️  WARNING: /tmp directory may not be memory-backed. Temporary files might persist on disk.${NC}"
fi

# Set build flags based on options
BUILD_FLAGS="--release"

if [ "$STATIC" = true ]; then
    echo -e "${BLUE}Building with static linking for maximum portability...${NC}"
    echo -e "${YELLOW}Note: If you encounter issues with static building, try using --docker-static instead.${NC}"
    # Set environment variables for static linking
    export RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes -C prefer-dynamic=no"
fi

# Build the binary
echo -e "Building File Analyzer binary..."
cargo build $BUILD_FLAGS

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    
    # Create the output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Copy the built binary to our output directory
    cp target/release/file_analyzer "$OUTPUT_DIR/file_analyzer"
    
    # Copy to main directory for convenience
    cp "$OUTPUT_DIR/file_analyzer" ./file_analyzer
    
    # Make executable
    chmod +x ./file_analyzer "$OUTPUT_DIR/file_analyzer"
    
    echo -e "${BLUE}Applying binary hardening...${NC}"
    
    # Apply strip to make binary smaller and harder to reverse-engineer
    echo -e "Stripping debug symbols and other metadata..."
    strip -s ./file_analyzer
    
    # Check if we should apply additional hardening
    if [ "$MINIMAL" = true ]; then
        # Check if UPX is available
        if command -v upx &> /dev/null; then
            echo -e "Applying UPX compression to reduce binary size..."
            
            if [ "$ULTRA_MINIMAL" = true ]; then
                echo -e "${YELLOW}Using extreme compression (may slow startup time)...${NC}"
                upx --best --ultra-brute ./file_analyzer 2>/dev/null || echo -e "${YELLOW}UPX compression failed, continuing without it.${NC}"
            else
                upx --best ./file_analyzer 2>/dev/null || echo -e "${YELLOW}UPX compression failed, continuing without it.${NC}"
            fi
        else
            echo -e "${YELLOW}UPX not found. Install UPX for better compression.${NC}"
        fi
    fi
    
    # Apply sstrip for even more aggressive stripping if available
    if command -v sstrip &> /dev/null && [ "$ULTRA_MINIMAL" = true ]; then
        echo -e "Applying super strip (sstrip) for maximum size reduction..."
        sstrip ./file_analyzer 2>/dev/null || echo -e "${YELLOW}Super strip failed, continuing without it.${NC}"
    fi
    
    echo -e "${GREEN}Binary built and hardened successfully!${NC}"
    
    # Show binary size
    bin_size=$(du -h ./file_analyzer | cut -f1)
    echo -e "File Analyzer binary size: ${YELLOW}$bin_size${NC}"
    
    # Run file command to verify binary type
    echo -e "\n${BLUE}Binary information:${NC}"
    file ./file_analyzer
else
    echo -e "${RED}Build failed!${NC}"
    echo -e "${YELLOW}If you're trying to build a static binary and encountering issues,${NC}"
    echo -e "${YELLOW}try using the --docker-static option instead, which uses Docker to build a fully static binary.${NC}"
    exit 1
fi

# Move build artifacts to build directory
echo -e "Organizing build artifacts..."
if [ -d "target" ]; then
    # Move target directory to build folder
    mv target "$BUILD_DIR/"
fi

# Create examples directory in the output
mkdir -p "$OUTPUT_DIR/examples"
cp -r examples/* "$OUTPUT_DIR/examples/"

# Provide security-focused usage instructions
echo -e "\n${GREEN}=== Build Completed Successfully ===${NC}"
echo -e "\n${BLUE}Operational Security Tips:${NC}"
echo -e "- Run with limited privileges when possible"
echo -e "- Consider executing in a non-persistent environment"
echo -e "- Be aware that sensitive data found will be in memory"
echo -e "- Use the '--no-color' option when capturing output to avoid leaking formatting"

echo -e "\n${BLUE}Basic Usage:${NC}"
echo -e "  ${YELLOW}./file_analyzer <file_path>${NC}                  Analyze a single file"
echo -e "  ${YELLOW}./file_analyzer --dir <directory_path>${NC}       Recursively analyze a directory"
echo -e "  ${YELLOW}./file_analyzer <file_path> --json results.json${NC}  Output to JSON"
echo -e "\n${BLUE}Advanced Options:${NC}"
echo -e "  ${YELLOW}./file_analyzer --help${NC}                     Show all available options"
echo -e "  ${YELLOW}./file_analyzer --entropy-threshold 5.5${NC}    Set entropy threshold for secret detection" 
echo -e "  ${YELLOW}./file_analyzer --scan-limit 100MB${NC}         Limit scan size for large files"

echo -e "\n${BLUE}Build Options:${NC}"
echo -e "  ${YELLOW}./build.sh --clean${NC}           Clean build files only"
echo -e "  ${YELLOW}./build.sh --full-clean${NC}      Remove all generated files including binaries"
echo -e "  ${YELLOW}./build.sh --minimal${NC}         Build minimal size binary with UPX compression"
echo -e "  ${YELLOW}./build.sh --ultra-minimal${NC}   Build extremely small binary (slower startup)"
echo -e "  ${YELLOW}./build.sh --static${NC}          Build fully static binary (no external dependencies)"
echo -e "  ${YELLOW}./build.sh --docker-static${NC}   Build fully static binary using Docker (recommended)"
echo -e "\nFor more information, please read the README.md file."

echo -e "${GREEN}Done!${NC}" 