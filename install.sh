#!/bin/bash

# Eloid Vulnerability Scraper Installation Script
# Automates setup of Python dependencies, system libraries, and environment
# Compatible with Linux (Ubuntu/Debian) and macOS; Windows instructions included
# Run with: bash install.sh

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'  # No Color

# Log functions
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# Check for required tools
command -v python3 >/dev/null 2>&1 || log_error "Python3 not found. Install Python 3.8+."
command -v pip3 >/dev/null 2>&1 || log_error "pip3 not found. Install pip for Python 3."
command -v git >/dev/null 2>&1 || log_error "Git not found. Install git."

# Detect OS
OS=$(uname -s)
case "$OS" in
    Linux*)     PLATFORM=Linux;;
    Darwin*)    PLATFORM=macOS;;
    *)          PLATFORM=Unknown;;
esac
log_info "Detected platform: $PLATFORM"

# Create project directory
PROJECT_DIR="eloid_vuln_scraper"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR" || log_error "Failed to enter $PROJECT_DIR"

# Create requirements.txt if not exists
if [ ! -f "requirements.txt" ]; then
    log_info "Creating requirements.txt"
    cat > requirements.txt << EOL
requests==2.31.0
javalang==0.13.0
esprima==4.0.1
clang==16.0.6
EOL
fi

# Set up virtual environment
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    log_info "Creating virtual environment"
    python3 -m venv "$VENV_DIR" || log_error "Failed to create virtual environment"
fi
source "$VENV_DIR/bin/activate" || log_error "Failed to activate virtual environment"

# Upgrade pip
log_info "Upgrading pip"
pip install --upgrade pip || log_error "Failed to upgrade pip"

# Install Python dependencies
log_info "Installing Python dependencies from requirements.txt"
pip install -r requirements.txt || log_error "Failed to install dependencies. Check network or PyPI availability."

# Install system dependencies
if [ "$PLATFORM" = "Linux" ]; then
    log_info "Installing libclang on Linux (Ubuntu/Debian)"
    sudo apt-get update && sudo apt-get install -y libclang-dev || log_error "Failed to install libclang"
elif [ "$PLATFORM" = "macOS" ]; then
    log_info "Installing libclang on macOS"
    brew install llvm || log_error "Failed to install llvm. Ensure Homebrew is installed."
    # Set LLVM path
    export PATH="/usr/local/opt/llvm/bin:$PATH"
    echo 'export PATH="/usr/local/opt/llvm/bin:$PATH"' >> ~/.bash_profile
else
    log_info "Windows detected or unknown platform. Manual libclang installation required."
    echo "1. Install LLVM from https://llvm.org/"
    echo "2. Set LIBCLANG_PATH environment variable to the libclang.dll directory"
    echo "3. Ensure LLVM bin directory is in PATH"
fi

# Verify installations
log_info "Verifying Python dependencies"
for pkg in requests javalang esprima clang; do
    python -c "import $pkg" 2>/dev/null && log_info "$pkg installed successfully" || log_error "$pkg failed to import"
done

# Instructions for Go and Rust parsers
log_info "Non-Python dependencies (Go, Rust) require manual setup:"
echo "1. **Go Parser**:"
echo "   - Install Go: https://golang.org/doc/install"
echo "   - Use 'go get golang.org/x/tools/go/ast' for parsing"
echo "   - Modify eloid_vuln_scraper.py to call Go parser via subprocess"
echo "2. **Rust Parser**:"
echo "   - Install Rust: https://www.rust-lang.org/tools/install"
echo "   - Use 'cargo install syn' for parsing"
echo "   - Integrate via PyO3 or call clippy as an external tool"
echo "Note: Go/Rust parsing is not fully automated in this version."

# Create sample directory structure
log_info "Creating test_cases and results directories"
mkdir -p test_cases/{python,cpp,c,javascript,java,go,rust} results

# Instructions for running the scraper
log_info "Installation complete! Next steps:"
echo "1. Place eloid_vuln_scraper.py in $PROJECT_DIR"
echo "2. Add test files to test_cases/<language>/ (e.g., vuln.py, vuln.c)"
echo "3. Run the scraper: python eloid_vuln_scraper.py"
echo "4. Check results in results/report.json"

# Security warning
log_info "Security note: Verify package integrity with 'pip hash' and use a sandbox (e.g., Docker) for untrusted code."

exit 0
