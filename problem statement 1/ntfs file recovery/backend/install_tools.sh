#!/bin/bash
#
# NFSU - NTFS Forensic Recovery System
# System Tools Installation Script
#
# This script installs all required forensic analysis tools
# for the NFSU backend system.
#

set -e  # Exit on error

echo "========================================="
echo "NFSU System Tools Installation"
echo "========================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "Cannot detect OS. Please install tools manually."
    exit 1
fi

echo "Detected OS: $OS $VERSION"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install packages on Debian/Ubuntu
install_debian() {
    echo "Installing forensic tools for Debian/Ubuntu..."
    sudo apt-get update
    
    echo "Installing Sleuth Kit..."
    sudo apt-get install -y sleuthkit
    
    echo "Installing libewf (EWF Tools)..."
    sudo apt-get install -y libewf-tools ewf-tools
    
    echo "Installing Scalpel..."
    sudo apt-get install -y scalpel
    
    echo "Installing optional tools..."
    sudo apt-get install -y afflib-tools bulk-extractor || true
}

# Function to install packages on RHEL/CentOS/Fedora
install_rhel() {
    echo "Installing forensic tools for RHEL/CentOS/Fedora..."
    
    # Enable EPEL repository if not already enabled
    if ! command_exists dnf && ! command_exists yum; then
        echo "Neither dnf nor yum found. Cannot install packages."
        exit 1
    fi
    
    if command_exists dnf; then
        PKG_MGR="dnf"
    else
        PKG_MGR="yum"
    fi
    
    echo "Installing Sleuth Kit..."
    sudo $PKG_MGR install -y sleuthkit
    
    echo "Installing libewf..."
    sudo $PKG_MGR install -y libewf ewf-tools || echo "EWF tools may need manual installation"
    
    echo "Installing Scalpel..."
    sudo $PKG_MGR install -y scalpel || echo "Scalpel may need manual installation"
}

# Function to install packages on macOS
install_macos() {
    echo "Installing forensic tools for macOS..."
    
    if ! command_exists brew; then
        echo "Homebrew is required but not installed."
        echo "Please install Homebrew from https://brew.sh"
        exit 1
    fi
    
    echo "Installing Sleuth Kit..."
    brew install sleuthkit
    
    echo "Installing libewf..."
    brew install libewf
    
    echo "Installing Scalpel..."
    brew install scalpel
}

# Install based on OS
case "$OS" in
    ubuntu|debian)
        install_debian
        ;;
    rhel|centos|fedora)
        install_rhel
        ;;
    darwin)
        install_macos
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Please install the following tools manually:"
        echo "  - Sleuth Kit (https://www.sleuthkit.org/)"
        echo "  - libewf (https://github.com/libyal/libewf)"
        echo "  - Scalpel (https://github.com/sleuthkit/scalpel)"
        exit 1
        ;;
esac

echo ""
echo "========================================="
echo "Verifying Installation"
echo "========================================="
echo ""

# Verify installations
ERRORS=0

echo "Checking Sleuth Kit (mmls)..."
if command_exists mmls; then
    mmls -V 2>&1 | head -n 1
else
    echo "  ✗ mmls not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking libewf (ewfinfo)..."
if command_exists ewfinfo; then
    ewfinfo -V 2>&1 | head -n 1
else
    echo "  ✗ ewfinfo not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking Scalpel..."
if command_exists scalpel; then
    scalpel -V 2>&1 | head -n 1
else
    echo "  ✗ scalpel not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking fls (Sleuth Kit)..."
if command_exists fls; then
    echo "  ✓ fls found"
else
    echo "  ✗ fls not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking icat (Sleuth Kit)..."
if command_exists icat; then
    echo "  ✓ icat found"
else
    echo "  ✗ icat not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking ewfmount..."
if command_exists ewfmount; then
    echo "  ✓ ewfmount found"
else
    echo "  ✗ ewfmount not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "========================================="

if [ $ERRORS -eq 0 ]; then
    echo "✓ All tools installed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Install Python dependencies: pip install -r requirements.txt"
    echo "  2. Create directories: mkdir -p forensics/{evidence,mounts,output,recovered,carved}"
    echo "  3. Configure: cp config/config.example.yaml config/config.yaml"
    echo "  4. Initialize database: alembic upgrade head"
    echo "  5. Run: uvicorn app.main:app --host 0.0.0.0 --port 8000"
else
    echo "✗ Installation completed with $ERRORS error(s)"
    echo "Please check the error messages above and install missing tools manually."
    exit 1
fi

echo "========================================="
