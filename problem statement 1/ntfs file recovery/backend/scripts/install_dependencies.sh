#!/bin/bash

# Installation script for NTFS Forensic Recovery System
# Ubuntu/Debian Linux

set -e

echo "========================================================================"
echo "NTFS Forensic Recovery System - Dependency Installation"
echo "========================================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

echo ""
echo "📦 Updating package lists..."
apt-get update

echo ""
echo "🔧 Installing forensic tools..."

# SleuthKit (fls, icat, mmls)
echo "  - Installing SleuthKit..."
apt-get install -y sleuthkit

# EWF Tools (ewfmount)
echo "  - Installing libewf-tools..."
apt-get install -y ewf-tools libewf-dev

# Scalpel (file carving)
echo "  - Installing Scalpel..."
apt-get install -y scalpel

# FUSE (for mounting)
echo "  - Installing FUSE..."
apt-get install -y fuse

# Python 3
echo "  - Installing Python 3.10+..."
apt-get install -y python3 python3-pip python3-venv

# Additional utilities
echo "  - Installing utilities..."
apt-get install -y \
    build-essential \
    pkg-config \
    git \
    curl

echo ""
echo "✅ All system dependencies installed!"

echo ""
echo "📋 Verifying installations..."

# Verify tools
tools=(
    "ewfmount:libewf"
    "fls:SleuthKit"
    "mmls:SleuthKit"
    "icat:SleuthKit"
    "scalpel:Scalpel"
    "python3:Python"
)

all_ok=true

for tool in "${tools[@]}"; do
    IFS=':' read -r cmd name <<< "$tool"
    if command -v "$cmd" &> /dev/null; then
        version=$("$cmd" -V 2>&1 | head -n 1 || "$cmd" --version 2>&1 | head -n 1 || echo "installed")
        echo "  ✓ $name: $version"
    else
        echo "  ✗ $name: NOT FOUND"
        all_ok=false
    fi
done

if [ "$all_ok" = false ]; then
    echo ""
    echo "⚠️  Some tools are missing. Please check the installation."
    exit 1
fi

echo ""
echo "========================================================================"
echo "✅ Installation complete!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "  1. Create virtual environment: python3 -m venv venv"
echo "  2. Activate it: source venv/bin/activate"
echo "  3. Install Python packages: pip install -r requirements.txt"
echo "  4. Copy config: cp config/config.example.yaml config/config.yaml"
echo "  5. Initialize database: python scripts/init_db.py"
echo "  6. Start server: uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "For documentation: http://localhost:8000/docs"
echo ""
