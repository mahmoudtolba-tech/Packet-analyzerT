#!/bin/bash

# Advanced Packet Analyzer Launcher
# Automatically activates venv and runs the application

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

# Activate venv
source venv/bin/activate

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This application requires root privileges for packet capture."
    echo "Restarting with sudo..."
    sudo -E env PATH="$PATH" "$SCRIPT_DIR/venv/bin/python" main.py "$@"
else
    python main.py "$@"
fi
