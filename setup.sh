#!/bin/bash

###############################################################################
# Advanced Packet Analyzer - Setup Script
# Automatically creates virtual environment and installs dependencies
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║         ADVANCED PACKET ANALYZER - SETUP                  ║"
echo "║         Automated Installation Script                     ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Warning: Running as root. This is not recommended for setup.${NC}"
    echo -e "${YELLOW}  The virtual environment will be owned by root.${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 1: Check Python version
echo -e "${BLUE}[1/7]${NC} Checking Python version..."
PYTHON_CMD=""

if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python found: ${PYTHON_VERSION}"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python found: ${PYTHON_VERSION}"
else
    echo -e "${RED}✗ Error: Python 3.7+ is required but not found.${NC}"
    exit 1
fi

# Check version is at least 3.7
PYTHON_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.minor)')

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    echo -e "${RED}✗ Error: Python 3.7+ is required. Found: ${PYTHON_VERSION}${NC}"
    exit 1
fi

# Step 2: Check for pip
echo -e "${BLUE}[2/7]${NC} Checking pip..."
if ! $PYTHON_CMD -m pip --version &> /dev/null; then
    echo -e "${RED}✗ Error: pip is not installed.${NC}"
    echo "Install pip with: sudo apt install python3-pip"
    exit 1
fi
echo -e "${GREEN}✓${NC} pip is installed"

# Step 3: Check for venv module
echo -e "${BLUE}[3/7]${NC} Checking venv module..."
if ! $PYTHON_CMD -m venv --help &> /dev/null; then
    echo -e "${YELLOW}⚠ venv module not found. Installing...${NC}"
    sudo apt-get update
    sudo apt-get install -y python3-venv
fi
echo -e "${GREEN}✓${NC} venv module is available"

# Step 4: Create virtual environment
VENV_DIR="venv"
echo -e "${BLUE}[4/7]${NC} Creating virtual environment..."

if [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}⚠ Virtual environment already exists.${NC}"
    read -p "Remove and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        $PYTHON_CMD -m venv "$VENV_DIR"
        echo -e "${GREEN}✓${NC} Virtual environment recreated"
    else
        echo -e "${YELLOW}→${NC} Using existing virtual environment"
    fi
else
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo -e "${GREEN}✓${NC} Virtual environment created"
fi

# Step 5: Activate virtual environment
echo -e "${BLUE}[5/7]${NC} Activating virtual environment..."
source "$VENV_DIR/bin/activate"
echo -e "${GREEN}✓${NC} Virtual environment activated"

# Step 6: Upgrade pip
echo -e "${BLUE}[6/7]${NC} Upgrading pip..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
echo -e "${GREEN}✓${NC} pip upgraded"

# Step 7: Install dependencies
echo -e "${BLUE}[7/7]${NC} Installing dependencies..."
echo -e "${CYAN}This may take a few minutes...${NC}"

if pip install -r requirements.txt; then
    echo -e "${GREEN}✓${NC} All dependencies installed successfully"
else
    echo -e "${RED}✗ Error installing dependencies${NC}"
    exit 1
fi

# Step 8: Compile C++ module (optional)
echo -e "${BLUE}[OPTIONAL]${NC} Compiling C++ performance module..."
if command -v g++ &> /dev/null; then
    if [ -f "packet_processor.cpp" ]; then
        if g++ -O3 -shared -fPIC -o packet_processor.so packet_processor.cpp 2>&1 | grep -v "warning"; then
            echo -e "${GREEN}✓${NC} C++ module compiled successfully"
        else
            echo -e "${YELLOW}⚠ C++ module compilation had warnings (non-critical)${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠ g++ not found. Skipping C++ module compilation.${NC}"
    echo -e "${YELLOW}  Install with: sudo apt install g++${NC}"
fi

# Create launcher script
echo -e "${BLUE}[EXTRA]${NC} Creating launcher script..."
cat > run.sh << 'EOF'
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
EOF

chmod +x run.sh
echo -e "${GREEN}✓${NC} Launcher script created (run.sh)"

# Summary
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "\n${YELLOW}To run the packet analyzer:${NC}"
echo -e "  ${CYAN}./run.sh${NC}     (Recommended - handles venv automatically)"
echo -e "\n${YELLOW}Or manually:${NC}"
echo -e "  ${CYAN}source venv/bin/activate${NC}"
echo -e "  ${CYAN}sudo python3 main.py${NC}"
echo -e "\n${YELLOW}Note:${NC} Root privileges are required for packet capture."
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
