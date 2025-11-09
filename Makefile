# Makefile for Advanced Packet Analyzer C++ Module

CXX = g++
CXXFLAGS = -O3 -Wall -Wextra -std=c++11 -fPIC
TARGET = packet_processor.so
SOURCE = packet_processor.cpp

# Default target
all: $(TARGET)
	@echo "✓ C++ performance module compiled successfully"
	@echo "  Output: $(TARGET)"

# Compile shared library
$(TARGET): $(SOURCE)
	@echo "Compiling C++ performance module..."
	$(CXX) $(CXXFLAGS) -shared -o $(TARGET) $(SOURCE)

# Test compilation (standalone executable)
test: $(SOURCE)
	@echo "Compiling standalone test..."
	$(CXX) $(CXXFLAGS) -DBUILD_STANDALONE -o packet_processor_test $(SOURCE)
	@echo "✓ Test executable created: packet_processor_test"
	@echo "  Run with: ./packet_processor_test"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET) packet_processor_test *.o
	@echo "✓ Clean complete"

# Install system dependencies (Debian/Ubuntu)
install-deps:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential g++ python3 python3-pip python3-venv
	@echo "✓ System dependencies installed"

# Help
help:
	@echo "Advanced Packet Analyzer - C++ Module Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Compile C++ performance module (default)"
	@echo "  make test     - Compile standalone test executable"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install-deps - Install system dependencies"
	@echo "  make help     - Show this help message"

.PHONY: all test clean install-deps help
