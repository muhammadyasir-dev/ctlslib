# Secure Data Handler Makefile
# Supports Linux, macOS, and cross-platform compilation

# Project Configuration
PROJECT_NAME = secure_data_handler
VERSION = 1.0.0

# Compiler Settings
CC = gcc
CSTANDARD = -std=c11
WARNINGS = -Wall -Wextra -Werror
OPTIMIZATION = -O2

# Debugging Flags
DEBUG_FLAGS = -g -DDEBUG

# Directories
SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

# Source Files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# Library Configuration
LIBS = ssl crypto curl
LIB_DIRS = /usr/local/lib /usr/lib

# Include Paths
INCLUDE_PATHS = \
    -I$(INCLUDE_DIR) \
    -I/usr/local/include \
    -I/usr/include/openssl

# Linker Flags
LDFLAGS = $(foreach dir,$(LIB_DIRS),-L$(dir))
LDLIBS = $(foreach lib,$(LIBS),-l$(lib))

# Platform Detection
UNAME_S := $(shell uname -s)

# Platform-Specific Flags
ifeq ($(UNAME_S),Darwin)
    # macOS Specific Flags
    CFLAGS += -framework Security
    LDFLAGS += -L/usr/local/opt/openssl/lib
    INCLUDE_PATHS += -I/usr/local/opt/openssl/include
endif

ifeq ($(UNAME_S),Linux)
    # Linux Specific Flags
    LDFLAGS += -Wl,-rpath-link
endif

# Compilation Targets
TARGET = $(BUILD_DIR)/$(PROJECT_NAME)
DEBUG_TARGET = $(BUILD_DIR)/$(PROJECT_NAME)_debug

# Default Target
all: $(TARGET)

# Debug Build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(DEBUG_TARGET)

# Main Executable
$(TARGET): $(OBJECTS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(WARNINGS) $(OPTIMIZATION) -o $@ $^ $(LDFLAGS) $(LDLIBS)
	@echo "✅ Build complete: $@"

# Debug Executable
$(DEBUG_TARGET): $(OBJECTS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)
	@echo "🐞 Debug build complete: $@"

# Compile Source Files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CSTANDARD) $(CFLAGS) $(WARNINGS) $(OPTIMIZATION) $(INCLUDE_PATHS) -c -o $@ $<

# Clean Build Artifacts
clean:
	@rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build directory"

# Install Target (requires root)
install: $(TARGET)
	@install -m 755 $(TARGET) /usr/local/bin/$(PROJECT_NAME)
	@echo "📦 Installed to /usr/local/bin"

# Uninstall Target
uninstall:
	@rm -f /usr/local/bin/$(PROJECT_NAME)
	@echo "🗑️ Uninstalled from /usr/local/bin"

# Dependency Check
deps:
	@echo "Checking dependencies..."
	@pkg-config --exists openssl || (echo "OpenSSL not found" && exit 1)
	@pkg-config --exists libcurl || (echo "libcurl not found" && exit 1)
	@echo "✅ All dependencies satisfied"

# Static Analysis
lint:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRC_DIR)
	@echo "🔍 Static analysis complete"

# Generate Documentation
docs:
	doxygen Doxyfile
	@echo "📄 Documentation generated"

# Run Tests
test: $(TARGET)
	@./$(TARGET) --test
	@echo "✅ Tests completed"

# Phony Targets
.PHONY: all debug clean install uninstall deps lint docs test

# Help Target
help:
	@echo "Secure Data Handler Build System"
	@echo "--------------------------------"
	@echo "Targets:"
	@echo "  all      - Build release version (default)"
	@echo "  debug    - Build with debugging symbols"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  uninstall- Remove installed binary"
	@echo "  deps     - Check project dependencies"
	@echo "  lint     - Run static code analysis"
	@echo "  docs     - Generate documentation"
	@echo "  test     - Run project tests"
