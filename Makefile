# SPDX-License-Identifier: GPL-2.0
#
# XDP TCP Server Makefile
#

# Compiler settings
CLANG ?= clang
LLC ?= llc
CC ?= gcc

# Detect architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
SRC_DIR := src
INC_DIR := include
BUILD_DIR := build

# BPF settings - use system headers
BPF_CFLAGS := -O2 -g -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(INC_DIR)
BPF_CFLAGS += -I/usr/include/aarch64-linux-gnu
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types

# Loader settings
LOADER_CFLAGS := -g -O2 -Wall -Wextra
LOADER_CFLAGS += -I$(INC_DIR)
LOADER_LDFLAGS := -lbpf -lelf -lz

# Source files
BPF_SRC := $(SRC_DIR)/xdp_tcp_server.c
LOADER_SRC := $(SRC_DIR)/loader.c

# Output files
BPF_OBJ := xdp_tcp_server.o
LOADER_BIN := xdp_loader

.PHONY: all clean install deps help

all: $(BPF_OBJ) $(LOADER_BIN)

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(INC_DIR)/common.h
	@echo "  BPF      $@ (arch: $(ARCH))"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile loader
$(LOADER_BIN): $(LOADER_SRC) $(INC_DIR)/common.h
	@echo "  CC       $@"
	$(CC) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LDFLAGS)

# Install dependencies (Debian/Ubuntu)
deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		libelf-dev \
		zlib1g-dev \
		linux-tools-common

# Clean build artifacts
clean:
	@echo "  CLEAN"
	rm -f $(BPF_OBJ) $(LOADER_BIN)
	rm -rf $(BUILD_DIR)

# Install (copy to /usr/local/bin)
install: all
	@echo "  INSTALL  $(LOADER_BIN) -> /usr/local/bin/"
	sudo cp $(LOADER_BIN) /usr/local/bin/
	sudo cp $(BPF_OBJ) /usr/local/lib/

help:
	@echo "XDP TCP Server - Full kernel-mode TCP server"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build BPF program and loader (default)"
	@echo "  deps     - Install build dependencies"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system directories"
	@echo "  help     - Show this message"
	@echo ""
	@echo "Usage:"
	@echo "  1. make deps     # Install dependencies (first time only)"
	@echo "  2. make          # Build the project"
	@echo "  3. sudo ./xdp_loader <interface>"
	@echo ""
	@echo "Options for xdp_loader:"
	@echo "  -S    Use SKB mode (generic, works everywhere)"
	@echo "  -N    Use native mode (requires driver support)"
	@echo "  -O    Use offload mode (requires hardware support)"
	@echo "  -F    Force attach (replace existing program)"
	@echo ""
	@echo "Example:"
	@echo "  sudo ./xdp_loader -S eth0"
