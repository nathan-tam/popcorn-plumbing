# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Makefile for eBPF Hook Point Comparison Project
#
# This Makefile compiles eBPF programs for XDP, TC, and socket layer hooks.
# It generates kernel type definitions (vmlinux.h) and compiles C code to
# eBPF bytecode that can be loaded into the Linux kernel.
#



# WARNING: you have to use TABS and not SPACES for indenting!




#
# Build Configuration Variables
#
# OUTPUT: Directory where compiled objects are placed (safe: doesn't touch system)
OUTPUT := .output

# Compiler toolchain (uses system defaults, can be overridden)
CLANG ?= clang
LLC ?= llc
STRIP ?= llvm-strip


# LIBBPF_DIR: Location of libbpf headers (standard system location)
# SAFE: Only used for include paths, no write operations
LIBBPF_DIR := /usr

# Include paths for BPF compilation
# -I$(OUTPUT): For generated vmlinux.h
# -I$(LIBBPF_DIR)/include/bpf: For bpf_helpers.h, bpf_endian.h
# -Isrc/ebpf: For our common.h
INCLUDES := -I. -I$(OUTPUT) -I$(LIBBPF_DIR)/include/bpf -Isrc/ebpf

#
# Auto-detect clang system includes for BPF compilation
# 
# This complex shell command extracts clang's built-in include paths.
# SAFE: Read-only operation, only queries clang configuration
# 
# Breakdown:
# 1. clang -v -E - </dev/null: Run preprocessor with verbose output
# 2. sed extracts lines between "#include <...>" and "End"
# 3. awk formats each path as "-isystem<path>"
#
CLANG_BPF_SYS_INCLUDES = $(shell clang -v -E - </dev/null 2>&1 | \
	sed -n '/^\#include <...>/,/^End/p' | \
	sed '/^\#include/d;/^End/d' | \
	awk '{printf "-isystem%s ", $$0}')

#
# Source and Object File Definitions
#
# BPF_SOURCES: All eBPF C source files to compile
BPF_SOURCES := src/ebpf/socket_hook.c src/ebpf/tc_hook.c

# BPF_OBJS: Corresponding output object files (.o)
# Pattern substitution: src/ebpf/foo.c -> .output/foo.o
BPF_OBJS := $(patsubst src/ebpf/%.c,$(OUTPUT)/%.o,$(BPF_SOURCES))

#
# Default Target
#
.PHONY: all
all: vmlinux.h $(BPF_OBJS)
	@echo ""
	@echo "Build complete! Generated files:"
	@echo "  vmlinux.h - Kernel type definitions"
	@echo "  $(BPF_OBJS)"
	@echo ""
	@echo "To load these programs, you'll need a userspace loader."

#
# Generate vmlinux.h - Kernel Type Definitions
#
# This rule extracts kernel type definitions from BTF (BPF Type Format).
# 
# SAFETY CHECK:
# - Reads from: /sys/kernel/btf/vmlinux (read-only kernel interface)
# - Writes to: vmlinux.h (local file in project directory)
# - NO SYSTEM MODIFICATION: This only reads kernel metadata
#
# The prerequisite checks that BTF is available. If not, build fails safely
# rather than creating an empty/broken vmlinux.h.
#
vmlinux.h: /sys/kernel/btf/vmlinux
	@echo "Generating vmlinux.h from kernel BTF..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/ebpf/vmlinux.h || \
		(echo "ERROR: Failed to generate vmlinux.h. Is bpftool installed?" && \
		echo "Install with: sudo apt-get install linux-tools-generic" && \
		rm -f src/ebpf/vmlinux.h && exit 1)
	@echo "Generated vmlinux.h (kernel type definitions)"

#
# Create Output Directory
#
# SAFETY: Only creates .output/ in the current project directory
# No system directories are touched
#
$(OUTPUT):
	@echo "Creating output directory: $(OUTPUT)"
	@mkdir -p $(OUTPUT)

#
# Compile eBPF Programs
#
# This pattern rule compiles each .c file to eBPF bytecode (.o)
#
# SAFETY ANALYSIS:
# - Reads from: src/ebpf/*.c (project source files)
# - Writes to: .output/*.o (project build directory)
# - NO SYSTEM MODIFICATION: Output confined to project directory
#
# Compilation flags:
# -O2: Optimize (required for BPF, complexity limits)
# -target bpf: Generate BPF bytecode, not native x86/ARM code
# -c: Compile only, don't link
# $<: Input file (src/ebpf/foo.c)
# $@: Output file (.output/foo.o)
#
# STRIP removes debug symbols to reduce object file size
# -g: Remove debug information only, doesn't affect functionality
#
$(OUTPUT)/%.o: src/ebpf/%.c src/ebpf/vmlinux.h src/ebpf/common.h | $(OUTPUT)
	@echo "Compiling $< -> $@"
	@$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-Wall -Werror \
		-c $< -o $@
	@$(STRIP) -g $@
	@echo "  Compiled and stripped $@"

#
# Clean Build Artifacts
#
# SAFETY ANALYSIS:
# - Removes: .output/ directory (build artifacts only)
# - Removes: vmlinux.h (generated file)
# - SAFE: Only removes files/directories in project folder
# - NO SYSTEM FILES TOUCHED
#
# Using rm -rf is safe here because:
# 1. $(OUTPUT) is a relative path (.output)
# 2. We're not using any user input or variables that could expand to "/"
# 3. vmlinux.h is an explicit filename in current directory
#
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUTPUT)
	@rm -f src/ebpf/vmlinux.h
	@echo "Clean complete"

#
# Verify Build Environment
#
# Checks that required tools are installed before attempting to build
# SAFE: Read-only checks, no modifications
#
.PHONY: check-deps
check-deps:
	@echo "Checking build dependencies..."
	@command -v clang >/dev/null 2>&1 || \
		(echo "ERROR: clang not found. Install with: sudo apt-get install clang" && exit 1)
	@command -v llvm-strip >/dev/null 2>&1 || \
		(echo "ERROR: llvm-strip not found. Install with: sudo apt-get install llvm" && exit 1)
	@command -v bpftool >/dev/null 2>&1 || \
		(echo "ERROR: bpftool not found. Install with: sudo apt-get install linux-tools-generic" && exit 1)
	@test -d $(LIBBPF_DIR)/include/bpf || \
		(echo "ERROR: libbpf headers not found. Install with: sudo apt-get install libbpf-dev" && exit 1)
	@test -f /sys/kernel/btf/vmlinux || \
		(echo "ERROR: Kernel BTF not available. You need a kernel with CONFIG_DEBUG_INFO_BTF=y" && exit 1)
	@echo "All dependencies satisfied!"

#
# Help Target
#
.PHONY: help
help:
	@echo "eBPF Hook Point Comparison - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build all eBPF programs (default)"
	@echo "  check-deps - Verify build dependencies are installed"
	@echo "  clean      - Remove build artifacts (safe: only touches .output/ and vmlinux.h)"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Build artifacts:"
	@echo "  .output/socket_hook.o - Socket hook eBPF bytecode"
	@echo "  .output/tc_hook.o     - TC (Traffic Control) eBPF bytecode"
	@echo ""
	@echo "Safety notes:"
	@echo "  - All output confined to project directory"
	@echo "  - No system files modified"
	@echo "  - 'make clean' only removes build artifacts"