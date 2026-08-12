# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2

# Directories
SRC_DIR = src

# Target executables
TARGETS = compiler decompiler main

# Default rule to build everything
all: $(TARGETS)

# Rule to compile the assembler/compiler
compiler: $(SRC_DIR)/compiler.c $(SRC_DIR)/common.h
	$(CC) $(CFLAGS) $(SRC_DIR)/compiler.c -o assembler

# Rule to compile the C language compiler
clang: $(SRC_DIR)/clang.c $(SRC_DIR)/common.h
	$(CC) $(CFLAGS) $(SRC_DIR)/clang.c -o clang

# Rule to compile the decompiler
decompiler: $(SRC_DIR)/decompiler.c $(SRC_DIR)/common.h
	$(CC) $(CFLAGS) $(SRC_DIR)/decompiler.c -o disassembler

# Rule to compile the VM runner / main executor with raylib linked
main: $(SRC_DIR)/main.c $(SRC_DIR)/common.h
	$(CC) $(CFLAGS) $(SRC_DIR)/main.c -o main -lraylib -lGL -lm -lpthread -ldl -lrt -lX11

# Clean up build artifacts
clean:
	rm -f $(TARGETS) *.bin assembler disassembler main clang

# Phony targets to prevent conflicts with files named 'all' or 'clean'
.PHONY: all clean