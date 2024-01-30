# Makefile for Filament Network Packet Analysis Engine
# Author: Filament Contributors
# License: MIT

CRYSTAL ?= crystal
SHARDS  ?= shards
CC      ?= clang
CFLAGS  ?= -O3 -Wall -Wextra -pedantic

C_SOURCES = ext/checksum/checksum.c ext/hexsimd/hexsimd.c
C_OBJECTS = $(C_SOURCES:.c=.o)

.PHONY: all build release test spec clean lint fmt help

all: build

# Build debug binary
build:
	$(SHARDS) build

# Build optimized release binary
release:
	$(SHARDS) build --release --no-debug

# Build C extensions
c-ext: $(C_OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run test suite
test: spec

spec:
	$(CRYSTAL) spec

# Format Crystal codebase
fmt:
	$(CRYSTAL) tool format src/ spec/

# Check formatting without modifying files
lint:
	$(CRYSTAL) tool format --check src/ spec/

# Clean build artifacts
clean:
	rm -rf bin/ .crystal/ $(C_OBJECTS)
	rm -rf analysis/__pycache__

# Run smoke test on sample pcap if available
smoke: build
	./bin/filament --version
	./bin/filament --help

help:
	@echo "Filament Build System"
	@echo "  make build    - Compile development binary in bin/filament"
	@echo "  make release  - Compile optimized release binary"
	@echo "  make test     - Run full Crystal test suite (crystal spec)"
	@echo "  make fmt      - Format all source files"
	@echo "  make lint     - Check code formatting"
	@echo "  make clean    - Remove build artifacts and temporary files"
