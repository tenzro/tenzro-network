.PHONY: all clean lint format check generate help

# Default target
all: generate

# Generate code from proto files
generate:
	@echo "Generating code from proto files..."
	buf generate

# Lint proto files
lint:
	@echo "Linting proto files..."
	buf lint

# Format proto files
format:
	@echo "Formatting proto files..."
	buf format -w

# Check for breaking changes
check:
	@echo "Checking for breaking changes..."
	buf breaking --against '.git#branch=main'

# Build with protoc (fallback)
protoc-rust:
	@echo "Generating Rust code with protoc..."
	mkdir -p ../crates/tenzro-types/src/proto
	protoc --rust_out=../crates/tenzro-types/src/proto \
		--proto_path=. \
		tenzro/v1/*.proto

protoc-go:
	@echo "Generating Go code with protoc..."
	mkdir -p ../gen/go
	protoc --go_out=../gen/go --go-grpc_out=../gen/go \
		--proto_path=. \
		tenzro/v1/*.proto

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	rm -rf ../crates/tenzro-types/src/proto/*
	rm -rf ../gen/go/*
	rm -rf ../sdk/tenzro-ts-sdk/src/proto/*

# Validate proto files
validate:
	@echo "Validating proto files..."
	buf build

# Install buf
install-buf:
	@echo "Installing buf..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install bufbuild/buf/buf; \
	else \
		echo "Please install buf manually from https://buf.build/docs/installation"; \
	fi

# Help
help:
	@echo "Tenzro Network Proto Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Generate all code (default)"
	@echo "  generate      - Generate code using buf"
	@echo "  lint          - Lint proto files"
	@echo "  format        - Format proto files"
	@echo "  check         - Check for breaking changes"
	@echo "  validate      - Validate proto files"
	@echo "  protoc-rust   - Generate Rust code using protoc"
	@echo "  protoc-go     - Generate Go code using protoc"
	@echo "  clean         - Remove generated files"
	@echo "  install-buf   - Install buf tool"
	@echo "  help          - Show this help message"
