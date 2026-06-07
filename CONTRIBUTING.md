# Contributing to Tenzro Network

Thank you for your interest in contributing to Tenzro Network! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style and Conventions](#code-style-and-conventions)
- [Making Changes](#making-changes)
- [Testing Requirements](#testing-requirements)
- [Crate-Specific Guidelines](#crate-specific-guidelines)
- [Desktop App Development](#desktop-app-development)
- [Reporting Issues](#reporting-issues)
- [License](#license)

---

## Getting Started

### Prerequisites

**Rust Development:**
- Rust 1.85+ (2024 edition, per rust-toolchain.toml)
- cargo (comes with Rust)
- git

**Desktop App Development:**
- Node.js 18+
- npm or yarn
- System dependencies for Tauri (see [Tauri prerequisites](https://tauri.app/v1/guides/getting-started/prerequisites))

**Platform Support:**
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows support is experimental

### Clone the Repository

```bash
git clone https://github.com/tenzro/tenzro-network.git
cd tenzro-network
```

### Build the Project

```bash
# Check that everything compiles
cargo check --workspace

# Build all crates in debug mode
cargo build

# Build all crates in release mode
cargo build --release

# Run all tests
cargo test
```

### Run the Node

```bash
cargo run --bin tenzro-node -- --role validator --listen-addr /ip4/0.0.0.0/tcp/9000
```

### Run the CLI

```bash
cargo run --bin tenzro-cli -- --help
```

### Run the Desktop App

```bash
cd apps/tenzro-desktop
npm install
npm run tauri dev
```

---

## Development Setup

### Recommended Tools

- **IDE:** VS Code with rust-analyzer extension, or IntelliJ IDEA with Rust plugin
- **Linting:** Run `cargo clippy` to catch common mistakes
- **Formatting:** Run `cargo fmt` before committing
- **Testing:** Use `cargo test` for unit tests, `cargo test --all-features` for all feature combinations

### Environment Variables

No special environment variables are required for basic development. Configuration is loaded from TOML files (when implemented) or uses sensible defaults.

### Feature Flags

Several crates use feature flags for optional functionality:

- **tenzro-tee:**
  - `intel-tdx` — Intel TDX provider
  - `amd-sev-snp` — AMD SEV-SNP provider
  - `aws-nitro` — AWS Nitro Enclaves provider
  - `nvidia-gpu` — NVIDIA Confidential Computing provider
  - `intel-tiber` — Intel Tiber Trust Authority hosted attestation

- **tenzro-payments:**
  - `mpp` (default) — Machine Payments Protocol
  - `x402` (default) — Coinbase x402 protocol
  - `tempo-bridge` — Tempo network integration

Example: Build with specific features:

```bash
cargo build --features intel-tdx,amd-sev-snp
```

---

## Code Style and Conventions

### Rust Code Style

1. **Follow Rust standard style:** Use `cargo fmt` to format code automatically.

2. **Async runtime:** All async code uses tokio with full features.

3. **Error handling:**
   - Library crates: Use `thiserror` for custom error types
   - Binary crates: Use `anyhow` for error handling
   - All public APIs should return `Result<T, CrateError>`

4. **Serialization:**
   - Use `serde` + `serde_json` for APIs
   - Use `bincode` for storage serialization
   - Use `prost` for proto definitions (when implemented)

5. **Logging:** Use the `tracing` crate for all logging:
   ```rust
   use tracing::{info, debug, warn, error, trace};

   info!("Starting node with role: {:?}", role);
   debug!(peer_id = %peer_id, "Connected to peer");
   error!(error = ?err, "Failed to process transaction");
   ```

6. **Async traits:** Use `async_trait` for async trait methods:
   ```rust
   #[async_trait]
   pub trait VmExecutor: Send + Sync {
       async fn execute(&self, tx: &Transaction) -> Result<ExecutionResult, VmError>;
   }
   ```

7. **Concurrency patterns:**
   - Prefer `Arc<T>` + `dashmap::DashMap` for concurrent shared state
   - Use `parking_lot::RwLock`/`Mutex` over std variants for synchronous locking

8. **DashMap safety (CRITICAL):**
   Never hold a `Ref` (from `get()`) or `RefMut` (from `get_mut()`) across a call that acquires another lock on the same map. This causes deadlocks.

   **Bad:**
   ```rust
   let value = map.get(&key).unwrap();
   let other = map.get_mut(&other_key); // DEADLOCK!
   ```

   **Good:**
   ```rust
   let value = {
       let v = map.get(&key).unwrap();
       v.clone() // or copy what you need
   }; // Ref dropped here
   let other = map.get_mut(&other_key); // Safe
   ```

9. **u128 arithmetic safety (CRITICAL):**
   When multiplying two values that are both scaled by 10^18 (e.g., token amounts × exchange rates), use quotient/remainder decomposition to avoid overflow:

   **Bad:**
   ```rust
   let result = a * c / b; // Overflows if a * c > u128::MAX
   ```

   **Good:**
   ```rust
   let result = (a / b) * c + (a % b) * c / b;
   ```

10. **Builder pattern:** Use builder methods for configuration structs:
    ```rust
    let config = VmConfig::default()
        .with_max_gas_limit(30_000_000)
        .with_default_gas_limit(10_000_000)
        .with_min_gas_price(1_000_000_000);
    ```

11. **Feature gates:** Platform-specific code must be feature-gated:
    ```rust
    #[cfg(feature = "intel-tdx")]
    mod intel_tdx;
    ```

12. **Testing:** Test async code with `#[tokio::test]`:
    ```rust
    #[tokio::test]
    async fn test_async_function() {
        let result = my_async_function().await;
        assert!(result.is_ok());
    }
    ```

### Documentation

- Add doc comments to all public APIs
- Use `///` for outer doc comments and `//!` for module-level documentation
- Include examples in doc comments where appropriate:
  ```rust
  /// Creates a new wallet with the specified threshold.
  ///
  /// # Example
  ///
  /// ```
  /// use tenzro_wallet::Wallet;
  ///
  /// let wallet = Wallet::new(2, 3)?;
  /// assert_eq!(wallet.threshold(), 2);
  /// ```
  pub fn new(threshold: usize, total: usize) -> Result<Self, WalletError> {
      // ...
  }
  ```

### Naming Conventions

- **Crates:** Use `tenzro-` prefix (e.g., `tenzro-crypto`, `tenzro-vm`)
- **Types:** PascalCase (e.g., `Transaction`, `BlockHeight`)
- **Functions/methods:** snake_case (e.g., `execute_transaction`, `verify_signature`)
- **Constants:** SCREAMING_SNAKE_CASE (e.g., `MAX_GAS_LIMIT`, `DEFAULT_CHAIN_ID`)
- **Modules:** snake_case (e.g., `consensus`, `storage`)

---

## Making Changes

### Branching Strategy

- `main` — Stable branch, always passing tests
- `develop` — Integration branch for next release
- Feature branches: `feature/description` or `feat/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`

### Workflow

1. **Create a branch:**
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes:**
   - Write code following the conventions above
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes:**
   ```bash
   cargo test
   cargo clippy
   cargo fmt --check
   ```

4. **Commit your changes:**
   - Write clear, descriptive commit messages
   - Use conventional commit format:
     - `feat: Add new feature`
     - `fix: Fix bug in module`
     - `docs: Update documentation`
     - `test: Add tests for feature`
     - `refactor: Refactor module`
     - `chore: Update dependencies`

   Example:
   ```bash
   git add .
   git commit -m "feat(consensus): implement view change timeout for liveness"
   ```

5. **Push your branch:**
   ```bash
   git push origin feature/my-new-feature
   ```

6. **Open a Pull Request:**
   - Provide a clear description of the changes
   - Reference any related issues
   - Ensure CI checks pass (when implemented)
   - Request review from maintainers

### Pull Request Guidelines

- **Title:** Use conventional commit format (e.g., `feat: Add feature`)
- **Description:** Explain what changed and why
- **Testing:** Describe how you tested the changes
- **Breaking changes:** Clearly document any breaking API changes
- **Documentation:** Update relevant documentation (README.md, inline docs)

### Code Review Process

- At least one maintainer review is required
- Address all review comments
- Keep PRs focused and reasonably sized (< 500 lines when possible)
- Rebase on main/develop before merging if needed

---

## Testing Requirements

### Unit Tests

- All public APIs must have unit tests
- Place tests in a `mod tests` block within the same file:
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_something() {
          // ...
      }

      #[tokio::test]
      async fn test_async_something() {
          // ...
      }
  }
  ```

### Integration Tests

- Place integration tests in `tests/` directory at the crate root
- Integration tests should test cross-module interactions

### Test Coverage

- Aim for > 80% code coverage on new code
- Critical paths (consensus, crypto, VM execution) require > 90% coverage
- Run tests with coverage (requires tarpaulin):
  ```bash
  cargo install cargo-tarpaulin
  cargo tarpaulin --workspace --out Html
  ```

### Test Conventions

- Test names should be descriptive: `test_wallet_creation_with_valid_threshold`
- Use `assert!`, `assert_eq!`, `assert_ne!` for assertions
- Test both success and error cases
- Test edge cases and boundary conditions
- Use `#[should_panic]` for tests that expect panics
- Mock external dependencies when necessary

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p tenzro-consensus

# Run a specific test
cargo test test_wallet_creation

# Run tests with output
cargo test -- --nocapture

# Run tests with all features
cargo test --all-features
```

---

## Crate-Specific Guidelines

### Crate Dependency Rules

The workspace follows a strict dependency hierarchy to prevent circular dependencies:

```
tenzro-types (foundation — no internal deps)
  ├── tenzro-crypto → types
  │     ├── tenzro-tee → types, crypto
  │     ├── tenzro-zk → types, crypto
  │     ├── tenzro-wallet → types, crypto
  │     ├── tenzro-network → types, crypto
  │     ├── tenzro-auth → types, crypto
  │     └── tenzro-bridge → types, crypto, token
  ├── tenzro-storage → types
  │     ├── tenzro-vm → types, storage
  │     ├── tenzro-token → types, storage
  │     ├── tenzro-events → types, storage
  │     └── tenzro-settlement → types, token, wallet, storage
  ├── tenzro-consensus → types, crypto
  ├── tenzro-identity → types, crypto, wallet
  ├── tenzro-payments → types, crypto, identity, settlement, bridge, wallet
  ├── tenzro-agent → types, crypto, wallet, identity
  ├── tenzro-agent-kit → types, agent
  ├── tenzro-cortex → types, crypto, network, model
  ├── tenzro-iroh → types, crypto, network, storage
  ├── tenzro-wasm → types
  ├── tenzro-training → types, crypto, storage, network, vm, model
  ├── tenzro-workflow → types, crypto, storage, vm, settlement
  ├── tenzro-model → types, network
  └── tenzro-node → ALL 24 crates above
      └── tenzro-cli → types, crypto, wallet, node
```

**Rules:**
1. `tenzro-types` has zero internal dependencies
2. Never create circular dependencies
3. Lower-level crates cannot depend on higher-level crates
4. `tenzro-node` integrates all subsystems but no other crate depends on it (except `tenzro-cli`)
5. The workspace has 26 crates total (25 libraries + tenzro-cli), plus `tools/genkeys` as a workspace member

### When to Create a New Crate

Create a new crate when:
- The functionality is logically distinct and self-contained
- It could be used independently of other parts of the system
- It represents a major subsystem (e.g., consensus, storage, VM)
- It needs different feature flags or platform support

Do NOT create a new crate when:
- The code is a small utility (add to `tenzro-types`)
- It's tightly coupled to an existing crate (add as a module within that crate)

### Crate Structure

```
tenzro-mycrate/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Public API and re-exports
│   ├── config.rs       # Configuration types
│   ├── error.rs        # Error types (using thiserror)
│   ├── types.rs        # Crate-specific types
│   ├── module1.rs      # Feature modules
│   ├── module2.rs
│   └── tests.rs        # Integration-style tests (optional)
└── tests/              # Integration tests
    └── integration.rs
```

### Error Handling Template

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyCrateError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Operation failed: {0}")]
    OperationFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, MyCrateError>;
```

---

## Desktop App Development

### Stack

- **Frontend:** React 18 + TypeScript
- **Styling:** Tailwind CSS 4 (OKLCH monochromatic dark theme)
- **UI Components:** 14 shadcn-style components
- **Icons:** lucide-react
- **Backend:** Tauri (Rust)

### Project Structure

```
apps/tenzro-desktop/
├── src/                    # React frontend
│   ├── components/
│   │   └── ui/             # Reusable UI components
│   ├── pages/              # Page components
│   ├── lib/                # Utilities and helpers
│   ├── App.tsx
│   └── main.tsx
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── main.rs         # Tauri commands and app builder
│   │   └── state.rs        # AppState with node RPC client
│   ├── Cargo.toml
│   └── tauri.conf.json
├── package.json
└── tsconfig.json
```

### Development Workflow

1. **Start dev server:**
   ```bash
   cd apps/tenzro-desktop
   npm run tauri dev
   ```

2. **Make changes:**
   - Frontend changes hot-reload automatically
   - Backend changes require restart

3. **Add Tauri commands:**
   ```rust
   // src-tauri/src/commands/wallet.rs

   #[tauri::command]
   pub async fn get_wallet_balance(address: String) -> Result<String, String> {
       // Implementation
       Ok("1000.0".to_string())
   }
   ```

   ```typescript
   // src/lib/tauri.ts

   import { invoke } from '@tauri-apps/api/tauri';

   export async function getWalletBalance(address: string): Promise<string> {
       return await invoke('get_wallet_balance', { address });
   }
   ```

4. **Build for production:**
   ```bash
   npm run tauri build
   ```

### UI Guidelines

- Use OKLCH color space for all colors (defined in Tailwind config)
- Follow the monochromatic dark theme (oklch-950 to oklch-50)
- Use lucide-react icons consistently
- Ensure all interactive elements have proper hover/focus states
- Test on all target platforms (Linux, macOS, Windows)

### Desktop App Testing

- **Frontend:** Use Vitest for unit tests
  ```bash
  npm run test
  ```

- **Backend:** Use cargo test
  ```bash
  cd src-tauri
  cargo test
  ```

- **E2E:** Use Tauri's WebDriver testing (when implemented)

---

## Reporting Issues

### Before Reporting

1. Search existing issues to avoid duplicates
2. Verify the issue exists on the latest version
3. Collect relevant information:
   - Operating system and version
   - Rust version (`rustc --version`)
   - Node.js version (for desktop app)
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages and stack traces

### Issue Template

```markdown
**Description:**
A clear and concise description of the issue.

**Steps to Reproduce:**
1. Step one
2. Step two
3. ...

**Expected Behavior:**
What you expected to happen.

**Actual Behavior:**
What actually happened.

**Environment:**
- OS: [e.g., Ubuntu 22.04, macOS 13.0]
- Rust version: [e.g., 1.70.0]
- Node.js version: [e.g., 18.16.0]
- Tenzro version: [e.g., 0.1.0]

**Additional Context:**
Any other relevant information, logs, or screenshots.
```

### Security Issues

**DO NOT** report security vulnerabilities as public issues. Instead, email security@tenzro.network with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

---

## License

By contributing to Tenzro Network, you agree that your contributions will be licensed under the Apache License 2.0 (the project's single license — see [LICENSE](LICENSE)).

### Contributor License Agreement

By submitting a contribution, you represent that:
1. You have the right to submit the contribution
2. You grant the project maintainers a perpetual, worldwide, non-exclusive, royalty-free license to use your contribution
3. Your contribution does not violate any third-party rights

---

## Questions?

- Open a discussion on GitHub
- Join our Discord (link TBD)
- Email dev@tenzro.network

Thank you for contributing to Tenzro Network!
