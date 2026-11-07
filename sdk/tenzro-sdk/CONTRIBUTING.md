# Contributing

This repository is a synced mirror of the `sdk/tenzro-sdk/` directory in
[tenzro-network](https://github.com/tenzro/tenzro-network). Its contents are
overwritten from upstream, so pull requests opened here cannot be merged as-is.

- **Code changes** (fixes, features, docs in `src/`, `examples/`, `tests/`):
  make them in `sdk/tenzro-sdk/` in [tenzro-network](https://github.com/tenzro/tenzro-network).
  They arrive here on the next sync.
- **Bugs and questions**: open an issue in this repository. It is the home for
  `tenzro-sdk` on crates.io.
- **Security issues**: do not open an issue. See [SECURITY.md](SECURITY.md).

Before sending a change upstream, run `cargo build` and `cargo test` in the
SDK directory (Rust 1.85 or newer).
