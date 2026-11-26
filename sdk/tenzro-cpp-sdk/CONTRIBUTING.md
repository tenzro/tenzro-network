# Contributing

Issues and pull requests are welcome. Keep changes small and tested.

- Build: `cmake -S . -B build && cmake --build build && ctest --test-dir build`.
- New RPC calls must use methods the node lists as open (no-auth), come with an offline test in `tests/`, and keep the C ABI ownership rules in `include/tenzro/tenzro.h`: no heap memory returned to callers.
- Do not claim support (TLS, platforms, GPUs) that has not been tested.
- Vulnerabilities: see [SECURITY.md](SECURITY.md); do not open public issues for them.
- By contributing you agree your work is licensed under Apache-2.0.
