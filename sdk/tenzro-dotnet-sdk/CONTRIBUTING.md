# Contributing

1. Fork and branch from `main`.
2. Install the .NET 10 SDK. Build with `dotnet build`, test with `dotnet test`.
3. Live-node tests need `TENZRO_RPC_URL` (and optionally `TENZRO_EXPECTED_CHAIN_ID`); add offline tests with a stub `HttpMessageHandler` for anything that does not need a node.
4. Keep the library compatible with `netstandard2.1` (no APIs missing there) and keep public members documented.
5. Open a pull request describing the change and how you tested it.

Report security issues privately, see [SECURITY.md](SECURITY.md). Contributions are licensed under Apache-2.0.
