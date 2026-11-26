# Tenzro .NET SDK

A minimal, read-only .NET client for the [Tenzro](https://tenzro.com) node JSON-RPC.
Status: early (0.1.0). It is not a port of the Rust or TypeScript SDKs.

## What it does

`TenzroClient` (async, `System.Text.Json`, injectable `HttpClient`):

| Method | RPC |
|---|---|
| `GetChainIdAsync` | `eth_chainId` |
| `GetBlockNumberAsync` | `tenzro_blockNumber` |
| `GetPeerCountAsync` | `tenzro_peerCount` |
| `GetGasPriceAsync` | `eth_gasPrice` |
| `GetBalanceAsync(address)` | `eth_getBalance` (latest) |
| `CallAsync(method, params)` | any JSON-RPC method, raw result |

Signing: `Composite` builds the composite message representative and account address Tenzro keys use, and `P256Signer` (an `ISigner`) makes the P-256 leg with any `ECDsa` key; on Windows `P256Signer.OpenOrCreatePlatformKey(name)` keeps that key in the TPM through the Microsoft Platform Crypto Provider; that path has not yet been run against a real TPM. It makes no ML-DSA-65 leg, which transactions and payment authorizations need, and nothing sends transactions yet.

Targets: `net10.0` and `netstandard2.1`. Only `net10.0` is exercised by tests; `netstandard2.1` compiles but has not been run.

## Install

Not yet published to NuGet.org. Until then, clone and reference the project:

```sh
git clone https://github.com/tenzro/tenzro-network
dotnet add <your.csproj> reference tenzro-network/sdk/tenzro-dotnet-sdk/src/Tenzro.Sdk/Tenzro.Sdk.csproj
```

## Quickstart

```csharp
using Tenzro.Sdk;

using var http = new HttpClient();
var client = new TenzroClient(http, new Uri("http://127.0.0.1:28545"));
Console.WriteLine(await client.GetChainIdAsync());
Console.WriteLine(await client.GetBalanceAsync("0x0000000000000000000000000000000000000001"));
```

Run the example: `dotnet run --project examples/Console -- http://127.0.0.1:28545`

## Tests

```sh
dotnet test                                   # offline tests only; live tests return early
TENZRO_RPC_URL=http://127.0.0.1:28545 TENZRO_EXPECTED_CHAIN_ID=13380 dotnet test
```

Live tests report as passed when `TENZRO_RPC_URL` is unset (xUnit 2 cannot skip at runtime); the console prints a notice.

## Unity

`examples/Unity/TenzroBalanceBehaviour.cs` is a usage sketch, **untested in a real Unity project**.

## Not included yet

Transactions, the ML-DSA-65 leg, `/status` REST (served on a different port than JSON-RPC), websockets, NuGet.org package.

License: Apache-2.0.
