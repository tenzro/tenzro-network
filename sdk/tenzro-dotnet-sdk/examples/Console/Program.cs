using Tenzro.Sdk;

// Usage: dotnet run --project examples/Console -- [rpc-url] [address]
// Defaults to a local dev node.
var url = args.Length > 0 ? args[0] : Environment.GetEnvironmentVariable("TENZRO_RPC_URL") ?? "http://127.0.0.1:28545";
var address = args.Length > 1 ? args[1] : "0x0000000000000000000000000000000000000001";

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
var client = new TenzroClient(http, new Uri(url));

Console.WriteLine($"endpoint:     {url}");
Console.WriteLine($"chain id:     {await client.GetChainIdAsync()}");
Console.WriteLine($"block number: {await client.GetBlockNumberAsync()}");
Console.WriteLine($"peer count:   {await client.GetPeerCountAsync()}");
Console.WriteLine($"balance({address}): {await client.GetBalanceAsync(address)} wei");
