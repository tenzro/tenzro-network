using System;
using System.Globalization;
using System.Net.Http;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Tenzro.Sdk
{
    /// <summary>
    /// Minimal read-only client for a Tenzro node's JSON-RPC endpoint.
    /// Pass in an <see cref="HttpClient"/> you own (e.g. from IHttpClientFactory); the client never disposes it.
    /// </summary>
    public sealed class TenzroClient
    {
        private readonly HttpClient _http;
        private readonly Uri _endpoint;
        private long _nextId;

        /// <summary>A client for the node at <paramref name="endpoint"/>, sending its requests through <paramref name="httpClient"/>.</summary>
        public TenzroClient(HttpClient httpClient, Uri endpoint)
        {
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        }

        /// <summary>Convenience: creates a client with its own default HttpClient (you should prefer the injecting constructor).</summary>
        public TenzroClient(string endpoint) : this(new HttpClient(), new Uri(endpoint)) { }

        /// <summary>Chain id via <c>eth_chainId</c>.</summary>
        public async Task<long> GetChainIdAsync(CancellationToken ct = default)
            => (long)ParseHex(await CallStringAsync("eth_chainId", Array.Empty<object>(), ct).ConfigureAwait(false));

        /// <summary>Latest block number via <c>tenzro_blockNumber</c>.</summary>
        public async Task<long> GetBlockNumberAsync(CancellationToken ct = default)
            => (long)ParseHex(await CallStringAsync("tenzro_blockNumber", Array.Empty<object>(), ct).ConfigureAwait(false));

        /// <summary>Connected peer count via <c>tenzro_peerCount</c>.</summary>
        public async Task<long> GetPeerCountAsync(CancellationToken ct = default)
            => (long)ParseHex(await CallStringAsync("tenzro_peerCount", Array.Empty<object>(), ct).ConfigureAwait(false));

        /// <summary>Current gas price in wei via <c>eth_gasPrice</c>.</summary>
        public async Task<BigInteger> GetGasPriceAsync(CancellationToken ct = default)
            => ParseHex(await CallStringAsync("eth_gasPrice", Array.Empty<object>(), ct).ConfigureAwait(false));

        /// <summary>Balance in wei of a 0x-prefixed address at the latest block via <c>eth_getBalance</c>.</summary>
        public async Task<BigInteger> GetBalanceAsync(string address, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(address)) throw new ArgumentException("address is required", nameof(address));
            return ParseHex(await CallStringAsync("eth_getBalance", new object[] { address, "latest" }, ct).ConfigureAwait(false));
        }

        /// <summary>Calls any JSON-RPC method and returns its raw <c>result</c> element (cloned, safe to keep).</summary>
        public async Task<JsonElement> CallAsync(string method, object[]? parameters = null, CancellationToken ct = default)
        {
            var id = Interlocked.Increment(ref _nextId);
            var body = JsonSerializer.Serialize(new { jsonrpc = "2.0", id, method, @params = parameters ?? Array.Empty<object>() });
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await _http.PostAsync(_endpoint, content, ct).ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!response.IsSuccessStatusCode && text.Length == 0)
                throw new TenzroRpcException(0, $"HTTP {(int)response.StatusCode} from node");
            JsonDocument doc;
            try { doc = JsonDocument.Parse(text); }
            catch (JsonException e) { throw new TenzroRpcException(0, "Node returned non-JSON response: " + e.Message); }
            using (doc)
            {
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.Object)
                {
                    var code = err.TryGetProperty("code", out var c) && c.TryGetInt32(out var ci) ? ci : 0;
                    var msg = err.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
                    throw new TenzroRpcException(code, msg);
                }
                if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("result", out var result))
                    throw new TenzroRpcException(0, "Response has neither result nor error");
                return result.Clone();
            }
        }

        private async Task<string> CallStringAsync(string method, object[] parameters, CancellationToken ct)
        {
            var r = await CallAsync(method, parameters, ct).ConfigureAwait(false);
            if (r.ValueKind != JsonValueKind.String) throw new TenzroRpcException(0, $"{method}: expected hex string result, got {r.ValueKind}");
            return r.GetString()!;
        }

        /// <summary>Parses a 0x-prefixed hex quantity (non-negative) into a BigInteger.</summary>
        public static BigInteger ParseHex(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            var s = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex.Substring(2) : hex;
            if (s.Length == 0) return BigInteger.Zero;
            // Leading "0" keeps the value non-negative under BigInteger's two's-complement hex parsing.
            if (!BigInteger.TryParse("0" + s, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var v))
                throw new TenzroRpcException(0, "Invalid hex quantity: " + hex);
            return v;
        }
    }
}
