using System;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Tenzro.Sdk;
using Xunit;

namespace Tenzro.Sdk.Tests
{
    /// <summary>Deterministic tests with a stub HttpMessageHandler; these run in CI.</summary>
    public class OfflineTests
    {
        private sealed class Stub : HttpMessageHandler
        {
            private readonly string _body;
            public string? LastRequest;
            public Stub(string body) { _body = body; }
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
            {
                LastRequest = await r.Content!.ReadAsStringAsync();
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(_body) };
            }
        }

        private static (TenzroClient, Stub) Make(string body)
        {
            var s = new Stub(body);
            return (new TenzroClient(new HttpClient(s), new Uri("http://stub")), s);
        }

        [Theory]
        [InlineData("0x0", "0")]
        [InlineData("0x3444", "13380")]
        [InlineData("0xff", "255")]
        [InlineData("0xde0b6b3a7640000", "1000000000000000000")]
        public void ParseHex_works(string hex, string dec) => Assert.Equal(BigInteger.Parse(dec), TenzroClient.ParseHex(hex));

        [Fact]
        public async Task ChainId_parses_and_sends_correct_request()
        {
            var (c, s) = Make("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x3444\"}");
            Assert.Equal(13380, await c.GetChainIdAsync());
            Assert.Contains("\"method\":\"eth_chainId\"", s.LastRequest);
        }

        [Fact]
        public async Task Balance_sends_address_and_latest()
        {
            var (c, s) = Make("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xde0b6b3a7640000\"}");
            Assert.Equal(BigInteger.Pow(10, 18), await c.GetBalanceAsync("0xabc"));
            Assert.Contains("[\"0xabc\",\"latest\"]", s.LastRequest);
        }

        [Fact]
        public async Task RpcError_throws()
        {
            var (c, _) = Make("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid address param\"}}");
            var ex = await Assert.ThrowsAsync<TenzroRpcException>(() => c.GetBalanceAsync("x"));
            Assert.Equal(-32602, ex.Code);
        }

        [Fact]
        public async Task NonJson_throws()
        {
            var (c, _) = Make("<html>");
            await Assert.ThrowsAsync<TenzroRpcException>(() => c.GetChainIdAsync());
        }
    }
}
