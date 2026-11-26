using System;
using System.Net.Http;
using System.Numerics;
using System.Threading.Tasks;
using Tenzro.Sdk;
using Xunit;

namespace Tenzro.Sdk.Tests
{
    /// <summary>
    /// Live tests against a real node. Set TENZRO_RPC_URL (e.g. http://127.0.0.1:28545) and optionally
    /// TENZRO_EXPECTED_CHAIN_ID. When unset, each test returns immediately and passes (xunit 2.x has no
    /// runtime skip; the message is written to stdout).
    /// </summary>
    public class LiveNodeTests
    {
        private static TenzroClient? Make()
        {
            var url = Environment.GetEnvironmentVariable("TENZRO_RPC_URL");
            if (string.IsNullOrWhiteSpace(url)) { Console.WriteLine("TENZRO_RPC_URL unset: live test skipped"); return null; }
            return new TenzroClient(new HttpClient { Timeout = TimeSpan.FromSeconds(15) }, new Uri(url));
        }

        [Fact]
        public async Task ChainId_matches_expected_or_is_positive()
        {
            var c = Make(); if (c is null) return;
            var id = await c.GetChainIdAsync();
            var expected = Environment.GetEnvironmentVariable("TENZRO_EXPECTED_CHAIN_ID");
            if (!string.IsNullOrEmpty(expected)) Assert.Equal(long.Parse(expected), id);
            else Assert.True(id > 0);
        }

        [Fact]
        public async Task BlockNumber_and_peerCount_and_gasPrice_read()
        {
            var c = Make(); if (c is null) return;
            Assert.True(await c.GetBlockNumberAsync() >= 0);
            Assert.True(await c.GetPeerCountAsync() >= 0);
            Assert.True(await c.GetGasPriceAsync() > BigInteger.Zero);
        }

        [Fact]
        public async Task Balance_of_unused_address_is_zero()
        {
            var c = Make(); if (c is null) return;
            Assert.Equal(BigInteger.Zero, await c.GetBalanceAsync("0x0000000000000000000000000000000000000001"));
        }

        [Fact]
        public async Task Invalid_address_surfaces_rpc_error()
        {
            var c = Make(); if (c is null) return;
            var ex = await Assert.ThrowsAsync<TenzroRpcException>(() => c.GetBalanceAsync("nope"));
            Assert.NotEqual(0, ex.Code);
        }
    }
}
