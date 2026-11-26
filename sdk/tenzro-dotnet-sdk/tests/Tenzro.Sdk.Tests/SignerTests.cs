using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Tenzro.Sdk;
using Xunit;

namespace Tenzro.Sdk.Tests
{
    /// <summary>The composite format and the P-256 signer, held to the shared hardware-signing vectors.</summary>
    public class SignerTests
    {
        private static readonly JsonElement Vectors =
            JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors", "hwsign.json"))).RootElement;

        private static byte[] Hex(string h) => Convert.FromHexString(h.StartsWith("0x") ? h[2..] : h);

        private static byte[] VectorKeyXy => Hex(Vectors.GetProperty("p256_public_key_xy_hex").GetString()!);

        /// <summary>The vectors' test-only key, secret 0x07 repeated 32 times.</summary>
        private static ECDsa VectorKey()
        {
            var xy = VectorKeyXy;
            var d = new byte[32];
            Array.Fill(d, (byte)0x07);
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d,
                Q = new ECPoint { X = xy[..32], Y = xy[32..] },
            });
        }

        [Fact]
        public void The_message_representative_and_digest_match_every_vector()
        {
            foreach (var c in Vectors.GetProperty("cases").EnumerateArray())
            {
                var context = c.GetProperty("context").GetString()!;
                var message = Hex(c.GetProperty("message_hex").GetString()!);
                Assert.Equal(Hex(c.GetProperty("m_prime_hex").GetString()!), Composite.MessageRepresentative(context, message));
                Assert.Equal(Hex(c.GetProperty("signing_digest_hex").GetString()!), Composite.ClassicalDigest(context, message));
            }
        }

        [Fact]
        public void The_account_address_matches_the_vector() =>
            Assert.Equal("0x" + Vectors.GetProperty("account_address_hex").GetString(), Composite.AccountAddress(VectorKeyXy));

        [Fact]
        public void A_vector_signature_verifies_only_under_its_own_context()
        {
            foreach (var c in Vectors.GetProperty("cases").EnumerateArray())
            {
                var context = c.GetProperty("context").GetString()!;
                var message = Hex(c.GetProperty("message_hex").GetString()!);
                var sig = Hex(c.GetProperty("raw_signature_hex").GetString()!);
                Assert.True(Composite.VerifyClassical(VectorKeyXy, context, message, sig));
                Assert.False(Composite.VerifyClassical(VectorKeyXy, context + "/other", message, sig));
            }
        }

        /// <summary>A high-S signature comes back in its low-S form, which still verifies.</summary>
        [Fact]
        public void A_high_s_signature_is_normalised_to_low_s()
        {
            var n = System.Numerics.BigInteger.Parse(
                "0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber);
            foreach (var c in Vectors.GetProperty("cases").EnumerateArray())
            {
                var sig = Hex(c.GetProperty("raw_signature_hex").GetString()!);
                var s = new System.Numerics.BigInteger(sig.AsSpan(32), isUnsigned: true, isBigEndian: true);
                var other = (n - s).ToByteArray(isUnsigned: true, isBigEndian: true);
                var flipped = new byte[64];
                Buffer.BlockCopy(sig, 0, flipped, 0, 32);
                Buffer.BlockCopy(other, 0, flipped, 64 - other.Length, other.Length);
                var high = s > n / 2 ? sig : flipped;
                var low = Composite.LowS(high);
                Assert.True(new System.Numerics.BigInteger(low.AsSpan(32), isUnsigned: true, isBigEndian: true) <= n / 2);
                Assert.True(Composite.VerifyClassical(VectorKeyXy, c.GetProperty("context").GetString()!,
                    Hex(c.GetProperty("message_hex").GetString()!), low));
            }
        }

        [Fact]
        public async Task The_signer_makes_the_p256_leg_of_its_account()
        {
            using var signer = new P256Signer(VectorKey());
            Assert.Equal(VectorKeyXy, signer.PublicKeyXY);
            Assert.Equal("0x" + Vectors.GetProperty("account_address_hex").GetString(), signer.Address);
            var message = new byte[] { 1, 2, 3 };
            var sig = await signer.SignAsync("tenzro/signed-message", message);
            Assert.Null(sig.MlDsa);
            Assert.True(Composite.VerifyClassical(signer.PublicKeyXY, "tenzro/signed-message", message, sig.Classical));
            Assert.False(Composite.VerifyClassical(signer.PublicKeyXY, "tenzro/tx", message, sig.Classical));
        }

        /// <summary>A named CNG key is made once and opened again under the same account. The software key
        /// storage provider stands in for the TPM's, which tests never touch.</summary>
        [Fact]
        public async Task A_named_cng_key_is_made_once_and_reopened()
        {
            if (!OperatingSystem.IsWindows()) return;
            var name = "tenzro-sdk-test-" + Guid.NewGuid().ToString("N");
            var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            try
            {
                string address;
                using (var made = P256Signer.OpenOrCreate(name, provider)) address = made.Address;
                using var reopened = P256Signer.OpenOrCreate(name, provider);
                Assert.Equal(address, reopened.Address);
                var sig = await reopened.SignAsync("tenzro/tx", new byte[] { 9 });
                Assert.True(Composite.VerifyClassical(reopened.PublicKeyXY, "tenzro/tx", new byte[] { 9 }, sig.Classical));
            }
            finally
            {
                using var k = CngKey.Open(name, provider);
                k.Delete();
            }
        }

        /// <summary>An ML-DSA-65 key that records what it is asked to sign.</summary>
        private sealed class RecordingMlDsa : IMlDsaSigner
        {
            private readonly int _size;
            public RecordingMlDsa(int size = HybridSigner.MlDsaSignatureSize) { _size = size; }
            public byte[] PublicKey { get; } = new byte[1952];
            public string? AskedContext;
            public byte[]? AskedMessage;
            public Task<byte[]> SignAsync(string context, byte[] message, System.Threading.CancellationToken cancellationToken = default)
            {
                AskedContext = context;
                AskedMessage = message;
                var sig = new byte[_size];
                Array.Fill(sig, (byte)5);
                return Task.FromResult(sig);
            }
        }

        [Fact]
        public async Task TheHybridSignerAsksTheMlDsaKeyToSignTheSameRepresentativeUnderTheLabel()
        {
            using var key = VectorKey();
            var p256 = new P256Signer(key);
            var mlDsa = new RecordingMlDsa();
            var signer = new HybridSigner(p256, mlDsa);
            Assert.Equal(p256.PublicKeyXY, signer.PublicKeyXY);
            var m = new byte[] { 1, 2, 3 };
            var sig = await signer.SignAsync("tenzro/tx", m);
            Assert.True(Composite.VerifyClassical(p256.PublicKeyXY, "tenzro/tx", m, sig.Classical));
            Assert.Equal(HybridSigner.MlDsaSignatureSize, sig.MlDsa!.Length);
            Assert.Equal("COMPSIG-MLDSA65-ECDSA-P256-SHA512", mlDsa.AskedContext);
            Assert.Equal(Composite.MessageRepresentative("tenzro/tx", m), mlDsa.AskedMessage);
        }

        [Fact]
        public async Task AnMlDsaSignatureOfTheWrongSizeIsRefused()
        {
            using var key = VectorKey();
            var signer = new HybridSigner(new P256Signer(key), new RecordingMlDsa(64));
            await Assert.ThrowsAsync<ArgumentException>(() => signer.SignAsync("tenzro/tx", new byte[] { 1 }));
        }
    }
}
