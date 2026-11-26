using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Tenzro.Sdk
{
    /// <summary>
    /// The P-256 leg of an account key held by an <see cref="ECDsa"/> key: on Windows a key in the TPM through
    /// the Microsoft Platform Crypto Provider (<c>OpenOrCreatePlatformKey</c>), which never lets the private
    /// key leave the TPM.
    /// <para>
    /// It holds no ML-DSA-65 key, so its signatures carry only the P-256 leg. An account that has enrolled an
    /// ML-DSA-65 key, and every transaction and payment authorization the ledger admits, need both legs: wrap
    /// it in a <see cref="HybridSigner"/> with the account's ML-DSA-65 key.
    /// </para>
    /// </summary>
    public sealed class P256Signer : ISigner, IDisposable
    {
        private readonly ECDsa _key;

        /// <summary>A signer over <paramref name="key"/>, which must be a P-256 key. The signer owns and disposes it.</summary>
        public P256Signer(ECDsa key)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
            var q = key.ExportParameters(false).Q;
            if (key.KeySize != 256 || q.X is null || q.Y is null) throw new ArgumentException("not a P-256 key", nameof(key));
            var xy = new byte[64];
            Buffer.BlockCopy(q.X, 0, xy, 32 - q.X.Length, q.X.Length);
            Buffer.BlockCopy(q.Y, 0, xy, 64 - q.Y.Length, q.Y.Length);
            PublicKeyXY = xy;
            Address = Composite.AccountAddress(xy);
        }

        /// <inheritdoc/>
        public byte[] PublicKeyXY { get; }

        /// <inheritdoc/>
        public string Address { get; }

        /// <inheritdoc/>
        public Task<CompositeSignature> SignAsync(string context, byte[] message, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var classical = Composite.LowS(_key.SignHash(Composite.ClassicalDigest(context, message)));
            return Task.FromResult(new CompositeSignature(classical, null));
        }

#if NET8_0_OR_GREATER
        /// <summary>
        /// The P-256 key named <paramref name="name"/> in this machine's TPM, made there on first use. The key is
        /// not exportable and is used through the Microsoft Platform Crypto Provider. Windows only. This path has
        /// not yet run against a real TPM; tests use the same code with the software key storage provider.
        /// </summary>
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        public static P256Signer OpenOrCreatePlatformKey(string name) =>
            OpenOrCreate(name, new CngProvider("Microsoft Platform Crypto Provider"));

        /// <summary>The P-256 key named <paramref name="name"/> in the CNG key storage provider <paramref name="provider"/>, made there on first use, not exportable. Windows only.</summary>
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        public static P256Signer OpenOrCreate(string name, CngProvider provider)
        {
            if (string.IsNullOrEmpty(name)) throw new ArgumentException("a key needs a name", nameof(name));
            var key = CngKey.Exists(name, provider)
                ? CngKey.Open(name, provider)
                : CngKey.Create(CngAlgorithm.ECDsaP256, name, new CngKeyCreationParameters
                {
                    Provider = provider,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                });
            return new P256Signer(new ECDsaCng(key));
        }
#endif

        /// <inheritdoc/>
        public void Dispose() => _key.Dispose();
    }
}
