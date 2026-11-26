using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tenzro.Sdk
{
    /// <summary>
    /// A key that signs for a Tenzro account in the composite format (<see cref="Composite"/>).
    /// </summary>
    public interface ISigner
    {
        /// <summary>The account's P-256 public key, <c>x || y</c> (64 bytes).</summary>
        byte[] PublicKeyXY { get; }

        /// <summary>The account address the key derives (<see cref="Composite.AccountAddress"/>).</summary>
        string Address { get; }

        /// <summary>Signs <paramref name="message"/> for <paramref name="context"/>.</summary>
        Task<CompositeSignature> SignAsync(string context, byte[] message, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// A key that makes the ML-DSA-65 leg of an account's composite signature: the account's enrolled
    /// one, held where its owner keeps it. <see cref="HybridSigner"/> only asks it to sign.
    /// </summary>
    public interface IMlDsaSigner
    {
        /// <summary>The ML-DSA-65 public key (1952 bytes).</summary>
        byte[] PublicKey { get; }

        /// <summary>
        /// Signs <paramref name="message"/>, the composite message representative <c>M'</c>, with
        /// <paramref name="context"/> as its FIPS 204 context string: the composite label.
        /// </summary>
        Task<byte[]> SignAsync(string context, byte[] message, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// An account's whole composite signature: the P-256 leg from one signer and the ML-DSA-65 leg from
    /// another, both over the same <c>M'</c>.
    /// </summary>
    public sealed class HybridSigner : ISigner
    {
        /// <summary>The size of an ML-DSA-65 signature.</summary>
        public const int MlDsaSignatureSize = 3309;

        private readonly ISigner _p256;
        private readonly IMlDsaSigner _mlDsa;

        /// <summary>A signer whose P-256 leg is <paramref name="p256"/>'s and whose ML-DSA-65 leg is <paramref name="mlDsa"/>'s.</summary>
        public HybridSigner(ISigner p256, IMlDsaSigner mlDsa)
        {
            _p256 = p256;
            _mlDsa = mlDsa;
        }

        /// <inheritdoc />
        public byte[] PublicKeyXY => _p256.PublicKeyXY;

        /// <inheritdoc />
        public string Address => _p256.Address;

        /// <inheritdoc />
        public async Task<CompositeSignature> SignAsync(string context, byte[] message, CancellationToken cancellationToken = default)
        {
            var classical = (await _p256.SignAsync(context, message, cancellationToken).ConfigureAwait(false)).Classical;
            var m = Composite.MessageRepresentative(context, message);
            var leg = await _mlDsa.SignAsync(Composite.LabelContext, m, cancellationToken).ConfigureAwait(false);
            if (leg.Length != MlDsaSignatureSize)
            {
                throw new ArgumentException($"an ML-DSA-65 signature is {MlDsaSignatureSize} bytes");
            }
            return new CompositeSignature(classical, leg);
        }
    }

    /// <summary>A composite signature: the P-256 leg and, when the signer holds one, the ML-DSA-65 leg.</summary>
    public sealed class CompositeSignature
    {
        /// <summary>Creates a signature from its legs.</summary>
        public CompositeSignature(byte[] classical, byte[]? mlDsa)
        {
            Classical = classical;
            MlDsa = mlDsa;
        }

        /// <summary>ECDSA P-256 over <c>SHA-256(M')</c>, <c>r || s</c> (64 bytes).</summary>
        public byte[] Classical { get; }

        /// <summary>The ML-DSA-65 leg over <c>M'</c>, or null when the signer holds no ML-DSA-65 key.</summary>
        public byte[]? MlDsa { get; }
    }
}
