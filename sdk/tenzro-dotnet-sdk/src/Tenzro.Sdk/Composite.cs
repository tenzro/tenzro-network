using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tenzro.Sdk
{
    /// <summary>
    /// The composite signature format Tenzro accounts sign with: ML-DSA-65 paired with ECDSA over P-256
    /// (draft-ietf-lamps-pq-composite-sigs). Both legs sign the message representative
    /// <c>M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)</c>, where <c>ctx</c> names the protocol the
    /// signature is for, so a signature made for one context does not verify under another. The P-256 leg is
    /// ECDSA over <c>SHA-256(M')</c>.
    /// </summary>
    public static class Composite
    {
        private static readonly byte[] Prefix = Encoding.ASCII.GetBytes("CompositeAlgorithmSignatures2025");
        private const string LabelText = "COMPSIG-MLDSA65-ECDSA-P256-SHA512";
        private static readonly byte[] Label = Encoding.ASCII.GetBytes(LabelText);

        /// <summary>The composite label, which the ML-DSA-65 leg uses as its FIPS 204 context string.</summary>
        public static string LabelContext => LabelText;
        private static readonly byte[] AccountDomain = Encoding.ASCII.GetBytes("tenzro/account");

        /// <summary>The message representative <c>M'</c> of <paramref name="message"/> under <paramref name="context"/>.</summary>
        public static byte[] MessageRepresentative(string context, byte[] message)
        {
            if (context is null) throw new ArgumentNullException(nameof(context));
            if (message is null) throw new ArgumentNullException(nameof(message));
            var ctx = Encoding.ASCII.GetBytes(context);
            if (ctx.Length > 255) throw new ArgumentException("a context is at most 255 bytes", nameof(context));
            byte[] ph;
            using (var sha = SHA512.Create()) ph = sha.ComputeHash(message);
            var m = new byte[Prefix.Length + Label.Length + 1 + ctx.Length + ph.Length];
            var at = 0;
            Buffer.BlockCopy(Prefix, 0, m, at, Prefix.Length); at += Prefix.Length;
            Buffer.BlockCopy(Label, 0, m, at, Label.Length); at += Label.Length;
            m[at++] = (byte)ctx.Length;
            Buffer.BlockCopy(ctx, 0, m, at, ctx.Length); at += ctx.Length;
            Buffer.BlockCopy(ph, 0, m, at, ph.Length);
            return m;
        }

        /// <summary>The digest the P-256 leg signs: <c>SHA-256(M')</c>.</summary>
        public static byte[] ClassicalDigest(string context, byte[] message)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(MessageRepresentative(context, message));
        }

        /// <summary>The account address of a P-256 key <c>x || y</c>, hex: <c>SHA-256("tenzro/account" || 0x02 || 0x40 || x || y)[..20]</c>.</summary>
        public static string AccountAddress(byte[] p256Xy)
        {
            if (p256Xy is null || p256Xy.Length != 64) throw new ArgumentException("a P-256 key is 64 bytes, x || y", nameof(p256Xy));
            var pre = new byte[AccountDomain.Length + 2 + 64];
            Buffer.BlockCopy(AccountDomain, 0, pre, 0, AccountDomain.Length);
            pre[AccountDomain.Length] = 0x02;
            pre[AccountDomain.Length + 1] = 0x40;
            Buffer.BlockCopy(p256Xy, 0, pre, AccountDomain.Length + 2, 64);
            byte[] h;
            using (var sha = SHA256.Create()) h = sha.ComputeHash(pre);
            var sb = new StringBuilder("0x", 42);
            for (var i = 0; i < 20; i++) sb.Append(h[i].ToString("x2"));
            return sb.ToString();
        }

        private static readonly BigInteger Order = BigInteger.Parse(
            "0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber);

        /// <summary>
        /// <paramref name="signature"/> (<c>r || s</c>) with <c>s</c> in the lower half of the group order: one canonical
        /// form of the same signature; the node accepts either. CNG does not normalise <c>s</c>.
        /// </summary>
        public static byte[] LowS(byte[] signature)
        {
            if (signature is null || signature.Length != 64) throw new ArgumentException("a P-256 signature is 64 bytes, r || s", nameof(signature));
            var s = new BigInteger(signature.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
            if (s <= Order / 2) return signature;
            var low = (Order - s).ToByteArray(isUnsigned: true, isBigEndian: true);
            var outSig = new byte[64];
            Buffer.BlockCopy(signature, 0, outSig, 0, 32);
            Buffer.BlockCopy(low, 0, outSig, 64 - low.Length, low.Length);
            return outSig;
        }

        /// <summary>Whether <paramref name="signature"/> (<c>r || s</c>, 64 bytes) is the P-256 leg of the key <c>x || y</c> over <paramref name="message"/> under <paramref name="context"/>.</summary>
        public static bool VerifyClassical(byte[] p256Xy, string context, byte[] message, byte[] signature)
        {
            if (p256Xy is null || p256Xy.Length != 64 || signature is null || signature.Length != 64) return false;
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = p256Xy[..32], Y = p256Xy[32..] },
            });
            return key.VerifyHash(ClassicalDigest(context, message), signature);
        }
    }
}
