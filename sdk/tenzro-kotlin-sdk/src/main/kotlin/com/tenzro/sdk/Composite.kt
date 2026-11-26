package com.tenzro.sdk

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * The composite signature format Tenzro accounts sign with: ML-DSA-65 paired with ECDSA over P-256
 * (draft-ietf-lamps-pq-composite-sigs). Both legs sign the message representative
 * `M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)`, where `ctx` names the protocol the
 * signature is for; the P-256 leg is ECDSA over `SHA-256(M')`.
 */
object Composite {
    private val PREFIX = "CompositeAlgorithmSignatures2025".toByteArray(Charsets.US_ASCII)
    /** The composite label, which the ML-DSA-65 leg uses as its FIPS 204 context string. */
    const val LABEL_CONTEXT = "COMPSIG-MLDSA65-ECDSA-P256-SHA512"
    private val LABEL = LABEL_CONTEXT.toByteArray(Charsets.US_ASCII)
    private val ACCOUNT_DOMAIN = "tenzro/account".toByteArray(Charsets.US_ASCII)

    /** The message representative `M'` of [message] under [context]. */
    fun messageRepresentative(context: String, message: ByteArray): ByteArray {
        val ctx = context.toByteArray(Charsets.US_ASCII)
        require(ctx.size <= 255) { "a context is at most 255 bytes" }
        val ph = MessageDigest.getInstance("SHA-512").digest(message)
        return PREFIX + LABEL + byteArrayOf(ctx.size.toByte()) + ctx + ph
    }

    /** The account address of a P-256 key `x || y`, `0x`-prefixed hex. */
    fun accountAddress(p256Xy: ByteArray): String {
        require(p256Xy.size == 64) { "a P-256 key is 64 bytes, x || y" }
        val h = MessageDigest.getInstance("SHA-256").digest(ACCOUNT_DOMAIN + byteArrayOf(0x02, 0x40) + p256Xy)
        return "0x" + h.copyOf(20).joinToString("") { "%02x".format(it) }
    }

    /** Whether [signature] (`r || s`) is the P-256 leg of the key `x || y` over [message] under [context]. */
    fun verifyClassical(p256Xy: ByteArray, context: String, message: ByteArray, signature: ByteArray): Boolean {
        if (p256Xy.size != 64 || signature.size != 64) return false
        val point = ECPoint(BigInteger(1, p256Xy.copyOfRange(0, 32)), BigInteger(1, p256Xy.copyOfRange(32, 64)))
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256Params()))
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(key)
        v.update(messageRepresentative(context, message))
        return runCatching { v.verify(rawToDer(signature)) }.getOrDefault(false)
    }

    internal fun p256Params(): ECParameterSpec {
        val p = AlgorithmParameters.getInstance("EC")
        p.init(ECGenParameterSpec("secp256r1"))
        return p.getParameterSpec(ECParameterSpec::class.java)
    }

    /** `x || y` of a P-256 public key. */
    internal fun xy(key: ECPublicKey): ByteArray = fixed32(key.w.affineX) + fixed32(key.w.affineY)

    private fun fixed32(n: BigInteger): ByteArray {
        val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        require(b.size <= 32) { "not a P-256 coordinate" }
        return ByteArray(32 - b.size) + b
    }

    /** The order of the P-256 group. */
    private val N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    /**
     * `signature` (`r || s`) with `s` in the lower half of the group order: one canonical form of the
     * same signature; the node accepts either (the Android Keystore does not normalise).
     */
    internal fun lowS(signature: ByteArray): ByteArray {
        require(signature.size == 64) { "a raw P-256 signature is 64 bytes, r || s" }
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        if (s <= N.shiftRight(1)) return signature
        return signature.copyOfRange(0, 32) + fixed32(N - s)
    }

    /** An ASN.1 DER ECDSA signature as `r || s`. */
    internal fun derToRaw(der: ByteArray): ByteArray {
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f
        fun int(): BigInteger {
            require(der[i] == 0x02.toByte()) { "not a DER integer" }
            val len = der[i + 1].toInt()
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len))
            i += 2 + len
            return v
        }
        val r = int()
        val s = int()
        return fixed32(r) + fixed32(s)
    }

    /** `r || s` as an ASN.1 DER ECDSA signature. */
    internal fun rawToDer(raw: ByteArray): ByteArray {
        fun int(b: ByteArray): ByteArray {
            val v = BigInteger(1, b).toByteArray()
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
