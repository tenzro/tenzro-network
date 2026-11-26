package com.tenzro.keystore

import java.math.BigInteger

/** The byte forms the Keystore and Tenzro use for P-256 points and signatures. */
internal object Encoding {
    /** A non-negative integer as exactly 32 big-endian bytes. */
    fun fixed32(n: BigInteger): ByteArray {
        require(n.signum() >= 0 && n.bitLength() <= 256) { "not a 32-byte integer" }
        val raw = n.toByteArray()
        val out = ByteArray(32)
        val take = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - take, out, 32 - take, take)
        return out
    }

    /** `0x04 || x || y`. */
    fun uncompressed(x: BigInteger, y: BigInteger): ByteArray =
        byteArrayOf(0x04) + fixed32(x) + fixed32(y)

    /** `r || s` (64 bytes) of a DER `SEQUENCE { INTEGER r, INTEGER s }`. */
    fun derToRaw(der: ByteArray): ByteArray {
        var i = 0
        fun byte(): Int {
            require(i < der.size) { "truncated signature" }
            return der[i++].toInt() and 0xff
        }
        fun length(): Int {
            val first = byte()
            if (first < 0x80) return first
            require(first == 0x81) { "signature length form" }
            return byte().also { require(it >= 0x80) { "signature length is not minimal" } }
        }
        fun integer(): BigInteger {
            require(byte() == 0x02) { "signature integer tag" }
            val len = length()
            require(len in 1..33 && i + len <= der.size) { "signature integer length" }
            val bytes = der.copyOfRange(i, i + len)
            i += len
            require(bytes[0] >= 0) { "negative signature integer" }
            require(len == 1 || bytes[0] != 0.toByte() || bytes[1] < 0) { "signature integer is not minimal" }
            return BigInteger(1, bytes)
        }
        require(byte() == 0x30) { "signature sequence tag" }
        require(length() == der.size - i) { "signature sequence length" }
        val r = integer()
        val s = integer()
        require(i == der.size) { "bytes after the signature" }
        return fixed32(r) + fixed32(s)
    }
}
