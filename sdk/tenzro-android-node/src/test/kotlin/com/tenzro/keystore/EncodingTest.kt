package com.tenzro.keystore

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EncodingTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun derSignaturesBecome64Bytes() {
        // r with a leading zero byte (high bit set), s short: both padded to 32 bytes.
        val r = "00" + "ff".repeat(32)
        val s = "01" + "02".repeat(30)
        val der = hex("30" + "%02x".format(2 + 33 + 2 + 31) + "0221" + r + "021f" + s)
        val raw = Encoding.derToRaw(der)
        assertEquals(64, raw.size)
        assertArrayEquals(hex("ff".repeat(32)), raw.copyOfRange(0, 32))
        assertArrayEquals(hex("00" + "01" + "02".repeat(30)), raw.copyOfRange(32, 64))
    }

    @Test
    fun malformedDerIsRefused() {
        for (bad in listOf("", "3000", "300602010102", "3006020101020101ff", "30070201010202000102", "3006020180020101")) {
            assertThrows(IllegalArgumentException::class.java) { Encoding.derToRaw(hex(bad)) }
        }
    }

    @Test
    fun signaturesOfTheJvmProviderRoundTrip() {
        val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        repeat(32) {
            val pair = gen.generateKeyPair()
            val signer = Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private); update(byteArrayOf(it.toByte())) }
            val der = signer.sign()
            val raw = Encoding.derToRaw(der)
            val r = BigInteger(1, raw.copyOfRange(0, 32))
            val s = BigInteger(1, raw.copyOfRange(32, 64))
            // Re-encode r and s and check the provider accepts them.
            fun int(n: BigInteger) = n.toByteArray().let { byteArrayOf(0x02, it.size.toByte()) + it }
            val body = int(r) + int(s)
            val back = byteArrayOf(0x30, body.size.toByte()) + body
            val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(pair.public); update(byteArrayOf(it.toByte())) }
            assertTrue(verifier.verify(back))
            val w = (pair.public as ECPublicKey).w
            val point = Encoding.uncompressed(w.affineX, w.affineY)
            assertEquals(65, point.size)
            assertEquals(4, point[0].toInt())
            assertEquals(w.affineX, BigInteger(1, point.copyOfRange(1, 33)))
        }
    }
}
