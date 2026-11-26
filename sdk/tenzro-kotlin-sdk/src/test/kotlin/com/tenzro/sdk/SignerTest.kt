package com.tenzro.sdk

import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The composite format and the JCA signer, held to the shared hardware-signing vectors. */
class SignerTest {
    private val vectors = File("../fixtures/hwsign/vectors.json").readText()

    private fun field(json: String, name: String): String =
        Regex("\"$name\"\\s*:\\s*\"([^\"]*)\"").find(json)!!.groupValues[1]

    private val cases: List<String> = Regex("\\{[^{}]*\"context\"[^{}]*\\}").findAll(vectors).map { it.value }.toList()

    private fun hex(s: String) = s.removePrefix("0x").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private val keyXy = hex(field(vectors, "p256_public_key_xy_hex"))

    @Test
    fun theRepresentativeMatchesEveryVector() {
        assertEquals(3, cases.size)
        for (c in cases) {
            assertContentEquals(
                hex(field(c, "m_prime_hex")),
                Composite.messageRepresentative(field(c, "context"), hex(field(c, "message_hex"))),
            )
        }
    }

    @Test
    fun theAccountAddressMatchesTheVector() =
        assertEquals("0x" + field(vectors, "account_address_hex"), Composite.accountAddress(keyXy))

    @Test
    fun aVectorSignatureVerifiesOnlyUnderItsOwnContext() {
        for (c in cases) {
            val m = hex(field(c, "message_hex"))
            val sig = hex(field(c, "raw_signature_hex"))
            assertTrue(Composite.verifyClassical(keyXy, field(c, "context"), m, sig))
            assertFalse(Composite.verifyClassical(keyXy, field(c, "context") + "/other", m, sig))
        }
    }

    /** A high-S signature is returned in its low-S form, which still verifies. */
    @Test
    fun aHighSSignatureIsNormalisedToLowS() {
        val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        for (c in cases) {
            val raw = hex(field(c, "raw_signature_hex"))
            val s = BigInteger(1, raw.copyOfRange(32, 64))
            val high = n - s
            val highBytes = high.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            val highRaw = raw.copyOfRange(0, 32) + ByteArray(32 - highBytes.size) + highBytes
            val lowS = if (s > n.shiftRight(1)) high else s
            val back = Composite.lowS(Composite.derToRaw(Composite.rawToDer(highRaw)))
            assertEquals(lowS, BigInteger(1, back.copyOfRange(32, 64)))
            assertTrue(lowS <= n.shiftRight(1))
            assertTrue(Composite.verifyClassical(keyXy, field(c, "context"), hex(field(c, "message_hex")), back))
        }
    }

    /** A signature that is not 64 bytes is refused rather than passed through. */
    @Test
    fun aSignatureThatIsNot64BytesIsRefused() {
        assertFailsWith<IllegalArgumentException> { Composite.lowS(ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { Composite.lowS(ByteArray(72)) }
    }

    @Test
    fun theSignerMakesTheP256LegOfItsAccount() {
        val params = Composite.p256Params()
        val kf = KeyFactory.getInstance("EC")
        val private = kf.generatePrivate(ECPrivateKeySpec(BigInteger(1, ByteArray(32) { 7 }), params))
        val point = ECPoint(BigInteger(1, keyXy.copyOfRange(0, 32)), BigInteger(1, keyXy.copyOfRange(32, 64)))
        val public = kf.generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey
        val signer = JcaSigner(private, public)
        assertContentEquals(keyXy, signer.publicKeyXy)
        assertEquals("0x" + field(vectors, "account_address_hex"), signer.address)
        val m = byteArrayOf(1, 2, 3)
        val sig = signer.sign("tenzro/signed-message", m)
        assertNull(sig.mlDsa)
        assertTrue(Composite.verifyClassical(keyXy, "tenzro/signed-message", m, sig.classical))
        assertFalse(Composite.verifyClassical(keyXy, "tenzro/tx", m, sig.classical))
    }

    private fun vectorSigner(): JcaSigner {
        val params = Composite.p256Params()
        val kf = KeyFactory.getInstance("EC")
        val private = kf.generatePrivate(ECPrivateKeySpec(BigInteger(1, ByteArray(32) { 7 }), params))
        val point = ECPoint(BigInteger(1, keyXy.copyOfRange(0, 32)), BigInteger(1, keyXy.copyOfRange(32, 64)))
        return JcaSigner(private, kf.generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey)
    }

    /** An ML-DSA-65 key that records what it is asked to sign. */
    private class RecordingMlDsa(private val size: Int = HybridSigner.ML_DSA_SIGNATURE_SIZE) : MlDsaSigner {
        override val publicKey = ByteArray(1952)
        var askedContext: String? = null
        var askedMessage: ByteArray? = null
        override fun sign(context: String, message: ByteArray): ByteArray {
            askedContext = context
            askedMessage = message
            return ByteArray(size) { 5 }
        }
    }

    @Test
    fun theHybridSignerAsksTheMlDsaKeyToSignTheSameRepresentativeUnderTheLabel() {
        val mlDsa = RecordingMlDsa()
        val signer = HybridSigner(vectorSigner(), mlDsa)
        assertContentEquals(keyXy, signer.publicKeyXy)
        val m = byteArrayOf(1, 2, 3)
        val sig = signer.sign("tenzro/tx", m)
        assertTrue(Composite.verifyClassical(keyXy, "tenzro/tx", m, sig.classical))
        assertEquals(HybridSigner.ML_DSA_SIGNATURE_SIZE, sig.mlDsa!!.size)
        assertEquals("COMPSIG-MLDSA65-ECDSA-P256-SHA512", mlDsa.askedContext)
        assertContentEquals(Composite.messageRepresentative("tenzro/tx", m), mlDsa.askedMessage)
    }

    @Test
    fun anMlDsaSignatureOfTheWrongSizeIsRefused() {
        val signer = HybridSigner(vectorSigner(), RecordingMlDsa(64))
        assertFailsWith<IllegalArgumentException> { signer.sign("tenzro/tx", byteArrayOf(1)) }
    }
}
