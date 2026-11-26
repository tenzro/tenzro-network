package com.tenzro.keystore

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** On a device or emulator: the key in the Keystore it runs on. */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreKeyTest {
    private val label = "tenzro/test/keystore"

    @After
    fun cleanUp() = AndroidKeystoreKey.delete(label)

    private fun ecKey(point: ByteArray, params: java.security.spec.ECParameterSpec) =
        KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(ECPoint(BigInteger(1, point.copyOfRange(1, 33)), BigInteger(1, point.copyOfRange(33, 65))), params),
        ) as ECPublicKey

    @Test
    fun aKeyIsMadeOnceAndSignsPrehashesItsPublicKeyVerifies() {
        assertNull(AndroidKeystoreKey.open(label))
        val key = AndroidKeystoreKey.openOrCreate(label, "challenge".toByteArray())
        val public = key.publicKey()
        assertEquals(65, public.size)
        assertArrayEquals(public, AndroidKeystoreKey.openOrCreate(label).publicKey())
        assertArrayEquals(public, AndroidKeystoreKey.open(label)!!.publicKey())

        val message = "tenzro".toByteArray()
        val raw = key.signPrehash(MessageDigest.getInstance("SHA-256").digest(message))
        assertEquals(64, raw.size)
        fun int(n: BigInteger) = n.toByteArray().let { byteArrayOf(0x02, it.size.toByte()) + it }
        val body = int(BigInteger(1, raw.copyOfRange(0, 32))) + int(BigInteger(1, raw.copyOfRange(32, 64)))
        val der = byteArrayOf(0x30, body.size.toByte()) + body
        val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val params = (gen.generateKeyPair().public as ECPublicKey).params
        val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(ecKey(public, params)); update(message) }
        assertTrue(verifier.verify(der))

        assertTrue(key.certificateChain().isNotEmpty())
        Log.i("AndroidKeystoreKeyTest", "key security level: ${key.securityLevel()}, root: ${key.hmacSecurityLevel()}, SDK ${Build.VERSION.SDK_INT}")
    }

    @Test
    fun theDerivationRootIsStablePerLabelAndInput() {
        val key = AndroidKeystoreKey.openOrCreate(label)
        val a = key.hmac("a".toByteArray())
        assertEquals(32, a.size)
        assertArrayEquals(a, AndroidKeystoreKey.open(label)!!.hmac("a".toByteArray()))
        assertFalse(a.contentEquals(key.hmac("b".toByteArray())))
    }

    @Test
    fun keyAgreementGivesTheSecretThePeerComputes() {
        if (Build.VERSION.SDK_INT < 31) return
        val key = AndroidKeystoreKey.openOrCreate(label)
        val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val peer = gen.generateKeyPair()
        val w = (peer.public as ECPublicKey).w
        val ours = key.agree(Encoding.uncompressed(w.affineX, w.affineY))
        val theirs = KeyAgreement.getInstance("ECDH").run {
            init(peer.private)
            doPhase(ecKey(key.publicKey(), (peer.public as ECPublicKey).params), true)
            generateSecret()
        }
        assertNotNull(ours)
        assertArrayEquals(theirs, ours)
    }
}
