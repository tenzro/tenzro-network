package com.tenzro.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** Where a key's private half lives, as the Keystore reports for the key it made. */
enum class SecurityLevel { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX }

/**
 * A P-256 key held by the Android Keystore under a label, and the label's
 * HMAC-SHA256 key, the derivation root the node derives its other keys from.
 *
 * Keys are made in StrongBox where the device has one, else in the trusted
 * environment; [securityLevel] says which the key got. The aliases are
 * `<label>#p256` and `<label>#hmac`; other key types under the same label use
 * their own suffix.
 */
class AndroidKeystoreKey private constructor(
    /** The label the key is held under. */
    val label: String,
) {
    private val alias = label + P256_SUFFIX

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        const val P256_SUFFIX = "#p256"
        const val HMAC_SUFFIX = "#hmac"

        private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

        /**
         * The key under [label], made now if there is none. [attestationChallenge]
         * is set when the key is made: the Keystore attests a key once, when it
         * makes it, so the chain of an existing key carries the challenge it was
         * made with.
         */
        @JvmStatic
        @JvmOverloads
        fun openOrCreate(label: String, attestationChallenge: ByteArray? = null): AndroidKeystoreKey {
            require(label.isNotEmpty() && label.length <= 200) { "a label is 1 to 200 characters" }
            val key = AndroidKeystoreKey(label)
            if (!keyStore().containsAlias(key.alias)) {
                generate(key.alias, attestationChallenge)
            }
            return key
        }

        /** The key under [label], or null when there is none. */
        @JvmStatic
        fun open(label: String): AndroidKeystoreKey? =
            AndroidKeystoreKey(label).takeIf { keyStore().containsAlias(it.alias) }

        /** Deletes the P-256 key and the HMAC key under [label]. */
        @JvmStatic
        fun delete(label: String) {
            val ks = keyStore()
            ks.deleteEntry(label + P256_SUFFIX)
            ks.deleteEntry(label + HMAC_SUFFIX)
        }

        private fun purposes(): Int {
            var p = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            if (Build.VERSION.SDK_INT >= 31) p = p or KeyProperties.PURPOSE_AGREE_KEY
            return p
        }

        private fun generate(alias: String, challenge: ByteArray?) {
            fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, purposes())
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                .apply { if (challenge != null) setAttestationChallenge(challenge) }
                .setIsStrongBoxBacked(strongBox)
                .build()
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
            // A device without StrongBox, or whose StrongBox refuses these
            // parameters, makes the key in the trusted environment instead.
            try {
                gen.initialize(spec(true))
                gen.generateKeyPair()
            } catch (e: Exception) {
                keyStore().deleteEntry(alias)
                gen.initialize(spec(false))
                gen.generateKeyPair()
            }
        }

        private fun level(info: KeyInfo): SecurityLevel =
            if (Build.VERSION.SDK_INT >= 31) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> SecurityLevel.TRUSTED_ENVIRONMENT
                    else -> SecurityLevel.SOFTWARE
                }
            } else {
                @Suppress("DEPRECATION")
                if (info.isInsideSecureHardware) SecurityLevel.TRUSTED_ENVIRONMENT else SecurityLevel.SOFTWARE
            }
    }

    private fun privateKey(): PrivateKey =
        keyStore().getKey(alias, null) as? PrivateKey ?: error("no key under $label")

    private fun ecPublic(): ECPublicKey =
        keyStore().getCertificate(alias)?.publicKey as? ECPublicKey ?: error("no key under $label")

    /** The public key, `0x04 || x || y` (65 bytes). */
    fun publicKey(): ByteArray = ecPublic().w.let { Encoding.uncompressed(it.affineX, it.affineY) }

    /** ECDSA over a 32-byte SHA-256 prehash, `r || s` (64 bytes). */
    fun signPrehash(hash: ByteArray): ByteArray {
        require(hash.size == 32) { "a prehash is 32 bytes" }
        val s = Signature.getInstance("NONEwithECDSA")
        s.initSign(privateKey())
        s.update(hash)
        return Encoding.derToRaw(s.sign())
    }

    /**
     * ECDH with [peer] (`0x04 || x || y`): the x-coordinate of the shared
     * point (32 bytes). Android 12 (API 31) or later.
     */
    fun agree(peer: ByteArray): ByteArray {
        check(Build.VERSION.SDK_INT >= 31) { "key agreement in the Keystore needs Android 12 or later" }
        require(peer.size == 65 && peer[0] == 0x04.toByte()) { "a peer key is 65 bytes, 0x04 first" }
        val params = ecPublic().params
        val point = ECPoint(BigInteger(1, peer.copyOfRange(1, 33)), BigInteger(1, peer.copyOfRange(33, 65)))
        val peerKey = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(ECPublicKeySpec(point, params))
        val ka = KeyAgreement.getInstance("ECDH", PROVIDER)
        ka.init(privateKey())
        ka.doPhase(peerKey, true)
        return ka.generateSecret()
    }

    /** The attestation certificate chain of the key, leaf first, each DER. */
    fun certificateChain(): Array<ByteArray> =
        keyStore().getCertificateChain(alias)?.map { it.encoded }?.toTypedArray() ?: emptyArray()

    /** Where the key's private half lives. */
    fun securityLevel(): SecurityLevel {
        val pk = privateKey()
        val info = KeyFactory.getInstance(pk.algorithm, PROVIDER).getKeySpec(pk, KeyInfo::class.java)
        return level(info)
    }

    private fun hmacKey(): SecretKey {
        val ks = keyStore()
        val alias = label + HMAC_SUFFIX
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
        return try {
            gen.init(spec(true))
            gen.generateKey()
        } catch (e: Exception) {
            ks.deleteEntry(alias)
            gen.init(spec(false))
            gen.generateKey()
        }
    }

    /** HMAC-SHA256 of [data] by the label's derivation root, made on first use. */
    fun hmac(data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(hmacKey())
            doFinal(data)
        }

    /** Where the derivation root's key lives. */
    fun hmacSecurityLevel(): SecurityLevel {
        val key = hmacKey()
        val info = SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return level(info)
    }
}
