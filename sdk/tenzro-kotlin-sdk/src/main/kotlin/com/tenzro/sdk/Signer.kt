package com.tenzro.sdk

import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey

/** A composite signature: the P-256 leg and, when the signer holds one, the ML-DSA-65 leg. */
class CompositeSignature(
    /** ECDSA P-256 over `SHA-256(M')`, `r || s` (64 bytes). */
    val classical: ByteArray,
    /** The ML-DSA-65 leg over `M'`, or null when the signer holds no ML-DSA-65 key. */
    val mlDsa: ByteArray?,
)

/** A key that signs for a Tenzro account in the [Composite] format. */
interface TenzroSigner {
    /** The account's P-256 public key, `x || y` (64 bytes). */
    val publicKeyXy: ByteArray

    /** The account address the key derives. */
    val address: String get() = Composite.accountAddress(publicKeyXy)

    /** Signs [message] for [context]. */
    fun sign(context: String, message: ByteArray): CompositeSignature
}

/**
 * A key that makes the ML-DSA-65 leg of an account's composite signature: the account's enrolled one,
 * held where its owner keeps it. [HybridSigner] only asks it to sign.
 */
interface MlDsaSigner {
    /** The ML-DSA-65 public key (1952 bytes). */
    val publicKey: ByteArray

    /**
     * Signs [message], the composite message representative `M'`, with [context] as its FIPS 204
     * context string: the composite label.
     */
    fun sign(context: String, message: ByteArray): ByteArray
}

/**
 * An account's whole composite signature: the P-256 leg from [p256] and the ML-DSA-65 leg from
 * [mlDsa], both over the same `M'`.
 */
class HybridSigner(private val p256: TenzroSigner, private val mlDsa: MlDsaSigner) : TenzroSigner {
    override val publicKeyXy: ByteArray get() = p256.publicKeyXy

    override fun sign(context: String, message: ByteArray): CompositeSignature {
        val classical = p256.sign(context, message).classical
        val leg = mlDsa.sign(Composite.LABEL_CONTEXT, Composite.messageRepresentative(context, message))
        require(leg.size == ML_DSA_SIGNATURE_SIZE) { "an ML-DSA-65 signature is $ML_DSA_SIGNATURE_SIZE bytes" }
        return CompositeSignature(classical, leg)
    }

    companion object {
        /** The size of an ML-DSA-65 signature. */
        const val ML_DSA_SIGNATURE_SIZE = 3309
    }
}

/**
 * The P-256 leg of an account key held by a JCA [PrivateKey] whose public key is [publicKey].
 * On Android, open it from the `AndroidKeyStore` key store ([fromKeyStore]), where the key lives in
 * the device's TEE or StrongBox and never leaves it; make the key there with `KeyGenParameterSpec`
 * (`KeyProperties.PURPOSE_SIGN`, `ECGenParameterSpec("secp256r1")`, `KeyProperties.DIGEST_SHA256`).
 *
 * It holds no ML-DSA-65 key, so its signatures carry only the P-256 leg. An account that has
 * enrolled an ML-DSA-65 key, and every transaction and payment authorization the ledger admits,
 * need both legs: wrap it in a [HybridSigner] with the account's ML-DSA-65 key.
 */
class JcaSigner(private val key: PrivateKey, publicKey: ECPublicKey) : TenzroSigner {
    override val publicKeyXy: ByteArray = Composite.xy(publicKey)

    override fun sign(context: String, message: ByteArray): CompositeSignature {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(key)
        s.update(Composite.messageRepresentative(context, message))
        return CompositeSignature(Composite.lowS(Composite.derToRaw(s.sign())), null)
    }

    companion object {
        /** The key under [alias] in [keyStore], such as the `AndroidKeyStore`. */
        fun fromKeyStore(keyStore: KeyStore, alias: String, password: CharArray? = null): JcaSigner {
            val key = requireNotNull(keyStore.getKey(alias, password) as? PrivateKey) { "no private key under $alias" }
            val public = requireNotNull(keyStore.getCertificate(alias)?.publicKey as? ECPublicKey) {
                "no EC public key under $alias"
            }
            return JcaSigner(key, public)
        }
    }
}
