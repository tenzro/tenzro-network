# tenzro-kotlin-sdk

A minimal Kotlin/JVM library for Tenzro account keys on Android and the JVM. Status: 0.1.0,
early.

## What it does

- `Composite`: the composite signature format Tenzro accounts sign with (ML-DSA-65 paired with
  ECDSA P-256): the message representative `M'` for a protocol context, the account address of a
  P-256 key, and a check of a P-256 leg.
- `TenzroSigner` and `JcaSigner`: the P-256 leg with any JCA key. On Android,
  `JcaSigner.fromKeyStore(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }, alias)`
  signs with a key in the device's TEE or StrongBox; create it with `KeyGenParameterSpec`
  (`PURPOSE_SIGN`, `secp256r1`, `DIGEST_SHA256`).

Tests hold the format and the signer to the shared vectors in `../fixtures/hwsign/vectors.json`.

## Not done

- The ML-DSA-65 leg, which transactions and payment authorizations need.
- A JSON-RPC client, passkey signing, and an Android library (AAR) build; the Android Keystore
  path has not run on a device.

## Build

```sh
gradle test
```

Needs Gradle 9 and a JDK 17 or newer.
