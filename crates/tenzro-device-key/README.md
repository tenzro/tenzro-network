# tenzro-device-key

Hardware-backed device keys for Tenzro: P-256 keys created and used inside a
TPM 2.0 (Linux `/dev/tpmrm0`, Windows TBS), the Apple Secure Enclave
(CryptoKit) or the Android Keystore (StrongBox, else the trusted environment),
and keys the hardware cannot hold derived on demand from one it does.

## Capabilities

1. **Signing** (`signer::open_or_create(label)`, `DeviceKey::sign_prehash`):
   ECDSA P-256 inside the hardware. The private key never enters process
   memory.
2. **Secret wrapping** (`DeviceKey::wrap_secret` / `unwrap_secret`): ECIES to
   the device's agreement key, recoverable only by the same hardware.
3. **Derivation** (`derive::DerivationRoot`): Ed25519, X25519 and ML-DSA-65
   keys derived on demand. The root is a non-exportable hardware
   key:
   - TPM: an HMAC-SHA256 key the TPM generated (`TPM2_Create`), usable only
     through `TPM2_PolicySigned` by the machine's attestation key: every use
     carries that key's fresh signature, made inside the TPM, over the
     session's `nonceTPM` with a short expiration. The attestation key is a
     restricted signing key in the endorsement hierarchy at a persistent
     handle, checked against the TPM's endorsement key by credential
     activation before the root is used. The wrapped key blob is
     `derive-root.tpm` in `$TENZRO_DEVICE_KEY_DIR` (default
     `~/.local/state/tenzro/device-keys`).
   - Secure Enclave: ECDH between the enclave agreement key and a fixed point
     with no known discrete logarithm.
   - Passkey: the WebAuthn `prf` extension (CTAP2 `hmac-secret`) evaluated
     with `derive::prf_salt(label)`.
   - Android Keystore: an HMAC-SHA256 key the Keystore generated for the
     hidden root label, in StrongBox where the device has one.

   The hardware output is expanded with HKDF-SHA256 under the backend, the key
   kind and a label into a seed that wipes itself on drop. The key is handed
   to a closure and dropped when it returns; no function returns a seed or a
   key, and nothing is cached or written.

   ```rust,ignore
   let root = tenzro_device_key::DerivationRoot::open_or_create()?;
   let sig = root.with_ed25519("tenzro/validator/ed25519", |k| k.sign(b"message"))?;
   ```

   A machine with no TPM, no Secure Enclave and no hardware-backed Android
   Keystore has no root, and the call refuses. There is no software fallback.

## Android

Android has no native Keystore API, so `backend_android` calls the Kotlin
class `com.tenzro.keystore.AndroidKeystoreKey` (`sdk/tenzro-android-node`)
through JNI. The app that carries the node calls
`com.tenzro.keystore.KeystoreBridge.install()` once, on a Java thread, after
loading the node's native library; until then the node finds no hardware key.
A key or a derivation root the Keystore holds in software is refused (a key
made that way is deleted): such a device is enrolled under another machine of
its operator. A key is attested once, when it is made, over a challenge bound
to its label; `DeviceKey::attest` returns its certificate chain, leaf first,
each certificate as a 4-byte big-endian length and its DER. Key agreement
(`unwrap_secret`) needs Android 12 (API 31). ML-DSA-65 is derived from the
Keystore root, not held in the Keystore.

## Provisioning the TPM root

```sh
tenzro-node tpm provision
```

once per machine, as a user that can open `/dev/tpmrm0`. It makes the
storage root, the attestation key and the node identity key at persistent
handles; the attestation key (`[tpm] root_authorization_handle`, default
`0x81018001`) authorises the derivation root. No secret is stored: each use of
the root needs that key's signature over a fresh `nonceTPM`, made in the TPM,
so a signature authorises one session only, and PCR 7 (the secure-boot state)
holding the value it held when the root was made. Changing the secure-boot
state (turning secure boot off, enrolling other boot authorities) makes the root
unusable and its derived keys must be replaced. The boundary is the TPM device: a
process that can open the TPM and read the wrapped root can use it, so keep
`/dev/tpmrm0` to the node's user. Give the unit and any `tenzro-node init` run
the same `TENZRO_DEVICE_KEY_DIR`: the wrapped root blob lives there.

## Removing stale TPM handles

Provisioning never overwrites or deletes a persistent handle, and no
`tenzro-node` command does either. The handles it may create are:

| handle | key |
|---|---|
| `0x81018000` | storage root |
| `0x81018001` | machine attestation key |
| `0x81018100` | default node identity key |
| `0x81018101` to `0x810181ff` | one identity key per key namespace, from the slot its label hashes to |
| an `EK_PROFILES` handle | the certified endorsement key that attestation reads |

Every key namespace a machine ever ran under keeps its identity slot. Once all
255 namespace slots are held, provisioning a new namespace stops with "every
one of the 255 namespace identity slots holds another key". Free a slot by
hand, with the node stopped, as a user that can open `/dev/tpmrm0`:

1. List the persistent handles: `tpm2_getcap handles-persistent`.
2. For each namespace still in use, run `tenzro-node tpm provision` under it.
   Its `node identity key` line names that namespace's slot. Keep those
   slots.
3. Remove a namespace slot that no namespace in use holds:
   `tpm2_evictcontrol -C o -c 0x810181NN`. The keys derived under that
   namespace are gone for good, and so is the identity that key made.

Never evict `0x81018000`, `0x81018001` or the endorsement key's handle while
any namespace on the machine is in use. Every identity and the machine's
attestation depend on them.

## Secure Enclave notes

The enclave key is a SEP-wrapped blob stored under
`~/Library/Application Support/Tenzro/device-keys/<sha256(label)>/`
(override with `TENZRO_DEVICE_KEY_DIR`); it is useless on any other machine.
There is no Secure Enclave in virtual machines, and the enclave offers no
Ed25519, which is why keys on other curves are derived.

## Cargo features

| Feature | Default | Adds |
|---|---|---|
| `test-root` | off | `DerivationRoot::for_tests`, a fixed software root for other crates' tests. Enabled only from dev-dependencies. |

## License

Apache-2.0
