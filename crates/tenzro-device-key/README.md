# tenzro-device-key

Hardware-backed device keys for Tenzro: P-256 keys created and used inside a
TPM 2.0 (Linux `/dev/tpmrm0`, Windows TBS) or the Apple Secure Enclave
(CryptoKit), and keys the hardware cannot hold derived on demand from one it
does.

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

   The hardware output is expanded with HKDF-SHA256 under the backend, the key
   kind and a label into a seed that wipes itself on drop. The key is handed
   to a closure and dropped when it returns; no function returns a seed or a
   key, and nothing is cached or written.

   ```rust,ignore
   let root = tenzro_device_key::DerivationRoot::open_or_create()?;
   let sig = root.with_ed25519("tenzro/validator/ed25519", |k| k.sign(b"message"))?;
   ```

   A machine with no TPM and no Secure Enclave has no root, and the call
   refuses. There is no software fallback.

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
