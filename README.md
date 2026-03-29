# Sifero Cloud - Cryptography Module

**Open-source client-side encryption used by [Sifero Cloud](https://sifero.cloud)**

This is the complete cryptographic layer that protects your data. We publish it so anyone can verify that Sifero Cloud implements true Zero-Knowledge encryption.

## Architecture

All encryption happens **in your browser** before data leaves your device. The server never sees your plaintext data, encryption keys, or password.

```
Password (user's brain)
|
v
PBKDF2 (600,000 iterations, SHA-256) -> Master Key (encryption)
Argon2id (server-side auth hash) -> Password Verifier (login only)
|
v
Master Key (256-bit, never leaves client)
|
|--- HKDF("file-encryption") -> File Encryption Key
|--- HKDF("metadata-encryption") -> Metadata Key
|--- HKDF("metadata-signing") -> HMAC Signing Key
|--- HKDF("notes-encryption") -> Notes Key
|--- HKDF("search-encryption") -> Search Index Key
+--- HKDF("chat-encryption") -> Chat Key
|
v
AES-256-GCM (per-file random IV, with AAD binding)

```


## Key Derivation

**PBKDF2** with 600,000 iterations converts your password into a master encryption key. This makes brute-force attacks computationally infeasible. The master key never leaves the browser.

**Argon2id** is used separately for server-side password verification (login). The Argon2id hash cannot be used to derive encryption keys - these are two independent processes.

**HKDF** (HMAC-based Key Derivation Function) derives separate sub-keys for each purpose, so compromising one doesn't compromise others.

## Encryption

**AES-256-GCM** (Galois/Counter Mode) provides both confidentiality and authenticity. Each encryption operation uses a cryptographically random 12-byte IV (Initialization Vector).

**AAD (Additional Authenticated Data)**: New files are encrypted with the file ID bound as AAD, preventing ciphertext swap attacks where a malicious server could substitute one file's ciphertext for another.

Encrypted output format:

```
v1 (legacy): [12 bytes IV][N bytes ciphertext][16 bytes auth tag]
v2 (current): [0x02 version][12 bytes IV][N bytes ciphertext][16 bytes auth tag]
```


Both formats are supported for backward compatibility.

## Metadata Integrity

File metadata (encrypted names, types) is signed with **HMAC-SHA256** using a dedicated signing key derived via HKDF. This prevents a malicious server from tampering with file metadata without detection.

## What Gets Encrypted

| Data | Encrypted Client-Side | Key Used |
|------|----------------------|----------|
| File contents | Yes | file-encryption |
| File names | Yes | metadata-encryption |
| File metadata | Yes + HMAC signed | metadata-encryption + metadata-signing |
| Notes (title + body) | Yes | notes-encryption |
| Search index | Yes | search-encryption |
| Chat messages | Yes | chat-encryption |

## What The Server Sees

- Encrypted blobs (indistinguishable from random bytes)
- Argon2id password hash (for login verification only - cannot reverse to password or derive encryption keys)
- File sizes and timestamps
- User actions (upload, download, delete)
- IP addresses and session metadata

## What The Server Cannot See

- File contents
- File names
- Note contents
- Chat messages
- Your password
- Your encryption keys

## Verification

To verify this is the actual code running on sifero.cloud:

1. Open https://sifero.cloud
2. Open browser DevTools (F12) - Sources
3. Search for `PBKDF2` or `AES-GCM`
4. Compare with this repository

## Security Properties

- **Password = Key**: If you forget your password, your data is permanently lost. We cannot recover it.
- **No key escrow**: We never store, transmit, or have access to your encryption keys.
- **Nonce uniqueness**: Each encryption operation uses a cryptographically random IV, so identical files produce different ciphertext.
- **Authenticated encryption**: AES-GCM detects any tampering with encrypted data.
- **AAD binding**: File ciphertext is cryptographically bound to the file ID, preventing swap attacks.
- **Metadata signing**: HMAC signatures detect unauthorized changes to file metadata.

## Dependencies

Zero external cryptography dependencies. Uses only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) built into every modern browser.

## License

MIT License - see [LICENSE](LICENSE)

## Audit & Security

We welcome independent security audits and run periodic [Encryption Challenges](https://sifero.cloud/challenge.html) to publicly verify our encryption strength.

If you find a vulnerability, please report it to security@sifero.cloud.

---

**Sifero Cloud** - Zero-Knowledge Encrypted Cloud Storage
https://sifero.cloud

