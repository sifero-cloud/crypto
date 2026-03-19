# Sifero Cloud - Cryptography Module

**Open-source client-side encryption used by [Sifero Cloud](https://sifero.cloud)**

This is the complete cryptographic layer that protects your data. We publish it so anyone can verify that Sifero Cloud implements true Zero-Knowledge encryption.

## Architecture

All encryption happens **in your browser** before data leaves your device. The server never sees your plaintext data, encryption keys, or password.

```
Password (user's brain)
    |
    v
PBKDF2 (600,000 iterations, SHA-256)
    |
    v
Master Key (256-bit)
    |
    |--- HKDF("file-encryption")     -> File Encryption Key
    |--- HKDF("metadata-encryption")  -> Metadata Key
    |--- HKDF("notes-encryption")     -> Notes Key
    |--- HKDF("search-encryption")    -> Search Index Key
    +--- HKDF("chat-encryption")      -> Chat Key
              |
              v
        AES-256-GCM (per-file random IV)
```

## Key Derivation

**PBKDF2** with 600,000 iterations converts your password into a master key. This makes brute-force attacks computationally infeasible.

**HKDF** (HMAC-based Key Derivation Function) derives separate sub-keys for each purpose, so compromising one doesn't compromise others.

## Encryption

**AES-256-GCM** (Galois/Counter Mode) provides both confidentiality and authenticity. Each file gets a unique random 12-byte IV (Initialization Vector).

Encrypted output format:
```
[12 bytes IV][N bytes ciphertext][16 bytes auth tag]
```

## What Gets Encrypted

| Data | Encrypted Client-Side | Key Used |
|------|----------------------|----------|
| File contents | Yes | file-encryption |
| File names | Yes | metadata-encryption |
| Notes (title + body) | Yes | notes-encryption |
| Search index | Yes | search-encryption |
| Chat messages | Yes | chat-encryption |

## What The Server Sees

- Encrypted blobs (random bytes)
- Argon2id password hash (cannot reverse to password or encryption key)
- File sizes and timestamps
- User actions (upload, download, delete)

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

## Security Considerations

- **Password = Key**: If you forget your password, your data is permanently lost. We cannot recover it.
- **No key escrow**: We never store, transmit, or have access to your encryption keys.
- **Forward secrecy**: Each file uses a unique IV, so identical files produce different ciphertext.
- **Authenticated encryption**: AES-GCM detects any tampering with encrypted data.

## Dependencies

Zero external cryptography dependencies. Uses only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) built into every modern browser.

## License

MIT License - see [LICENSE](LICENSE)

## Audit

We welcome independent security audits. If you find a vulnerability, please report it to security@sifero.cloud.

---

**Sifero Cloud** - Zero-Knowledge Encrypted Cloud Storage
https://sifero.cloud
