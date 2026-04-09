# Sifero Cloud - Cryptography Module

**Open-source client-side encryption used by [Sifero Cloud](https://sifero.cloud)**

This is the complete cryptographic layer that protects your data. We publish it so anyone can verify that Sifero Cloud implements true Zero-Knowledge encryption.

## Architecture

All encryption happens **in your browser** before data leaves your device. The server never sees your plaintext data, encryption keys, or password.

```
Password (user's brain)
|
v
Argon2id (64MB, 3 iterations, 4 parallelism) -> Master Key (KDF v2)
PBKDF2 (600,000 iterations, SHA-256)          -> Master Key (KDF v1, legacy)
|
Argon2id (client-side) -> Password Hash -> HMAC-SHA256 (server-side) -> Auth Verifier
|
v
Master Key (256-bit AES, never leaves client)
|
|--- HKDF(userSalt, "file-encryption")     -> File Encryption Key
|--- HKDF(userSalt, "metadata-encryption") -> Metadata Key
|--- HKDF(userSalt, "metadata-signing")    -> HMAC Signing Key (HMAC-SHA256)
|--- HKDF(userSalt, "search-encryption")   -> Search Index Key
|--- HKDF(userSalt, "chat-{roomId}")       -> Per-Room Chat Key
|--- HKDF(userSalt, "dead-drop-wrap")      -> Dead Drop Key Wrapping Key
|
v
Per-File DEK (random AES-256-GCM key, wrapped with File Encryption Key)
|
v
AES-256-GCM (random 12-byte IV, mandatory AAD binding to fileId)
```

## Key Derivation

### Master Key (KDF)
- **Argon2id** (v2, new users): 64MB memory, 3 iterations, 4 parallelism, 32-byte output
- **PBKDF2** (v1, legacy): 600,000 iterations, SHA-256, 32-byte output
- Salt is per-user, generated at registration, stored on server

### Sub-Key Derivation (HKDF)
- **HKDF-SHA256** with per-user salt (HKDF v2) or static salt (HKDF v1, legacy)
- Each purpose gets a separate derived key via `info` parameter
- Sub-keys are non-extractable (cannot be exported from WebCrypto)

### Authentication (separate from encryption)
- Client computes `Argon2id(password, authSalt)` -> sends hash to server
- Server applies `HMAC-SHA256(jwtSecret, clientHash)` -> stores result
- Server never sees the raw password
- Timing-safe comparison (`crypto.timingSafeEqual`) for all hash checks

## Encryption

### Files
- **Per-file DEK**: Each file gets a unique random AES-256-GCM key (Data Encryption Key)
- **DEK wrapping**: DEK is encrypted with the user's File Encryption Key (derived via HKDF)
- **AAD binding**: File ID is bound as Additional Authenticated Data — prevents ciphertext swapping
- **Format**: `[0x02][IV: 12 bytes][Ciphertext + GCM Tag]`
- Legacy format (v1, no AAD): `[IV: 12 bytes][Ciphertext + GCM Tag]`

### Metadata
- File names and metadata encrypted with Metadata Key (AES-256-GCM)
- Stored as JSON: `{"ciphertext": "base64", "iv": "base64"}`

### Metadata Signatures
- HMAC-SHA256 over `fileId:encryptedName:encryptedMeta`
- Signing key derived via HKDF with purpose `"metadata-signing"`
- Client verifies signatures on download to detect tampering

## Sharing
- Random 256-bit share key generated per share link
- File re-encrypted with share key (AES-256-GCM)
- Share key transmitted in URL fragment (`#key`) — NOT sent to server
- Optional password protection (Argon2id server-side)

## Dead Drop (Anonymous File Receiving)
- RSA-4096 OAEP key pair generated per drop
- Public key shared publicly, private key wrapped with user's master key
- Hybrid encryption: ephemeral AES-256-GCM key per file, wrapped with RSA public key
- Format: `[wrappedKeyLen: 2 bytes][RSA-wrapped AES key][IV: 12 bytes][Ciphertext]`

## Chat (End-to-End Encryption)
- Per-room key derived via HKDF with purpose `"chat-{roomId}"`
- Messages encrypted with AES-256-GCM
- Sender name encrypted within message payload

## What the Server Stores
| Data | Format | Server Can Read? |
|------|--------|-----------------|
| File content | AES-256-GCM ciphertext | No |
| File name | AES-256-GCM ciphertext | No |
| File metadata | AES-256-GCM ciphertext | No |
| File size | Plaintext (bytes) | Yes |
| Timestamps | Plaintext | Yes |
| Wrapped DEK | AES-256-GCM ciphertext | No |
| Password hash | HMAC(Argon2id(pw)) | No (cannot reverse) |
| Key salt | Plaintext | Yes (public parameter) |
| Auth salt | Plaintext | Yes (public parameter) |
| Chat messages | AES-256-GCM ciphertext | No |
| Notes | AES-256-GCM ciphertext | No |
| Search index | AES-256-GCM ciphertext | No |

## Security Properties
- **Zero-Knowledge**: Server cannot decrypt any user data
- **Forward secrecy**: Per-file DEKs limit exposure if one key is compromised
- **Tamper detection**: HMAC signatures on metadata
- **No downgrade**: v2 clients never fall back to weaker v1 encryption
- **Timing-safe**: All hash comparisons use constant-time algorithms
- **AAD binding**: Prevents ciphertext substitution attacks

## Dependencies
- `hash-wasm` — Argon2id (WebAssembly, runs in browser)
- `Web Crypto API` — AES-GCM, HKDF, PBKDF2, RSA-OAEP, HMAC (browser-native)

## Audit Status
This code is prepared for independent security audit. All cryptographic operations are contained in a single file (`crypto.ts`) for easy review.

## License
MIT — See [LICENSE](LICENSE)
