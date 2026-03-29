/**
 * ═══════════════════════════════════════════════
 * SIFERO CLOUD - Client-Side Zero-Knowledge Crypto
 * ═══════════════════════════════════════════════
 *
 * ALL encryption/decryption happens HERE, in the browser.
 * The server NEVER sees plaintext data.
 *
 * Key hierarchy:
 * 1. User enters password
 * 2. PBKDF2(password, salt, 600K) → Master Key (never leaves client)
 * 3. HKDF(masterKey, "file-encryption") → File Encryption Key
 * 4. HKDF(masterKey, "metadata-encryption") → Metadata Key
 * 5. HKDF(masterKey, "metadata-signing") → HMAC Signing Key
 * 6. Each file gets a random IV (AES-256-GCM) with AAD binding
 *
 * What server stores:
 * - Salt (public, needed for key derivation)
 * - Encrypted blobs (ciphertext)
 * - Encrypted metadata (ciphertext)
 * Server CANNOT decrypt anything without the master password.
 */

// ═══════════════════════════════════════
// KEY DERIVATION
// ═══════════════════════════════════════

/** Generate a random salt for new users */
export function generateSalt(): string {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  return bufferToBase64(salt);
}

/** Derive master key from password using PBKDF2 (Web Crypto API)
 *  PBKDF2-SHA256 with 600,000 iterations (OWASP recommended minimum)
 *  Argon2id is used separately for server-side password verification */
export async function deriveMasterKey(
  password: string,
  saltBase64: string
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const salt = base64ToBuffer(saltBase64);

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive master key with PBKDF2
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 600_000, // OWASP recommended minimum
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true, // extractable for sub-key derivation
    ['encrypt', 'decrypt']
  );
}

/** Derive a sub-key for specific purpose (file encryption, metadata, etc.) */
export async function deriveSubKey(
  masterKey: CryptoKey,
  purpose: string
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const masterKeyRaw = await crypto.subtle.exportKey('raw', masterKey);

  // Import as HKDF key material
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    masterKeyRaw,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('darkcloud-v1'),
      info: encoder.encode(purpose),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Derive HMAC signing key for metadata integrity */
export async function deriveSigningKey(
  masterKey: CryptoKey
): Promise<CryptoKey> {
  const masterKeyRaw = await crypto.subtle.exportKey('raw', masterKey);
  const hkdfKey = await crypto.subtle.importKey('raw', masterKeyRaw, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('darkcloud-v1'), info: new TextEncoder().encode('metadata-signing') },
    hkdfKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']
  );
}

/** Sign metadata with HMAC-SHA256 */
export async function signMetadata(
  signingKey: CryptoKey,
  fileId: string,
  encryptedName: string,
  encryptedMeta: string
): Promise<string> {
  const data = new TextEncoder().encode(fileId + ':' + encryptedName + ':' + encryptedMeta);
  const sig = await crypto.subtle.sign('HMAC', signingKey, data);
  return bufferToBase64(new Uint8Array(sig));
}

/** Verify metadata HMAC signature */
export async function verifyMetadata(
  signingKey: CryptoKey,
  fileId: string,
  encryptedName: string,
  encryptedMeta: string,
  signature: string
): Promise<boolean> {
  const data = new TextEncoder().encode(fileId + ':' + encryptedName + ':' + encryptedMeta);
  const sig = base64ToBuffer(signature);
  return crypto.subtle.verify('HMAC', signingKey, sig, data);
}

// ═══════════════════════════════════════
// ENCRYPTION / DECRYPTION
// ═══════════════════════════════════════

export interface EncryptedData {
  ciphertext: string;  // Base64
  iv: string;          // Base64
}

/** Encrypt data with AES-256-GCM */
export async function encrypt(
  key: CryptoKey,
  plaintext: ArrayBuffer
): Promise<EncryptedData> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintext
  );

  return {
    ciphertext: bufferToBase64(new Uint8Array(ciphertext)),
    iv: bufferToBase64(iv),
  };
}

/** Decrypt data with AES-256-GCM */
export async function decrypt(
  key: CryptoKey,
  encryptedData: EncryptedData
): Promise<ArrayBuffer> {
  const iv = base64ToBuffer(encryptedData.iv);
  const ciphertext = base64ToBuffer(encryptedData.ciphertext);

  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    ciphertext as BufferSource
  );
}

/** Encrypt a string (for filenames, metadata) */
export async function encryptString(
  key: CryptoKey,
  text: string
): Promise<string> {
  const encoder = new TextEncoder();
  const encrypted = await encrypt(key, encoder.encode(text).buffer as ArrayBuffer);
  return JSON.stringify(encrypted);
}

/** Decrypt a string */
export async function decryptString(
  key: CryptoKey,
  encryptedJson: string
): Promise<string> {
  const decoder = new TextDecoder();
  const encrypted: EncryptedData = JSON.parse(encryptedJson);
  const decrypted = await decrypt(key, encrypted);
  return decoder.decode(decrypted);
}

/** Encrypt a file (ArrayBuffer)
 *  Format v2 (with AAD): [0x02][12-byte IV][ciphertext+tag]
 *  Format v1 (legacy):   [12-byte IV][ciphertext+tag]
 *  AAD = fileId encoded as UTF-8, binds ciphertext to specific file (prevents swap attacks)
 */
export async function encryptFile(
  key: CryptoKey,
  fileData: ArrayBuffer,
  fileId?: string
): Promise<Blob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const aad = fileId ? encoder.encode(fileId) : undefined;

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, ...(aad ? { additionalData: aad as BufferSource } : {}) },
    key,
    fileData
  );

  if (aad) {
    // v2 format: version byte + IV + ciphertext
    const combined = new Uint8Array(1 + iv.length + ciphertext.byteLength);
    combined[0] = 0x02; // version marker
    combined.set(iv, 1);
    combined.set(new Uint8Array(ciphertext), 1 + iv.length);
    return new Blob([combined], { type: 'application/octet-stream' });
  } else {
    // v1 format (legacy): IV + ciphertext
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return new Blob([combined], { type: 'application/octet-stream' });
  }
}

/** Decrypt a file - supports both v1 (no AAD) and v2 (with AAD) formats */
export async function decryptFile(
  key: CryptoKey,
  encryptedBlob: ArrayBuffer,
  fileId?: string
): Promise<ArrayBuffer> {
  const data = new Uint8Array(encryptedBlob);
  const encoder = new TextEncoder();

  // Check version marker
  if (data[0] === 0x02 && fileId) {
    // v2 format: [0x02][12-byte IV][ciphertext+tag]
    const iv = data.slice(1, 13);
    const ciphertext = data.slice(13);
    const aad = encoder.encode(fileId);
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad as BufferSource },
      key,
      ciphertext
    );
  }

  // v1 format (legacy) or no fileId: [12-byte IV][ciphertext+tag]
  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12);
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
}

// ═══════════════════════════════════════
// SHARE LINK CRYPTO
// ═══════════════════════════════════════

/** Generate a random key for share links (goes in URL fragment #) */
export function generateShareKey(): string {
  const key = crypto.getRandomValues(new Uint8Array(32));
  return bufferToHex(key);
}

/** Import a share key from hex for encrypt/decrypt */
async function importShareKey(shareKeyHex: string, usages: KeyUsage[]): Promise<CryptoKey> {
  const keyData = hexToBuffer(shareKeyHex);
  return crypto.subtle.importKey(
    'raw',
    keyData.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

/** Encrypt file data with a share-specific key */
export async function encryptForShare(
  shareKeyHex: string,
  plaintext: ArrayBuffer
): Promise<Blob> {
  const key = await importShareKey(shareKeyHex, ['encrypt']);
  return encryptFile(key, plaintext);
}

/** Encrypt filename with share key (for share metadata) */
export async function encryptNameForShare(
  shareKeyHex: string,
  fileName: string
): Promise<string> {
  const key = await importShareKey(shareKeyHex, ['encrypt']);
  return encryptString(key, fileName);
}

/** Decrypt shared file using key from URL fragment */
export async function decryptShared(
  shareKeyHex: string,
  encryptedBlob: ArrayBuffer
): Promise<ArrayBuffer> {
  const key = await importShareKey(shareKeyHex, ['decrypt']);
  return decryptFile(key, encryptedBlob);
}

/** Decrypt shared filename using key from URL fragment */
export async function decryptNameFromShare(
  shareKeyHex: string,
  encryptedName: string
): Promise<string> {
  const key = await importShareKey(shareKeyHex, ['decrypt']);
  return decryptString(key, encryptedName);
}

// ═══════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════

function bufferToBase64(buffer: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer;
}

function bufferToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/** Format file size for display */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
