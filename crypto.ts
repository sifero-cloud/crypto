/**
 * ═══════════════════════════════════════════════
 * SIFERO CLOUD — Client-Side Zero-Knowledge Crypto
 * ═══════════════════════════════════════════════
 *
 * ALL encryption/decryption happens HERE, in the browser.
 * The server NEVER sees plaintext data.
 *
 * Key hierarchy:
 * 1. User enters password
 * 2. Argon2id(password, salt) → Master Key (never leaves client)
 * 3. HKDF(masterKey, "file-encryption") → File Encryption Key
 * 4. HKDF(masterKey, "metadata-encryption") → Metadata Key
 * 5. Each file gets a random IV (AES-256-GCM)
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
 *  In production: use Argon2id via WASM for stronger KDF
 *  For MVP: PBKDF2 with high iterations is acceptable */
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
      salt,
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
    { name: 'AES-GCM', iv },
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
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
}

/** Encrypt a string (for filenames, metadata) */
export async function encryptString(
  key: CryptoKey,
  text: string
): Promise<string> {
  const encoder = new TextEncoder();
  const encrypted = await encrypt(key, encoder.encode(text));
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

/** Encrypt a file (ArrayBuffer) */
export async function encryptFile(
  key: CryptoKey,
  fileData: ArrayBuffer
): Promise<Blob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    fileData
  );

  // Prepend IV to ciphertext (first 12 bytes = IV)
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return new Blob([combined], { type: 'application/octet-stream' });
}

/** Decrypt a file (IV is prepended to ciphertext) */
export async function decryptFile(
  key: CryptoKey,
  encryptedBlob: ArrayBuffer
): Promise<ArrayBuffer> {
  const data = new Uint8Array(encryptedBlob);
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

/** Encrypt file data with a share-specific key */
export async function encryptForShare(
  shareKeyHex: string,
  plaintext: ArrayBuffer
): Promise<Blob> {
  const keyData = hexToBuffer(shareKeyHex);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  return encryptFile(key, plaintext);
}

/** Decrypt shared file using key from URL fragment */
export async function decryptShared(
  shareKeyHex: string,
  encryptedBlob: ArrayBuffer
): Promise<ArrayBuffer> {
  const keyData = hexToBuffer(shareKeyHex);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  return decryptFile(key, encryptedBlob);
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
