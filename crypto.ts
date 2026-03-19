/**
 * Sifero Cloud - Client-Side Encryption Module
 * 
 * This module implements Zero-Knowledge encryption using:
 * - PBKDF2 (600,000 iterations) for key derivation from password
 * - HKDF for deriving purpose-specific sub-keys
 * - AES-256-GCM for authenticated encryption
 * 
 * All operations use the Web Crypto API (no external dependencies).
 * 
 * Source: https://github.com/sifero-cloud/crypto
 * License: MIT
 */

// ═══════════════════════════════════════
// TYPES
// ═══════════════════════════════════════

export type CryptoKey = globalThis.CryptoKey;

// ═══════════════════════════════════════
// KEY DERIVATION
// ═══════════════════════════════════════

/**
 * Derive a master key from password using PBKDF2
 * 600,000 iterations makes brute-force infeasible
 */
export async function deriveMasterKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

/**
 * Derive a purpose-specific sub-key using HKDF
 * Each data type gets its own key, so compromising one
 * doesn't compromise others.
 * 
 * Purposes: "file-encryption", "metadata-encryption", 
 *           "notes-encryption", "search-encryption", "chat-encryption"
 */
export async function deriveSubKey(masterKey: CryptoKey, purpose: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const masterBits = await crypto.subtle.exportKey("raw", masterKey);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", masterBits, "HKDF", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode(purpose) },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ═══════════════════════════════════════
// ENCRYPTION / DECRYPTION
// ═══════════════════════════════════════

/**
 * Encrypt data with AES-256-GCM
 * Returns: [12-byte IV][ciphertext][16-byte auth tag]
 * Each call generates a fresh random IV
 */
export async function encrypt(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  // Prepend IV to ciphertext
  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encrypted), iv.length);
  return result.buffer;
}

/**
 * Decrypt data encrypted with AES-256-GCM
 * Expects: [12-byte IV][ciphertext][16-byte auth tag]
 * Throws if key is wrong or data has been tampered with
 */
export async function decrypt(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  const bytes = new Uint8Array(data);
  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
}

// ═══════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════

/**
 * Encrypt a string (UTF-8) and return as base64
 */
export async function encryptString(key: CryptoKey, text: string): Promise<string> {
  const encoded = new TextEncoder().encode(text);
  const encrypted = await encrypt(key, encoded.buffer);
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

/**
 * Decrypt a base64 string back to UTF-8
 */
export async function decryptString(key: CryptoKey, base64: string): Promise<string> {
  const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  const decrypted = await decrypt(key, bytes.buffer);
  return new TextDecoder().decode(decrypted);
}

/**
 * Encrypt JSON object
 */
export async function encryptJSON(key: CryptoKey, obj: any): Promise<string> {
  return encryptString(key, JSON.stringify(obj));
}

/**
 * Decrypt to JSON object
 */
export async function decryptJSON(key: CryptoKey, base64: string): Promise<any> {
  const str = await decryptString(key, base64);
  return JSON.parse(str);
}

/**
 * Generate a random salt for PBKDF2
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Format file size for display
 */
export function formatFileSize(bytes: number): string {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[Math.min(i, sizes.length - 1)];
}
