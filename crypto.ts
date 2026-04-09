import { argon2id } from "hash-wasm";

export function generateSalt(): string {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  return bufferToBase64(salt);
}

export async function hashPasswordClient(password: string, saltBase64: string): Promise<string> {
  const salt = base64ToBuffer(saltBase64);
  const hash = await argon2id({
    password,
    salt,
    parallelism: 4,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: "encoded",
  });
  return hash;
}

export async function verifyPasswordClient(password: string, saltBase64: string, storedHash: string): Promise<boolean> {
  const computed = await hashPasswordClient(password, saltBase64);
  return computed === storedHash;
}

export async function deriveMasterKey(
  password: string,
  saltBase64: string,
  kdfVersion?: number
): Promise<CryptoKey> {
  const salt = base64ToBuffer(saltBase64);

  if (kdfVersion && kdfVersion >= 2) {
    const keyBytes = await argon2id({
      password,
      salt,
      parallelism: 4,
      iterations: 3,
      memorySize: 65536,
      hashLength: 32,
      outputType: "binary",
    });

    return crypto.subtle.importKey(
      'raw',
      new Uint8Array(keyBytes) as unknown as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 600_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function deriveSubKey(
  masterKey: CryptoKey,
  purpose: string,
  userSalt?: string
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const masterKeyRaw = await crypto.subtle.exportKey('raw', masterKey);

  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    masterKeyRaw,
    'HKDF',
    false,
    ['deriveKey']
  );

  const salt = userSalt ? base64ToBuffer(userSalt) : encoder.encode('darkcloud-v1');

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: encoder.encode(purpose),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function deriveSigningKey(
  masterKey: CryptoKey,
  userSalt?: string
): Promise<CryptoKey> {
  const masterKeyRaw = await crypto.subtle.exportKey('raw', masterKey);
  const hkdfKey = await crypto.subtle.importKey('raw', masterKeyRaw, 'HKDF', false, ['deriveKey']);
  const salt = userSalt ? base64ToBuffer(userSalt) : new TextEncoder().encode('darkcloud-v1');
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode('metadata-signing') },
    hkdfKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']
  );
}

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

export async function verifyMetadata(
  signingKey: CryptoKey,
  fileId: string,
  encryptedName: string,
  encryptedMeta: string,
  signature: string
): Promise<boolean> {
  const data = new TextEncoder().encode(fileId + ':' + encryptedName + ':' + encryptedMeta);
  const sig = base64ToBuffer(signature);
  return crypto.subtle.verify('HMAC', signingKey, sig as BufferSource, data as BufferSource);
}

export async function generateDEK(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function wrapDEK(
  fileKey: CryptoKey,
  dek: CryptoKey
): Promise<string> {
  const rawDEK = await crypto.subtle.exportKey('raw', dek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    fileKey,
    rawDEK
  );
  const combined = new Uint8Array(iv.length + wrapped.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(wrapped), iv.length);
  return bufferToBase64(combined);
}

export async function unwrapDEK(
  fileKey: CryptoKey,
  wrappedDEKBase64: string
): Promise<CryptoKey> {
  const data = base64ToBuffer(wrappedDEKBase64);
  const iv = data.slice(0, 12);
  const wrapped = data.slice(12);
  const rawDEK = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    fileKey,
    wrapped as BufferSource
  );
  return crypto.subtle.importKey(
    'raw',
    rawDEK,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export interface EncryptedData {
  ciphertext: string;
  iv: string;
}

export async function encrypt(
  key: CryptoKey,
  plaintext: ArrayBuffer
): Promise<EncryptedData> {
  const iv = crypto.getRandomValues(new Uint8Array(12));

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

export async function encryptString(
  key: CryptoKey,
  text: string
): Promise<string> {
  const encoder = new TextEncoder();
  const encrypted = await encrypt(key, encoder.encode(text).buffer as ArrayBuffer);
  return JSON.stringify(encrypted);
}

export async function decryptString(
  key: CryptoKey,
  encryptedJson: string
): Promise<string> {
  const decoder = new TextDecoder();
  const encrypted: EncryptedData = JSON.parse(encryptedJson);
  const decrypted = await decrypt(key, encrypted);
  return decoder.decode(decrypted);
}

export async function encryptFile(
  key: CryptoKey,
  fileData: ArrayBuffer,
  fileId?: string
): Promise<Blob> {
  if (!fileId) throw new Error("fileId is required for AAD binding");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const aad = encoder.encode(fileId);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource },
    key,
    fileData
  );

  const combined = new Uint8Array(1 + iv.length + ciphertext.byteLength);
  combined[0] = 0x02;
  combined.set(iv, 1);
  combined.set(new Uint8Array(ciphertext), 1 + iv.length);
  return new Blob([combined], { type: 'application/octet-stream' });
}

export async function decryptFile(
  key: CryptoKey,
  encryptedBlob: ArrayBuffer,
  fileId?: string
): Promise<ArrayBuffer> {
  const data = new Uint8Array(encryptedBlob);
  const encoder = new TextEncoder();

  if (data[0] === 0x02 && fileId) {
    const iv = data.slice(1, 13);
    const ciphertext = data.slice(13);
    const aad = encoder.encode(fileId);
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad as BufferSource },
      key,
      ciphertext
    );
  }

  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12);
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
}

export function generateShareKey(): string {
  const key = crypto.getRandomValues(new Uint8Array(32));
  return bufferToHex(key);
}

export async function deriveShareKeyFromPassword(password: string, token: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  const salt = encoder.encode('sifero-share:' + token);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
  );
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufferToHex(new Uint8Array(raw));
}

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

export async function encryptForShare(
  shareKeyHex: string,
  plaintext: ArrayBuffer,
  shareId?: string
): Promise<Blob> {
  const key = await importShareKey(shareKeyHex, ['encrypt']);
  return encryptFile(key, plaintext, shareId);
}

export async function encryptNameForShare(
  shareKeyHex: string,
  fileName: string
): Promise<string> {
  const key = await importShareKey(shareKeyHex, ['encrypt']);
  return encryptString(key, fileName);
}

export async function decryptShared(
  shareKeyHex: string,
  encryptedBlob: ArrayBuffer
): Promise<ArrayBuffer> {
  const key = await importShareKey(shareKeyHex, ['decrypt']);
  return decryptFile(key, encryptedBlob);
}

export async function decryptNameFromShare(
  shareKeyHex: string,
  encryptedName: string
): Promise<string> {
  const key = await importShareKey(shareKeyHex, ['decrypt']);
  return decryptString(key, encryptedName);
}

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

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export async function generateDropKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
  const pubRaw = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return { publicKey: bufferToBase64(new Uint8Array(pubRaw)), privateKey: bufferToBase64(new Uint8Array(privRaw)) };
}

export async function wrapDropPrivateKey(masterKey: CryptoKey, privateKeyBase64: string): Promise<string> {
  const wrapKey = await deriveSubKey(masterKey, "dead-drop-wrap");
  const encrypted = await encrypt(wrapKey, base64ToBuffer(privateKeyBase64).buffer as ArrayBuffer);
  return JSON.stringify(encrypted);
}

export async function unwrapDropPrivateKey(masterKey: CryptoKey, wrappedJson: string): Promise<CryptoKey> {
  const wrapKey = await deriveSubKey(masterKey, "dead-drop-wrap");
  const decrypted = await decrypt(wrapKey, JSON.parse(wrappedJson));
  return crypto.subtle.importKey("pkcs8", decrypted, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

export async function importDropPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", base64ToBuffer(publicKeyBase64).buffer as ArrayBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
}

export async function encryptForDrop(publicKey: CryptoKey, data: ArrayBuffer): Promise<Blob> {
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const aesRaw = await crypto.subtle.exportKey("raw", aesKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, data);
  const wrappedAesKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesRaw);
  const wrappedKeyBytes = new Uint8Array(wrappedAesKey);
  const wrappedKeyLen = new Uint8Array(2);
  wrappedKeyLen[0] = (wrappedKeyBytes.length >> 8) & 0xff;
  wrappedKeyLen[1] = wrappedKeyBytes.length & 0xff;
  const combined = new Uint8Array(2 + wrappedKeyBytes.length + 12 + ciphertext.byteLength);
  combined.set(wrappedKeyLen, 0);
  combined.set(wrappedKeyBytes, 2);
  combined.set(iv, 2 + wrappedKeyBytes.length);
  combined.set(new Uint8Array(ciphertext), 2 + wrappedKeyBytes.length + 12);
  return new Blob([combined], { type: "application/octet-stream" });
}

export async function decryptFromDrop(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  const bytes = new Uint8Array(data);
  const wrappedKeyLen = (bytes[0] << 8) | bytes[1];
  const wrappedAesKey = bytes.slice(2, 2 + wrappedKeyLen);
  const iv = bytes.slice(2 + wrappedKeyLen, 2 + wrappedKeyLen + 12);
  const ciphertext = bytes.slice(2 + wrappedKeyLen + 12);
  const aesRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedAesKey);
  const aesKey = await crypto.subtle.importKey("raw", aesRaw, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
}
