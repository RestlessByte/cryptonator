'use client';

/**
 * Secure symmetric crypto for the browser (and Node fallback).
 * - Keeps original API and message layout:
 *   Base64( salt | iv | authTag(16) | ciphertext )
 * - Uses WebCrypto (fast, non-blocking) with Node fallback if needed.
 *
 * Developer: RestlessByte (https://github.com/RestlessByte)
 * Maintainer notes:
 * - We do not change the external function names or behavior contracts.
 * - We harden inputs, lengths, and add AAD binding option (context) kept internal for compatibility.
 */

type ICryptoKey = string[];

interface ICryptoConfig {
  ivLength: number;      // 12 bytes is standard for AES-GCM
  saltLength: number;    // 16 bytes salt
  tagLength: number;     // bits
}

const CONFIG: ICryptoConfig = {
  ivLength: 12,
  saltLength: 16,
  tagLength: 128, // AES-GCM tag length in bits (16 bytes)
};

/* --------------------------
   Environment abstractions
---------------------------*/

/** Get WebCrypto subtle (browser or Node). */
const getSubtle = (): SubtleCrypto => {
  if (typeof globalThis !== 'undefined') {
    // Browser crypto
    // @ts-ignore
    if (globalThis.crypto && globalThis.crypto.subtle) return globalThis.crypto.subtle as SubtleCrypto;
    // Node >= 19 has global crypto.subtle
    // @ts-ignore
    if (typeof require === 'function') {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const nodeCrypto = require('crypto');
        if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) return nodeCrypto.webcrypto.subtle as SubtleCrypto;
      } catch { }
    }
  }
  throw new Error('SubtleCrypto is not available in this environment.');
};

/** CSPRNG bytes (browser or Node). */
const randomBytes = (len: number): Uint8Array => {
  const out = new Uint8Array(len);
  if (typeof globalThis !== 'undefined' && (globalThis.crypto?.getRandomValues)) {
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  // @ts-ignore
  if (typeof require === 'function') {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('crypto');
      return new Uint8Array(nodeCrypto.randomBytes(len));
    } catch { }
  }
  throw new Error('Secure random generator is not available.');
};

/* --------------------------
   Encoding helpers
---------------------------*/

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Base64 encode ArrayBuffer */
const toBase64 = (buf: ArrayBuffer | Uint8Array): string => {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (typeof btoa === 'function') {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }
  // Node
  // @ts-ignore
  return Buffer.from(u8).toString('base64');
};

/** Base64 decode to Uint8Array */
const fromBase64 = (b64: string): Uint8Array => {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node
  // @ts-ignore
  return new Uint8Array(Buffer.from(b64, 'base64'));
};

const isBase64 = (data: string): boolean => {
  if (typeof data !== 'string' || data.length === 0) return false;
  try {
    const dec = fromBase64(data);
    return toBase64(dec) === data;
  } catch {
    return false;
  }
};

/* --------------------------
   Key derivation (compatible)
---------------------------*/

/**
 * Derive 32-byte key from array of strings + salt using SHA-256 over concatenation.
 * We keep the logic shape (concat + hash) to stay compatible, but use WebCrypto.
 */
const deriveCombinedKey = async (keys: ICryptoKey, salt: Uint8Array): Promise<Uint8Array> => {
  if (!Array.isArray(keys) || keys.length === 0 || keys.some(k => typeof k !== 'string' || !k.trim())) {
    throw new Error('Valid non-empty keys must be provided.');
  }
  const combined = enc.encode(keys.join('') + Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''));
  const subtle = getSubtle();
  const digest = await subtle.digest('SHA-256', combined);
  return new Uint8Array(digest); // 32 bytes
};

/* --------------------------
   AES-GCM wrappers
---------------------------*/

const importAesKey = async (rawKey32: Uint8Array): Promise<CryptoKey> => {
  const subtle = getSubtle();
  return subtle.importKey(
    'raw',
    rawKey32,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

/**
 * Encrypt data (keeps output layout: salt | iv | authTag | ciphertext).
 * @returns Base64 string
 */
export const encryptedDataClient = async (data: any, keys: ICryptoKey): Promise<string> => {
  if (data === undefined || data === null) {
    throw new Error('No data to encrypt.');
  }

  const salt = randomBytes(CONFIG.saltLength);
  const iv = randomBytes(CONFIG.ivLength);
  const keyMaterial = await deriveCombinedKey(keys, salt);
  const aesKey = await importAesKey(keyMaterial);

  const subtle = getSubtle();
  const plaintext = enc.encode(JSON.stringify(data));
  const ciphertextWithTag = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: CONFIG.tagLength },
    aesKey,
    plaintext
  ));

  // Split tag (last 16 bytes) to keep your original layout
  if (ciphertextWithTag.length < 16) throw new Error('Encryption failed (ciphertext too short).');
  const authTag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);
  const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);

  const out = new Uint8Array(salt.length + iv.length + authTag.length + ciphertext.length);
  out.set(salt, 0);
  out.set(iv, salt.length);
  out.set(authTag, salt.length + iv.length);
  out.set(ciphertext, salt.length + iv.length + authTag.length);

  return toBase64(out);
};

/**
 * Decrypt data (expects layout: salt | iv | authTag | ciphertext).
 * If input is not base64, returns it as-is (compatibility).
 */
export const decryptedDataClient = async (encryptedData: any, keys: ICryptoKey): Promise<any> => {
  if (!encryptedData) {
    throw new Error('No data provided for decryption or data is invalid.');
  }
  if (typeof encryptedData !== 'string' || !isBase64(encryptedData)) {
    return encryptedData;
  }

  const buf = fromBase64(encryptedData);
  const need = CONFIG.saltLength + CONFIG.ivLength + 16; // + at least 1 byte ciphertext
  if (buf.length <= need) throw new Error('Encrypted payload is too short.');

  const salt = buf.slice(0, CONFIG.saltLength);
  const iv = buf.slice(CONFIG.saltLength, CONFIG.saltLength + CONFIG.ivLength);
  const authTag = buf.slice(CONFIG.saltLength + CONFIG.ivLength, CONFIG.saltLength + CONFIG.ivLength + 16);
  const ciphertext = buf.slice(CONFIG.saltLength + CONFIG.ivLength + 16);

  const keyMaterial = await deriveCombinedKey(keys, salt);
  const aesKey = await importAesKey(keyMaterial);

  // Re-attach tag (WebCrypto expects tag appended)
  const cipherWithTag = new Uint8Array(ciphertext.length + authTag.length);
  cipherWithTag.set(ciphertext, 0);
  cipherWithTag.set(authTag, ciphertext.length);

  const subtle = getSubtle();
  try {
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: CONFIG.tagLength },
      aesKey,
      cipherWithTag
    );
    return JSON.parse(dec.decode(new Uint8Array(plain)));
  } catch {
    throw new Error('Failed to decrypt. Check keys or data integrity.');
  }
};
