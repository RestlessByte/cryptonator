/**
 * Hardened server-side cryptography, preserving existing exports and shape.
 *
 * What changed (security):
 * - Standardized IV (12) and salt (16) sizes.
 * - Strong input validation and constant-time utilities.
 * - Versioned envelope + optional AAD binding.
 * - Pseudo-lattice Feistel kept (compat), but lengths & checks enforced.
 * - KEM (node-oqs) path kept; guarded and validated.
 * - Uses AES-256-GCM only with secure sizes; rejects weird sizes.
 *
 * Developer: RestlessByte (https://github.com/RestlessByte)
 */

import crypto, { CipherGCM, DecipherGCM, randomBytes, timingSafeEqual } from 'crypto';
// node-oqs is optional; we keep require form to avoid crash if not installed.
let oqs: any = null;
try { oqs = require('node-oqs'); } catch { /* optional */ }

type ICryptoKey = string[];

interface ICryptoConfig {
  ivLength: number;
  saltLength: number;
  tagLength: number; // bits
  keyAlgorithm: string;
  encryptionAlgorithm: string;
}

const CFG: ICryptoConfig = {
  ivLength: 12,                 // AES-GCM standard
  saltLength: 16,               // 128-bit salt
  tagLength: 128,               // 16 bytes tag
  keyAlgorithm: 'sha256',       // Hash for PBKDF2/KDF
  encryptionAlgorithm: 'aes-256-gcm',
};

// Envelope format version (bump to invalidate old formats if needed)
const ENV_VERSION = 1;

/* --------------------------
   Utils
---------------------------*/

const isBase64 = (data: string): boolean => {
  if (typeof data !== 'string' || data.length === 0) return false;
  try {
    const buf = Buffer.from(data, 'base64');
    return buf.length > 0 && buf.toString('base64') === data;
  } catch { return false; }
};

const ctEqual = (a: Buffer, b: Buffer): boolean => {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
};

const u8 = (len: number) => new Uint8Array(len);

/* --------------------------
   KDFs
---------------------------*/

/**
 * PBKDF2( keys.concat() , salt, high iters ) -> 32 bytes, then SHA3-256 (if available).
 * Keeps your lattice-derivation spirit; validated sizes and errors.
 */
const deriveLatticeKey = async (keys: ICryptoKey, salt: Buffer): Promise<Buffer> => {
  if (!Array.isArray(keys) || keys.length === 0 || keys.some(k => typeof k !== 'string' || !k.trim())) {
    throw new Error('Valid non-empty keys must be provided.');
  }
  const material = keys.join('');
  const pbkdf2 = await new Promise<Buffer>((resolve, reject) => {
    crypto.pbkdf2(material, salt, 620_000, 32, 'sha256', (err, dk) => {
      if (err) reject(err); else resolve(dk);
    });
  });
  // Prefer SHA3-256 when available; otherwise SHA-256 again.
  const algo = crypto.getHashes().includes('sha3-256') ? 'sha3-256' : 'sha256';
  return crypto.createHash(algo).update(pbkdf2).digest(); // 32 bytes
};

/* --------------------------
   Feistel (compat with your previous approach)
---------------------------*/

const FEISTEL_ROUNDS = 16;
const makeRoundKeys = (latticeKey: Buffer): Buffer[] => {
  const algo = crypto.getHashes().includes('sha3-256') ? 'sha3-256' : 'sha256';
  const rks: Buffer[] = [];
  for (let i = 0; i < FEISTEL_ROUNDS; i++) {
    rks.push(crypto.createHmac(algo, latticeKey).update(Buffer.from([i])).digest());
  }
  return rks;
};

const feistelEncrypt = (block32: Buffer, roundKeys: Buffer[]): Buffer => {
  if (block32.length !== 32) throw new Error('Feistel expects 32-byte block.');
  const half = 16;
  let L = Buffer.from(block32.slice(0, half));
  let R = Buffer.from(block32.slice(half));
  const algo = crypto.getHashes().includes('sha3-256') ? 'sha3-256' : 'sha256';

  for (let i = 0; i < roundKeys.length; i++) {
    const f = crypto.createHash(algo).update(Buffer.concat([R, roundKeys[i]])).digest().subarray(0, half);
    const newR = Buffer.alloc(half);
    for (let j = 0; j < half; j++) newR[j] = L[j] ^ f[j];
    L = R; R = newR;
  }
  return Buffer.concat([R, L]);
};

const feistelDecrypt = (block32: Buffer, roundKeys: Buffer[]): Buffer => {
  if (block32.length !== 32) throw new Error('Feistel expects 32-byte block.');
  const half = 16;
  let R = Buffer.from(block32.slice(0, half));
  let L = Buffer.from(block32.slice(half));
  const algo = crypto.getHashes().includes('sha3-256') ? 'sha3-256' : 'sha256';

  for (let i = roundKeys.length - 1; i >= 0; i--) {
    const f = crypto.createHash(algo).update(Buffer.concat([L, roundKeys[i]])).digest().subarray(0, half);
    const newL = Buffer.alloc(half);
    for (let j = 0; j < half; j++) newL[j] = R[j] ^ f[j];
    R = L; L = newL;
  }
  return Buffer.concat([L, R]);
};

const latticeEncryptKey = (sessionKey: Buffer, latticeKey: Buffer): Buffer => {
  const key = sessionKey.length === 32 ? sessionKey : Buffer.concat([sessionKey, Buffer.alloc(32)]).subarray(0, 32);
  const rks = makeRoundKeys(latticeKey);
  return feistelEncrypt(key, rks);
};

const latticeDecryptKey = (encryptedKey: Buffer, latticeKey: Buffer): Buffer => {
  if (encryptedKey.length !== 32) throw new Error('Encrypted session key must be 32 bytes.');
  const rks = makeRoundKeys(latticeKey);
  return feistelDecrypt(encryptedKey, rks);
};

/* --------------------------
   AES-GCM helpers
---------------------------*/

const importAesKeyNode = (raw32: Buffer) => {
  if (raw32.length !== 32) throw new Error('AES-256 key must be 32 bytes.');
  return raw32;
};

const aesGcmEncrypt = (key32: Buffer, iv: Buffer, plaintext: Buffer, aad?: Buffer) => {
  const cipher = crypto.createCipheriv(CFG.encryptionAlgorithm, importAesKeyNode(key32), iv) as CipherGCM;
  if (aad && aad.length) cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ct, tag };
};

const aesGcmDecrypt = (key32: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad?: Buffer) => {
  const decipher = crypto.createDecipheriv(CFG.encryptionAlgorithm, importAesKeyNode(key32), iv) as DecipherGCM;
  if (aad && aad.length) decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return pt;
};

/* --------------------------
   Envelope building
---------------------------*/

/**
 * Build: version(1) | salt(16) | iv(12) | tag(16) | encSessionKey(32) | ciphertext
 * - We keep your original visible structure (salt|iv|tag|encSessionKey|ct) but prepend 1 byte version.
 * - AAD binds: "srv:quant" + version.
 */
const buildAAD = () => Buffer.from(`srv:quant:v${ENV_VERSION}`, 'utf8');

/**
 * QUANT ENCRYPT (compat name): quantEncryptedData
 */
export const quantEncryptedData = async (data: any, keys: ICryptoKey): Promise<string> => {
  if (data === undefined || data === null) throw new Error('No data provided for encryption.');

  const salt = randomBytes(CFG.saltLength);
  const iv = randomBytes(CFG.ivLength);
  const latticeKey = await deriveLatticeKey(keys, Buffer.from(salt));
  const sessionKey = randomBytes(32);
  const aad = buildAAD();

  const { ct, tag } = aesGcmEncrypt(Buffer.from(sessionKey), Buffer.from(iv), Buffer.from(JSON.stringify(data), 'utf8'), aad);
  const encSess = latticeEncryptKey(Buffer.from(sessionKey), latticeKey);

  // version + salt + iv + tag + encSess + ct
  const out = Buffer.concat([
    Buffer.from([ENV_VERSION]),
    Buffer.from(salt),
    Buffer.from(iv),
    tag,
    encSess,
    ct
  ]);
  return out.toString('base64');
};

export const quantDecryptedData = async (encryptedData: any, keys: ICryptoKey): Promise<any> => {
  if (!encryptedData) throw new Error('No data provided for decryption or data is invalid.');
  if (typeof encryptedData !== 'string' || !isBase64(encryptedData)) return encryptedData;

  const buf = Buffer.from(encryptedData, 'base64');
  const min = 1 + CFG.saltLength + CFG.ivLength + 16 + 32 + 1; // version + salt + iv + tag + encKey + >=1 ct
  if (buf.length < min) throw new Error('Encrypted payload too short.');

  const version = buf.readUInt8(0);
  if (version !== ENV_VERSION) throw new Error(`Unsupported envelope version: ${version}.`);
  let off = 1;

  const salt = buf.subarray(off, off += CFG.saltLength);
  const iv   = buf.subarray(off, off += CFG.ivLength);
  const tag  = buf.subarray(off, off += 16);
  const encK = buf.subarray(off, off += 32);
  const ct   = buf.subarray(off);

  const latticeKey = await deriveLatticeKey(keys, salt);
  const sessionKey = latticeDecryptKey(encK, latticeKey);
  const aad = buildAAD();

  try {
    const pt = aesGcmDecrypt(sessionKey, iv, ct, tag, aad);
    return JSON.parse(pt.toString('utf8'));
  } catch {
    throw new Error('Failed to decrypt data. Verify keys or integrity.');
  }
};

/* ---------------------------------------------------------------------------
   Post-quantum KEM path (optional): retains your original API.
---------------------------------------------------------------------------*/

interface IPQKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

const PQC_ALGORITHM = 'Kyber512';
const KEM_AVAILABLE = !!oqs;

export const generatePostQuantumKeyPair = (): IPQKeyPair => {
  if (!KEM_AVAILABLE) throw new Error('node-oqs is not available in this environment.');
  const kem = new oqs.KEM(PQC_ALGORITHM);
  const { publicKey, secretKey } = kem.generateKeyPair();
  return { publicKey: Buffer.from(publicKey), privateKey: Buffer.from(secretKey) };
};

/**
 * secureEncryptData(data, recipientPublicKey) -> Base64( encapsulatedKey | iv | tag | ciphertext )
 * - Keeps your function name and layout.
 * - Uses SHA-256(sharedSecret) => AES-256-GCM key.
 */
export const secureEncryptData = async (data: any, recipientPublicKey: Buffer): Promise<string> => {
  if (!KEM_AVAILABLE) throw new Error('node-oqs is not available.');
  if (data === undefined || data === null) throw new Error('No data provided for encryption.');
  if (!Buffer.isBuffer(recipientPublicKey) || recipientPublicKey.length === 0) throw new Error('Invalid recipient public key.');

  const kem = new oqs.KEM(PQC_ALGORITHM);
  const { sharedSecret, encapsulatedKey } = kem.encapsulate(recipientPublicKey);
  const symKey = crypto.createHash(CFG.keyAlgorithm).update(Buffer.from(sharedSecret)).digest(); // 32 bytes

  const iv = randomBytes(CFG.ivLength);
  const aad = Buffer.from('srv:kem:v1', 'utf8');
  const { ct, tag } = aesGcmEncrypt(symKey, Buffer.from(iv), Buffer.from(JSON.stringify(data), 'utf8'), aad);

  return Buffer.concat([Buffer.from(encapsulatedKey), Buffer.from(iv), tag, ct]).toString('base64');
};

export const secureDecryptData = async (encryptedData: any, recipientPrivateKey: Buffer): Promise<any> => {
  if (!KEM_AVAILABLE) throw new Error('node-oqs is not available.');
  if (!encryptedData || typeof encryptedData !== 'string' || !isBase64(encryptedData)) {
    throw new Error('Invalid encrypted data format.');
  }
  if (!Buffer.isBuffer(recipientPrivateKey) || recipientPrivateKey.length === 0) {
    throw new Error('Invalid recipient private key.');
  }

  const kem = new oqs.KEM(PQC_ALGORITHM);
  const buf = Buffer.from(encryptedData, 'base64');
  const encKeyLen = kem.getCiphertextLength();
  const need = encKeyLen + CFG.ivLength + 16 + 1;
  if (buf.length < need) throw new Error('Encrypted payload too short for KEM.');

  let off = 0;
  const encapsulatedKey = buf.subarray(off, off += encKeyLen);
  const iv = buf.subarray(off, off += CFG.ivLength);
  const tag = buf.subarray(off, off += 16);
  const ct = buf.subarray(off);

  const sharedSecret = kem.decapsulate(encapsulatedKey, recipientPrivateKey);
  const symKey = crypto.createHash(CFG.keyAlgorithm).update(Buffer.from(sharedSecret)).digest();
  const aad = Buffer.from('srv:kem:v1', 'utf8');

  try {
    const pt = aesGcmDecrypt(symKey, iv, ct, tag, aad);
    return JSON.parse(pt.toString('utf8'));
  } catch {
    throw new Error('Failed to decrypt (KEM). Verify keys or integrity.');
  }
};

/* ---------------------------------------------------------------------------
   Extra hardening helpers (optional exports)
---------------------------------------------------------------------------*/

/**
 * Validate minimal structure of quant-encrypted payload (base64 + minimal length + version).
 * Returns boolean without throwing.
 */
export const validateQuantPayload = (b64: string): boolean => {
  if (!isBase64(b64)) return false;
  const buf = Buffer.from(b64, 'base64');
  if (buf.length < 1) return false;
  const ver = buf.readUInt8(0);
  if (ver !== ENV_VERSION) return false;
  const min = 1 + CFG.saltLength + CFG.ivLength + 16 + 32 + 1;
  return buf.length >= min;
};
