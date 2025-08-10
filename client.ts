'use client';
/**
 * Ultra-hardened multi-layer transport crypto (browser + Node via WebCrypto).
 * Layers cycle: [0] AES-256-GCM (AEAD), [1] AES-CTR + HMAC-SHA-256 (EtM),
 *               [2] AES-CBC + HMAC-SHA-256 (PKCS#7 + EtM), then repeat.
 *
 * Кол-во слоёв = keys.length.
 * Главный фикс: ВСЕ данные в WebCrypto передаются как КОПИЯ Uint8Array -> ArrayBuffer
 * (никаких .buffer напрямую), чтобы исключить SharedArrayBuffer/ArrayBufferLike конфликты.
 */

type ICryptoKey = string[];

interface IConfig {
  pbkdf2Iterations: number;
  pbkdf2SaltLen: number;
  hkdfSaltLen: number;
  gcmIvLen: number;   // 12 bytes
  ctrIvLen: number;   // 16 bytes
  cbcIvLen: number;   // 16 bytes
  gcmTagLen: number;  // bits
}

const CONFIG: IConfig = {
  pbkdf2Iterations: 310_000,
  pbkdf2SaltLen: 16,
  hkdfSaltLen: 16,
  gcmIvLen: 12,
  ctrIvLen: 16,
  cbcIvLen: 16,
  gcmTagLen: 128,
};

/* ---------- Env ---------- */
type AnySubtle = SubtleCrypto;

const getSubtle = (): AnySubtle => {
  if (typeof globalThis !== 'undefined' && (globalThis as any).crypto?.subtle) {
    return (globalThis as any).crypto.subtle as AnySubtle;
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require('crypto');
    if (nodeCrypto?.webcrypto?.subtle) return nodeCrypto.webcrypto.subtle as AnySubtle;
  } catch { }
  throw new Error('SubtleCrypto is not available.');
};

const getCrypto = (): Crypto => {
  if (typeof globalThis !== 'undefined' && (globalThis as any).crypto) {
    return (globalThis as any).crypto as Crypto;
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require('crypto');
    return nodeCrypto.webcrypto as unknown as Crypto;
  } catch { }
  throw new Error('Crypto is not available.');
};

const randomBytes = (len: number): Uint8Array => {
  const out = new Uint8Array(len);
  getCrypto().getRandomValues(out);
  return out;
};

/* ---------- Encoding ---------- */
const enc = new TextEncoder();
const dec = new TextDecoder();

const toBase64 = (buf: ArrayBuffer | Uint8Array): string => {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (typeof btoa === 'function') {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('buffer').Buffer.from(u8).toString('base64');
};

const fromBase64 = (b64: string): Uint8Array => {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return new (require('buffer').Buffer)(b64, 'base64');
};

const isBase64 = (s: string): boolean => {
  if (typeof s !== 'string' || !s.length) return false;
  try { return toBase64(fromBase64(s)) === s; } catch { return false; }
};

const concatU8 = (...parts: Uint8Array[]) => {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

/** Гарантированный обычный ArrayBuffer (не SharedArrayBuffer) */
const toArrayBuffer = (u8: Uint8Array): ArrayBuffer => {
  const copy = new Uint8Array(u8.byteLength);
  copy.set(u8);
  return copy.buffer;
};

/* ---------- Context ---------- */
const ctxBase = 'ctx:v3|purpose=app-transport|suite=GCM+CTR-HMAC+CBC-HMAC|v=3';
const aadFor = (saltLen: number, layerIndex: number): Uint8Array =>
  enc.encode(`${ctxBase}|pbkdf2SaltLen=${saltLen}|layer=${layerIndex}`);

/* ---------- Key material ---------- */
const joinKeysMaterial = (keys: ICryptoKey): Uint8Array => {
  if (!Array.isArray(keys) || keys.length === 0 || keys.some(k => typeof k !== 'string' || !k.trim())) {
    throw new Error('Valid non-empty keys must be provided.');
  }
  const parts: number[] = [];
  for (const k of keys) {
    const b = enc.encode(k);
    parts.push((b.length >>> 24) & 0xff, (b.length >>> 16) & 0xff, (b.length >>> 8) & 0xff, b.length & 0xff);
    for (let i = 0; i < b.length; i++) parts.push(b[i]);
    parts.push(0x00);
  }
  return new Uint8Array(parts);
};

const importPBKDF2Base = async (keys: ICryptoKey): Promise<CryptoKey> => {
  const material = joinKeysMaterial(keys);
  return getSubtle().importKey('raw', toArrayBuffer(material), 'PBKDF2', false, ['deriveBits']);
};

// PBKDF2 -> IKM(32B) -> HKDF key
const deriveHKDFMaster = async (keys: ICryptoKey, saltPBKDF2: Uint8Array): Promise<CryptoKey> => {
  const base = await importPBKDF2Base(keys);
  const subtle = getSubtle();
  const ikmBits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: toArrayBuffer(saltPBKDF2), iterations: CONFIG.pbkdf2Iterations, hash: 'SHA-256' },
    base,
    32 * 8
  );
  const ikm = new Uint8Array(ikmBits);
  return subtle.importKey('raw', toArrayBuffer(ikm), 'HKDF', false, ['deriveBits']);
};

// HKDF derive bytes
const hkdfBytes = async (hkdfKey: CryptoKey, salt: Uint8Array, info: Uint8Array, nBytes: number): Promise<Uint8Array> => {
  const subtle = getSubtle();
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: toArrayBuffer(salt), info: toArrayBuffer(info) },
    hkdfKey,
    nBytes * 8
  );
  return new Uint8Array(bits);
};

// Import helpers that ALWAYS take Uint8Array and convert via toArrayBuffer
const importAesGcmKey = async (raw: Uint8Array): Promise<CryptoKey> =>
  getSubtle().importKey('raw', toArrayBuffer(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

const importAesCtrKey = async (raw: Uint8Array): Promise<CryptoKey> =>
  getSubtle().importKey('raw', toArrayBuffer(raw), { name: 'AES-CTR' }, false, ['encrypt', 'decrypt']);

const importAesCbcKey = async (raw: Uint8Array): Promise<CryptoKey> =>
  getSubtle().importKey('raw', toArrayBuffer(raw), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);

const importHmacKey = async (raw: Uint8Array): Promise<CryptoKey> =>
  getSubtle().importKey('raw', toArrayBuffer(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

/* ---------- PKCS#7 for CBC ---------- */
function pkcs7Pad(data: Uint8Array, blockSize = 16): Uint8Array {
  // ФИКС: при длине, кратной блоку, добавляем полный блок паддинга
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : (blockSize - rem);
  const pad = new Uint8Array(padLen);
  pad.fill(padLen);
  return concatU8(data, pad);
}
function pkcs7Unpad(data: Uint8Array, blockSize = 16): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) throw new Error('Invalid PKCS#7 length.');
  const padLen = data[data.length - 1];
  if (padLen === 0 || padLen > blockSize || padLen > data.length) throw new Error('Invalid PKCS#7 pad.');
  for (let i = 1; i <= padLen; i++) if (data[data.length - i] !== padLen) throw new Error('Invalid PKCS#7 pad bytes.');
  return data.slice(0, data.length - padLen);
}

/* ---------- Layer primitives (ArrayBuffer-safe) ---------- */
async function encryptGCM(plaintext: Uint8Array, key: CryptoKey, iv: Uint8Array, aad: Uint8Array) {
  const subtle = getSubtle();
  const params: AesGcmParams = { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: CONFIG.gcmTagLen, additionalData: toArrayBuffer(aad) };
  const out = new Uint8Array(await subtle.encrypt(params, key, toArrayBuffer(plaintext)));
  const tagLenB = CONFIG.gcmTagLen / 8;
  return { ct: out.slice(0, out.length - tagLenB), tag: out.slice(out.length - tagLenB) };
}
async function decryptGCM(ciphertext: Uint8Array, tag: Uint8Array, key: CryptoKey, iv: Uint8Array, aad: Uint8Array) {
  const subtle = getSubtle();
  const params: AesGcmParams = { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: CONFIG.gcmTagLen, additionalData: toArrayBuffer(aad) };
  const plain = await subtle.decrypt(params, key, toArrayBuffer(concatU8(ciphertext, tag)));
  return new Uint8Array(plain);
}

async function encryptCTR_HMAC(plaintext: Uint8Array, encKey: CryptoKey, macKey: CryptoKey, iv: Uint8Array, context: Uint8Array) {
  const subtle = getSubtle();
  const params: AesCtrParams = { name: 'AES-CTR', counter: toArrayBuffer(iv), length: 64 };
  const ct = new Uint8Array(await subtle.encrypt(params, encKey, toArrayBuffer(plaintext)));
  const macInput = concatU8(iv, ct, context);
  const tag = new Uint8Array(await subtle.sign({ name: 'HMAC' }, macKey, toArrayBuffer(macInput)));
  return { ct, tag };
}
async function decryptCTR_HMAC(ciphertext: Uint8Array, tag: Uint8Array, encKey: CryptoKey, macKey: CryptoKey, iv: Uint8Array, context: Uint8Array) {
  const subtle = getSubtle();
  const macInput = concatU8(iv, ciphertext, context);
  const ok = await subtle.verify({ name: 'HMAC' }, macKey, toArrayBuffer(tag), toArrayBuffer(macInput));
  if (!ok) throw new Error('Integrity check failed (HMAC-CTR).');
  const params: AesCtrParams = { name: 'AES-CTR', counter: toArrayBuffer(iv), length: 64 };
  const plain = await subtle.decrypt(params, encKey, toArrayBuffer(ciphertext));
  return new Uint8Array(plain);
}

async function encryptCBC_HMAC(plaintext: Uint8Array, encKey: CryptoKey, macKey: CryptoKey, iv: Uint8Array, context: Uint8Array) {
  const subtle = getSubtle();
  const padded = pkcs7Pad(plaintext, 16);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, encKey, toArrayBuffer(padded)));
  const macInput = concatU8(iv, ct, context);
  const tag = new Uint8Array(await subtle.sign({ name: 'HMAC' }, macKey, toArrayBuffer(macInput)));
  return { ct, tag };
}
async function decryptCBC_HMAC(ciphertext: Uint8Array, tag: Uint8Array, encKey: CryptoKey, macKey: CryptoKey, iv: Uint8Array, context: Uint8Array) {
  const subtle = getSubtle();
  const macInput = concatU8(iv, ciphertext, context);
  const ok = await subtle.verify({ name: 'HMAC' }, macKey, toArrayBuffer(tag), toArrayBuffer(macInput));
  if (!ok) throw new Error('Integrity check failed (HMAC-CBC).');
  const padded = new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, encKey, toArrayBuffer(ciphertext)));
  return pkcs7Unpad(padded, 16);
}

/* ---------- Public API ---------- */
type AlgId = 'GCM' | 'CTR-HMAC' | 'CBC-HMAC';

interface LayerMeta {
  a: AlgId;
  sl: string; // hkdf salt (b64)
  iv: string; // iv/counter (b64)
  tg: string; // tag (b64)
}

interface Envelope {
  v: number;
  kdf: string;
  s: string;  // pbkdf2 salt (b64)
  t: number;  // gcm tag bits
  n: number;  // layers count
  layers: LayerMeta[]; // outer -> inner
  ct: string; // outermost ciphertext
}

const algByIndex = (i: number): AlgId => {
  const m = i % 3;
  return m === 0 ? 'GCM' : m === 1 ? 'CTR-HMAC' : 'CBC-HMAC';
};

export const encryptedDataClient = async (data: any, keys: ICryptoKey): Promise<string> => {
  if (data === undefined || data === null) throw new Error('No data to encrypt.');
  if (!Array.isArray(keys) || keys.length === 0) throw new Error('keys[] must be non-empty.');
  const plaintext = enc.encode(JSON.stringify(data));

  const saltPBKDF2 = randomBytes(CONFIG.pbkdf2SaltLen);
  const hkdfMaster = await deriveHKDFMaster(keys, saltPBKDF2);

  let payload = new Uint8Array(plaintext);
  const layers: LayerMeta[] = [];

  for (let i = 0; i < keys.length; i++) {
    const alg = algByIndex(i);
    const layerSalt = randomBytes(CONFIG.hkdfSaltLen);
    const info = enc.encode(`layer-${i}|alg=${alg}`);
    const context = aadFor(CONFIG.pbkdf2SaltLen, i);

    if (alg === 'GCM') {
      const keyBytes = await hkdfBytes(hkdfMaster, layerSalt, info, 32);
      const aesKey = await importAesGcmKey(keyBytes);
      const iv = randomBytes(CONFIG.gcmIvLen);
      const { ct, tag } = await encryptGCM(payload, aesKey, iv, context);
      payload = ct;
      layers.push({ a: 'GCM', sl: toBase64(layerSalt), iv: toBase64(iv), tg: toBase64(tag) });

    } else if (alg === 'CTR-HMAC') {
      const keyBytes = await hkdfBytes(hkdfMaster, layerSalt, info, 64); // 32 enc + 32 mac
      const encKey = await importAesCtrKey(keyBytes.slice(0, 32));
      const macKey = await importHmacKey(keyBytes.slice(32));
      const iv = randomBytes(CONFIG.ctrIvLen);
      const { ct, tag } = await encryptCTR_HMAC(payload, encKey, macKey, iv, context);
      payload = ct;
      layers.push({ a: 'CTR-HMAC', sl: toBase64(layerSalt), iv: toBase64(iv), tg: toBase64(tag) });

    } else { // CBC-HMAC
      const keyBytes = await hkdfBytes(hkdfMaster, layerSalt, info, 64); // 32 enc + 32 mac
      const encKey = await importAesCbcKey(keyBytes.slice(0, 32));
      const macKey = await importHmacKey(keyBytes.slice(32));
      const iv = randomBytes(CONFIG.cbcIvLen);
      const { ct, tag } = await encryptCBC_HMAC(payload, encKey, macKey, iv, context);
      payload = ct;
      layers.push({ a: 'CBC-HMAC', sl: toBase64(layerSalt), iv: toBase64(iv), tg: toBase64(tag) });
    }
  }

  const env: Envelope = {
    v: 3,
    kdf: `PBKDF2-${CONFIG.pbkdf2Iterations}->HKDF`,
    s: toBase64(saltPBKDF2),
    t: CONFIG.gcmTagLen,
    n: keys.length,
    layers,
    ct: toBase64(payload),
  };
  return toBase64(enc.encode(JSON.stringify(env)));
};

export const decryptedDataClient = async (encryptedData: any, keys: ICryptoKey): Promise<any> => {
  if (!encryptedData) throw new Error('No data provided for decryption.');
  if (typeof encryptedData !== 'string' || !isBase64(encryptedData)) {
    throw new TypeError('Expected Base64-encoded payload.');
  }

  let jsonStr = '';
  try {
    jsonStr = dec.decode(fromBase64(encryptedData));
  } catch {
    throw new Error('Invalid envelope (not Base64(JSON)).');
  }

  let env: Envelope;
  try {
    env = JSON.parse(jsonStr);
  } catch {
    throw new Error('Invalid JSON envelope.');
  }

  if (!env || env.v !== 3 || !Array.isArray(env.layers) || typeof env.ct !== 'string' || typeof env.s !== 'string') {
    throw new Error('Malformed envelope.');
  }
  if (env.n !== keys.length || env.layers.length !== env.n) {
    throw new Error('Layers/keys mismatch.');
  }

  const hkdfMaster = await deriveHKDFMaster(keys, fromBase64(env.s));
  let payload = fromBase64(env.ct);

  for (let i = 0; i < env.layers.length; i++) {
    const layer = env.layers[i];
    const layerSalt = fromBase64(layer.sl);
    const iv = fromBase64(layer.iv);
    const tag = fromBase64(layer.tg);
    const info = enc.encode(`layer-${i}|alg=${layer.a}`);
    const context = aadFor(CONFIG.pbkdf2SaltLen, i);

    if (layer.a === 'GCM') {
      const keyBytes = await hkdfBytes(hkdfMaster, layerSalt, info, 32);
      const aesKey = await importAesGcmKey(keyBytes);
      payload = await decryptGCM(payload, tag, aesKey, iv, context);

    } else if (layer.a === 'CTR-HMAC') {
      const keyBytes = await hkdfBytes(hkdfMaster, layerSalt, info, 64);
      const encKey = await importAesCtrKey(keyBytes.slice(0, 32));
      const macKey = await importHmacKey(keyBytes.slice(32));
      payload = await decryptCTR_HMAC(payload, tag, encKey, macKey, iv, context);

    } else if (layer.a === 'CBC-HMAC') {
      const keyBytes = await hkdfBytes(hkdfMaster, layerSalt, info, 64);
      const encKey = await importAesCbcKey(keyBytes.slice(0, 32));
      const macKey = await importHmacKey(keyBytes.slice(32));
      payload = await decryptCBC_HMAC(payload, tag, encKey, macKey, iv, context);

    } else {
      throw new Error(`Unknown layer algorithm: ${layer.a}`);
    }
  }

  try {
    return JSON.parse(dec.decode(payload));
  } catch {
    throw new Error('Decrypted payload is not valid JSON.');
  }
};
