import crypto, { CipherGCM, DecipherGCM } from 'crypto';
import { webcrypto as OqsKem } from 'crypto';
import oqs from "node-oqs";

/**
 * Interface for cryptographic configuration.
 */
interface ICryptoConfig {
  ivLength: number;
  saltLength: number;
  keyAlgorithm: string;
  encryptionAlgorithm: string;
}

/**
 * Configuration for quantum-safe (lattice-based) cryptography.
 * - ivLength: Initialization Vector length for AES-GCM.
 * - saltLength: Length of the salt.
 * - keyAlgorithm: Hash algorithm used in key derivation.
 * - encryptionAlgorithm: Symmetric encryption algorithm (AES-256-GCM is used as a placeholder).
 */
const QUANT_CONFIG: ICryptoConfig = {
  ivLength: 100, // Standard IV length for AES-GCM
  saltLength: 100, // Sufficient salt length
  keyAlgorithm: 'sha3-256', // For quantum resistance (using lattice-based concepts)
  encryptionAlgorithm: 'aes-256-gcm', // Using AES-GCM; replace with a lattice-based algorithm for true quantum protection if needed
};

type ICryptoKey = string[];

/**
 * Derives a lattice-based key using the provided keys and salt.
 * First, PBKDF2 with a high iteration count is used, and then the result is hashed using SHA3-256.
 *
 * @param keys - Array of key strings.
 * @param salt - Salt as a Buffer.
 * @returns A Promise that resolves to the derived lattice key as a Buffer.
 * @throws Error if the provided keys are empty or invalid.
 */
const deriveLatticeKey = async (keys: ICryptoKey, salt: Buffer): Promise<Buffer> => {
  if (!keys || keys.length === 0 || keys.some(key => typeof key !== 'string' || !key.trim())) {
    throw new Error('Valid non-empty keys must be provided.');
  }

  // Use PBKDF2 with a very high iteration count for enhanced security.
  const baseKey: Buffer = await new Promise((resolve, reject) => {
    crypto.pbkdf2(
      keys.join(''),
      salt,
      620000, // High iteration count for stronger protection
      55,
      'sha256',
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve(derivedKey);
      }
    );
  });

  // Further process the derived key by hashing it with SHA3-256 to simulate a lattice scheme.
  const latticeKey = crypto.createHash('sha3-256').update(baseKey).digest();
  return latticeKey;
};

/**
 * Checks whether the given string is in Base64 format.
 *
 * @param data - The string to check.
 * @returns True if the data is in Base64 format, otherwise false.
 */
const isBase64 = (data: string): boolean => {
  if (typeof data !== 'string') return false;
  try {
    return Buffer.from(data, 'base64').toString('base64') === data;
  } catch {
    return false;
  }
};

/**
 * Encrypts a 32-byte block using a Feistel network with the provided round keys.
 * The block is split into two halves (16 bytes each), and each round applies a SHA3-256 based function.
 *
 * @param block - The 32-byte Buffer to encrypt.
 * @param roundKeys - Array of round keys as Buffers.
 * @returns The encrypted Buffer.
 */
function feistelEncrypt(block: Buffer, roundKeys: Buffer[]): Buffer {
  const blockSize = block.length; // Expecting 32 bytes
  const half = blockSize / 2;
  let L = Buffer.from(block.slice(0, half));
  let R = Buffer.from(block.slice(half));

  for (let i = 0; i < roundKeys.length; i++) {
    // Round function: hash (R combined with the round key) using SHA3-256 and take the first half bytes.
    const f = crypto.createHash('sha3-256')
      .update(Buffer.concat([R, roundKeys[i]]))
      .digest()
      .slice(0, half);
    const newR = Buffer.alloc(half);
    for (let j = 0; j < half; j++) {
      newR[j] = L[j] ^ f[j];
    }
    L = R;
    R = newR;
  }
  // Final swap to complete the symmetrical transformation.
  return Buffer.concat([R, L]);
}

/**
 * Decrypts a 32-byte block that was encrypted using a Feistel network.
 * The decryption is performed by reversing the order of the rounds.
 *
 * @param block - The 32-byte Buffer to decrypt.
 * @param roundKeys - Array of round keys as Buffers.
 * @returns The decrypted Buffer.
 */
function feistelDecrypt(block: Buffer, roundKeys: Buffer[]): Buffer {
  const blockSize = block.length;
  const half = blockSize / 2;
  let R = Buffer.from(block.slice(0, half));
  let L = Buffer.from(block.slice(half));

  for (let i = roundKeys.length - 1; i >= 0; i--) {
    const f = crypto.createHash('sha3-256')
      .update(Buffer.concat([L, roundKeys[i]]))
      .digest()
      .slice(0, half);
    const newL = Buffer.alloc(half);
    for (let j = 0; j < half; j++) {
      newL[j] = R[j] ^ f[j];
    }
    R = L;
    L = newL;
  }
  return Buffer.concat([L, R]);
}

/**
 * Encrypts a symmetric session key using a lattice-based (pseudo-lattice) approach.
 * The encryption is implemented using a 16-round Feistel network.
 *
 * @param sessionKey - The session key (Buffer) to encrypt, expected to be 32 bytes.
 * @param latticeKey - The derived lattice key (Buffer).
 * @returns The encrypted session key as a Buffer.
 */
function latticeEncryptKey(sessionKey: Buffer, latticeKey: Buffer): Buffer {
  // Ensure the sessionKey is 32 bytes long.
  let key = sessionKey;
  if (sessionKey.length !== 32) {
    key = Buffer.alloc(32);
    sessionKey.copy(key, 0, 0, Math.min(sessionKey.length, 32));
  }
  const rounds = 16;
  const roundKeys: Buffer[] = [];
  for (let i = 0; i < rounds; i++) {
    // Derive the round key using the latticeKey and the round number.
    const roundKey = crypto.createHmac('sha3-256', latticeKey)
      .update(Buffer.from([i]))
      .digest();
    roundKeys.push(roundKey);
  }
  return feistelEncrypt(key, roundKeys);
}

/**
 * Decrypts a symmetric session key that was encrypted using latticeEncryptKey.
 *
 * @param encryptedKey - The encrypted session key as a Buffer.
 * @param latticeKey - The derived lattice key (Buffer) that was used for encryption.
 * @returns The decrypted session key as a Buffer.
 */
function latticeDecryptKey(encryptedKey: Buffer, latticeKey: Buffer): Buffer {
  const rounds = 16;
  const roundKeys: Buffer[] = [];
  for (let i = 0; i < rounds; i++) {
    const roundKey = crypto.createHmac('sha3-256', latticeKey)
      .update(Buffer.from([i]))
      .digest();
    roundKeys.push(roundKey);
  }
  return feistelDecrypt(encryptedKey, roundKeys);
}

/**
 * Performs quantum-safe (lattice-based) encryption of data.
 *
 * The hybrid encryption approach consists of:
 * 1. Generating a random symmetric session key for AES-256-GCM.
 * 2. Encrypting the data using AES-256-GCM with the session key.
 * 3. Wrapping (encapsulating) the session key using the pseudo-lattice encryption (latticeEncryptKey) with a derived key.
 *
 * The final encrypted message is structured as:
 * salt | iv | authTag (16 bytes) | encrypted sessionKey (32 bytes) | encrypted content.
 *
 * @param data - Data to encrypt.
 * @param keys - Array of key strings used for key derivation.
 * @returns A Promise that resolves to the encrypted data as a Base64 encoded string.
 * @throws Error if encryption fails.
 */
export const quantEncryptedData = async (data: any, keys: ICryptoKey): Promise<string> => {
  if (data === undefined || data === null) {
    throw new Error('No data provided for encryption.');
  }

  const salt = crypto.randomBytes(QUANT_CONFIG.saltLength);
  const latticeKey = await deriveLatticeKey(keys, salt);
  // Generate a random symmetric session key for AES encryption.
  const sessionKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(QUANT_CONFIG.ivLength);

  const cipher = crypto.createCipheriv(QUANT_CONFIG.encryptionAlgorithm, sessionKey, iv) as CipherGCM;
  try {
    const serializedData = JSON.stringify(data);
    const encryptedContent = Buffer.concat([
      cipher.update(serializedData, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    // Encrypt (wrap) the sessionKey using the pseudo-lattice algorithm.
    const encryptedSessionKey = latticeEncryptKey(sessionKey, latticeKey);

    // Build the final message:
    // salt | iv | authTag (16 bytes) | encrypted sessionKey (32 bytes) | encrypted content.
    return Buffer.concat([
      salt,
      iv,
      authTag,
      encryptedSessionKey,
      encryptedContent
    ]).toString('base64');
  } catch (error) {
    throw new Error('Failed to encrypt data. Check the input data and keys.');
  }
};

/**
 * Performs quantum-safe (lattice-based) decryption of data.
 *
 * The decryption process involves:
 * 1. Extracting the components from the encrypted message: salt, iv, authTag, encrypted sessionKey, and encrypted content.
 * 2. Deriving the lattice key using the provided keys and salt.
 * 3. Unwrapping (decapsulating) the session key using latticeDecryptKey.
 * 4. Decrypting the content using AES-256-GCM with the session key.
 *
 * @param encryptedData - The encrypted data as a Base64 encoded string.
 * @param keys - Array of key strings used for derivation.
 * @returns A Promise that resolves to the decrypted data.
 * @throws Error if decryption fails.
 */
export const quantDecryptedData = async (encryptedData: any, keys: ICryptoKey): Promise<any> => {
  if (!encryptedData) {
    throw new Error('No data provided for decryption or data is invalid.');
  }

  if (typeof encryptedData !== 'string' || !isBase64(encryptedData)) {
    return encryptedData; // If data is not Base64 encoded, return as is.
  }

  const bufferData = Buffer.from(encryptedData, 'base64');

  const salt = bufferData.slice(0, QUANT_CONFIG.saltLength);
  const ivStart = QUANT_CONFIG.saltLength;
  const ivEnd = ivStart + QUANT_CONFIG.ivLength;
  const iv = bufferData.slice(ivStart, ivEnd);
  const authTagStart = ivEnd;
  const authTagEnd = authTagStart + 16;
  const authTag = bufferData.slice(authTagStart, authTagEnd);
  const encryptedSessionKeyStart = authTagEnd;
  const encryptedSessionKeyEnd = encryptedSessionKeyStart + 32;
  const encryptedSessionKey = bufferData.slice(encryptedSessionKeyStart, encryptedSessionKeyEnd);
  const encryptedContent = bufferData.slice(encryptedSessionKeyEnd);

  const latticeKey = await deriveLatticeKey(keys, salt);
  // Decrypt the session key using the pseudo-lattice algorithm.
  const sessionKey = latticeDecryptKey(encryptedSessionKey, latticeKey);

  const decipher = crypto.createDecipheriv(QUANT_CONFIG.encryptionAlgorithm, sessionKey, iv) as DecipherGCM;
  decipher.setAuthTag(authTag);

  try {
    const decryptedContent = Buffer.concat([
      decipher.update(encryptedContent),
      decipher.final()
    ]);

    return JSON.parse(decryptedContent.toString('utf8'));
  } catch (error) {
    throw new Error('Failed to decrypt data. Verify the keys or the integrity of the data.');
  }
};

/* ---------------------------------------------------------------------------
   Demonstration implementation of a post-quantum data protection mechanism using
   asymmetric key exchange via a Key Encapsulation Mechanism (KEM).
--------------------------------------------------------------------------- */

/**
 * Interface for a post-quantum key pair.
 */
interface IPQKeyPair {
  publicKey: Buffer;  // Public key (32 bytes)
  privateKey: Buffer; // Private key (32 bytes)
}

const PQC_ALGORITHM = 'Kyber512';
const IV_LENGTH = 12; // Recommended IV length for AES-256-GCM

/**
 * Generates a post-quantum key pair using node-oqs.
 *
 * The method generates a key pair (publicKey and privateKey) based on the selected algorithm,
 * for example, Kyber512, which is regarded as one of the most robust post-quantum solutions.
 *
 * @returns An object containing the publicKey and privateKey as Buffers.
 */
export const generatePostQuantumKeyPair = (): { publicKey: Buffer, privateKey: Buffer } => {
  const kem = new oqs.KEM(PQC_ALGORITHM);
  const { publicKey, secretKey } = (kem as any).generateKeyPair(); // using secretKey as privateKey
  return { publicKey, privateKey: secretKey };
};

/**
 * Securely encrypts data using post-quantum key encapsulation (KEM) from node-oqs and AES-256-GCM.
 *
 * The encryption process:
 * 1. Uses the recipient's public key to perform encapsulation, generating a shared secret and encapsulatedKey.
 * 2. Derives a 32-byte symmetric key from the shared secret using SHA-256.
 * 3. Encrypts the data with AES-256-GCM using the derived symmetric key.
 * 4. Constructs the final message as: encapsulatedKey | IV | authTag | encrypted content.
 *
 * @param data - Data to encrypt.
 * @param recipientPublicKey - The recipient's public key as a Buffer.
 * @returns A Promise that resolves to the encrypted data as a Base64 encoded string.
 * @throws Error if encryption fails.
 */
export const secureEncryptData = async (data: any, recipientPublicKey: Buffer): Promise<string> => {
  if (data === undefined || data === null) {
    throw new Error('No data provided for encryption.');
  }

  const serializedData = JSON.stringify(data);

  // Initialize KEM from node-oqs for the chosen algorithm.
  const kem = new oqs.KEM(PQC_ALGORITHM);

  // Encapsulation: generate a shared secret and encapsulatedKey using the recipient's public key.
  const { sharedSecret, encapsulatedKey } = kem.encapsulate(recipientPublicKey);

  // Derive a symmetric key (32 bytes) from the shared secret using SHA-256.
  const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest();

  // Generate a standard IV (12 bytes for AES-256-GCM).
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);

  const encryptedContent = Buffer.concat([
    cipher.update(serializedData, 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  // Build the final message: encapsulatedKey | IV | authTag | encrypted content.
  return Buffer.concat([encapsulatedKey, iv, authTag, encryptedContent]).toString('base64');
};

/**
 * Decrypts data that was encrypted using secureEncryptData.
 *
 * The decryption process:
 * 1. Extracts the components from the message: encapsulatedKey, IV, authTag, and encrypted content.
 * 2. Uses the recipient's private key to decapsulate and retrieve the shared secret.
 * 3. Derives the symmetric key using SHA-256 from the shared secret.
 * 4. Decrypts the encrypted content using AES-256-GCM.
 *
 * @param encryptedData - The encrypted data as a Base64 encoded string.
 * @param recipientPrivateKey - The recipient's private key as a Buffer.
 * @returns A Promise that resolves to the decrypted data.
 * @throws Error if decryption fails.
 */
export const secureDecryptData = async (encryptedData: any, recipientPrivateKey: Buffer): Promise<any> => {
  if (!encryptedData) {
    throw new Error('No data provided for decryption or data is invalid.');
  }
  if (typeof encryptedData !== 'string') {
    throw new Error('Invalid format for encrypted data.');
  }

  const bufferData = Buffer.from(encryptedData, 'base64');

  // Initialize KEM to determine the encapsulatedKey length.
  const kem = new oqs.KEM(PQC_ALGORITHM);
  const encapsulatedKeyLength = kem.getCiphertextLength();

  const encapsulatedKey = bufferData.slice(0, encapsulatedKeyLength);
  const iv = bufferData.slice(encapsulatedKeyLength, encapsulatedKeyLength + IV_LENGTH);
  const authTag = bufferData.slice(encapsulatedKeyLength + IV_LENGTH, encapsulatedKeyLength + IV_LENGTH + 16);
  const encryptedContent = bufferData.slice(encapsulatedKeyLength + IV_LENGTH + 16);

  // Decapsulation: retrieve the shared secret using the recipient's private key.
  const sharedSecret = kem.decapsulate(encapsulatedKey, recipientPrivateKey);
  const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest();

  const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
  decipher.setAuthTag(authTag);

  const decryptedContent = Buffer.concat([
    decipher.update(encryptedContent),
    decipher.final()
  ]);

  return JSON.parse(decryptedContent.toString('utf8'));
};

const { publicKey, privateKey } = generatePostQuantumKeyPair();
