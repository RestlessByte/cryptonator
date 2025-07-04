'use client';

import crypto, { CipherGCM, DecipherGCM } from 'crypto';

interface ICryptoConfig {
  ivLength: number;
  saltLength: number;
  keyAlgorithm: string;
  encryptionAlgorithm: string;
}

type ICryptoKey = string[];

// Конфигурация
const CONFIG: ICryptoConfig = {
  ivLength: 120, // Оптимальная длина для AES-GCM
  saltLength: 120, // Достаточная длина соли
  keyAlgorithm: 'sha256', // Алгоритм для хэширования
  encryptionAlgorithm: 'aes-256-gcm', // Алгоритм шифрования
};

// Генерация соли
const generateSalt = (): Buffer => crypto.randomBytes(CONFIG.saltLength);

// Генерация комбинированного ключа
const deriveCombinedKey = async (keys: ICryptoKey, salt: Buffer): Promise<Buffer> => {
  if (!keys || keys.length === 0 || keys.some((key) => typeof key !== 'string' || !key.trim())) {
    throw new Error('Необходимо предоставить корректные непустые ключи.');
  }

  const combinedInput = keys.join('') + salt.toString('hex');
  return crypto.createHash(CONFIG.keyAlgorithm).update(combinedInput).digest();
};

// Проверка: данные в формате Base64
const isBase64 = (data: string): boolean => {
  if (typeof data !== 'string') return false;
  try {
    return Buffer.from(data, 'base64').toString('base64') === data;
  } catch {
    return false;
  }
};

// Шифрование данных
export const encryptedDataClient = async (data: any, keys: ICryptoKey): Promise<string> => {
  if (data === undefined || data === null) {
    throw new Error('Данные для шифрования отсутствуют.');
  }

  const salt = generateSalt();
  const combinedKey = await deriveCombinedKey(keys, salt);
  const iv = crypto.randomBytes(CONFIG.ivLength);

  // Явно используем CipherGCM
  const cipher = crypto.createCipheriv(CONFIG.encryptionAlgorithm, combinedKey.slice(0, 32), iv) as CipherGCM;

  try {
    const serializedData = JSON.stringify(data);
    const encryptedContent = Buffer.concat([cipher.update(serializedData, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Результат шифрования - Base64 строка
    return Buffer.concat([salt, iv, authTag, encryptedContent]).toString('base64');
  } catch (error) {
    throw new Error('Не удалось зашифровать данные. Проверьте входные данные и ключи.');
  }
};

// Дешифрование данных
export const decryptedDataClient = async (encryptedData: any, keys: ICryptoKey): Promise<any> => {
  if (!encryptedData) {
    throw new Error('Данные для дешифровки отсутствуют или некорректны.');
  }

  if (typeof encryptedData !== 'string' || !isBase64(encryptedData)) {
    return encryptedData; // Если это не строка Base64, возвращаем как есть
  }

  const bufferData = Buffer.from(encryptedData, 'base64');

  const salt = bufferData.slice(0, CONFIG.saltLength);
  const iv = bufferData.slice(CONFIG.saltLength, CONFIG.saltLength + CONFIG.ivLength);
  const authTag = bufferData.slice(
    CONFIG.saltLength + CONFIG.ivLength,
    CONFIG.saltLength + CONFIG.ivLength + 16
  );
  const encryptedContent = bufferData.slice(CONFIG.saltLength + CONFIG.ivLength + 16);

  const combinedKey = await deriveCombinedKey(keys, salt);

  // Явно используем DecipherGCM
  const decipher = crypto.createDecipheriv(CONFIG.encryptionAlgorithm, combinedKey.slice(0, 32), iv) as DecipherGCM;
  decipher.setAuthTag(authTag); // Теперь TypeScript знает, что метод существует

  try {
    const decryptedContent = Buffer.concat([decipher.update(encryptedContent), decipher.final()]);
    return JSON.parse(decryptedContent.toString('utf8'));
  } catch (error) {
    throw new Error('Не удалось расшифровать данные. Проверьте ключи или целостность данных.');
  }
};