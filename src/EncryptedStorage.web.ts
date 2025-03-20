import AsyncStorage from '@react-native-async-storage/async-storage';
import crypto from "crypto";

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const ITERATIONS = 100000;

async function deriveKeyFromPassword(password: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  const keyMaterial = await crypto.subtle.importKey(
    'raw', 
    new TextEncoder().encode(password), 
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', derivedKey));
  return rawKey;
}

export default class EncryptedStorage {
  /**
   * Converts a string to a Uint8Array (needed for the Web Crypto API)
   * @param {string} str - The string to convert.
   */
  static stringToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  /**
   * Converts a Uint8Array back to a string
   * @param {Uint8Array} uint8Array - The Uint8Array to convert.
   */
  static uint8ArrayToString(uint8Array: Uint8Array): string {
    return new TextDecoder().decode(uint8Array);
  }

  /**
   * Encrypt data using AES-GCM.
   * @param {string} data - The data to encrypt.
   * @param {string} password - The password used for key derivation.
   */
  static async encrypt(data: string, password: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await deriveKeyFromPassword(password);

    const encodedData = this.stringToUint8Array(data);
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key as any,
      encodedData
    );

    const encryptedArray = new Uint8Array(encryptedData);
    const encryptedBase64 = btoa(String.fromCharCode(...encryptedArray));

    // Return IV + encrypted data as Base64
    return `${btoa(String.fromCharCode(...iv))}:${encryptedBase64}`;
  }

  /**
   * Decrypt data using AES-GCM.
   * @param {string} encryptedData - The encrypted data (with IV).
   * @param {string} password - The password used for key derivation.
   */
  static async decrypt(encryptedData: string, password: string): Promise<string> {
    const [ivBase64, encryptedBase64] = encryptedData.split(':');
    const iv = new Uint8Array(atob(ivBase64 ?? "").split('').map((c) => c.charCodeAt(0)));
    const encrypted = new Uint8Array(atob(encryptedBase64 ?? "").split('').map((c) => c.charCodeAt(0)));

    const key = await deriveKeyFromPassword(password);

    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key as any,
      encrypted
    );

    return this.uint8ArrayToString(new Uint8Array(decryptedData));
  }

  /**
   * Writes encrypted data to AsyncStorage.
   * @param {string} key - The key for the item.
   * @param {string} value - The value to store (it will be encrypted).
   * @param {string} password - The password used to derive the encryption key.
   */
  static async setItem(key: string, value: string, password: string): Promise<void> {
    try {
      const encryptedValue = await this.encrypt(value, password);
      await AsyncStorage.setItem(key, encryptedValue);
    } catch (error) {
      throw new Error(`Failed to set item in AsyncStorage: ${error}`);
    }
  }

  /**
   * Retrieves and decrypts data from AsyncStorage.
   * @param {string} key - The key for the item.
   * @param {string} password - The password used to derive the encryption key.
   */
  static async getItem(key: string, password: string): Promise<string | null> {
    try {
      const encryptedValue = await AsyncStorage.getItem(key);
      if (encryptedValue) {
        return await this.decrypt(encryptedValue, password);
      }
      return null;
    } catch (error) {
      throw new Error(`Failed to get item from AsyncStorage: ${error}`);
    }
  }

  /**
   * Removes data from AsyncStorage.
   * @param {string} key - The key for the item.
   */
  static async removeItem(key: string): Promise<void> {
    try {
      await AsyncStorage.removeItem(key);
    } catch (error) {
      throw new Error(`Failed to remove item from AsyncStorage: ${error}`);
    }
  }

  /**
   * Clears all data from AsyncStorage.
   */
  static async clear(): Promise<void> {
    try {
      await AsyncStorage.clear();
    } catch (error) {
      throw new Error(`Failed to clear AsyncStorage: ${error}`);
    }
  }
}
