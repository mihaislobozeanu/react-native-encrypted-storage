/// <reference lib="dom" />
/* eslint-disable no-dupe-class-members */

/**
 * Web implementation of EncryptedStorage using the Web Crypto API and localStorage.
 *
 * Security model:
 * - The AES-GCM 256-bit key is **non-extractable** and stored in IndexedDB as a CryptoKey
 *   object. Because the key is non-extractable, it cannot be exported or exfiltrated by
 *   XSS code — an attacker would have to decrypt within the browser using the same API,
 *   which limits offline attacks.
 * - Encrypted values are stored in localStorage, prefixed with STORAGE_PREFIX.
 * - This implementation requires a **secure context** (HTTPS or localhost), where
 *   crypto.subtle is available.
 *
 * Limitations vs native:
 * - Not backed by hardware (Keychain / EncryptedSharedPreferences). An attacker with
 *   full JavaScript access to the origin can still use the key in-browser to decrypt.
 * - Provides meaningful protection against: raw storage inspection, non-JS access to
 *   localStorage files, and key exfiltration to remote servers.
 */

const STORAGE_PREFIX = 'RNEncryptedStorage_';
const DB_NAME = 'RNEncryptedStorageDB';
const DB_STORE = 'cryptoKeys';
const KEY_ID = 'main';

// ─── IndexedDB ───────────────────────────────────────────────────────────────

// Singleton DB connection — opened once and reused across all operations.
let _dbPromise: Promise<IDBDatabase> | null = null;

function getDatabase(): Promise<IDBDatabase> {
  if (!_dbPromise) {
    _dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(DB_STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => {
        _dbPromise = null;
        reject(request.error);
      };
    });
  }
  return _dbPromise;
}

// ─── Crypto key ──────────────────────────────────────────────────────────────

// Singleton key promise — guarantees the key is initialised exactly once, even
// when multiple operations are called concurrently before the first key is ready.
let _cryptoKeyPromise: Promise<CryptoKey> | null = null;

/**
 * Resets module-level singletons. Intended for use in tests only.
 * Call this in beforeEach alongside a fresh IDBFactory instance to guarantee
 * each test starts with a clean DB connection and no cached CryptoKey.
 * @internal
 */
export function __resetForTesting(): void {
  _dbPromise = null;
  _cryptoKeyPromise = null;
}

function getOrCreateCryptoKey(): Promise<CryptoKey> {
  if (!_cryptoKeyPromise) {
    _cryptoKeyPromise = initCryptoKey().catch((err: unknown) => {
      // Reset on failure so the next call can retry.
      _cryptoKeyPromise = null;
      throw err;
    });
  }
  return _cryptoKeyPromise;
}

async function initCryptoKey(): Promise<CryptoKey> {
  const db = await getDatabase();

  // Attempt to load an existing key from IndexedDB.
  const existing = await new Promise<CryptoKey | undefined>(
    (resolve, reject) => {
      const tx = db.transaction(DB_STORE, 'readonly');
      const req = tx.objectStore(DB_STORE).get(KEY_ID);
      req.onsuccess = () => resolve(req.result as CryptoKey | undefined);
      req.onerror = () => reject(req.error);
    }
  );

  if (existing) return existing;

  // Generate a new non-extractable AES-GCM 256-bit key.
  // Non-extractable means the raw key bytes are never exposed to JavaScript,
  // so an XSS script cannot exfiltrate the key material to a remote server.
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );

  // Persist the CryptoKey object in IndexedDB.
  // IndexedDB can store CryptoKey objects natively, even non-extractable ones.
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).put(key, KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });

  return key;
}

// ─── Encrypt / Decrypt ───────────────────────────────────────────────────────

/**
 * Encrypts a string value using AES-GCM with a random 12-byte IV.
 * The result is base64-encoded and contains the IV prepended to the ciphertext.
 * Uses chunked string conversion to avoid stack overflow on large payloads.
 * @param {CryptoKey} key - The AES-GCM key to use for encryption.
 * @param {string} value - The plaintext string to encrypt.
 */
async function encryptValue(key: CryptoKey, value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(value);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  // Combine iv (12 bytes) + ciphertext into a single Uint8Array.
  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);

  // Chunked conversion avoids a stack overflow when spread-calling
  // String.fromCharCode on large arrays (> ~100 KB).
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < combined.length; i += chunkSize) {
    binary += String.fromCharCode(...combined.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/**
 * Decrypts a base64-encoded AES-GCM encrypted string.
 * Expects the first 12 bytes to be the IV, followed by the ciphertext.
 * @param {CryptoKey} key - The AES-GCM key to use for decryption.
 * @param {string} stored - The base64-encoded string to decrypt.
 */
async function decryptValue(key: CryptoKey, stored: string): Promise<string> {
  const combined = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// ─── Public API ──────────────────────────────────────────────────────────────

export type StorageErrorCallback = (error?: Error) => void;
export type StorageValueCallback = (error?: Error, value?: string) => void;

export default class EncryptedStorage {
  /**
   * Writes data to localStorage, encrypted with AES-GCM using the Web Crypto API.
   * Requires a secure context (HTTPS or localhost).
   * @param {string} key - A string that will be associated to the value for later retrieval.
   * @param {string} value - The data to store.
   */
  static setItem(key: string, value: string): Promise<void>;

  /**
   * Writes data to localStorage, encrypted with AES-GCM using the Web Crypto API.
   * Requires a secure context (HTTPS or localhost).
   * @param {string} key - A string that will be associated to the value for later retrieval.
   * @param {string} value - The data to store.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static setItem(key: string, value: string, cb: StorageErrorCallback): void;
  static setItem(
    key: string,
    value: string,
    cb?: StorageErrorCallback
  ): void | Promise<void> {
    const operation = async (): Promise<void> => {
      const cryptoKey = await getOrCreateCryptoKey();
      const encrypted = await encryptValue(cryptoKey, value);
      localStorage.setItem(STORAGE_PREFIX + key, encrypted);
    };

    if (cb) {
      operation().then(() => cb()).catch(cb);
      return;
    }

    return operation();
  }

  /**
   * Retrieves and decrypts data from localStorage.
   * Returns null if no value is found for the given key.
   * @param {string} key - A string that is associated to a value.
   */
  static getItem(key: string): Promise<string | null>;

  /**
   * Retrieves and decrypts data from localStorage.
   * Returns null if no value is found for the given key.
   * The callback receives undefined as the value when the key does not exist.
   * @param {string} key - A string that is associated to a value.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static getItem(key: string, cb: StorageValueCallback): void;
  static getItem(
    key: string,
    cb?: StorageValueCallback
  ): void | Promise<string | null> {
    const operation = async (): Promise<string | null> => {
      const stored = localStorage.getItem(STORAGE_PREFIX + key);
      if (stored === null) return null;

      const cryptoKey = await getOrCreateCryptoKey();
      return await decryptValue(cryptoKey, stored);
    };

    if (cb) {
      operation()
        .then((value) => cb(undefined, value ?? undefined))
        .catch(cb);
      return;
    }

    return operation();
  }

  /**
   * Removes an encrypted entry from localStorage.
   * @param {string} key - A string that is associated to a value.
   */
  static removeItem(key: string): Promise<void>;

  /**
   * Removes an encrypted entry from localStorage.
   * @param {string} key - A string that is associated to a value.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static removeItem(key: string, cb: StorageErrorCallback): void;
  static removeItem(
    key: string,
    cb?: StorageErrorCallback
  ): void | Promise<void> {
    const operation = (): Promise<void> => {
      localStorage.removeItem(STORAGE_PREFIX + key);
      return Promise.resolve();
    };

    if (cb) {
      operation().then(() => cb()).catch(cb);
      return;
    }

    return operation();
  }

  /**
   * Clears all entries written by EncryptedStorage from localStorage.
   * Only removes keys with the RNEncryptedStorage_ prefix; other localStorage entries are unaffected.
   */
  static clear(): Promise<void>;

  /**
   * Clears all entries written by EncryptedStorage from localStorage.
   * Only removes keys with the RNEncryptedStorage_ prefix; other localStorage entries are unaffected.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static clear(cb: StorageErrorCallback): void;
  static clear(cb?: StorageErrorCallback): void | Promise<void> {
    const operation = (): Promise<void> => {
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith(STORAGE_PREFIX)) {
          keysToRemove.push(k);
        }
      }
      keysToRemove.forEach((k) => localStorage.removeItem(k));
      return Promise.resolve();
    };

    if (cb) {
      operation().then(() => cb()).catch(cb);
      return;
    }

    return operation();
  }
}
