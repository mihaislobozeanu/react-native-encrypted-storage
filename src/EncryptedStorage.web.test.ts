/**
 * @jest-environment node
 */

import { webcrypto } from 'crypto';
import { IDBFactory } from 'fake-indexeddb';
import EncryptedStorage, { __resetForTesting } from './EncryptedStorage.web';

// Polyfill Web Crypto API (available natively in Node 15+)
Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  writable: true,
});

// Minimal localStorage implementation for the Node test environment
const localStorageStore: Record<string, string> = {};
const localStorageMock = {
  getItem: jest.fn((key: string) => localStorageStore[key] ?? null),
  setItem: jest.fn((key: string, value: string) => {
    localStorageStore[key] = value;
  }),
  removeItem: jest.fn((key: string) => {
    delete localStorageStore[key];
  }),
  get length() {
    return Object.keys(localStorageStore).length;
  },
  key: jest.fn(
    (index: number) => Object.keys(localStorageStore)[index] ?? null
  ),
  clear: jest.fn(() => {
    Object.keys(localStorageStore).forEach((k) => delete localStorageStore[k]);
  }),
};

Object.defineProperty(globalThis, 'localStorage', {
  value: localStorageMock,
  writable: true,
});

beforeEach(() => {
  // Fresh in-memory IDB instance — each test gets an empty database.
  // Combined with __resetForTesting(), this guarantees _dbPromise and
  // _cryptoKeyPromise are re-created from scratch, not carried over from
  // a previous test (jest.resetModules() alone doesn't help because the
  // module is already imported at the top level).
  globalThis.indexedDB = new IDBFactory();

  // Reset module-level singletons so the next operation re-opens the DB
  // and re-generates the CryptoKey against the fresh IDB instance above.
  __resetForTesting();

  localStorageMock.clear();
  jest.clearAllMocks();
});

describe('EncryptedStorage (web)', () => {
  describe('using Promises', () => {
    describe('setItem(key, value)', () => {
      it('should resolve without errors', () => {
        return expect(
          EncryptedStorage.setItem('key', 'value')
        ).resolves.toBeUndefined();
      });

      it('should store an encrypted (non-plaintext) value in localStorage', async () => {
        await EncryptedStorage.setItem('key', 'secret');
        const stored = localStorageMock.getItem('RNEncryptedStorage_key');
        expect(stored).not.toBeNull();
        expect(stored).not.toEqual('secret');
      });
    });

    describe('getItem(key)', () => {
      it('should return the original value after storing it', async () => {
        await EncryptedStorage.setItem('key', 'hello world');
        return expect(EncryptedStorage.getItem('key')).resolves.toEqual(
          'hello world'
        );
      });

      it('should return null if no value was found for that key', () => {
        return expect(EncryptedStorage.getItem('missing')).resolves.toBeNull();
      });

      it('should correctly round-trip a JSON string', async () => {
        const json = JSON.stringify({ foo: 1, bar: [2, 3] });
        await EncryptedStorage.setItem('json', json);
        return expect(EncryptedStorage.getItem('json')).resolves.toEqual(json);
      });

      it('should correctly round-trip a large payload (> 8 KB)', async () => {
        const large = 'x'.repeat(100_000);
        await EncryptedStorage.setItem('large', large);
        return expect(EncryptedStorage.getItem('large')).resolves.toEqual(
          large
        );
      });
    });

    describe('removeItem(key)', () => {
      it('should resolve without errors', async () => {
        await EncryptedStorage.setItem('key', 'value');
        return expect(
          EncryptedStorage.removeItem('key')
        ).resolves.toBeUndefined();
      });

      it('should make the value unretrievable after removal', async () => {
        await EncryptedStorage.setItem('key', 'value');
        await EncryptedStorage.removeItem('key');
        return expect(EncryptedStorage.getItem('key')).resolves.toBeNull();
      });
    });

    describe('clear()', () => {
      it('should resolve without errors', () => {
        return expect(EncryptedStorage.clear()).resolves.toBeUndefined();
      });

      it('should remove all EncryptedStorage entries', async () => {
        await EncryptedStorage.setItem('key1', 'value1');
        await EncryptedStorage.setItem('key2', 'value2');
        await EncryptedStorage.clear();
        await expect(EncryptedStorage.getItem('key1')).resolves.toBeNull();
        await expect(EncryptedStorage.getItem('key2')).resolves.toBeNull();
      });

      it('should not remove unrelated localStorage entries', async () => {
        localStorageMock.setItem('unrelated', 'keep-me');
        await EncryptedStorage.setItem('key', 'value');
        await EncryptedStorage.clear();
        expect(localStorageMock.getItem('unrelated')).toEqual('keep-me');
      });
    });
  });

  describe('using callbacks', () => {
    describe('setItem(key, value, cb)', () => {
      it('should call the callback without errors', (done) => {
        EncryptedStorage.setItem('key', 'value', (error) => {
          expect(error).toBeUndefined();
          done();
        });
      });
    });

    describe('getItem(key, cb)', () => {
      it('should call the callback with the stored value', (done) => {
        EncryptedStorage.setItem('key', 'hello', () => {
          EncryptedStorage.getItem('key', (error, value) => {
            expect(error).toBeUndefined();
            expect(value).toEqual('hello');
            done();
          });
        });
      });

      it('should call the callback with undefined if key does not exist', (done) => {
        EncryptedStorage.getItem('missing', (error, value) => {
          expect(error).toBeUndefined();
          expect(value).toBeUndefined();
          done();
        });
      });
    });

    describe('removeItem(key, cb)', () => {
      it('should call the callback without errors', (done) => {
        EncryptedStorage.setItem('key', 'value', () => {
          EncryptedStorage.removeItem('key', (error) => {
            expect(error).toBeUndefined();
            done();
          });
        });
      });
    });

    describe('clear(cb)', () => {
      it('should call the callback without errors', (done) => {
        EncryptedStorage.clear((error) => {
          expect(error).toBeUndefined();
          done();
        });
      });
    });
  });

  describe('encryption', () => {
    it('should produce different ciphertext for the same value on each write (random IV)', async () => {
      await EncryptedStorage.setItem('key', 'same-value');
      const first = localStorageMock.getItem('RNEncryptedStorage_key');

      localStorageMock.removeItem('RNEncryptedStorage_key');

      await EncryptedStorage.setItem('key', 'same-value');
      const second = localStorageMock.getItem('RNEncryptedStorage_key');

      expect(first).not.toEqual(second);
    });

    it('should reject when stored data is corrupted (invalid base64 content)', async () => {
      // Inject corrupted ciphertext directly into localStorage
      localStorageMock.setItem('RNEncryptedStorage_corrupted', '!!!not-base64!!!');
      await expect(EncryptedStorage.getItem('corrupted')).rejects.toThrow();
    });

    it('should reject when stored data has been tampered with (valid base64, wrong ciphertext)', async () => {
      // Store a valid item, then corrupt the ciphertext bytes
      await EncryptedStorage.setItem('key', 'original');
      const stored = localStorageMock.getItem('RNEncryptedStorage_key') as string;

      // Flip bytes after the 12-byte IV
      const bytes = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
      // bytes always has iv (12) + ciphertext (≥16) bytes, so index 12 is safe
      bytes.set([((bytes[12] ?? 0) ^ 0xff)], 12);
      const tampered = btoa(String.fromCharCode(...bytes));
      localStorageMock.setItem('RNEncryptedStorage_key', tampered);

      await expect(EncryptedStorage.getItem('key')).rejects.toThrow();
    });
  });

  describe('concurrency', () => {
    it('should handle multiple concurrent setItem calls without race conditions', async () => {
      // Fire 10 concurrent writes before the key is initialized.
      // All must succeed and be independently retrievable.
      await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          EncryptedStorage.setItem(`k${i}`, `v${i}`)
        )
      );

      const results = await Promise.all(
        Array.from({ length: 10 }, (_, i) => EncryptedStorage.getItem(`k${i}`))
      );

      results.forEach((value, i) => {
        expect(value).toEqual(`v${i}`);
      });
    });

    it('should use only one CryptoKey regardless of concurrent initialization', async () => {
      // Trigger concurrent initialization
      await Promise.all([
        EncryptedStorage.setItem('a', '1'),
        EncryptedStorage.setItem('b', '2'),
        EncryptedStorage.setItem('c', '3'),
      ]);

      // All values must be decryptable, proving only one key was used
      expect(await EncryptedStorage.getItem('a')).toEqual('1');
      expect(await EncryptedStorage.getItem('b')).toEqual('2');
      expect(await EncryptedStorage.getItem('c')).toEqual('3');
    });
  });
});
