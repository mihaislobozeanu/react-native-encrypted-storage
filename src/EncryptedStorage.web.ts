/* eslint-disable no-dupe-class-members */

import AsyncStorage from '@react-native-async-storage/async-storage';

export type StorageErrorCallback = (error?: Error) => void;
export type StorageValueCallback = (error?: Error, value?: string) => void;

export default class EncryptedStorage {
  /**
   * Writes data to async storage.
   * @param {string} key - A string that will be associated with the value for later retrieval.
   * @param {string} value - The data to store.
   */
  static setItem(key: string, value: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        AsyncStorage.setItem(key, value)
          .then(() => resolve())
          .catch((error) => reject(new Error("Failed to set item in AsyncStorage: " + error)));
      } catch (error) {
        reject(new Error("Failed to set item in AsyncStorage: " + error));
      }
    });
  }

  /**
   * Retrieves data from async storage.
   * @param {string} key - A string that is associated with a value.
   */
  static getItem(key: string): Promise<string | null> {
    return new Promise((resolve, reject) => {
      try {
        AsyncStorage.getItem(key)
          .then((value) => resolve(value))
          .catch((error) => reject(new Error("Failed to get item from AsyncStorage: " + error)));
      } catch (error) {
        reject(new Error("Failed to get item from AsyncStorage: " + error));
      }
    });
  }

  /**
   * Deletes data from async storage.
   * @param {string} key - A string that is associated with a value.
   */
  static removeItem(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        AsyncStorage.removeItem(key)
          .then(() => resolve())
          .catch((error) => reject(new Error("Failed to remove item from AsyncStorage: " + error)));
      } catch (error) {
        reject(new Error("Failed to remove item from AsyncStorage: " + error));
      }
    });
  }

  /**
   * Clears all data from async storage.
   */
  static clear(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        AsyncStorage.clear()
          .then(() => resolve())
          .catch((error) => reject(new Error("Failed to clear AsyncStorage: " + error)));
      } catch (error) {
        reject(new Error("Failed to clear AsyncStorage: " + error));
      }
    });
  }
}
