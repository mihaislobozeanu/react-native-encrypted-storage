'use strict';

/**
 * Jest configuration for running tests inside node_modules.
 *
 * Three non-obvious settings are required:
 *
 * 1. haste.retainAllFiles — jest-haste-map hard-codes a filter that drops any
 *    file whose absolute path contains "/node_modules/". retainAllFiles bypasses
 *    that filter so our test files (which live inside a parent project's
 *    node_modules) are actually discovered.
 *
 * 2. haste platform fields — our haste override would otherwise lose the
 *    defaultPlatform / platforms values from the react-native preset, causing
 *    platform-specific files (e.g. Image.ios.js) to be unresolvable and
 *    breaking the preset's setup.js.
 *
 * 3. transformIgnorePatterns — with retainAllFiles the preset's regex
 *    "node_modules/(?!...)" matches the FIRST "node_modules" segment in our
 *    absolute path (the parent project's), so @react-native packages end up
 *    untransformed and fail on Flow syntax. Anchoring to <rootDir> fixes this.
 *
 * 4. moduleNameMapper for react-native — the preset's setup.js mocks
 *    NativeModules without RNEncryptedStorage; our __mocks__/react-native.js
 *    is only picked up when explicitly requested via jest.mock(), which the
 *    test file does not call. Mapping the module directly bypasses that gap.
 */
module.exports = {
  preset: 'react-native',

  haste: {
    defaultPlatform: 'ios',
    platforms: ['android', 'ios', 'native'],
    retainAllFiles: true,
  },

  transformIgnorePatterns: [
    '<rootDir>/node_modules/(?!(@react-native|react-native)/)',
  ],

  testPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/lib/',
  ],

  modulePathIgnorePatterns: [
    '<rootDir>/example/node_modules',
    '<rootDir>/lib/',
  ],

  moduleNameMapper: {
    // Replace the real react-native package with the project's hand-rolled mock
    // so that NativeModules.RNEncryptedStorage is available when EncryptedStorage.ts
    // is loaded (the module guard throws immediately if the native module is absent).
    '^react-native$': '<rootDir>/src/__mocks__/react-native.js',
  },

};
