/* eslint-disable max-len */
import assert from 'node:assert';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import { address } from '../lib/address.js';

describe('address', () => {
  describe('decode', () => {
    it('should decode address', () => {
      const decoded = address('mainnet').decode('47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1xXgiDt');
      assert.strictEqual(decoded.type, 'address');
      assert.deepStrictEqual(decoded.publicSpendKey, hexToBytes('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7'));
      assert.deepStrictEqual(decoded.publicViewKey, hexToBytes('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108'));
    });

    it('should decode subaddress', () => {
      const decoded = address('mainnet').decode('8BKDtGLgpy8GKMhxBYNjK3Y1XW1yzKQ8aeR88i84521NZ4XHtk9wtTZX988HHUdsFL5eYZTrzPGmtiiLvdDJVvNRNCJKsR7');
      assert.strictEqual(decoded.type, 'subaddress');
      assert.deepStrictEqual(decoded.publicSpendKey, hexToBytes('e9d78cb7bebdbb5b924556a5ce5e36b9641ee7b90c14d3dfb1f4189ffdc929bf'));
      assert.deepStrictEqual(decoded.publicViewKey, hexToBytes('adb6f3010be5c0b4321191f6f9d9171bc8d2d231e0fe67f962789feeb789bebb'));
    });

    it('should decode integrated address', () => {
      const decoded = address('mainnet').decode('4HNXMYnW5mZ8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax2SEU4v4fc3hLJGgron');
      assert.strictEqual(decoded.type, 'integratedaddress');
      assert.deepStrictEqual(decoded.publicSpendKey, hexToBytes('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7'));
      assert.deepStrictEqual(decoded.publicViewKey, hexToBytes('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108'));
      assert.deepStrictEqual(decoded.paymentID, hexToBytes('945c0d11d13908ab'));
    });

    it('should throw invalid checksum', () => {
      assert.throws(() => {
        address('mainnet').decode('47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1uMFe9D');
      }, { message: 'Invalid address checksum' });
    });

    it('should throw invalid prefix', () => {
      assert.throws(() => {
        address('mainnet').decode('173k6DE8Xgj8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1yJVx47');
      }, { message: 'Invalid address prefix' });
    });
  });

  describe('encode', () => {
    it('round-trips address / subaddress / integrated address', () => {
      const coder = address('mainnet');
      const cases = [
        '47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1xXgiDt',
        '8BKDtGLgpy8GKMhxBYNjK3Y1XW1yzKQ8aeR88i84521NZ4XHtk9wtTZX988HHUdsFL5eYZTrzPGmtiiLvdDJVvNRNCJKsR7',
        '4HNXMYnW5mZ8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax2SEU4v4fc3hLJGgron',
      ];
      for (const str of cases) {
        assert.strictEqual(coder.encode(coder.decode(str)), str);
      }
    });
  });
});
