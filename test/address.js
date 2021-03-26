/* eslint-disable max-len */
import assert from 'assert';
import Address from '../lib/address.js';

describe('Address', () => {
  describe('fromString', () => {
    it('should decode address', () => {
      const address = Address.fromString('47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1xXgiDt');
      assert.strictEqual(address.nettype, 'mainnet');
      assert.strictEqual(address.isSubaddress, false);
      assert.deepStrictEqual(address.publicSpendKey, Buffer.from('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7', 'hex'));
      assert.deepStrictEqual(address.publicViewKey, Buffer.from('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108', 'hex'));
    });

    it('should decode subaddress', () => {
      const address = Address.fromString('8BKDtGLgpy8GKMhxBYNjK3Y1XW1yzKQ8aeR88i84521NZ4XHtk9wtTZX988HHUdsFL5eYZTrzPGmtiiLvdDJVvNRNCJKsR7');
      assert.strictEqual(address.nettype, 'mainnet');
      assert.strictEqual(address.isSubaddress, true);
      assert.deepStrictEqual(address.publicSpendKey, Buffer.from('e9d78cb7bebdbb5b924556a5ce5e36b9641ee7b90c14d3dfb1f4189ffdc929bf', 'hex'));
      assert.deepStrictEqual(address.publicViewKey, Buffer.from('adb6f3010be5c0b4321191f6f9d9171bc8d2d231e0fe67f962789feeb789bebb', 'hex'));
    });

    it('should throw invalid checksum', () => {
      assert.throws(() => {
        Address.fromString('47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1uMFe9D');
      }, { message: 'Invalid address checksum' });
    });

    it('should throw invalid prefix', () => {
      assert.throws(() => {
        Address.fromString('173k6DE8Xgj8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1yJVx47');
      }, { message: 'Invalid address prefix' });
    });
  });
});

