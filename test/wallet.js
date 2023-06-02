/* eslint-disable max-len */
import Wallet from '../lib/Wallet.js';
import assert from 'assert';

describe('Wallet', () => {
  describe('constructor', () => {
    it('should create random wallet in mainnet', () => {
      const wallet = new Wallet();
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
    });

    it('should create random wallet in stagenet', () => {
      const wallet = new Wallet({ nettype: 'stagenet' });
      assert.deepStrictEqual(wallet.nettype, 'stagenet');
    });

    it('should throw on unknown nettype', () => {
      assert.throws(() => {
        new Wallet({ nettype: 'blabla' });
      }, { message: 'Invalid network type: blabla' });
    });

    it('should create wallet from seed', () => {
      const wallet = new Wallet({
        seed: Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex'),
      });
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
      assert.deepStrictEqual(wallet.seed, Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex'));
      assert.deepStrictEqual(wallet.secretSpendKey, Buffer.from('1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f', 'hex'));
      assert.deepStrictEqual(wallet.publicSpendKey, Buffer.from('db27fe4b7a4beb8c1b8c38a21e943a852304c9bb3035a5f36626b51162a68f9c', 'hex'));
      assert.deepStrictEqual(wallet.secretViewKey, Buffer.from('9fe83aa6104612b587eb2e6ee1f0c929f85ce047804a789f4d579f9d2e20de0b', 'hex'));
      assert.deepStrictEqual(wallet.publicViewKey, Buffer.from('beb87b123ca0be6228ef692cecc4ba5170cc55f3987f08006dc638743776ebb3', 'hex'));
    });

    it('should create wallet from seed (hex)', () => {
      const wallet = new Wallet({
        seed: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      });
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
      assert.deepStrictEqual(wallet.seed, Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex'));
      assert.deepStrictEqual(wallet.secretSpendKey, Buffer.from('1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f', 'hex'));
      assert.deepStrictEqual(wallet.publicSpendKey, Buffer.from('db27fe4b7a4beb8c1b8c38a21e943a852304c9bb3035a5f36626b51162a68f9c', 'hex'));
      assert.deepStrictEqual(wallet.secretViewKey, Buffer.from('9fe83aa6104612b587eb2e6ee1f0c929f85ce047804a789f4d579f9d2e20de0b', 'hex'));
      assert.deepStrictEqual(wallet.publicViewKey, Buffer.from('beb87b123ca0be6228ef692cecc4ba5170cc55f3987f08006dc638743776ebb3', 'hex'));
    });

    it('should create wallet from secret spend key and secret view key', () => {
      const wallet = new Wallet({
        secretSpendKey: Buffer.from('99095987370c530487be61900a4b167e4107ad39bb08b60256dc3c6a3e83ff03', 'hex'),
        secretViewKey: Buffer.from('21c7754089a21b4c326181f30c9616dce510e9007eaea65ef952b0a4de4bee0c', 'hex'),
      });
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
      assert.deepStrictEqual(wallet.secretSpendKey, Buffer.from('99095987370c530487be61900a4b167e4107ad39bb08b60256dc3c6a3e83ff03', 'hex'));
      assert.deepStrictEqual(wallet.publicSpendKey, Buffer.from('3d5ac932714307e24e10971a93ed267de205768387c55e4a097def70dadadd11', 'hex'));
      assert.deepStrictEqual(wallet.secretViewKey, Buffer.from('21c7754089a21b4c326181f30c9616dce510e9007eaea65ef952b0a4de4bee0c', 'hex'));
      assert.deepStrictEqual(wallet.publicViewKey, Buffer.from('181e4f7b6815c390b86db550b3f08b35e9b55931fc1215e4c97ee07d59d7e839', 'hex'));
    });

    it('should create wallet from secret spend key and secret view key (hex)', () => {
      const wallet = new Wallet({
        secretSpendKey: '99095987370c530487be61900a4b167e4107ad39bb08b60256dc3c6a3e83ff03',
        secretViewKey: '21c7754089a21b4c326181f30c9616dce510e9007eaea65ef952b0a4de4bee0c',
      });
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
      assert.deepStrictEqual(wallet.secretSpendKey, Buffer.from('99095987370c530487be61900a4b167e4107ad39bb08b60256dc3c6a3e83ff03', 'hex'));
      assert.deepStrictEqual(wallet.publicSpendKey, Buffer.from('3d5ac932714307e24e10971a93ed267de205768387c55e4a097def70dadadd11', 'hex'));
      assert.deepStrictEqual(wallet.secretViewKey, Buffer.from('21c7754089a21b4c326181f30c9616dce510e9007eaea65ef952b0a4de4bee0c', 'hex'));
      assert.deepStrictEqual(wallet.publicViewKey, Buffer.from('181e4f7b6815c390b86db550b3f08b35e9b55931fc1215e4c97ee07d59d7e839', 'hex'));
    });

    it('should create view only wallet from public spend key and secret view key', () => {
      const wallet = new Wallet({
        publicSpendKey: Buffer.from('74621fc98ad596d225e38f580836c85b50097c06bfba379599168bad649ec618', 'hex'),
        secretViewKey: Buffer.from('5fa548f256045ebe8e53f83554c106bbac2b34d9dacd040b6c5e0f96478bf005', 'hex'),
      });
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
      assert.deepStrictEqual(wallet.publicSpendKey, Buffer.from('74621fc98ad596d225e38f580836c85b50097c06bfba379599168bad649ec618', 'hex'));
      assert.deepStrictEqual(wallet.secretViewKey, Buffer.from('5fa548f256045ebe8e53f83554c106bbac2b34d9dacd040b6c5e0f96478bf005', 'hex'));
      assert.deepStrictEqual(wallet.publicViewKey, Buffer.from('cfda349dd1949862de366d070830c57bcbe1a53cbd8640016abde6f898abc273', 'hex'));
      assert.throws(() => {
        wallet.secretSpendKey;
      }, { message: 'Wallet in view only mode' });
      assert.throws(() => {
        wallet.seed;
      }, { message: 'Wallet in view only mode' });
    });

    it('should create view only wallet from public spend key and secret view key (hex)', () => {
      const wallet = new Wallet({
        publicSpendKey: '74621fc98ad596d225e38f580836c85b50097c06bfba379599168bad649ec618',
        secretViewKey: '5fa548f256045ebe8e53f83554c106bbac2b34d9dacd040b6c5e0f96478bf005',
      });
      assert.deepStrictEqual(wallet.nettype, 'mainnet');
      assert.deepStrictEqual(wallet.publicSpendKey, Buffer.from('74621fc98ad596d225e38f580836c85b50097c06bfba379599168bad649ec618', 'hex'));
      assert.deepStrictEqual(wallet.secretViewKey, Buffer.from('5fa548f256045ebe8e53f83554c106bbac2b34d9dacd040b6c5e0f96478bf005', 'hex'));
      assert.deepStrictEqual(wallet.publicViewKey, Buffer.from('cfda349dd1949862de366d070830c57bcbe1a53cbd8640016abde6f898abc273', 'hex'));
      assert.throws(() => {
        wallet.secretSpendKey;
      }, { message: 'Wallet in view only mode' });
      assert.throws(() => {
        wallet.seed;
      }, { message: 'Wallet in view only mode' });
    });
  });

  describe('getSubaddressSecret', () => {
    it('should generate the right subaddress secret key for account 1 with index 1', () => {
      const wallet = new Wallet({
        seed: Buffer.from('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903', 'hex'),
      });
      const actual = wallet.getSubaddressSecret(1, 1);
      assert.deepStrictEqual(actual, Buffer.from('81dea0953b33dcaed5097a7c2b94cf5e94a5d8fa9796631331ed656da187ea01', 'hex'));
    });
  });

  describe('getSubaddress from full wallet', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        seed: Buffer.from('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903', 'hex'),
      });
    });

    it('should generate the right address for default account 0 with index 0', () => {
      const actual = wallet.getSubaddress(0, 0);
      assert.strictEqual(actual.isViewOnly, false);
      assert.strictEqual(actual.type, 'address');
      assert.deepStrictEqual(actual.secretSpendKey, wallet.secretSpendKey);
      assert.deepStrictEqual(actual.publicSpendKey, wallet.publicSpendKey);
      assert.deepStrictEqual(actual.publicViewKey, wallet.publicViewKey);
      assert.deepStrictEqual(actual.index, { major: 0, minor: 0 });
    });

    it('should generate the right subaddress for account 1 with index 1', () => {
      const actual = wallet.getSubaddress(1, 1);
      assert.strictEqual(actual.isViewOnly, false);
      assert.strictEqual(actual.type, 'subaddress');
      assert.deepStrictEqual(actual.secretSpendKey, Buffer.from('0e6b2f82dfbd9f6340ac0d7a7d2f08bf7d113882d4a80c726f094448ad333405', 'hex'));
      assert.deepStrictEqual(actual.publicSpendKey, Buffer.from('4a3e863f2a7a43f7fbaa0320e06982009f2986dd04173eaee32aa8473317f19d', 'hex'));
      assert.deepStrictEqual(actual.publicViewKey, Buffer.from('d247f90799916273407c1c71230d5ae0a9c71b8a7492da035e5e8ad972eea18b', 'hex'));
      assert.deepStrictEqual(actual.index, { major: 1, minor: 1 });
    });
  });

  describe('getIntegratedAddress from full wallet', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        seed: Buffer.from('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903', 'hex'),
      });
    });

    it('should generate the right integrated address', () => {
      const actual = wallet.getIntegratedAddress(Buffer.from('1234567890abcdef', 'hex'));
      assert.strictEqual(actual.isViewOnly, false);
      assert.strictEqual(actual.type, 'integratedaddress');
      assert.deepStrictEqual(actual.secretSpendKey, wallet.secretSpendKey);
      assert.deepStrictEqual(actual.publicSpendKey, wallet.publicSpendKey);
      assert.deepStrictEqual(actual.publicViewKey, wallet.publicViewKey);
      assert.deepStrictEqual(actual.paymentID, Buffer.from('1234567890abcdef', 'hex'));
    });
  });

  describe('getSubaddress from view only wallet', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        publicSpendKey: Buffer.from('f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7', 'hex'),
        secretViewKey: Buffer.from('99c57d1f0f997bc8ca98559a0ccc3fada3899756e63d1516dba58b7e468cfc05', 'hex'),
      });
    });

    it('should generate the right address for default account 0 with index 0', () => {
      const actual = wallet.getSubaddress(0, 0);
      assert.strictEqual(actual.isViewOnly, true);
      assert.strictEqual(actual.type, 'address');
      assert.throws(() => {
        actual.secretSpendKey;
      }, { message: 'Address in view only mode' });
      assert.deepStrictEqual(actual.publicSpendKey, wallet.publicSpendKey);
      assert.deepStrictEqual(actual.publicViewKey, wallet.publicViewKey);
      assert.deepStrictEqual(actual.index, { major: 0, minor: 0 });
    });

    it('should generate the right subaddress for account 1 with index 1', () => {
      const actual = wallet.getSubaddress(1, 1);
      assert.strictEqual(actual.isViewOnly, true);
      assert.strictEqual(actual.type, 'subaddress');
      assert.throws(() => {
        actual.secretSpendKey;
      }, { message: 'Address in view only mode' });
      assert.deepStrictEqual(actual.publicSpendKey, Buffer.from('4a3e863f2a7a43f7fbaa0320e06982009f2986dd04173eaee32aa8473317f19d', 'hex'));
      assert.deepStrictEqual(actual.publicViewKey, Buffer.from('d247f90799916273407c1c71230d5ae0a9c71b8a7492da035e5e8ad972eea18b', 'hex'));
      assert.deepStrictEqual(actual.index, { major: 1, minor: 1 });
    });
  });

  describe('getIntegratedAddress from view only wallet', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        publicSpendKey: Buffer.from('f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7', 'hex'),
        secretViewKey: Buffer.from('99c57d1f0f997bc8ca98559a0ccc3fada3899756e63d1516dba58b7e468cfc05', 'hex'),
      });
    });

    it('should generate the right integrated address', () => {
      const actual = wallet.getIntegratedAddress(Buffer.from('1234567890abcdef', 'hex'));
      assert.strictEqual(actual.isViewOnly, true);
      assert.strictEqual(actual.type, 'integratedaddress');
      assert.throws(() => {
        actual.secretSpendKey;
      }, { message: 'Address in view only mode' });
      assert.deepStrictEqual(actual.publicSpendKey, wallet.publicSpendKey);
      assert.deepStrictEqual(actual.publicViewKey, wallet.publicViewKey);
      assert.deepStrictEqual(actual.paymentID, Buffer.from('1234567890abcdef', 'hex'));
    });
  });

  describe('getSubaddress toString', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        seed: Buffer.from('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903', 'hex'),
      });
    });

    it('should generate the right address for default account 0 with index 0', () => {
      const actual = wallet.getSubaddress(0, 0).toString();
      assert.strictEqual(actual, '4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey');
    });

    it('should generate the right subaddress for account 0 with index 1', () => {
      const actual = wallet.getSubaddress(0, 1).toString();
      assert.strictEqual(actual, '8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB');
    });

    it('should generate the right subaddress for account 0 with index 256', () => {
      const actual = wallet.getSubaddress(0, 256).toString();
      assert.strictEqual(actual, '883z7xonbVBGXpsatJZ53vcDiXQkrkTHUHPxrdrHXiPnZY8DMaYJ7a88C5ovncy5zHWkLc2cQ2hUoaKYCjFtjwFV4vtcpiF');
    });

    it('should generate the right subaddress for account 256 with index 1', () => {
      const actual = wallet.getSubaddress(256, 1).toString();
      assert.strictEqual(actual, '87X4ksVMRv2UGhHcgVjY6KJDjqP9S4zrCNkmomL1ziQVeZXF3RXbAx7i2rRt3UU5eXDzG9TWZ6Rk1Fyg6pZrAKQCNfLrSne');
    });

    it('should generate the right subaddress for account 256 with index 256', () => {
      const actual = wallet.getSubaddress(256, 256).toString();
      assert.strictEqual(actual, '86gYdT7yqDJUXegizt1vbF3YKz5qSYVaMB61DFBDzrpVEpYgDbmuXJbXE77LQfAygrVGwYpw8hxxx9DRTiyHAemA8B5yBAq');
    });
  });

  describe('getIntegratedAddress toString', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        seed: Buffer.from('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903', 'hex'),
      });
    });

    it('should generate the right integrated address', () => {
      const actual = wallet.getIntegratedAddress(Buffer.from('9d4d3c5cd422a218', 'hex')).toString();
      assert.strictEqual(actual, '4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbZRJmgNnw4d3pJGW3B');
    });
  });

  describe('addressFromString', () => {
    let wallet;
    before(() => {
      wallet = new Wallet({
        seed: Buffer.from('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903', 'hex'),
      });
    });

    it('should decode address', () => {
      const address = wallet.addressFromString('47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1xXgiDt');
      assert.strictEqual(address.nettype, 'mainnet');
      assert.strictEqual(address.type, 'address');
      assert.deepStrictEqual(address.publicSpendKey, Buffer.from('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7', 'hex'));
      assert.deepStrictEqual(address.publicViewKey, Buffer.from('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108', 'hex'));
    });

    it('should decode subaddress', () => {
      const address = wallet.addressFromString('8BKDtGLgpy8GKMhxBYNjK3Y1XW1yzKQ8aeR88i84521NZ4XHtk9wtTZX988HHUdsFL5eYZTrzPGmtiiLvdDJVvNRNCJKsR7');
      assert.strictEqual(address.nettype, 'mainnet');
      assert.strictEqual(address.type, 'subaddress');
      assert.deepStrictEqual(address.publicSpendKey, Buffer.from('e9d78cb7bebdbb5b924556a5ce5e36b9641ee7b90c14d3dfb1f4189ffdc929bf', 'hex'));
      assert.deepStrictEqual(address.publicViewKey, Buffer.from('adb6f3010be5c0b4321191f6f9d9171bc8d2d231e0fe67f962789feeb789bebb', 'hex'));
    });

    it('should decode integrated address', () => {
      const address = wallet.addressFromString('4HNXMYnW5mZ8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax2SEU4v4fc3hLJGgron');
      assert.strictEqual(address.nettype, 'mainnet');
      assert.strictEqual(address.type, 'integratedaddress');
      assert.deepStrictEqual(address.publicSpendKey, Buffer.from('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7', 'hex'));
      assert.deepStrictEqual(address.publicViewKey, Buffer.from('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108', 'hex'));
      assert.deepStrictEqual(address.paymentID, Buffer.from('945c0d11d13908ab', 'hex'));
    });
  });
});
