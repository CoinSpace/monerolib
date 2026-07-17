/* eslint-disable max-len */
import assert from 'node:assert';
import {
  before, describe, it,
} from 'node:test';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import * as ringct from '../lib/ringct.js';
import * as wallet from '../lib/wallet.js';
import { address } from '../lib/address.js';

describe('wallet', () => {
  describe('keysFromSeed', () => {
    it('derives spend/view keypairs', () => {
      const keys = wallet.keysFromSeed(hexToBytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'));
      assert.deepStrictEqual(keys.secretSpendKey, hexToBytes('1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f'));
      assert.deepStrictEqual(keys.publicSpendKey, hexToBytes('db27fe4b7a4beb8c1b8c38a21e943a852304c9bb3035a5f36626b51162a68f9c'));
      assert.deepStrictEqual(keys.secretViewKey, hexToBytes('9fe83aa6104612b587eb2e6ee1f0c929f85ce047804a789f4d579f9d2e20de0b'));
      assert.deepStrictEqual(keys.publicViewKey, hexToBytes('beb87b123ca0be6228ef692cecc4ba5170cc55f3987f08006dc638743776ebb3'));
    });
  });

  describe('keysFromSecretKeys', () => {
    it('derives public keys', () => {
      const keys = wallet.keysFromSecretKeys(
        hexToBytes('99095987370c530487be61900a4b167e4107ad39bb08b60256dc3c6a3e83ff03'),
        hexToBytes('21c7754089a21b4c326181f30c9616dce510e9007eaea65ef952b0a4de4bee0c')
      );
      assert.deepStrictEqual(keys.publicSpendKey, hexToBytes('3d5ac932714307e24e10971a93ed267de205768387c55e4a097def70dadadd11'));
      assert.deepStrictEqual(keys.publicViewKey, hexToBytes('181e4f7b6815c390b86db550b3f08b35e9b55931fc1215e4c97ee07d59d7e839'));
    });
  });

  describe('viewOnlyKeys', () => {
    it('derives the view public key and has no secret spend key', () => {
      const keys = wallet.viewOnlyKeys(
        hexToBytes('74621fc98ad596d225e38f580836c85b50097c06bfba379599168bad649ec618'),
        hexToBytes('5fa548f256045ebe8e53f83554c106bbac2b34d9dacd040b6c5e0f96478bf005')
      );
      assert.deepStrictEqual(keys.publicViewKey, hexToBytes('cfda349dd1949862de366d070830c57bcbe1a53cbd8640016abde6f898abc273'));
      assert.strictEqual(keys.secretSpendKey, undefined);
    });
  });

  describe('subaddressLookup', () => {
    it('maps subaddress spend keys to their index', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const lookup = wallet.subaddressLookup(keys, 2, 2);
      const spendKey = crypto.subaddressPublicSpendKey(helpers.decodeInt(keys.secretViewKey), keys.publicSpendKey, { major: 1, minor: 1 });
      assert.deepStrictEqual(lookup.get(bytesToHex(spendKey)), { major: 1, minor: 1 });
    });
  });

  describe('getSubaddress from full wallet', () => {
    let keys;
    before(() => {
      keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
    });

    it('account 0 index 0 is the primary address', () => {
      const decoded = address('mainnet').decode(wallet.getSubaddress(keys, { major: 0, minor: 0 }));
      assert.strictEqual(decoded.type, 'address');
      assert.deepStrictEqual(decoded.publicSpendKey, keys.publicSpendKey);
      assert.deepStrictEqual(decoded.publicViewKey, keys.publicViewKey);
    });

    it('account 1 index 1', () => {
      const decoded = address('mainnet').decode(wallet.getSubaddress(keys, { major: 1, minor: 1 }));
      assert.strictEqual(decoded.type, 'subaddress');
      assert.deepStrictEqual(decoded.publicSpendKey, hexToBytes('4a3e863f2a7a43f7fbaa0320e06982009f2986dd04173eaee32aa8473317f19d'));
      assert.deepStrictEqual(decoded.publicViewKey, hexToBytes('d247f90799916273407c1c71230d5ae0a9c71b8a7492da035e5e8ad972eea18b'));
    });
  });

  describe('getSubaddress from view only wallet', () => {
    let keys;
    before(() => {
      keys = wallet.viewOnlyKeys(
        hexToBytes('f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7'),
        hexToBytes('99c57d1f0f997bc8ca98559a0ccc3fada3899756e63d1516dba58b7e468cfc05')
      );
    });

    it('account 0 index 0 is the primary address', () => {
      const decoded = address('mainnet').decode(wallet.getSubaddress(keys, { major: 0, minor: 0 }));
      assert.strictEqual(decoded.type, 'address');
      assert.deepStrictEqual(decoded.publicSpendKey, keys.publicSpendKey);
      assert.deepStrictEqual(decoded.publicViewKey, keys.publicViewKey);
    });

    it('account 1 index 1', () => {
      const decoded = address('mainnet').decode(wallet.getSubaddress(keys, { major: 1, minor: 1 }));
      assert.strictEqual(decoded.type, 'subaddress');
      assert.deepStrictEqual(decoded.publicSpendKey, hexToBytes('4a3e863f2a7a43f7fbaa0320e06982009f2986dd04173eaee32aa8473317f19d'));
      assert.deepStrictEqual(decoded.publicViewKey, hexToBytes('d247f90799916273407c1c71230d5ae0a9c71b8a7492da035e5e8ad972eea18b'));
    });
  });

  describe('getIntegratedAddress', () => {
    it('from full wallet', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const decoded = address('mainnet').decode(wallet.getIntegratedAddress(keys, hexToBytes('1234567890abcdef')));
      assert.strictEqual(decoded.type, 'integratedaddress');
      assert.deepStrictEqual(decoded.publicSpendKey, keys.publicSpendKey);
      assert.deepStrictEqual(decoded.publicViewKey, keys.publicViewKey);
      assert.deepStrictEqual(decoded.paymentID, hexToBytes('1234567890abcdef'));
    });
  });

  describe('getSubaddress address strings', () => {
    let keys;
    before(() => {
      keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
    });

    it('account 0 index 0', () => {
      assert.strictEqual(wallet.getSubaddress(keys, { major: 0, minor: 0 }), '4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey');
    });

    it('account 0 index 1', () => {
      assert.strictEqual(wallet.getSubaddress(keys, { major: 0, minor: 1 }), '8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB');
    });

    it('account 0 index 256', () => {
      assert.strictEqual(wallet.getSubaddress(keys, { major: 0, minor: 256 }), '883z7xonbVBGXpsatJZ53vcDiXQkrkTHUHPxrdrHXiPnZY8DMaYJ7a88C5ovncy5zHWkLc2cQ2hUoaKYCjFtjwFV4vtcpiF');
    });

    it('account 256 index 1', () => {
      assert.strictEqual(wallet.getSubaddress(keys, { major: 256, minor: 1 }), '87X4ksVMRv2UGhHcgVjY6KJDjqP9S4zrCNkmomL1ziQVeZXF3RXbAx7i2rRt3UU5eXDzG9TWZ6Rk1Fyg6pZrAKQCNfLrSne');
    });

    it('account 256 index 256', () => {
      assert.strictEqual(wallet.getSubaddress(keys, { major: 256, minor: 256 }), '86gYdT7yqDJUXegizt1vbF3YKz5qSYVaMB61DFBDzrpVEpYgDbmuXJbXE77LQfAygrVGwYpw8hxxx9DRTiyHAemA8B5yBAq');
    });
  });

  describe('getIntegratedAddress address string', () => {
    it('matches the reference', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      assert.strictEqual(
        wallet.getIntegratedAddress(keys, hexToBytes('9d4d3c5cd422a218')),
        '4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbZRJmgNnw4d3pJGW3B'
      );
    });
  });

  describe('scanOutput', () => {
    // build an output paying `amount` to `keys`' main address, as a sender would
    function outputTo(keys, amount) {
      const txSecretKey = crypto.randomScalar();
      const txPublicKey = crypto.secretKeyToPublicKey(txSecretKey); // R = r*G (normal address)
      const index = 0;
      const derivation = crypto.generateKeyDerivation(keys.publicViewKey, txSecretKey); // 8*r*A
      const amountKey = crypto.derivationToScalar(derivation, index);
      const mask = ringct.genCommitmentMask(amountKey);
      return {
        txPublicKey,
        outputKey: crypto.derivePublicKey(derivation, index, keys.publicSpendKey),
        index,
        ecdhInfo: {
          amount: ringct.ecdhEncode({ amount: helpers.encodeInt(amount) }, amountKey, ringct.RCTTypes.CLSAG).amount.slice(0, 8),
        },
        outPk: ringct.pedersenCommitment(amount, mask),
        rctType: ringct.RCTTypes.CLSAG,
      };
    }

    it('full wallet: detects the output with spend material', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const owned = wallet.scanOutput(keys, outputTo(keys, 4000000n), wallet.subaddressLookup(keys, 1, 1));
      assert.strictEqual(owned.amount, 4000000n);
      assert.strictEqual(typeof owned.secretKey, 'bigint');
      assert.strictEqual(owned.keyImage.length, 32);
    });

    it('view-only wallet: detects the output and amount, no key image', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const viewOnly = wallet.viewOnlyKeys(keys.publicSpendKey, keys.secretViewKey);
      const owned = wallet.scanOutput(viewOnly, outputTo(keys, 4000000n), wallet.subaddressLookup(viewOnly, 1, 1));
      assert.strictEqual(owned.amount, 4000000n);
      assert.strictEqual(owned.secretKey, undefined);
      assert.strictEqual(owned.keyImage, undefined);
    });

    // a coinbase output: not RingCT (Null type), cleartext amount, no ecdh/commitment
    function coinbaseOutputTo(keys, amount) {
      const txSecretKey = crypto.randomScalar();
      const derivation = crypto.generateKeyDerivation(keys.publicViewKey, txSecretKey);
      return {
        txPublicKey: crypto.secretKeyToPublicKey(txSecretKey),
        outputKey: crypto.derivePublicKey(derivation, 0, keys.publicSpendKey),
        index: 0,
        rctType: ringct.RCTTypes.Null,
        amount,
      };
    }

    it('detects a coinbase output (cleartext amount, mask 1)', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const owned = wallet.scanOutput(keys, coinbaseOutputTo(keys, 600000000000n), wallet.subaddressLookup(keys, 1, 1));
      assert.strictEqual(owned.amount, 600000000000n);
      assert.strictEqual(owned.mask, 1n);
      assert.deepStrictEqual(owned.commitment, ringct.zeroCommit(600000000000n));
      assert.strictEqual(owned.keyImage.length, 32);
    });
  });

  describe('isMature', () => {
    it('regular output needs DEFAULT_SPENDABLE_AGE (10) confirmations', () => {
      assert.strictEqual(wallet.isMature({ height: 100 }, 109), false);
      assert.strictEqual(wallet.isMature({ height: 100 }, 110), true);
    });

    it('coinbase output needs COINBASE_UNLOCK_WINDOW (60) confirmations', () => {
      assert.strictEqual(wallet.isMature({ height: 100, isCoinbase: true }, 159), false);
      assert.strictEqual(wallet.isMature({ height: 100, isCoinbase: true }, 160), true);
    });
  });
});
