/* eslint-disable max-len */
import assert from 'node:assert';
import {
  before, describe, it,
} from 'node:test';
import {
  bytesToHex, hexToBytes, randomBytes,
} from '@noble/hashes/utils.js';

import * as clsag from '../lib/clsag.js';
import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import * as raw from '../lib/raw.js';
import * as ringct from '../lib/ringct.js';
import * as tx from '../lib/tx.js';
import * as wallet from '../lib/wallet.js';
import { address } from '../lib/address.js';
import constructFixtures from './fixtures/construct_txs.json' with { type: 'json' };
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/wallet/src/tests/scan.rs#L17-L167
import scanVector from './fixtures/monero_oxide_scan.json' with { type: 'json' };

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
    // build an output paying `amount` to `keys`' main address, as a sender would, plus the primary
    // (tx public key) derivation a scanner shares across the tx
    function outputTo(keys, amount) {
      const txSecretKey = crypto.randomScalar();
      const index = 0;
      const derivation = crypto.generateKeyDerivation(keys.publicViewKey, txSecretKey); // 8*r*A = 8*a*R
      const amountKey = crypto.derivationToScalar(derivation, index);
      const mask = ringct.genCommitmentMask(amountKey);
      const output = {
        txPublicKey: crypto.secretKeyToPublicKey(txSecretKey),
        outputKey: crypto.derivePublicKey(derivation, index, keys.publicSpendKey),
        index,
        ecdhInfo: {
          amount: ringct.ecdhEncode({ amount: helpers.encodeInt(amount) }, amountKey, ringct.RCTTypes.CLSAG).amount.slice(0, 8),
        },
        outPk: ringct.pedersenCommitment(amount, mask),
        rctType: ringct.RCTTypes.CLSAG,
      };
      return { output, derivation };
    }

    it('full wallet: detects the output with spend material', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const { output, derivation } = outputTo(keys, 4000000n);
      const owned = wallet.scanOutput(keys, output, wallet.subaddressLookup(keys, 1, 1), derivation);
      assert.strictEqual(owned.amount, 4000000n);
      assert.strictEqual(typeof owned.keyOffset, 'bigint');
      assert.strictEqual(owned.keyImage.length, 32);
    });

    it('view-only wallet: detects the output, amount and key offset, but no key image', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const viewOnly = wallet.viewOnlyKeys(keys.publicSpendKey, keys.secretViewKey);
      const { output, derivation } = outputTo(keys, 4000000n);
      const owned = wallet.scanOutput(viewOnly, output, wallet.subaddressLookup(viewOnly, 1, 1), derivation);
      assert.strictEqual(owned.amount, 4000000n);
      assert.strictEqual(typeof owned.keyOffset, 'bigint'); // view-only can produce the offset
      assert.strictEqual(owned.keyImage, undefined); // but not the key image (needs the spend key)
    });

    it('skips an output whose commitment does not match the encrypted amount', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const { output, derivation } = outputTo(keys, 4000000n);
      output.outPk[0] ^= 1;
      assert.strictEqual(wallet.scanOutput(keys, output, wallet.subaddressLookup(keys, 1, 1), derivation), null);
    });

    // a coinbase output: not RingCT (Null type), cleartext amount, no ecdh/commitment
    function coinbaseOutputTo(keys, amount) {
      const txSecretKey = crypto.randomScalar();
      const derivation = crypto.generateKeyDerivation(keys.publicViewKey, txSecretKey);
      const output = {
        outputKey: crypto.derivePublicKey(derivation, 0, keys.publicSpendKey),
        index: 0,
        rctType: ringct.RCTTypes.Null,
        amount,
      };
      return { output, derivation };
    }

    it('detects a coinbase output (cleartext amount, mask 1)', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const { output, derivation } = coinbaseOutputTo(keys, 600000000000n);
      const owned = wallet.scanOutput(keys, output, wallet.subaddressLookup(keys, 1, 1), derivation);
      assert.strictEqual(owned.amount, 600000000000n);
      assert.strictEqual(owned.mask, 1n);
      assert.deepStrictEqual(owned.commitment, ringct.zeroCommit(600000000000n));
      assert.strictEqual(owned.keyImage.length, 32);
    });

    it('view tag gates the derivation: a match still finds, a mismatch returns null', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const { output, derivation } = outputTo(keys, 4000000n);
      const viewTag = crypto.deriveViewTag(derivation, output.index)[0];
      const subaddresses = wallet.subaddressLookup(keys, 1, 1);
      assert.strictEqual(wallet.scanOutput(keys, { ...output, viewTag }, subaddresses, derivation).amount, 4000000n);
      assert.strictEqual(wallet.scanOutput(keys, { ...output, viewTag: viewTag ^ 0xff }, subaddresses, derivation), null);
    });

    it('derives on the fly from the output tx public key when no primary derivation is given', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const { output } = outputTo(keys, 4000000n); // output carries txPublicKey, no primary passed
      const owned = wallet.scanOutput(keys, output, wallet.subaddressLookup(keys, 1, 1));
      assert.strictEqual(owned.amount, 4000000n);
    });

    it('falls through to the additional key when the primary derivation does not match', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const subaddress = { major: 0, minor: 1 };
      const sub = crypto.subaddressPublicKeys(helpers.decodeInt(keys.secretViewKey), keys.publicSpendKey, subaddress);
      const other = wallet.randomKeys();
      // a mixed tx: a standard output to someone else (index 0) and our subaddress output (index 1),
      // so the primary tx public key is not ours and only the additional key at index 1 matches
      const generated = tx.generateOutputs([
        {
          type: 'address', publicSpendKey: other.publicSpendKey, publicViewKey: other.publicViewKey, amount: 1n,
        },
        {
          type: 'subaddress', publicSpendKey: sub.publicSpendKey, publicViewKey: sub.publicViewKey, amount: 5n,
        },
      ], { txSecretKey: crypto.randomScalar() });
      const gen = generated.outputs[1];
      const mask = ringct.genCommitmentMask(gen.amountKey);
      const output = {
        txPublicKey: generated.txKeys.txPublicKey,
        additionalTxPublicKey: generated.txKeys.additionalTxPublicKeys[1],
        outputKey: gen.key,
        viewTag: gen.viewTag,
        index: 1,
        ecdhInfo: {
          amount: ringct.ecdhEncode({ amount: helpers.encodeInt(5n) }, gen.amountKey, ringct.RCTTypes.CLSAG).amount.slice(0, 8),
        },
        outPk: ringct.pedersenCommitment(5n, mask),
        rctType: ringct.RCTTypes.CLSAG,
      };
      const owned = wallet.scanOutput(keys, output, wallet.subaddressLookup(keys, 1, 2));
      assert.strictEqual(owned.amount, 5n);
      assert.deepStrictEqual(owned.subaddress, subaddress);
    });

    it('does not compute the additional-key derivation when the primary matches', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const { output, derivation } = outputTo(keys, 4000000n); // primary derivation matches
      // reading any byte of the additional key means its derivation was computed; an eager scan would
      let additionalRead = false;
      const additionalTxPublicKey = new Proxy(crypto.secretKeyToPublicKey(crypto.randomScalar()), {
        get(target, prop, receiver) {
          additionalRead = true;
          return Reflect.get(target, prop, receiver);
        },
      });
      const owned = wallet.scanOutput(
        keys, { ...output, additionalTxPublicKey }, wallet.subaddressLookup(keys, 1, 1), derivation
      );
      assert.strictEqual(owned.amount, 4000000n);
      assert.strictEqual(additionalRead, false);
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

  describe('scanTransaction', () => {
    // a fake spendable input, unrelated to the recipient being scanned for (secretSpendKey 0n below,
    // so the one-time secret is keyOffset + 0 = keyOffset)
    const makeInput = (amount) => {
      const keyOffset = crypto.randomScalar();
      const mask = crypto.randomScalar();
      return {
        keyOffset, publicKey: crypto.secretKeyToPublicKey(keyOffset), amount, mask, commitment: ringct.pedersenCommitment(amount, mask), globalIndex: 1n, decoys: [],
      };
    };

    it('finds an owned output and the spent key image', () => {
      const recipient = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const sender = wallet.keysFromSeed(hexToBytes('9e9d9eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4904'));
      const input = makeInput(1000000n);
      const { bytes } = tx.createTransaction({
        inputs: [input],
        outputs: [
          {
            type: 'address', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, amount: 700000n,
          },
          {
            type: 'address', publicSpendKey: sender.publicSpendKey, publicViewKey: sender.publicViewKey, isChange: true, amount: 300000n,
          },
        ],
        secretSpendKey: 0n,
        secretViewKey: helpers.decodeInt(sender.secretViewKey),
        shuffleOutputs: false, // the recipient output stays at index 0
      });
      const decodedTx = raw.fullTransaction.decode(bytes);
      const subaddresses = wallet.subaddressLookup(recipient, 1, 1);

      const result = wallet.scanTransaction(recipient, decodedTx, subaddresses);
      assert.strictEqual(result.outputs.length, 1);
      assert.strictEqual(result.outputs[0].amount, 700000n);
      assert.strictEqual(result.outputs[0].index, 0);
      assert.deepStrictEqual(result.outputs[0].subaddress, { major: 0, minor: 0 });

      const expectedKeyImage = crypto.generateKeyImage(input.publicKey, input.keyOffset);
      assert.strictEqual(result.spentKeyImages.length, 1);
      assert.deepStrictEqual(result.spentKeyImages[0], expectedKeyImage);
    });

    it('finds an output paid through the second of two tx public keys', () => {
      const recipient = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const sender = wallet.keysFromSeed(hexToBytes('9e9d9eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4904'));
      const decodedTx = raw.fullTransaction.decode(tx.createTransaction({
        inputs: [makeInput(1000000n)],
        outputs: [
          {
            type: 'address', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, amount: 700000n,
          },
          {
            type: 'address', publicSpendKey: sender.publicSpendKey, publicViewKey: sender.publicViewKey, isChange: true, amount: 300000n,
          },
        ],
        secretSpendKey: 0n,
        secretViewKey: helpers.decodeInt(sender.secretViewKey),
      }).bytes);
      // a stray tx public key field before the real one, as the 2016 cold-signing bug wrote them
      const stray = crypto.secretKeyToPublicKey(crypto.randomScalar());
      decodedTx.prefix.extra = Uint8Array.from([1, ...stray, ...decodedTx.prefix.extra]);

      const result = wallet.scanTransaction(recipient, decodedTx, wallet.subaddressLookup(recipient, 1, 1));
      assert.strictEqual(result.outputs.length, 1);
      assert.strictEqual(result.outputs[0].amount, 700000n);
      // the dummy payment id decrypts with the real key, not the stray one
      assert.deepStrictEqual(result.outputs[0].paymentId, new Uint8Array(8));
    });

    it('decrypts the payment id of an integrated-address output', () => {
      const recipient = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const paymentId = randomBytes(8);
      const { bytes } = tx.createTransaction({
        inputs: [makeInput(1000000n)],
        outputs: [
          {
            type: 'integratedaddress', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, paymentID: paymentId, amount: 700000n,
          },
          {
            type: 'address', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, isChange: true, amount: 300000n,
          },
        ],
        secretSpendKey: 0n,
        secretViewKey: helpers.decodeInt(recipient.secretViewKey),
      });
      const decodedTx = raw.fullTransaction.decode(bytes);
      const subaddresses = wallet.subaddressLookup(recipient, 1, 1);

      const result = wallet.scanTransaction(recipient, decodedTx, subaddresses);
      const paid = result.outputs.find((o) => o.amount === 700000n);
      assert.deepStrictEqual(paid.paymentId, paymentId);
    });

    it('finds nothing for an unrelated wallet', () => {
      const recipient = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const other = wallet.keysFromSeed(hexToBytes('1a2b3c4d5e38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac490'));
      const { bytes } = tx.createTransaction({
        inputs: [makeInput(1000000n)],
        outputs: [
          {
            type: 'address', publicSpendKey: other.publicSpendKey, publicViewKey: other.publicViewKey, amount: 700000n,
          },
          {
            type: 'address', publicSpendKey: other.publicSpendKey, publicViewKey: other.publicViewKey, isChange: true, amount: 300000n,
          },
        ],
        secretSpendKey: 0n,
        secretViewKey: helpers.decodeInt(other.secretViewKey),
      });
      const decodedTx = raw.fullTransaction.decode(bytes);
      const subaddresses = wallet.subaddressLookup(recipient, 1, 1);

      const result = wallet.scanTransaction(recipient, decodedTx, subaddresses);
      assert.strictEqual(result.outputs.length, 0);
      assert.strictEqual(result.spentKeyImages.length, 1);
    });

    // independent cross-implementation vector (real serialized bytes, not a JS round-trip)
    it('scans a real serialized tx from the monero-oxide vector', () => {
      const keys = wallet.keysFromSecretKeys(
        hexToBytes(scanVector.secretSpendKey),
        hexToBytes(scanVector.secretViewKey)
      );
      const bytes = hexToBytes(scanVector.hex);
      // pruned tx: decode the prefix and rct base directly (no signatures follow)
      const prefix = raw.txPrefix.decode(bytes, { allowUnreadBytes: true });
      const rctSigBase = raw.rctBaseCoder(prefix.vin.length, prefix.vout.length)
        .decode(bytes.subarray(raw.txPrefix.encode(prefix).length), { allowUnreadBytes: true });
      const subaddresses = wallet.subaddressLookup(keys, 1, 1);

      const { outputs } = wallet.scanTransaction(keys, { prefix, rctSigBase }, subaddresses);
      assert.strictEqual(outputs.length, 2);
      outputs.forEach((output, i) => {
        assert.strictEqual(output.index, scanVector.outputs[i].index);
        assert.strictEqual(output.amount, BigInt(scanVector.outputs[i].amount));
        assert.deepStrictEqual(helpers.encodeInt(output.mask), hexToBytes(scanVector.outputs[i].mask));
        assert.deepStrictEqual(helpers.encodeInt(output.keyOffset), hexToBytes(scanVector.outputs[i].keyOffset));
        assert.deepStrictEqual(output.paymentId, new Uint8Array(8)); // dummy payment id
      });
    });

    it('spends a scanned output with a non-zero spend key, signing against the real output key', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      // an incoming tx to our main address; scan it for keyOffset, publicKey and keyImage (real b)
      const { bytes: incoming } = tx.createTransaction({
        inputs: [makeInput(2000000n)],
        outputs: [
          {
            type: 'address', publicSpendKey: keys.publicSpendKey, publicViewKey: keys.publicViewKey, amount: 1500000n,
          },
          {
            type: 'address', publicSpendKey: keys.publicSpendKey, publicViewKey: keys.publicViewKey, isChange: true, amount: 490000n,
          },
        ],
        secretSpendKey: 0n,
        secretViewKey: helpers.decodeInt(keys.secretViewKey),
      });
      const owned = wallet.scanTransaction(keys, raw.fullTransaction.decode(incoming), wallet.subaddressLookup(keys, 1, 1)).outputs[0];

      // spend it: signing reconstructs x = keyOffset + b with a non-zero b
      const decoys = Array.from({ length: 10 }, (unused, j) => ({
        publicKey: crypto.secretKeyToPublicKey(crypto.randomScalar()),
        commitment: crypto.secretKeyToPublicKey(crypto.randomScalar()),
        globalIndex: BigInt(2000 + j),
      }));
      const recipient = wallet.keysFromSeed(hexToBytes('9e9d9eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4904'));
      const spend = raw.fullTransaction.decode(tx.createTransaction({
        inputs: [{
          ...owned, globalIndex: 42n, decoys,
        }],
        outputs: [
          {
            type: 'address', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, amount: owned.amount - 20000n,
          },
          {
            type: 'address', publicSpendKey: keys.publicSpendKey, publicViewKey: keys.publicViewKey, isChange: true, amount: 10000n,
          },
        ],
        secretSpendKey: helpers.decodeInt(keys.secretSpendKey),
        secretViewKey: helpers.decodeInt(keys.secretViewKey),
      }).bytes);

      // the key image matches the one scanOutput computed (proves x = keyOffset + b)
      assert.deepStrictEqual(spend.prefix.vin[0].data.keyImage, owned.keyImage);

      // CLSAG verifies against the ring holding the real output key P (owned.publicKey)
      const {
        bulletproofsPlus, CLSAGs, pseudoOuts,
      } = spend.rctSigPrunable;
      const message = tx.getPreMlsagHash(crypto.fastHash(raw.txPrefix.encode(spend.prefix)), spend.rctSigBase, bulletproofsPlus[0]);
      const ring = [{
        publicKey: owned.publicKey, commitment: owned.commitment, globalIndex: 42n,
      }, ...decoys]
        .sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1))
        .map((member) => ({ publicKey: member.publicKey, commitment: member.commitment }));
      const sig = {
        s: CLSAGs[0].s, c1: CLSAGs[0].c1, I: spend.prefix.vin[0].data.keyImage, D: CLSAGs[0].D,
      };
      assert.ok(clsag.verifyClsag(message, ring, pseudoOuts[0], sig));
    });
  });

  describe('createTransaction', () => {
    const BASE_FEE = 1000n;
    const FEE_QUANTIZATION = 10000n;

    // a fake input paying the incoming tx (secretSpendKey 0n => one-time secret is keyOffset)
    const makeInput = (amount) => {
      const keyOffset = crypto.randomScalar();
      const mask = crypto.randomScalar();
      return {
        keyOffset, publicKey: crypto.secretKeyToPublicKey(keyOffset), amount, mask, commitment: ringct.pedersenCommitment(amount, mask), globalIndex: 1n, decoys: [],
      };
    };

    // a real spendable input of `amount` owned by `keys`: send it to the wallet, scan it, attach a ring
    const spendable = (keys, amount) => {
      const { bytes: incoming } = tx.createTransaction({
        inputs: [makeInput(amount + 2000000n)],
        outputs: [
          {
            type: 'address', publicSpendKey: keys.publicSpendKey, publicViewKey: keys.publicViewKey, amount,
          },
          {
            type: 'address', publicSpendKey: keys.publicSpendKey, publicViewKey: keys.publicViewKey, isChange: true, amount: 1000000n,
          },
        ],
        secretSpendKey: 0n,
        secretViewKey: helpers.decodeInt(keys.secretViewKey),
        shuffleOutputs: false, // outputs[0] below must be the `amount` output, not the change
      });
      const owned = wallet.scanTransaction(keys, raw.fullTransaction.decode(incoming), wallet.subaddressLookup(keys, 1, 1)).outputs[0];
      const decoys = Array.from({ length: 15 }, (unused, j) => ({
        publicKey: crypto.secretKeyToPublicKey(crypto.randomScalar()),
        commitment: crypto.secretKeyToPublicKey(crypto.randomScalar()),
        globalIndex: BigInt(2000 + j),
      }));
      return {
        ...owned, globalIndex: 42n, decoys,
      };
    };

    it('changeOutput and dummyOutput shapes', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const change = wallet.changeOutput(keys, 123n);
      assert.strictEqual(change.type, 'address');
      assert.strictEqual(change.isChange, true);
      assert.strictEqual(change.amount, 123n);
      assert.deepStrictEqual(change.publicSpendKey, keys.publicSpendKey);

      const dummy = wallet.dummyOutput();
      assert.strictEqual(dummy.type, 'address');
      assert.strictEqual(dummy.isChange, true);
      assert.strictEqual(dummy.amount, 0n);
      assert.strictEqual(dummy.publicSpendKey.length, 32);
      assert.notDeepEqual(dummy.publicSpendKey, wallet.dummyOutput().publicSpendKey); // random each call
    });

    it('appends a change output the wallet can scan', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const recipient = wallet.keysFromSeed(hexToBytes('9e9d9eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4904'));
      const input = spendable(keys, 5000000n);
      const {
        transaction: decoded, bytes, txKeys: { txSecretKey, additionalTxSecretKeys },
      } = wallet.createTransaction({
        inputs: [input],
        outputs: [{
          type: 'address', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, amount: 1000000n,
        }],
        keys,
        baseFee: BASE_FEE,
        feeQuantization: FEE_QUANTIZATION,
        txKeys: { additionalTxSecretKeys: [] },
      });
      assert.ok(txSecretKey instanceof Uint8Array);
      assert.equal(txSecretKey.length, 32);
      assert.deepStrictEqual(additionalTxSecretKeys, []);
      assert.deepStrictEqual(tx.parseTxExtra(decoded.prefix.extra).txPublicKeys, [crypto.secretKeyToPublicKey(helpers.decodeInt(txSecretKey))]);
      assert.ok(bytes instanceof Uint8Array);
      assert.deepStrictEqual(bytes, raw.fullTransaction.encode(decoded));
      assert.strictEqual(decoded.prefix.vout.length, 2); // recipient + change
      const found = wallet.scanTransaction(keys, decoded, wallet.subaddressLookup(keys, 1, 1)).outputs;
      assert.strictEqual(found.length, 1); // only our change (the recipient output is not ours)
      assert.strictEqual(found[0].amount, input.amount - 1000000n - decoded.rctSigBase.txnFee);
    });

    it('pads a single-subaddress send to two outputs with a dummy, extra not inflated', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const other = wallet.keysFromSeed(hexToBytes('9e9d9eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4904'));
      const sub = address('mainnet').decode(wallet.getSubaddress(other, { major: 1, minor: 1 }));
      // exact funds: input == recipient + the two-output fee => no change => a dummy is added
      const recipientAmount = 1000000n;
      const fee = tx.estimateFee(1, 15, 2, tx.estimateExtraSize([{ ...sub, amount: recipientAmount }, { isChange: true }]), BASE_FEE, 1n, FEE_QUANTIZATION);
      const input = spendable(keys, recipientAmount + fee);
      const suppliedKey = helpers.encodeInt(17n);
      const {
        transaction: decoded, txKeys: { txSecretKey, additionalTxSecretKeys },
      } = wallet.createTransaction({
        inputs: [input],
        outputs: [{ ...sub, amount: recipientAmount }],
        keys,
        baseFee: BASE_FEE,
        feeQuantization: FEE_QUANTIZATION,
        txKeys: { txSecretKey: suppliedKey, additionalTxSecretKeys: [helpers.encodeInt(19n)] },
      });
      assert.strictEqual(decoded.prefix.vout.length, 2); // subaddress recipient + dummy
      assert.strictEqual(decoded.prefix.extra.length, 44); // dummy classified as change: no additional keys
      assert.strictEqual(decoded.rctSigBase.txnFee, fee);
      assert.deepStrictEqual(txSecretKey, suppliedKey);
      assert.deepStrictEqual(additionalTxSecretKeys, []);
      assert.deepStrictEqual(tx.parseTxExtra(decoded.prefix.extra).txPublicKeys, [crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiplyUnsafe(17n))]);
      const found = wallet.scanTransaction(other, decoded, wallet.subaddressLookup(other, 2, 2)).outputs;
      assert.equal(found.length, 1);
      assert.equal(found[0].amount, recipientAmount);
    });

    for (const supplied of [false, true]) {
      it(`returns ${supplied ? 'supplied' : 'generated'} byte keys for mixed recipients and change`, () => {
        const keys = wallet.randomKeys();
        const recipient = wallet.randomKeys();
        const subRecipient = wallet.randomKeys();
        const sub = address('mainnet').decode(wallet.getSubaddress(subRecipient, { major: 0, minor: 1 }));
        const params = {
          inputs: [spendable(keys, 10000000n)],
          outputs: [
            {
              type: 'address', publicSpendKey: recipient.publicSpendKey, publicViewKey: recipient.publicViewKey, amount: 1000000n,
            },
            { ...sub, amount: 2000000n },
          ],
          keys,
          baseFee: BASE_FEE,
          feeQuantization: FEE_QUANTIZATION,
          shuffleOutputs: false,
          txKeys: supplied ? { txSecretKey: helpers.encodeInt(17n), additionalTxSecretKeys: [19n, 23n, 29n].map(helpers.encodeInt) } : undefined,
        };
        const originalTxKeys = structuredClone(params.txKeys);
        const result = wallet.createTransaction(params);
        assert.deepStrictEqual(params.txKeys, originalTxKeys);
        assert.deepStrictEqual(Object.keys(result).sort(), ['bytes', 'transaction', 'txKeys']);
        assert.ok(result.txKeys.txSecretKey instanceof Uint8Array);
        assert.equal(result.txKeys.txSecretKey.length, 32);
        assert.equal(result.txKeys.additionalTxSecretKeys.length, 3);
        if (supplied) {
          assert.deepStrictEqual(result.txKeys.txSecretKey, params.txKeys.txSecretKey);
          assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, params.txKeys.additionalTxSecretKeys);
          const reused = wallet.createTransaction({ ...params, txKeys: result.txKeys });
          assert.deepStrictEqual(reused.txKeys, result.txKeys);
          assert.deepStrictEqual(reused.transaction.prefix, result.transaction.prefix);
          assert.deepStrictEqual(reused.transaction.rctSigBase, result.transaction.rctSigBase);
        }
        assert.ok(result.bytes instanceof Uint8Array);
        const decoded = raw.fullTransaction.decode(result.bytes);
        assert.deepStrictEqual(decoded, result.transaction);
        assert.deepStrictEqual(Object.keys(decoded).sort(), ['prefix', 'rctSigBase', 'rctSigPrunable']);
        const extra = tx.parseTxExtra(decoded.prefix.extra);
        assert.deepStrictEqual(extra.txPublicKeys, [result.txKeys.txPublicKey]);
        assert.deepStrictEqual(extra.additionalTxPublicKeys, result.txKeys.additionalTxPublicKeys);
        assert.deepStrictEqual(extra.txPublicKeys, [crypto.secretKeyToPublicKey(helpers.decodeInt(result.txKeys.txSecretKey))]);
        result.txKeys.additionalTxSecretKeys.forEach((key, i) => {
          assert.ok(key instanceof Uint8Array);
          assert.equal(key.length, 32);
          const scalar = helpers.decodeInt(key);
          const expected = i === 1
            ? crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiplyUnsafe(scalar))
            : crypto.secretKeyToPublicKey(scalar);
          assert.deepStrictEqual(extra.additionalTxPublicKeys[i], expected);
        });
        [recipient, subRecipient, keys].forEach((owner, i) => {
          const found = wallet.scanTransaction(owner, decoded, wallet.subaddressLookup(owner, 1, 2)).outputs;
          assert.equal(found.length, 1);
          assert.equal(found[0].index, i);
          assert.equal(found[0].amount, i === 2 ? params.inputs[0].amount - 3000000n - decoded.rctSigBase.txnFee : params.outputs[i].amount);
        });
        for (const additionalTxSecretKeys of [[], [19n, 23n].map(helpers.encodeInt), [19n, 23n, 29n, 31n].map(helpers.encodeInt)]) {
          assert.throws(() => wallet.createTransaction({ ...params, txKeys: { ...params.txKeys, additionalTxSecretKeys } }), /additionalTxSecretKeys: expected/);
        }
      });
    }

    it('rejects transaction keys that are not 32-byte Uint8Arrays', () => {
      const keys = wallet.randomKeys();
      const params = {
        inputs: [], outputs: [], keys, baseFee: BASE_FEE, feeQuantization: FEE_QUANTIZATION,
      };
      for (const key of [new Uint8Array(31), new Uint8Array(33), 17n]) {
        assert.throws(() => wallet.createTransaction({ ...params, txKeys: { txSecretKey: key } }), /tx secret key/);
        assert.throws(() => wallet.createTransaction({ ...params, txKeys: { additionalTxSecretKeys: [key] } }), /additional tx secret key/);
      }
    });

    it('throws when inputs cannot cover the outputs and fee', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const input = spendable(keys, 100000n);
      assert.throws(() => wallet.createTransaction({
        inputs: [input],
        outputs: [{
          type: 'address', publicSpendKey: keys.publicSpendKey, publicViewKey: keys.publicViewKey, amount: 100000000000n,
        }],
        keys,
        baseFee: BASE_FEE,
        feeQuantization: FEE_QUANTIZATION,
      }), /not enough funds/);
    });
  });

  describe('checkTxKey', () => {
    // monero construct_tx vectors; shuffleOutputs is false, so vout[i] is outputs[i]
    const decode = (fixture) => raw.fullTransaction.decode(hexToBytes(fixture.hex));
    const txKeysOf = ({ construct }) => ({
      txSecretKey: hexToBytes(construct.txKeys.txSecretKey),
      additionalTxSecretKeys: construct.txKeys.additionalTxSecretKeys.map(hexToBytes),
    });
    const destinationOf = (output) => address('mainnet').encode({
      type: output.type,
      publicSpendKey: hexToBytes(output.publicSpendKey),
      publicViewKey: hexToBytes(output.publicViewKey),
      ...(output.paymentID ? { paymentID: hexToBytes(output.paymentID) } : {}),
    });
    const recipientsOf = ({ construct }) => construct.outputs
      .map((output, index) => ({ output, index }))
      .filter(({ output }) => !output.isChange);

    for (const fixture of constructFixtures) {
      it(`finds every recipient: ${fixture.label}`, () => {
        const recipients = recipientsOf(fixture);
        const destinations = recipients.map(({ output }) => destinationOf(output));
        const found = wallet.checkTxKey(decode(fixture), txKeysOf(fixture), destinations);
        assert.deepStrictEqual(
          found.map(({
            index, destination, amount,
          }) => ({
            index, destination, amount,
          })),
          recipients.map(({ output, index }) => ({
            index, destination: destinationOf(output), amount: BigInt(output.amount),
          }))
        );
      });
    }

    const mixed = constructFixtures[1]; // standard + subaddress, with additional keys
    const [standard, subaddress] = mixed.construct.outputs.map(destinationOf);

    it('without the tx secret key finds only the additional-key subaddress output', () => {
      const { additionalTxSecretKeys } = txKeysOf(mixed);
      const found = wallet.checkTxKey(decode(mixed), { additionalTxSecretKeys }, [standard, subaddress]);
      assert.deepStrictEqual(found.map(({ index, destination }) => ({ index, destination })), [{ index: 1, destination: subaddress }]);
    });

    it('without additional keys finds only the standard output', () => {
      const { txSecretKey } = txKeysOf(mixed);
      const found = wallet.checkTxKey(decode(mixed), { txSecretKey }, [standard, subaddress]);
      assert.deepStrictEqual(found.map(({ index, destination }) => ({ index, destination })), [{ index: 0, destination: standard }]);
    });

    it('accepts a short additional key list', () => {
      const { txSecretKey, additionalTxSecretKeys } = txKeysOf(mixed);
      const found = wallet.checkTxKey(decode(mixed), { txSecretKey, additionalTxSecretKeys: additionalTxSecretKeys.slice(0, 1) }, [standard, subaddress]);
      assert.deepStrictEqual(found.map(({ index }) => index), [0]);
    });

    it('keeps additional keys at their vout index when entries are missing', () => {
      const [, key1] = txKeysOf(mixed).additionalTxSecretKeys;
      // eslint-disable-next-line no-sparse-arrays
      for (const additionalTxSecretKeys of [[undefined, key1, null], [null, key1], [, key1]]) {
        const found = wallet.checkTxKey(decode(mixed), { txSecretKey: null, additionalTxSecretKeys }, [standard, subaddress]);
        assert.deepStrictEqual(found.map(({ index, destination }) => ({ index, destination })), [{ index: 1, destination: subaddress }]);
      }
    });

    it('checks only the given addresses', () => {
      const found = wallet.checkTxKey(decode(mixed), txKeysOf(mixed), [subaddress]);
      assert.deepStrictEqual(found.map(({ index, destination }) => ({ index, destination })), [{ index: 1, destination: subaddress }]);
    });

    it('keeps a matched recipient without an amount when the amount does not decode', () => {
      const decodedTx = decode(mixed);
      decodedTx.rctSigBase.ecdhInfo[0].amount = new Uint8Array(8).fill(0xff);
      delete decodedTx.rctSigBase.outPk[1];
      const found = wallet.checkTxKey(decodedTx, txKeysOf(mixed), [standard, subaddress]);
      assert.deepStrictEqual(found, [{ index: 0, destination: standard }, { index: 1, destination: subaddress }]);
    });

    it('continues after a malformed output key', () => {
      const decodedTx = decode(mixed);
      decodedTx.prefix.vout[0].target.data.key = new Uint8Array(32).fill(0xff);
      const found = wallet.checkTxKey(decodedTx, txKeysOf(mixed), [standard, subaddress]);
      assert.deepStrictEqual(found.map(({ index, amount }) => ({ index, amount })), [{ index: 1, amount: 2000000n }]);
    });

    it('has no amount, not 0n, for a v2 tx without its RingCT base', () => {
      const decodedTx = decode(mixed);
      delete decodedTx.rctSigBase;
      const found = wallet.checkTxKey(decodedTx, txKeysOf(mixed), [standard, subaddress]);
      assert.deepStrictEqual(found, [{ index: 0, destination: standard }, { index: 1, destination: subaddress }]);
    });

    it('returns nothing for bad or missing data without throwing', () => {
      const decodedTx = decode(mixed);
      const txKeys = txKeysOf(mixed);
      const other = wallet.getAddress(wallet.keysFromSeed(new Uint8Array(32).fill(7)));
      const stagenet = address('stagenet').encode(address('mainnet').decode(standard));
      const badPoint = address('mainnet').encode({
        type: 'address', publicSpendKey: new Uint8Array(32).fill(0xff), publicViewKey: new Uint8Array(32).fill(0xff),
      });
      assert.deepStrictEqual(wallet.checkTxKey(decodedTx, txKeys, [other, 'not an address', stagenet, badPoint]), []);
      assert.deepStrictEqual(wallet.checkTxKey(decodedTx, {}, [standard, subaddress]), []);
      assert.deepStrictEqual(wallet.checkTxKey(decodedTx, { txSecretKey: new Uint8Array(32).fill(0xff) }, [standard]), []);
      assert.deepStrictEqual(wallet.checkTxKey(decodedTx, txKeys, []), []);
    });
  });

  describe('annotateTransaction', () => {
    const mixed = constructFixtures[1];
    const { construct } = mixed;
    const decodedTx = raw.fullTransaction.decode(hexToBytes(mixed.hex));
    const keys = wallet.keysFromSecretKeys(hexToBytes(construct.secretSpendKey), hexToBytes(construct.secretViewKey));
    const subaddresses = wallet.subaddressLookup(keys, 1, 1);
    const txKeys = {
      txSecretKey: hexToBytes(construct.txKeys.txSecretKey),
      additionalTxSecretKeys: construct.txKeys.additionalTxSecretKeys.map(hexToBytes),
    };
    const destinations = construct.outputs.slice(0, 2).map((output) => address('mainnet').encode({
      type: output.type, publicSpendKey: hexToBytes(output.publicSpendKey), publicViewKey: hexToBytes(output.publicViewKey),
    }));

    it('marks recipients and the change', () => {
      const { prefix } = wallet.annotateTransaction(decodedTx, {
        keys, subaddresses, txKeys, destinations,
      });
      assert.deepStrictEqual(prefix.vout.map((vout) => vout.recipient?.destination), [...destinations, undefined]);
      assert.deepStrictEqual(prefix.vout.map((vout) => vout.recipient?.amount), [2000000n, 2000000n, undefined]);
      assert.deepStrictEqual(prefix.vout.map((vout) => vout.owned?.amount), [undefined, undefined, 1000000n]);
      assert.deepStrictEqual(prefix.vout[2].owned.subaddress, { major: 0, minor: 0 });
    });

    it('keeps the transaction unchanged without data and does not mutate the input', () => {
      const before = structuredClone(decodedTx);
      assert.deepStrictEqual(wallet.annotateTransaction(decodedTx), decodedTx);
      wallet.annotateTransaction(decodedTx, {
        keys, subaddresses, txKeys, destinations,
      });
      assert.deepStrictEqual(decodedTx, before);
    });

    it('accumulates annotations over calls and keeps a decoded amount', () => {
      const withOwned = wallet.annotateTransaction(decodedTx, { keys, subaddresses });
      const full = wallet.annotateTransaction(withOwned, { txKeys, destinations });
      assert.deepStrictEqual(full, wallet.annotateTransaction(decodedTx, {
        keys, subaddresses, txKeys, destinations,
      }));
      assert.deepStrictEqual(wallet.annotateTransaction(full), full);

      const withoutBase = structuredClone(full);
      delete withoutBase.rctSigBase;
      const again = wallet.annotateTransaction(withoutBase, { txKeys, destinations });
      assert.deepStrictEqual(again.prefix.vout, full.prefix.vout);
    });

    it('adds the amount to a recipient found earlier without it', () => {
      const withoutBase = structuredClone(decodedTx);
      delete withoutBase.rctSigBase;
      const partial = wallet.annotateTransaction(withoutBase, { txKeys, destinations });
      assert.deepStrictEqual(partial.prefix.vout[0].recipient, { index: 0, destination: destinations[0] });
      const restored = wallet.annotateTransaction({ ...partial, rctSigBase: decodedTx.rctSigBase }, { txKeys, destinations });
      assert.strictEqual(restored.prefix.vout[0].recipient.amount, 2000000n);
    });

    it('annotates a pruned transaction the same way', () => {
      const bytes = hexToBytes(mixed.hex);
      const pruned = raw.prunedTransaction.decode(raw.prunedTransaction.encode(raw.fullTransaction.decode(bytes)));
      const params = {
        keys, subaddresses, txKeys, destinations,
      };
      assert.deepStrictEqual(
        wallet.annotateTransaction(pruned, params).prefix.vout,
        wallet.annotateTransaction(decodedTx, params).prefix.vout
      );
    });
  });

  describe('isOwnKeyImage', () => {
    it('true for a genuine spend of our own output', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const txSecretKey = crypto.randomScalar();
      const txPublicKey = crypto.secretKeyToPublicKey(txSecretKey);
      const derivation = crypto.generateKeyDerivation(keys.publicViewKey, txSecretKey);
      const keyImage = crypto.outputKeyImage(
        helpers.decodeInt(keys.secretViewKey), helpers.decodeInt(keys.secretSpendKey), derivation, 0, { major: 0, minor: 0 }
      );
      assert.strictEqual(wallet.isOwnKeyImage(keys, {
        txPublicKey, index: 0, subaddress: { major: 0, minor: 0 },
      }, keyImage), true);
    });

    it('uses the additional tx public key for a subaddress output in a mixed transaction', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const subaddress = { major: 0, minor: 1 };
      const subaddressKeys = crypto.subaddressPublicKeys(
        helpers.decodeInt(keys.secretViewKey), keys.publicSpendKey, subaddress
      );
      const other = wallet.randomKeys();
      const generated = tx.generateOutputs([
        {
          type: 'address', publicSpendKey: other.publicSpendKey, publicViewKey: other.publicViewKey, amount: 1n,
        },
        {
          type: 'subaddress', ...subaddressKeys, amount: 1n,
        },
      ], { txSecretKey: crypto.randomScalar() });
      const additionalTxPublicKey = generated.txKeys.additionalTxPublicKeys[1];
      const derivation = crypto.generateKeyDerivation(
        additionalTxPublicKey, helpers.decodeInt(keys.secretViewKey)
      );
      const keyImage = crypto.outputKeyImage(
        helpers.decodeInt(keys.secretViewKey),
        helpers.decodeInt(keys.secretSpendKey),
        derivation,
        1,
        subaddress
      );

      assert.strictEqual(wallet.isOwnKeyImage(keys, {
        txPublicKey: generated.txKeys.txPublicKey,
        additionalTxPublicKey,
        index: 1,
        subaddress,
      }, keyImage), true);
    });

    it('false for an unrelated key image (output used only as a ring decoy)', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const txPublicKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      const someoneElsesKeyImage = crypto.secretKeyToPublicKey(crypto.randomScalar());
      assert.strictEqual(wallet.isOwnKeyImage(keys, {
        txPublicKey, index: 0, subaddress: { major: 0, minor: 0 },
      }, someoneElsesKeyImage), false);
    });

    it('matches through the primary key despite a malformed additional public key', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const txSecretKey = crypto.randomScalar();
      const txPublicKey = crypto.secretKeyToPublicKey(txSecretKey);
      const derivation = crypto.generateKeyDerivation(keys.publicViewKey, txSecretKey);
      const keyImage = crypto.outputKeyImage(
        helpers.decodeInt(keys.secretViewKey), helpers.decodeInt(keys.secretSpendKey), derivation, 0, { major: 0, minor: 0 }
      );
      assert.strictEqual(wallet.isOwnKeyImage(keys, {
        txPublicKey, additionalTxPublicKey: new Uint8Array(32).fill(0xff), index: 0, subaddress: { major: 0, minor: 0 },
      }, keyImage), true);
    });
  });
});
