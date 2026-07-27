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
      assert.strictEqual(typeof owned.keyOffset, 'bigint');
      assert.strictEqual(owned.keyImage.length, 32);
    });

    it('view-only wallet: detects the output, amount and key offset, but no key image', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const viewOnly = wallet.viewOnlyKeys(keys.publicSpendKey, keys.secretViewKey);
      const owned = wallet.scanOutput(viewOnly, outputTo(keys, 4000000n), wallet.subaddressLookup(viewOnly, 1, 1));
      assert.strictEqual(owned.amount, 4000000n);
      assert.strictEqual(typeof owned.keyOffset, 'bigint'); // view-only can produce the offset
      assert.strictEqual(owned.keyImage, undefined); // but not the key image (needs the spend key)
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

    it('finds the primary-key output despite a malformed additional public key', () => {
      const keys = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const output = { ...outputTo(keys, 4000000n), additionalPublicKey: new Uint8Array(32).fill(0xff) };
      const owned = wallet.scanOutput(keys, output, wallet.subaddressLookup(keys, 1, 1));
      assert.strictEqual(owned.amount, 4000000n);
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
      const bytes = tx.createTransaction({
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
      });
      const decodedTx = raw.transaction.decode(bytes);
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

    it('decrypts the payment id of an integrated-address output', () => {
      const recipient = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const paymentId = randomBytes(8);
      const bytes = tx.createTransaction({
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
      const decodedTx = raw.transaction.decode(bytes);
      const subaddresses = wallet.subaddressLookup(recipient, 1, 1);

      const result = wallet.scanTransaction(recipient, decodedTx, subaddresses);
      const paid = result.outputs.find((o) => o.amount === 700000n);
      assert.deepStrictEqual(paid.paymentId, paymentId);
    });

    it('finds nothing for an unrelated wallet', () => {
      const recipient = wallet.keysFromSeed(hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'));
      const other = wallet.keysFromSeed(hexToBytes('1a2b3c4d5e38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac490'));
      const bytes = tx.createTransaction({
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
      const decodedTx = raw.transaction.decode(bytes);
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
      const rctSigBase = raw.rctBase(prefix.vin.length, prefix.vout.length)
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
      const incoming = tx.createTransaction({
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
      const owned = wallet.scanTransaction(keys, raw.transaction.decode(incoming), wallet.subaddressLookup(keys, 1, 1)).outputs[0];

      // spend it: signing reconstructs x = keyOffset + b with a non-zero b
      const decoys = Array.from({ length: 10 }, (unused, j) => ({
        publicKey: crypto.secretKeyToPublicKey(crypto.randomScalar()),
        commitment: crypto.secretKeyToPublicKey(crypto.randomScalar()),
        globalIndex: BigInt(2000 + j),
      }));
      const recipient = wallet.keysFromSeed(hexToBytes('9e9d9eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4904'));
      const spend = raw.transaction.decode(tx.createTransaction({
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
      }));

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
      ], crypto.randomScalar());
      const additionalPublicKey = generated.additionalPublicKeys[1];
      const derivation = crypto.generateKeyDerivation(
        additionalPublicKey, helpers.decodeInt(keys.secretViewKey)
      );
      const keyImage = crypto.outputKeyImage(
        helpers.decodeInt(keys.secretViewKey),
        helpers.decodeInt(keys.secretSpendKey),
        derivation,
        1,
        subaddress
      );

      assert.strictEqual(wallet.isOwnKeyImage(keys, {
        txPublicKey: generated.txPublicKey,
        additionalPublicKey,
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
  });
});
