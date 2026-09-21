/* eslint-disable max-len */
import assert from 'node:assert';
import {
  bytesToHex, hexToBytes, randomBytes,
} from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as bulletproofs from '../lib/bulletproofs.js';
import * as clsag from '../lib/clsag.js';
import * as crypto from '../lib/crypto.js';
import * as cryptoData from '../lib/crypto-data.js';
import * as raw from '../lib/raw.js';
import * as ringct from '../lib/ringct.js';
import * as tx from '../lib/tx.js';
import txFixtures from './fixtures/txs.json' with { type: 'json' };

describe('tx', () => {

  describe('parseTxExtra', () => {

    const NIL_TX_PUB_KEY = new Uint8Array(32);
    const TX_EXTRA_PADDING_MAX_COUNT = 255;
    const empty = {
      txPublicKeys: [],
      additionalTxPublicKeys: [],
      encryptedPaymentId: undefined,
    };

    it('should handle empty extra', () => {
      const result = tx.parseTxExtra(Uint8Array.from([]));
      assert.deepStrictEqual(result, empty);
    });

    // https://xmrchain.net/tx/f64bbe722d0ef4ae96d8b6dccf693ce8ca9b525e8c47fe9642040f744870d64b
    it('should handle empty txPublicKey', () => {
      const result = tx.parseTxExtra(hexToBytes('0321001a36d20bc8a84a04be188f3a0f8b76b9f4e66f000230e8d3f8ab72777a7520f100000083d9c85c1dccceb0ee3532ef7c9528ae4dfe2ca79b139f4637a3ba16de8d02110000000000000000000000000000000000'));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only size 1', () => {
      const result = tx.parseTxExtra(Uint8Array.from([0]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only size 2', () => {
      const result = tx.parseTxExtra(Uint8Array.from([0, 0]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only max size', () => {
      const result = tx.parseTxExtra(new Uint8Array(TX_EXTRA_PADDING_MAX_COUNT));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only exceed max size', () => {
      const result = tx.parseTxExtra(new Uint8Array(TX_EXTRA_PADDING_MAX_COUNT + 1));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle invalid padding only', () => {
      const result = tx.parseTxExtra(Uint8Array.from([0, 42]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle pub key only', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6')],
        additionalTxPublicKeys: [],
        encryptedPaymentId: undefined,
      });
    });

    it('should handle extra nonce only', () => {
      const result = tx.parseTxExtra(Uint8Array.from([2, 1, 42]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle pub key and padding', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6')],
        additionalTxPublicKeys: [],
        encryptedPaymentId: undefined,
      });
    });

    it('should handle two pub keys', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [
          hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'),
          hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'),
        ],
        additionalTxPublicKeys: [],
        encryptedPaymentId: undefined,
      });
    });

    it('should keep an all-zero tx public key', () => {
      const result = tx.parseTxExtra(Uint8Array.from([
        1, ...new Uint8Array(32),
        1, ...new Uint8Array(32).fill(1),
      ]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [NIL_TX_PUB_KEY, new Uint8Array(32).fill(1)],
        additionalTxPublicKeys: [],
        encryptedPaymentId: undefined,
      });
    });

    it('should not read a payment id from a non-strict nonce', () => {
      // a 0x01 byte inside a wrong-sized nonce must not be taken as an encrypted payment id
      const result = tx.parseTxExtra(Uint8Array.from([2, 5, 42, 1, 9, 8, 7, 6]));
      assert.deepStrictEqual(result, empty);
    });

    it('should not emit a truncated txPublicKey', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 2, 3]));
      assert.deepStrictEqual(result, empty);
    });

    it('should not emit truncated additional pub keys', () => {
      const result = tx.parseTxExtra(Uint8Array.from([4, 1, 9, 9, 9]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle pub key with encrypted payment id', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6')],
        encryptedPaymentId: hexToBytes('0000000000000000'),
        additionalTxPublicKeys: [],
      });
    });

    it('should handle pub key with encrypted payment id (reverse order)', () => {
      const result = tx.parseTxExtra(Uint8Array.from([2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6')],
        encryptedPaymentId: hexToBytes('0000000000000000'),
        additionalTxPublicKeys: [],
      });
    });

    it('should additional pub keys', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 59, 54, 37, 207, 182, 88, 66, 252, 62, 68, 82, 69, 144, 143, 155, 23, 27, 78, 24, 153, 84, 63, 183, 13, 133, 66, 79, 217, 177, 201, 94, 185,
        4, 3, 252, 23, 118, 225, 66, 173, 231, 164, 173, 94, 0, 189, 39, 164, 128, 1, 63, 6, 196, 93, 90, 200, 8, 7, 211, 96, 149, 0, 189, 210, 108, 242, 152, 112, 95, 250, 198, 110, 246, 61, 103,
        203, 88, 114, 182, 252, 34, 40, 121, 144, 46, 219, 231, 163, 204, 184, 50, 120, 200, 42, 95, 173, 9, 124, 207, 193, 216, 157, 94, 95, 186, 83, 166, 138, 35, 130, 57, 235, 213, 246, 13, 96,
        50, 125, 34, 218, 62, 233, 90, 156, 7, 6, 116, 234, 82, 90]));
      assert.deepStrictEqual(result, {
        txPublicKeys: [hexToBytes('3b3625cfb65842fc3e445245908f9b171b4e1899543fb70d85424fd9b1c95eb9')],
        additionalTxPublicKeys: [
          hexToBytes('fc1776e142ade7a4ad5e00bd27a480013f06c45d5ac80807d3609500bdd26cf2'),
          hexToBytes('98705ffac66ef63d67cb5872b6fc222879902edbe7a3ccb83278c82a5fad097c'),
          hexToBytes('cfc1d89d5e5fba53a68a238239ebd5f60d60327d22da3ee95a9c070674ea525a'),
        ],
        encryptedPaymentId: undefined,
      });
    });
  });

  describe('buildTxExtra', () => {
    it('builds and round-trips through parseTxExtra', () => {
      const txPublicKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      const additionalTxPublicKeys = [crypto.secretKeyToPublicKey(crypto.randomScalar()), crypto.secretKeyToPublicKey(crypto.randomScalar())];
      const encryptedPaymentId = randomBytes(8);
      const parsed = tx.parseTxExtra(tx.buildTxExtra({
        txPublicKey, additionalTxPublicKeys, encryptedPaymentId,
      }));
      assert.deepStrictEqual(parsed.txPublicKeys, [txPublicKey]);
      assert.deepStrictEqual(parsed.additionalTxPublicKeys, additionalTxPublicKeys);
      assert.deepStrictEqual(parsed.encryptedPaymentId, encryptedPaymentId);
    });

    it('omits optional fields when not given', () => {
      const txPublicKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      const parsed = tx.parseTxExtra(tx.buildTxExtra({ txPublicKey }));
      assert.deepStrictEqual(parsed.txPublicKeys, [txPublicKey]);
      assert.deepStrictEqual(parsed.additionalTxPublicKeys, []);
      assert.strictEqual(parsed.encryptedPaymentId, undefined);
    });
  });

  describe('encryptPaymentId', () => {
    it('encrypts and decrypts symmetrically', () => {
      const txSecretKey = crypto.randomScalar();
      const secretViewKey = crypto.randomScalar();
      const publicViewKey = crypto.secretKeyToPublicKey(secretViewKey);
      const txPublicKey = crypto.secretKeyToPublicKey(txSecretKey);
      const paymentId = randomBytes(8);
      const encrypted = tx.encryptPaymentId(paymentId, publicViewKey, txSecretKey);
      assert.notDeepStrictEqual(encrypted, paymentId);
      // the recipient recovers it with the tx public key and its own view secret
      assert.deepStrictEqual(tx.encryptPaymentId(encrypted, txPublicKey, secretViewKey), paymentId);
    });
  });

  describe('generateOutputs', () => {
    // a standard wallet: random view/spend secrets, public keys s*G
    const stdWallet = () => {
      const secretView = crypto.randomScalar();
      const secretSpend = crypto.randomScalar();
      return {
        secretView,
        publicSpendKey: crypto.secretKeyToPublicKey(secretSpend),
        publicViewKey: crypto.secretKeyToPublicKey(secretView),
        type: 'address',
      };
    };
    // a subaddress wallet: spend key D is any point, view key C = a*D
    const subWallet = () => {
      const secretView = crypto.randomScalar();
      const publicSpendKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      return {
        secretView,
        publicSpendKey,
        publicViewKey: crypto.encodePoint(crypto.decodePoint(publicSpendKey).multiplyUnsafe(secretView)),
        type: 'subaddress',
      };
    };
    // scan output i as its recipient would: try the tx pub key and each additional pub key
    const recipientFinds = (out, i, w) => {
      const { key, viewTag } = out.outputs[i];
      return [out.txKeys.txPublicKey, ...out.txKeys.additionalTxPublicKeys].some((R) => {
        const derivation = crypto.generateKeyDerivation(R, w.secretView);
        return bytesToHex(crypto.derivePublicKey(derivation, i, w.publicSpendKey)) === bytesToHex(key)
          && crypto.deriveViewTag(derivation, i)[0] === viewTag;
      });
    };

    it('standard recipients are detectable (R = r*G, no additional keys)', () => {
      const a = stdWallet();
      const b = stdWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([a, b], { txSecretKey: r });
      assert.equal(out.txKeys.additionalTxPublicKeys.length, 0);
      assert.ok(recipientFinds(out, 0, a));
      assert.ok(recipientFinds(out, 1, b));
    });

    it('standard + subaddress uses additional keys', () => {
      const a = stdWallet();
      const s = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([a, s], { txSecretKey: r });
      assert.equal(out.txKeys.additionalTxPublicKeys.length, 2);
      assert.ok(recipientFinds(out, 0, a));
      assert.ok(recipientFinds(out, 1, s));
    });

    it('single subaddress sets R = r*D, no additional keys', () => {
      const s = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([s], { txSecretKey: r });
      assert.equal(out.txKeys.additionalTxPublicKeys.length, 0);
      assert.deepStrictEqual(out.txKeys.txPublicKey, crypto.encodePoint(crypto.decodePoint(s.publicSpendKey).multiplyUnsafe(r)));
      assert.ok(recipientFinds(out, 0, s));
    });

    it('two distinct subaddresses use additional keys (R = r*G)', () => {
      const s1 = subWallet();
      const s2 = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([s1, s2], { txSecretKey: r });
      assert.equal(out.txKeys.additionalTxPublicKeys.length, 2);
      assert.deepStrictEqual(out.txKeys.txPublicKey, crypto.secretKeyToPublicKey(r));
      assert.ok(recipientFinds(out, 0, s1));
      assert.ok(recipientFinds(out, 1, s2));
    });

    it('duplicate subaddress is deduped: R = r*D, no additional keys', () => {
      const s = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([s, s], { txSecretKey: r });
      assert.equal(out.txKeys.additionalTxPublicKeys.length, 0);
      assert.deepStrictEqual(out.txKeys.txPublicKey, crypto.encodePoint(crypto.decodePoint(s.publicSpendKey).multiplyUnsafe(r)));
      assert.ok(recipientFinds(out, 0, s));
      assert.ok(recipientFinds(out, 1, s));
    });

    it('change derives from a*R and stays detectable (single subaddress + change)', () => {
      const s = subWallet();
      const sender = stdWallet();
      const r = crypto.randomScalar();
      const change = { ...sender, isChange: true };
      const out = tx.generateOutputs([s, change], { txSecretKey: r }, sender.secretView);
      assert.ok(recipientFinds(out, 0, s));
      assert.ok(recipientFinds(out, 1, sender));
    });

    it('generates additional keys only when needed and omitted', () => {
      const standard = stdWallet();
      const sub = subWallet();
      const change = { ...standard, isChange: true };
      let randomCalls = 0;
      crypto.__mockRandomBytes__((length) => {
        randomCalls++;
        return new Uint8Array(length).fill(1);
      });
      try {
        for (const destinations of [[standard, change], [sub, change]]) {
          for (const keys of [undefined, [], [19n]]) {
            const result = tx.generateOutputs(destinations, { txSecretKey: 17n, additionalTxSecretKeys: keys }, standard.secretView);
            assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, []);
          }
        }
        const mixed = [standard, sub, change];
        const keys = [19n, 23n, 29n];
        assert.deepStrictEqual(tx.generateOutputs(mixed, { txSecretKey: 17n, additionalTxSecretKeys: keys }, standard.secretView).txKeys.additionalTxSecretKeys, keys);
        assert.throws(() => tx.generateOutputs(mixed, { txSecretKey: 17n, additionalTxSecretKeys: [] }, standard.secretView), /additionalTxSecretKeys: expected/);
        assert.equal(randomCalls, 0);
        assert.equal(tx.generateOutputs(mixed, { txSecretKey: 17n }, standard.secretView).txKeys.additionalTxSecretKeys.length, mixed.length);
        assert.equal(randomCalls, mixed.length);
      } finally {
        crypto.__mockRandomBytes__(randomBytes);
      }
    });

    it('accepts omitted, empty, partial, and returned txKeys without changing the supplied object', () => {
      const standard = stdWallet();
      const sub = subWallet();
      const destinations = [standard, sub];
      for (const txKeys of [undefined, {}, { txSecretKey: 17n }, { additionalTxSecretKeys: [19n, 23n] }]) {
        const original = structuredClone(txKeys);
        if (txKeys !== undefined) {
          Object.freeze(txKeys);
          if (txKeys.additionalTxSecretKeys !== undefined) Object.freeze(txKeys.additionalTxSecretKeys);
        }
        const result = tx.generateOutputs(destinations, txKeys);
        assert.deepStrictEqual(Object.keys(result).sort(), ['outputs', 'txKeys']);
        assert.deepStrictEqual(Object.keys(result.txKeys).sort(), ['additionalTxPublicKeys', 'additionalTxSecretKeys', 'txPublicKey', 'txSecretKey']);
        assert.deepStrictEqual(txKeys, original);
        assert.equal(typeof result.txKeys.txSecretKey, 'bigint');
        assert.deepStrictEqual(result.txKeys.txPublicKey, crypto.secretKeyToPublicKey(result.txKeys.txSecretKey));
        assert.equal(result.txKeys.additionalTxSecretKeys.length, destinations.length);
        if (txKeys?.txSecretKey !== undefined) assert.equal(result.txKeys.txSecretKey, txKeys.txSecretKey);
        if (txKeys?.additionalTxSecretKeys !== undefined) assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, txKeys.additionalTxSecretKeys);
        assert.deepStrictEqual(tx.generateOutputs(destinations, result.txKeys), result);
        assert.ok(recipientFinds(result, 0, standard));
        assert.ok(recipientFinds(result, 1, sub));
      }
    });

    it('derives public keys for the current destinations when txKeys are reused', () => {
      const standard = stdWallet();
      const sub = subWallet();
      const first = tx.generateOutputs([standard, sub]);
      const original = structuredClone(first.txKeys);
      const reordered = tx.generateOutputs([sub, standard], first.txKeys);
      assert.deepStrictEqual(first.txKeys, original);
      assert.equal(reordered.txKeys.txSecretKey, first.txKeys.txSecretKey);
      assert.deepStrictEqual(reordered.txKeys.additionalTxSecretKeys, first.txKeys.additionalTxSecretKeys);
      assert.deepStrictEqual(reordered.txKeys.additionalTxPublicKeys, [
        crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiplyUnsafe(first.txKeys.additionalTxSecretKeys[0])),
        crypto.secretKeyToPublicKey(first.txKeys.additionalTxSecretKeys[1]),
      ]);
      assert.ok(recipientFinds(reordered, 0, sub));
      assert.ok(recipientFinds(reordered, 1, standard));

      const singleSub = tx.generateOutputs([sub], first.txKeys);
      assert.deepStrictEqual(singleSub.txKeys.txPublicKey, crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiplyUnsafe(first.txKeys.txSecretKey)));
      assert.deepStrictEqual(singleSub.txKeys.additionalTxPublicKeys, []);
      assert.deepStrictEqual(singleSub.txKeys.additionalTxSecretKeys, []);
      assert.ok(recipientFinds(singleSub, 0, sub));
    });
  });

  describe('createTransaction', () => {
    // a fake owned output: view-only key offset, amount, mask, and a ring of decoys + the real one.
    // secretSpendKey is 0 in these tests, so the one-time secret is keyOffset + 0 = keyOffset.
    const makeInput = (amount, ringSize = 11) => {
      const keyOffset = crypto.randomScalar();
      const mask = crypto.randomScalar();
      const commitment = ringct.pedersenCommitment(amount, mask);
      const decoys = [];
      for (let j = 0; j < ringSize - 1; j++) {
        decoys.push({
          publicKey: crypto.secretKeyToPublicKey(crypto.randomScalar()),
          commitment: crypto.secretKeyToPublicKey(crypto.randomScalar()),
          globalIndex: BigInt(1000 + j * 7),
        });
      }
      return {
        keyOffset,
        publicKey: crypto.secretKeyToPublicKey(keyOffset),
        amount,
        mask,
        commitment,
        globalIndex: 9999n,
        decoys,
      };
    };
    // reconstruct the sorted ring createTransaction builds internally, as clsag ring members
    const sortedRing = (input) => {
      const real = {
        publicKey: input.publicKey,
        commitment: input.commitment,
        globalIndex: input.globalIndex,
      };
      return [real, ...input.decoys]
        .sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1))
        .map((m) => ({ publicKey: m.publicKey, commitment: m.commitment }));
    };
    const stdWallet = () => {
      const secretView = crypto.randomScalar();
      const secretSpend = crypto.randomScalar();
      return {
        secretView,
        publicViewKey: crypto.secretKeyToPublicKey(secretView),
        publicSpendKey: crypto.secretKeyToPublicKey(secretSpend),
        type: 'address',
      };
    };
    const sumPoints = (arr) => arr.reduce((acc, b) => acc.add(crypto.decodePoint(b)), crypto.Point.ZERO);

    it('builds a valid 2-in 2-out transaction', () => {
      const inputs = [makeInput(2000000n), makeInput(3000000n)];
      const sender = stdWallet();
      const recipient = stdWallet();
      const fee = 10000n;
      const outputs = [
        { ...recipient, amount: 4000000n },
        {
          ...sender, isChange: true, amount: 990000n,
        },
      ];
      const { bytes } = tx.createTransaction({
        inputs, outputs, secretSpendKey: 0n, secretViewKey: sender.secretView, shuffleOutputs: false, // output 0 stays the recipient
      });

      // serialization round-trips
      const decoded = raw.fullTransaction.decode(bytes);
      assert.equal(bytesToHex(raw.fullTransaction.encode(decoded)), bytesToHex(bytes));
      assert.equal(decoded.rctSigBase.type, 6);
      assert.equal(decoded.prefix.vin.length, 2);
      assert.equal(decoded.prefix.vout.length, 2);
      // fee is the remainder sum(inputs) - sum(outputs)
      assert.equal(decoded.rctSigBase.txnFee, fee);

      const { outPk } = decoded.rctSigBase;
      const {
        bulletproofsPlus, CLSAGs, pseudoOuts,
      } = decoded.rctSigPrunable;

      // range proof verifies
      assert.ok(bulletproofs.verifyBulletproofPlus(outPk, bulletproofsPlus[0]));

      // commitments balance: sum(pseudoOuts) == sum(outPk) + fee*H
      const lhs = sumPoints(pseudoOuts);
      const rhs = sumPoints(outPk).add(cryptoData.H.multiplyUnsafe(fee));
      assert.ok(lhs.equals(rhs));

      // each CLSAG verifies against the original ring and the signed message
      const message = tx.getPreMlsagHash(crypto.fastHash(raw.txPrefix.encode(decoded.prefix)), decoded.rctSigBase, bulletproofsPlus[0]);
      const ringByKi = new Map();
      for (const input of inputs) {
        const ki = bytesToHex(crypto.generateKeyImage(input.publicKey, input.keyOffset));
        ringByKi.set(ki, sortedRing(input));
      }
      decoded.prefix.vin.forEach((vin, i) => {
        const pubs = ringByKi.get(bytesToHex(vin.data.keyImage));
        assert.ok(pubs, 'key image not found among inputs');
        const sig = {
          s: CLSAGs[i].s, c1: CLSAGs[i].c1, I: vin.data.keyImage, D: CLSAGs[i].D,
        };
        assert.ok(clsag.verifyClsag(message, pubs, pseudoOuts[i], sig));
      });

      // the recipient (output 0) can decode the amount and the commitment matches
      const [txPublicKey] = tx.parseTxExtra(decoded.prefix.extra).txPublicKeys;
      const derivation = crypto.generateKeyDerivation(txPublicKey, recipient.secretView);
      const ecdh = ringct.decodeRct(decoded.rctSigBase.ecdhInfo[0], outPk[0], 6, 0, derivation);
      assert.equal(ecdh.amount, 4000000n);
    });

    it('rejects a wrong spend key: reconstructed key does not match the output', () => {
      // makeInput's publicKey is keyOffset*G (b = 0); a non-zero spend key makes (keyOffset + b)*G != P
      const inputs = [makeInput(5000000n)];
      const outputs = [{ ...stdWallet(), amount: 4000000n }, { ...stdWallet(), amount: 990000n }];
      assert.throws(() => tx.createTransaction({
        inputs, outputs, secretSpendKey: crypto.randomScalar(),
      }), /wrong spend key/);
    });

    it('rejects the same input twice and a duplicate ring member', () => {
      const input = makeInput(5000000n);
      const outputs = [{ ...stdWallet(), amount: 1000000n }, { ...stdWallet(), amount: 1000000n }];
      assert.throws(() => tx.createTransaction({
        inputs: [input, input], outputs, secretSpendKey: 0n,
      }), /duplicate input/);
      const decoys = [...input.decoys];
      decoys[0] = { ...decoys[0], globalIndex: decoys[1].globalIndex };
      assert.throws(() => tx.createTransaction({
        inputs: [{ ...input, decoys }], outputs, secretSpendKey: 0n,
      }), /duplicate ring member/);
    });

    it('returns the transaction or bytes alongside the used keys', () => {
      const inputs = [makeInput(5010000n)];
      const sender = stdWallet();
      const outputs = [
        { ...stdWallet(), amount: 4000000n },
        {
          ...sender, isChange: true, amount: 1000000n,
        },
      ];
      const params = {
        inputs, outputs, secretSpendKey: 0n, secretViewKey: sender.secretView,
      };
      const prepared = tx.prepareTransaction(params);
      assert.deepStrictEqual(Object.keys(prepared).sort(), ['transaction', 'txKeys']);
      assert.ok(prepared.transaction.prefix && prepared.transaction.rctSigBase && prepared.transaction.rctSigPrunable);
      const created = tx.createTransaction(params);
      assert.deepStrictEqual(Object.keys(created).sort(), ['bytes', 'txKeys']);
      assert.ok(created.bytes instanceof Uint8Array);
      for (const result of [prepared, created]) {
        const decoded = result.transaction ?? raw.fullTransaction.decode(result.bytes);
        assert.equal(decoded.prefix.vin.length, 1);
        assert.equal(typeof result.txKeys.txSecretKey, 'bigint');
        assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, []);
        assert.deepStrictEqual(result.txKeys.additionalTxPublicKeys, []);
        assert.deepStrictEqual(result.txKeys.txPublicKey, crypto.secretKeyToPublicKey(result.txKeys.txSecretKey));
        assert.deepStrictEqual(tx.parseTxExtra(decoded.prefix.extra).txPublicKeys, [result.txKeys.txPublicKey]);
        assert.deepStrictEqual(Object.keys(decoded).sort(), ['prefix', 'rctSigBase', 'rctSigPrunable']);
      }
    });

    for (const type of ['address', 'subaddress']) {
      it(`uses the supplied main key for a single ${type} and ignores unneeded additional keys`, () => {
        const recipient = stdWallet();
        recipient.type = type;
        if (type === 'subaddress') {
          recipient.publicViewKey = crypto.encodePoint(crypto.decodePoint(recipient.publicSpendKey).multiplyUnsafe(recipient.secretView));
        }
        const sender = stdWallet();
        const txSecretKey = 17n;
        const result = tx.prepareTransaction({
          inputs: [makeInput(20n, 2)],
          outputs: [{ ...recipient, amount: 10n }, {
            ...sender, isChange: true, amount: 9n,
          }],
          secretSpendKey: 0n,
          secretViewKey: sender.secretView,
          txKeys: { txSecretKey, additionalTxSecretKeys: [19n] },
          shuffleOutputs: false,
        });
        assert.strictEqual(result.txKeys.txSecretKey, txSecretKey);
        assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, []);
        const extra = tx.parseTxExtra(result.transaction.prefix.extra);
        const expected = type === 'subaddress'
          ? crypto.encodePoint(crypto.decodePoint(recipient.publicSpendKey).multiplyUnsafe(txSecretKey))
          : crypto.secretKeyToPublicKey(txSecretKey);
        assert.deepStrictEqual(extra.txPublicKeys, [expected]);
        assert.deepStrictEqual(extra.additionalTxPublicKeys, []);
        assert.deepStrictEqual(result.txKeys.txPublicKey, expected);
        assert.deepStrictEqual(result.txKeys.additionalTxPublicKeys, []);
        [recipient, sender].forEach((owner, i) => {
          const derivation = crypto.generateKeyDerivation(expected, owner.secretView);
          assert.deepStrictEqual(crypto.derivePublicKey(derivation, i, owner.publicSpendKey), result.transaction.prefix.vout[i].target.data.key);
          assert.equal(ringct.decodeRct(result.transaction.rctSigBase.ecdhInfo[i], result.transaction.rctSigBase.outPk[i], 6, i, derivation).amount, i === 0 ? 10n : 9n);
        });
      });
    }

    for (const supplied of [false, true]) {
      for (const shuffleOutputs of [false, true]) {
        it(`${supplied ? 'supplied' : 'generated'} keys match mixed outputs with shuffleOutputs=${shuffleOutputs}`, () => {
          const first = stdWallet();
          const sub = stdWallet();
          sub.type = 'subaddress';
          sub.publicViewKey = crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiplyUnsafe(sub.secretView));
          const sender = stdWallet();
          const input = makeInput(40n, 2);
          const outputs = [
            { ...first, amount: 10n },
            { ...sub, amount: 20n },
            {
              ...sender, isChange: true, amount: 9n,
            },
          ];
          const params = {
            inputs: [input], outputs, secretSpendKey: 0n, secretViewKey: sender.secretView, shuffleOutputs,
            txKeys: supplied ? { txSecretKey: 17n, additionalTxSecretKeys: [19n, 23n, 29n] } : undefined,
          };
          let prepared;
          let created;
          let randomCalls = 0;
          crypto.__mockRandomBytes__((length) => {
            randomCalls++;
            const bytes = new Uint8Array(length).fill(1);
            if (length === 32) {
              bytes[0] = randomCalls % 256;
            }
            return bytes;
          });
          try {
            prepared = tx.prepareTransaction(params);
            const prepareCalls = randomCalls;
            randomCalls = 0;
            created = tx.createTransaction(params);
            assert.equal(randomCalls, prepareCalls);
          } finally {
            crypto.__mockRandomBytes__(randomBytes);
          }
          assert.deepStrictEqual(created.bytes, raw.fullTransaction.encode(prepared.transaction));
          assert.deepStrictEqual(created.txKeys, prepared.txKeys);
          if (supplied) {
            assert.strictEqual(created.txKeys.txSecretKey, params.txKeys.txSecretKey);
            assert.deepStrictEqual(created.txKeys.additionalTxSecretKeys, params.txKeys.additionalTxSecretKeys);
          }
          const decoded = raw.fullTransaction.decode(created.bytes);
          const extra = tx.parseTxExtra(decoded.prefix.extra);
          assert.deepStrictEqual(extra.txPublicKeys, [created.txKeys.txPublicKey]);
          assert.deepStrictEqual(extra.additionalTxPublicKeys, created.txKeys.additionalTxPublicKeys);
          assert.equal(typeof created.txKeys.txSecretKey, 'bigint');
          assert.deepStrictEqual(extra.txPublicKeys, [crypto.secretKeyToPublicKey(created.txKeys.txSecretKey)]);
          assert.equal(created.txKeys.additionalTxSecretKeys.length, 3);
          const ordered = shuffleOutputs ? [outputs[0], outputs[2], outputs[1]] : outputs;
          ordered.forEach((owner, i) => {
            const secret = created.txKeys.additionalTxSecretKeys[i];
            assert.equal(typeof secret, 'bigint');
            const expected = owner.type === 'subaddress'
              ? crypto.encodePoint(crypto.decodePoint(owner.publicSpendKey).multiplyUnsafe(secret))
              : crypto.secretKeyToPublicKey(secret);
            assert.deepStrictEqual(extra.additionalTxPublicKeys[i], expected);
            const publicKey = owner.type === 'subaddress' ? expected : extra.txPublicKeys[0];
            const derivation = crypto.generateKeyDerivation(publicKey, owner.secretView);
            assert.deepStrictEqual(crypto.derivePublicKey(derivation, i, owner.publicSpendKey), decoded.prefix.vout[i].target.data.key);
            assert.equal(crypto.deriveViewTag(derivation, i)[0], decoded.prefix.vout[i].target.data.viewTag);
            assert.equal(ringct.decodeRct(decoded.rctSigBase.ecdhInfo[i], decoded.rctSigBase.outPk[i], 6, i, derivation).amount, owner.amount);
          });
          const {
            bulletproofsPlus, CLSAGs, pseudoOuts,
          } = decoded.rctSigPrunable;
          assert.ok(bulletproofs.verifyBulletproofPlus(decoded.rctSigBase.outPk, bulletproofsPlus[0]));
          const message = tx.getPreMlsagHash(crypto.fastHash(raw.txPrefix.encode(decoded.prefix)), decoded.rctSigBase, bulletproofsPlus[0]);
          assert.ok(clsag.verifyClsag(message, sortedRing(input), pseudoOuts[0], { ...CLSAGs[0], I: decoded.prefix.vin[0].data.keyImage }));
        });
      }
    }

    it('requires one additional key for every mixed output, including change or dummy', () => {
      const sender = stdWallet();
      const sub = stdWallet();
      sub.type = 'subaddress';
      sub.publicViewKey = crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiplyUnsafe(sub.secretView));
      for (const amount of [0n, 5n]) {
        const params = {
          inputs: [makeInput(40n, 2)],
          outputs: [{ ...stdWallet(), amount: 10n }, { ...sub, amount: 20n }, {
            ...sender, isChange: true, amount,
          }],
          secretSpendKey: 0n,
          secretViewKey: sender.secretView,
        };
        for (const additionalTxSecretKeys of [[], [11n, 13n], [11n, 13n, 17n, 19n]]) {
          assert.throws(() => tx.prepareTransaction({ ...params, txKeys: { additionalTxSecretKeys } }), {
            message: `generateOutputs: additionalTxSecretKeys: expected 3, got ${additionalTxSecretKeys.length}`,
          });
        }
        const result = tx.prepareTransaction({ ...params, txKeys: { additionalTxSecretKeys: [11n, 13n, 17n] } });
        assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, [11n, 13n, 17n]);
        assert.equal(tx.parseTxExtra(result.transaction.prefix.extra).additionalTxPublicKeys.length, 3);
      }
    });

    it('shuffles the outputs by default (shuffle_outs), keeps the caller order with shuffleOutputs: false', () => {
      const inputs = [makeInput(5000000n, 2)];
      const sender = stdWallet();
      const first = stdWallet();
      const second = stdWallet();
      const outputs = [
        { ...first, amount: 1000000n },
        { ...second, amount: 2000000n },
        {
          ...sender, isChange: true, amount: 1000000n,
        },
      ];
      // the wallet whose keys reproduce the one-time key at vout[index]
      const ownerOf = (decoded, index) => [first, second, sender].find((w) => {
        const [txPublicKey] = tx.parseTxExtra(decoded.prefix.extra).txPublicKeys;
        const derivation = crypto.generateKeyDerivation(txPublicKey, w.secretView);
        return bytesToHex(crypto.derivePublicKey(derivation, index, w.publicSpendKey)) === bytesToHex(decoded.prefix.vout[index].target.data.key);
      });
      const build = (shuffleOutputs) => {
        // constant random bytes make Fisher-Yates deterministic: j = 0x01010101 % (i + 1) is 1 for
        // i = 2 and for i = 1, so [first, second, sender] becomes [first, sender, second]
        crypto.__mockRandomBytes__((length) => new Uint8Array(length).fill(1));
        try {
          return raw.fullTransaction.decode(tx.createTransaction({
            inputs, outputs, secretSpendKey: 0n, secretViewKey: sender.secretView, shuffleOutputs,
          }).bytes);
        } finally {
          crypto.__mockRandomBytes__(randomBytes);
        }
      };
      const shuffled = build(true);
      assert.deepStrictEqual([0, 1, 2].map((i) => ownerOf(shuffled, i)), [first, sender, second]);
      const ordered = build(false);
      assert.deepStrictEqual([0, 1, 2].map((i) => ownerOf(ordered, i)), [first, second, sender]);
    });

    it('rejects empty inputs', () => {
      assert.throws(() => tx.createTransaction({
        inputs: [],
        outputs: [{ ...stdWallet(), amount: 1n }],
      }), /empty inputs/);
    });

    it('rejects invalid number of outputs', () => {
      assert.throws(() => tx.createTransaction({
        inputs: [makeInput(0n)],
        outputs: [],
      }), /at least two outputs/);
      // monero requires at least two outputs; a single-output tx is rejected on-chain
      assert.throws(() => tx.createTransaction({
        inputs: [makeInput(0n)],
        outputs: [{ ...stdWallet(), amount: 0n }],
      }), /at least two outputs/);
      assert.throws(() => tx.createTransaction({
        inputs: [makeInput(0n)],
        outputs: Array.from({ length: 17 }, () => ({ ...stdWallet(), amount: 0n })),
      }), /too many outputs/);
    });

    it('rejects non-uint64 amounts, unlock time and offsets, and outputs exceeding inputs', () => {
      const input = makeInput(10n);
      const output = { ...stdWallet(), amount: 9n };
      // a second (change) output so these reach the intended errors past the >=2 outputs guard
      const change = {
        ...stdWallet(), isChange: true, amount: 0n,
      };
      assert.throws(() => tx.createTransaction({ inputs: [{ ...input, amount: -1n }], outputs: [output, change] }), /uint64 bigint/);
      assert.throws(() => tx.createTransaction({ inputs: [input], outputs: [{ ...output, amount: 2n ** 64n }, change] }), /uint64 bigint/);
      assert.throws(() => tx.createTransaction({ inputs: [input], outputs: [{ ...output, amount: 100n }, change] }), /outputs exceed inputs/);
      assert.throws(() => tx.createTransaction({
        inputs: [input], outputs: [output, change], unlockTime: 2n ** 64n,
      }), /uint64 bigint/);
      input.decoys[0].globalIndex = -1n;
      assert.throws(() => tx.createTransaction({ inputs: [input], outputs: [output, change] }), /uint64 bigint/);
    });

    it('allows an integrated address alongside other recipients; the id goes to the integrated one', () => {
      const inputs = [makeInput(5010000n)];
      const integrated = stdWallet();
      const other = stdWallet();
      const paymentId = randomBytes(8);
      const outputs = [
        {
          ...integrated, type: 'integratedaddress', paymentID: paymentId, amount: 2000000n,
        },
        { ...other, amount: 3000000n },
      ];
      const { bytes } = tx.createTransaction({
        inputs, outputs, secretSpendKey: 0n,
      });
      const { encryptedPaymentId, txPublicKeys: [txPublicKey] } = tx.parseTxExtra(raw.fullTransaction.decode(bytes).prefix.extra);
      assert.equal(encryptedPaymentId.length, 8);
      // the integrated recipient recovers its id; the other recipient is unaffected
      assert.deepStrictEqual(tx.encryptPaymentId(encryptedPaymentId, txPublicKey, integrated.secretView), paymentId);
    });

    it('rejects more than one address with a payment id', () => {
      const inputs = [makeInput(5010000n)];
      const outputs = [
        {
          ...stdWallet(), type: 'integratedaddress', paymentID: randomBytes(8), amount: 2000000n,
        },
        {
          ...stdWallet(), type: 'integratedaddress', paymentID: randomBytes(8), amount: 3000000n,
        },
      ];
      assert.throws(() => tx.createTransaction({ inputs, outputs }), /multiple addresses with payment ids/);
    });

    it('encrypts the integrated payment id with the supplied main key', () => {
      const inputs = [makeInput(5010000n)];
      const recipient = stdWallet();
      const sender = stdWallet();
      const paymentId = randomBytes(8);
      const outputs = [
        {
          ...recipient, type: 'integratedaddress', paymentID: paymentId, amount: 4000000n,
        },
        {
          ...sender, isChange: true, amount: 1000000n,
        },
      ];
      const { bytes, txKeys } = tx.createTransaction({
        inputs, outputs, secretSpendKey: 0n, secretViewKey: sender.secretView, txKeys: { txSecretKey: 17n },
      });
      const { encryptedPaymentId, txPublicKeys: [txPublicKey] } = tx.parseTxExtra(raw.fullTransaction.decode(bytes).prefix.extra);
      assert.equal(txKeys.txSecretKey, 17n);
      assert.deepStrictEqual(txPublicKey, crypto.secretKeyToPublicKey(17n));
      assert.equal(encryptedPaymentId.length, 8);
      // the recipient recovers it with the tx pub key and its own view secret
      assert.deepStrictEqual(tx.encryptPaymentId(encryptedPaymentId, txPublicKey, recipient.secretView), paymentId);
    });
  });

  describe('globalIndexesFromOutputOffsets', () => {
    it('reconstructs absolute indexes with uint64 wraparound (unsorted ring)', () => {
      const mask = (1n << 64n) - 1n;
      // a "negative" relative delta stored as 2^64 - 30 lowers the next index by 30
      assert.deepStrictEqual(tx.globalIndexesFromOutputOffsets([100n, mask - 29n]), [100n, 70n]);
    });
  });

  describe('getPreMlsagHash', () => {
    // https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/src/tests/vectors/transactions.json#L99-L101
    // type 6 marker: #L150-L151
    it('matches monero-oxide type 6 tx', () => {
      txFixtures.filter((fixture) => fixture.signatureHash).forEach((fixture) => {
        const decoded = raw.fullTransaction.decode(hexToBytes(fixture.hex));
        const actual = tx.getPreMlsagHash(
          crypto.fastHash(raw.txPrefix.encode(decoded.prefix)),
          decoded.rctSigBase,
          decoded.rctSigPrunable.bulletproofsPlus[0]
        );
        assert.strictEqual(bytesToHex(actual), fixture.signatureHash);
      });
    });
  });

  describe('getTxId', () => {
    it('should work', () => {
      txFixtures.forEach((fixture) => {
        const actual = tx.getTxId(hexToBytes(fixture.hex));
        assert.strictEqual(bytesToHex(actual), fixture.id);
      });
    });
  });

  describe('estimateExtraSize', () => {
    const stdWallet = () => {
      const secretView = crypto.randomScalar();
      const secretSpend = crypto.randomScalar();
      return {
        secretView,
        publicSpendKey: crypto.secretKeyToPublicKey(secretSpend),
        publicViewKey: crypto.secretKeyToPublicKey(secretView),
        type: 'address',
      };
    };
    const subWallet = () => {
      const secretView = crypto.randomScalar();
      const publicSpendKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      return {
        secretView,
        publicSpendKey,
        publicViewKey: crypto.encodePoint(crypto.decodePoint(publicSpendKey).multiplyUnsafe(secretView)),
        type: 'subaddress',
      };
    };
    const makeInput = (amount) => {
      const keyOffset = crypto.randomScalar();
      const mask = crypto.randomScalar();
      return {
        keyOffset, publicKey: crypto.secretKeyToPublicKey(keyOffset), amount, mask, commitment: ringct.pedersenCommitment(amount, mask), globalIndex: 1n, decoys: [],
      };
    };

    // builds a real transaction for the full `outputs` list and returns the actual encoded
    // tx_extra length, to cross-check estimateExtraSize against buildTxExtra.
    function actualExtraSize(outputs) {
      const sender = outputs.find((o) => o.isChange) ?? stdWallet();
      const inputs = [makeInput(1000000n)];
      const { bytes } = tx.createTransaction({
        inputs, outputs, secretSpendKey: 0n, secretViewKey: sender.secretView,
      });
      return raw.fullTransaction.decode(bytes).prefix.extra.length;
    }

    it('single standard destination + change: no additional keys, short nonce', () => {
      const outputs = [{ ...stdWallet(), amount: 500000n }, {
        ...stdWallet(), isChange: true, amount: 0n,
      }];
      const size = tx.estimateExtraSize(outputs);
      assert.strictEqual(size, 44);
      assert.strictEqual(size, actualExtraSize(outputs));
    });

    it('single subaddress destination + change: R = r*D, no additional keys', () => {
      const outputs = [{ ...subWallet(), amount: 500000n }, {
        ...stdWallet(), isChange: true, amount: 0n,
      }];
      const size = tx.estimateExtraSize(outputs);
      assert.strictEqual(size, 44);
      assert.strictEqual(size, actualExtraSize(outputs));
    });

    it('standard + subaddress destinations: needs additional keys', () => {
      const outputs = [
        { ...stdWallet(), amount: 300000n },
        { ...subWallet(), amount: 200000n },
        {
          ...stdWallet(), isChange: true, amount: 0n,
        },
      ];
      const size = tx.estimateExtraSize(outputs);
      assert.strictEqual(size, 131); // 33 + (2 + 32*3) additional pubkeys, no nonce (3 outputs)
      assert.strictEqual(size, actualExtraSize(outputs));
    });

    it('two standard destinations, no change: two outputs, dummy nonce', () => {
      const outputs = [
        { ...stdWallet(), amount: 300000n },
        { ...stdWallet(), amount: 200000n },
      ];
      const size = tx.estimateExtraSize(outputs);
      assert.strictEqual(size, 44); // 33 + dummy payment id nonce (<= 2 outputs)
      assert.strictEqual(size, actualExtraSize(outputs));
    });

    it('integrated address destination: always includes the nonce', () => {
      const outputs = [
        {
          ...stdWallet(), type: 'integratedaddress', paymentID: randomBytes(8), amount: 500000n,
        },
        {
          ...stdWallet(), isChange: true, amount: 0n,
        },
      ];
      const size = tx.estimateExtraSize(outputs);
      assert.strictEqual(size, 44);
      assert.strictEqual(size, actualExtraSize(outputs));
    });
  });

  describe('estimate tx size', () => {
    it('should estimate tx size with 1 in 2 out', () => {
      const size = tx.estimateTxSize(1, 10, 2, 44);
      assert.strictEqual(size, 1366);
    });

    it('should estimate tx size with 2 in 2 out', () => {
      const size = tx.estimateTxSize(2, 10, 2, 44);
      assert.strictEqual(size, 1875);
    });

    it('should estimate tx size with 3 in 3 out', () => {
      const size = tx.estimateTxSize(3, 10, 3, 44);
      assert.strictEqual(size, 2527);
    });

    it('should estimate tx size with 1 in 2 out (bulletproof & clsag)', () => {
      const size = tx.estimateTxSize(1, 10, 2, 44, true, true, false, false);
      assert.strictEqual(size, 1460);
    });

    it('should estimate tx size with 2 in 2 out (bulletproof & clsag)', () => {
      const size = tx.estimateTxSize(2, 10, 2, 44, true, true, false, false);
      assert.strictEqual(size, 1969);
    });

    it('should estimate tx size with 3 in 3 out (bulletproof & clsag)', () => {
      const size = tx.estimateTxSize(3, 10, 3, 44, true, true, false, false);
      assert.strictEqual(size, 2620);
    });
  });

  describe('estimate tx weight', () => {
    it('should estimate tx weight with 1 in 2 out', () => {
      const weight = tx.estimateTxWeight(1, 10, 2, 44);
      assert.strictEqual(weight, 1366);
    });

    it('should estimate tx weight with 2 in 2 out', () => {
      const weight = tx.estimateTxWeight(2, 10, 2, 44);
      assert.strictEqual(weight, 1875);
    });

    it('should estimate tx weight with 3 in 3 out', () => {
      const weight = tx.estimateTxWeight(3, 10, 3, 44);
      assert.strictEqual(weight, 2987);
    });

    it('should estimate tx weight with 1 in 2 out (bulletproof & clsag)', () => {
      const weight = tx.estimateTxWeight(1, 10, 2, 44, true, true, false, false);
      assert.strictEqual(weight, 1460);
    });

    it('should estimate tx weight with 2 in 2 out (bulletproof & clsag)', () => {
      const weight = tx.estimateTxWeight(2, 10, 2, 44, true, true, false, false);
      assert.strictEqual(weight, 1969);
    });

    it('should estimate tx weight with 3 in 3 out (bulletproof & clsag)', () => {
      const weight = tx.estimateTxWeight(3, 10, 3, 44, true, true, false, false);
      assert.strictEqual(weight, 3157);
    });
  });

  describe('estimate tx fee', () => {
    it('should estimate tx fee with 1 in 2 out', () => {
      const fee = tx.estimateFee(1, 15, 2, 44, 6836n, 1n, 10000n);
      assert.strictEqual(fee, 10510000n);
    });

    it('should estimate tx fee with 2 in 2 out', () => {
      const fee = tx.estimateFee(2, 15, 2, 44, 6836n, 1n, 10000n);
      assert.strictEqual(fee, 15150000n);
    });

    it('should estimate tx fee with 3 in 3 out', () => {
      const fee = tx.estimateFee(3, 15, 3, 44, 6836n, 1n, 10000n);
      assert.strictEqual(fee, 23910000n);
    });

    it('should estimate tx fee with 1 in 2 out (bulletproof & clsag)', () => {
      const fee = tx.estimateFee(1, 15, 2, 44, 6836n, 1n, 10000n, true, true, false, false);
      assert.strictEqual(fee, 11150000n);
    });

    it('should estimate tx fee with 2 in 2 out (bulletproof & clsag)', () => {
      const fee = tx.estimateFee(2, 15, 2, 44, 6836n, 1n, 10000n, true, true, false, false);
      assert.strictEqual(fee, 15790000n);
    });

    it('should estimate tx fee with 3 in 3 out (bulletproof & clsag)', () => {
      const fee = tx.estimateFee(3, 15, 3, 44, 6836n, 1n, 10000n, true, true, false, false);
      assert.strictEqual(fee, 25070000n);
    });
  });

});
