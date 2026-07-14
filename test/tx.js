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

    const NIL = new Uint8Array(0);
    const NIL_TX_PUB_KEY = new Uint8Array(32);
    const TX_EXTRA_PADDING_MAX_COUNT = 255;
    const empty = {
      txPublicKey: NIL_TX_PUB_KEY,
      encryptedPaymentId: NIL,
      additionalPublicKeys: [],
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
        txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPublicKeys: [],
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
        txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPublicKeys: [],
      });
    });

    it('should handle two pub keys', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, {
        txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPublicKeys: [],
      });
    });

    it('should keep the first txPublicKey even if it is all zeroes', () => {
      const result = tx.parseTxExtra(Uint8Array.from([
        1, ...new Uint8Array(32),
        1, ...new Uint8Array(32).fill(1),
      ]));
      assert.deepStrictEqual(result, {
        txPublicKey: NIL_TX_PUB_KEY, encryptedPaymentId: NIL, additionalPublicKeys: [],
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
        txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBytes('0000000000000000'), additionalPublicKeys: [],
      });
    });

    it('should handle pub key with encrypted payment id (reverse order)', () => {
      const result = tx.parseTxExtra(Uint8Array.from([2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, {
        txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBytes('0000000000000000'), additionalPublicKeys: [],
      });
    });

    it('should additional pub keys', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 59, 54, 37, 207, 182, 88, 66, 252, 62, 68, 82, 69, 144, 143, 155, 23, 27, 78, 24, 153, 84, 63, 183, 13, 133, 66, 79, 217, 177, 201, 94, 185,
        4, 3, 252, 23, 118, 225, 66, 173, 231, 164, 173, 94, 0, 189, 39, 164, 128, 1, 63, 6, 196, 93, 90, 200, 8, 7, 211, 96, 149, 0, 189, 210, 108, 242, 152, 112, 95, 250, 198, 110, 246, 61, 103,
        203, 88, 114, 182, 252, 34, 40, 121, 144, 46, 219, 231, 163, 204, 184, 50, 120, 200, 42, 95, 173, 9, 124, 207, 193, 216, 157, 94, 95, 186, 83, 166, 138, 35, 130, 57, 235, 213, 246, 13, 96,
        50, 125, 34, 218, 62, 233, 90, 156, 7, 6, 116, 234, 82, 90]));
      assert.deepStrictEqual(result, {
        txPublicKey: hexToBytes('3b3625cfb65842fc3e445245908f9b171b4e1899543fb70d85424fd9b1c95eb9'),
        encryptedPaymentId: NIL,
        additionalPublicKeys: [
          hexToBytes('fc1776e142ade7a4ad5e00bd27a480013f06c45d5ac80807d3609500bdd26cf2'),
          hexToBytes('98705ffac66ef63d67cb5872b6fc222879902edbe7a3ccb83278c82a5fad097c'),
          hexToBytes('cfc1d89d5e5fba53a68a238239ebd5f60d60327d22da3ee95a9c070674ea525a'),
        ],
      });
    });
  });

  describe('buildTxExtra', () => {
    it('builds and round-trips through parseTxExtra', () => {
      const txPublicKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      const additionalPublicKeys = [crypto.secretKeyToPublicKey(crypto.randomScalar()), crypto.secretKeyToPublicKey(crypto.randomScalar())];
      const encryptedPaymentId = randomBytes(8);
      const parsed = tx.parseTxExtra(tx.buildTxExtra({
        txPublicKey, additionalPublicKeys, encryptedPaymentId,
      }));
      assert.deepStrictEqual(parsed.txPublicKey, txPublicKey);
      assert.deepStrictEqual(parsed.additionalPublicKeys, additionalPublicKeys);
      assert.deepStrictEqual(parsed.encryptedPaymentId, encryptedPaymentId);
    });

    it('omits optional fields when not given', () => {
      const txPublicKey = crypto.secretKeyToPublicKey(crypto.randomScalar());
      const parsed = tx.parseTxExtra(tx.buildTxExtra({ txPublicKey }));
      assert.deepStrictEqual(parsed.txPublicKey, txPublicKey);
      assert.deepStrictEqual(parsed.additionalPublicKeys, []);
      assert.deepStrictEqual(parsed.encryptedPaymentId, new Uint8Array(0));
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
      return [out.txPublicKey, ...out.additionalPublicKeys].some((R) => {
        const derivation = crypto.generateKeyDerivation(R, w.secretView);
        return bytesToHex(crypto.derivePublicKey(derivation, i, w.publicSpendKey)) === bytesToHex(key)
          && crypto.deriveViewTag(derivation, i)[0] === viewTag;
      });
    };

    it('standard recipients are detectable (R = r*G, no additional keys)', () => {
      const a = stdWallet();
      const b = stdWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([a, b], r);
      assert.equal(out.additionalPublicKeys.length, 0);
      assert.ok(recipientFinds(out, 0, a));
      assert.ok(recipientFinds(out, 1, b));
    });

    it('standard + subaddress uses additional keys', () => {
      const a = stdWallet();
      const s = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([a, s], r);
      assert.equal(out.additionalPublicKeys.length, 2);
      assert.ok(recipientFinds(out, 0, a));
      assert.ok(recipientFinds(out, 1, s));
    });

    it('single subaddress sets R = r*D, no additional keys', () => {
      const s = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([s], r);
      assert.equal(out.additionalPublicKeys.length, 0);
      assert.deepStrictEqual(out.txPublicKey, crypto.encodePoint(crypto.decodePoint(s.publicSpendKey).multiplyUnsafe(r)));
      assert.ok(recipientFinds(out, 0, s));
    });

    it('two distinct subaddresses use additional keys (R = r*G)', () => {
      const s1 = subWallet();
      const s2 = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([s1, s2], r);
      assert.equal(out.additionalPublicKeys.length, 2);
      assert.deepStrictEqual(out.txPublicKey, crypto.secretKeyToPublicKey(r));
      assert.ok(recipientFinds(out, 0, s1));
      assert.ok(recipientFinds(out, 1, s2));
    });

    it('duplicate subaddress is deduped: R = r*D, no additional keys', () => {
      const s = subWallet();
      const r = crypto.randomScalar();
      const out = tx.generateOutputs([s, s], r);
      assert.equal(out.additionalPublicKeys.length, 0);
      assert.deepStrictEqual(out.txPublicKey, crypto.encodePoint(crypto.decodePoint(s.publicSpendKey).multiplyUnsafe(r)));
      assert.ok(recipientFinds(out, 0, s));
      assert.ok(recipientFinds(out, 1, s));
    });

    it('change derives from a*R and stays detectable (single subaddress + change)', () => {
      const s = subWallet();
      const sender = stdWallet();
      const r = crypto.randomScalar();
      const change = { ...sender, isChange: true };
      const out = tx.generateOutputs([s, change], r, sender.secretView);
      assert.ok(recipientFinds(out, 0, s));
      assert.ok(recipientFinds(out, 1, sender));
    });
  });

  describe('createTransaction', () => {
    // a fake owned output: one-time secret key, amount, mask, and a ring of decoys + the real one
    const makeInput = (amount, ringSize = 11) => {
      const secretKey = crypto.randomScalar();
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
        secretKey, amount, mask, commitment, globalIndex: 9999n, decoys,
      };
    };
    // reconstruct the sorted ring createTransaction builds internally, as clsag ring members
    const sortedRing = (input) => {
      const real = {
        publicKey: crypto.secretKeyToPublicKey(input.secretKey),
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
      const bytes = tx.createTransaction({
        inputs, outputs, secretViewKey: sender.secretView,
      });

      // serialization round-trips
      const decoded = raw.transaction.decode(bytes);
      assert.equal(bytesToHex(raw.transaction.encode(decoded)), bytesToHex(bytes));
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
        const ki = bytesToHex(crypto.generateKeyImage(crypto.secretKeyToPublicKey(input.secretKey), input.secretKey));
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
      const { txPublicKey } = tx.parseTxExtra(decoded.prefix.extra);
      const derivation = crypto.generateKeyDerivation(txPublicKey, recipient.secretView);
      const ecdh = ringct.decodeRct(decoded.rctSigBase.ecdhInfo[0], outPk[0], 6, 0, derivation);
      assert.equal(ecdh.amount, 4000000n);
    });

    it('prepareTransaction returns the tx object, createTransaction returns its bytes', () => {
      const inputs = [makeInput(5010000n)];
      const sender = stdWallet();
      const outputs = [
        { ...stdWallet(), amount: 4000000n },
        {
          ...sender, isChange: true, amount: 1000000n,
        },
      ];
      const params = {
        inputs, outputs, secretViewKey: sender.secretView,
      };
      const prepared = tx.prepareTransaction(params);
      assert.ok(prepared.prefix && prepared.rctSigBase && prepared.rctSigPrunable);
      const bytes = tx.createTransaction(params);
      assert.ok(bytes instanceof Uint8Array);
      assert.equal(raw.transaction.decode(bytes).prefix.vin.length, 1);
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
      }), /invalid number of outputs/);
      assert.throws(() => tx.createTransaction({
        inputs: [makeInput(0n)],
        outputs: Array.from({ length: 17 }, () => ({ ...stdWallet(), amount: 0n })),
      }), /invalid number of outputs/);
    });

    it('rejects non-uint64 amounts, unlock time and offsets, and outputs exceeding inputs', () => {
      const input = makeInput(10n);
      const output = { ...stdWallet(), amount: 9n };
      assert.throws(() => tx.createTransaction({ inputs: [{ ...input, amount: -1n }], outputs: [output] }), /uint64 bigint/);
      assert.throws(() => tx.createTransaction({ inputs: [input], outputs: [{ ...output, amount: 2n ** 64n }] }), /uint64 bigint/);
      assert.throws(() => tx.createTransaction({ inputs: [input], outputs: [{ ...output, amount: 100n }] }), /outputs exceed inputs/);
      assert.throws(() => tx.createTransaction({
        inputs: [input], outputs: [output], unlockTime: 2n ** 64n,
      }), /uint64 bigint/);
      input.decoys[0].globalIndex = -1n;
      assert.throws(() => tx.createTransaction({ inputs: [input], outputs: [output] }), /uint64 bigint/);
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
      const bytes = tx.createTransaction({ inputs, outputs });
      const { encryptedPaymentId, txPublicKey } = tx.parseTxExtra(raw.transaction.decode(bytes).prefix.extra);
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

    it('embeds the payment id of an integrated-address recipient', () => {
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
      const bytes = tx.createTransaction({
        inputs, outputs, secretViewKey: sender.secretView,
      });
      const { encryptedPaymentId, txPublicKey } = tx.parseTxExtra(raw.transaction.decode(bytes).prefix.extra);
      assert.equal(encryptedPaymentId.length, 8);
      // the recipient recovers it with the tx pub key and its own view secret
      assert.deepStrictEqual(tx.encryptPaymentId(encryptedPaymentId, txPublicKey, recipient.secretView), paymentId);
    });
  });

  describe('globalIndexesFromKeyOffsets', () => {
    it('reconstructs absolute indexes with uint64 wraparound (unsorted ring)', () => {
      const mask = (1n << 64n) - 1n;
      // a "negative" relative delta stored as 2^64 - 30 lowers the next index by 30
      assert.deepStrictEqual(tx.globalIndexesFromKeyOffsets([100n, mask - 29n]), [100n, 70n]);
    });
  });

  describe('getPreMlsagHash', () => {
    // https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/src/tests/vectors/transactions.json#L99-L101
    // type 6 marker: #L150-L151
    it('matches monero-oxide type 6 tx', () => {
      txFixtures.filter((fixture) => fixture.signatureHash).forEach((fixture) => {
        const decoded = raw.transaction.decode(hexToBytes(fixture.hex));
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
      const fee = tx.estimateFee(1, 15, 2, 44, 6836, 1, 10000);
      assert.strictEqual(fee, '10510000');
    });

    it('should estimate tx fee with 2 in 2 out', () => {
      const fee = tx.estimateFee(2, 15, 2, 44, 6836, 1, 10000);
      assert.strictEqual(fee, '15150000');
    });

    it('should estimate tx fee with 3 in 3 out', () => {
      const fee = tx.estimateFee(3, 15, 3, 44, 6836, 1, 10000);
      assert.strictEqual(fee, '23910000');
    });

    it('should estimate tx fee with 1 in 2 out (bulletproof & clsag)', () => {
      const fee = tx.estimateFee(1, 15, 2, 44, 6836, 1, 10000, true, true, false, false);
      assert.strictEqual(fee, '11150000');
    });

    it('should estimate tx fee with 2 in 2 out (bulletproof & clsag)', () => {
      const fee = tx.estimateFee(2, 15, 2, 44, 6836, 1, 10000, true, true, false, false);
      assert.strictEqual(fee, '15790000');
    });

    it('should estimate tx fee with 3 in 3 out (bulletproof & clsag)', () => {
      const fee = tx.estimateFee(3, 15, 3, 44, 6836, 1, 10000, true, true, false, false);
      assert.strictEqual(fee, '25070000');
    });
  });

});
