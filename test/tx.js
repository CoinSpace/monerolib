/* eslint-disable max-len */
import { H } from '../lib/crypto-util-data.js';
import assert from 'node:assert';
import tx from '../lib/tx.js';
import { verifyBulletproofPlus } from '../lib/bulletproofs.js';
import { verifyClsag } from '../lib/clsag.js';
import {
  Point,
  decodePoint,
  derivePublicKey,
  deriveViewTag,
  encodePoint,
  fastHash,
  generateKeyDerivation,
  generateKeyImage,
  randomScalar,
  secretKeyToPublicKey,
} from '../lib/crypto-util.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { decodeRct, pedersenCommitment } from '../lib/ringct.js';
import { describe, it } from 'node:test';
import { transaction, txPrefix } from '../lib/raw.js';

import txFixtures from './fixtures/txs.json' with { type: 'json' };

describe('tx', () => {

  describe('parseTxExtra', () => {

    const NIL = new Uint8Array(0);
    const NIL_TX_PUB_KEY = new Uint8Array(32);
    const TX_EXTRA_PADDING_MAX_COUNT = 255;
    const empty = { txPublicKey: NIL_TX_PUB_KEY, encryptedPaymentId: NIL, additionalPublicKeys: [] };

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
      assert.deepStrictEqual(result, { txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPublicKeys: [] });
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
      assert.deepStrictEqual(result, { txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPublicKeys: [] });
    });

    it('should handle two pub keys', () => {
      const result = tx.parseTxExtra(Uint8Array.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPublicKeys: [] });
    });

    it('should keep the first txPublicKey even if it is all zeroes', () => {
      const result = tx.parseTxExtra(Uint8Array.from([
        1, ...new Uint8Array(32),
        1, ...new Uint8Array(32).fill(1),
      ]));
      assert.deepStrictEqual(result, { txPublicKey: NIL_TX_PUB_KEY, encryptedPaymentId: NIL, additionalPublicKeys: [] });
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
      assert.deepStrictEqual(result, { txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBytes('0000000000000000'), additionalPublicKeys: [] });
    });

    it('should handle pub key with encrypted payment id (reverse order)', () => {
      const result = tx.parseTxExtra(Uint8Array.from([2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPublicKey: hexToBytes('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBytes('0000000000000000'), additionalPublicKeys: [] });
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
      const txPublicKey = secretKeyToPublicKey(randomScalar());
      const additionalPublicKeys = [secretKeyToPublicKey(randomScalar()), secretKeyToPublicKey(randomScalar())];
      const encryptedPaymentId = randomBytes(8);
      const parsed = tx.parseTxExtra(tx.buildTxExtra({ txPublicKey, additionalPublicKeys, encryptedPaymentId }));
      assert.deepStrictEqual(parsed.txPublicKey, txPublicKey);
      assert.deepStrictEqual(parsed.additionalPublicKeys, additionalPublicKeys);
      assert.deepStrictEqual(parsed.encryptedPaymentId, encryptedPaymentId);
    });

    it('omits optional fields when not given', () => {
      const txPublicKey = secretKeyToPublicKey(randomScalar());
      const parsed = tx.parseTxExtra(tx.buildTxExtra({ txPublicKey }));
      assert.deepStrictEqual(parsed.txPublicKey, txPublicKey);
      assert.deepStrictEqual(parsed.additionalPublicKeys, []);
      assert.deepStrictEqual(parsed.encryptedPaymentId, new Uint8Array(0));
    });
  });

  describe('encryptPaymentId', () => {
    it('encrypts and decrypts symmetrically', () => {
      const txSecretKey = randomScalar();
      const viewSecretKey = randomScalar();
      const viewPublicKey = secretKeyToPublicKey(viewSecretKey);
      const txPublicKey = secretKeyToPublicKey(txSecretKey);
      const paymentId = randomBytes(8);
      const encrypted = tx.encryptPaymentId(paymentId, viewPublicKey, txSecretKey);
      assert.notDeepStrictEqual(encrypted, paymentId);
      // the recipient recovers it with the tx public key and its own view secret
      assert.deepStrictEqual(tx.encryptPaymentId(encrypted, txPublicKey, viewSecretKey), paymentId);
    });
  });

  describe('generateOutputs', () => {
    // a standard wallet: random view/spend secrets, public keys s*G
    const stdWallet = () => {
      const viewSecret = randomScalar();
      const spendSecret = randomScalar();
      return {
        viewSecret,
        spendPublicKey: secretKeyToPublicKey(spendSecret),
        viewPublicKey: secretKeyToPublicKey(viewSecret),
        isSubaddress: false,
      };
    };
    // a subaddress wallet: spend key D is any point, view key C = a*D
    const subWallet = () => {
      const viewSecret = randomScalar();
      const spendPublicKey = secretKeyToPublicKey(randomScalar());
      return {
        viewSecret,
        spendPublicKey,
        viewPublicKey: encodePoint(decodePoint(spendPublicKey).multiplyUnsafe(viewSecret)),
        isSubaddress: true,
      };
    };
    // scan output i as its recipient would: try the tx pub key and each additional pub key
    const recipientFinds = (out, i, w) => {
      const { key, viewTag } = out.vout[i].target.data;
      return [out.txPublicKey, ...out.additionalPublicKeys].some((R) => {
        const derivation = generateKeyDerivation(R, w.viewSecret);
        return bytesToHex(derivePublicKey(derivation, i, w.spendPublicKey)) === bytesToHex(key)
          && deriveViewTag(derivation, i)[0] === viewTag;
      });
    };

    it('standard recipients are detectable (R = r*G, no additional keys)', () => {
      const a = stdWallet();
      const b = stdWallet();
      const r = randomScalar();
      const out = tx.generateOutputs([a, b], r);
      assert.equal(out.additionalPublicKeys.length, 0);
      assert.ok(recipientFinds(out, 0, a));
      assert.ok(recipientFinds(out, 1, b));
    });

    it('standard + subaddress uses additional keys', () => {
      const a = stdWallet();
      const s = subWallet();
      const r = randomScalar();
      const out = tx.generateOutputs([a, s], r);
      assert.equal(out.additionalPublicKeys.length, 2);
      assert.ok(recipientFinds(out, 0, a));
      assert.ok(recipientFinds(out, 1, s));
    });

    it('single subaddress sets R = r*D, no additional keys', () => {
      const s = subWallet();
      const r = randomScalar();
      const out = tx.generateOutputs([s], r);
      assert.equal(out.additionalPublicKeys.length, 0);
      assert.deepStrictEqual(out.txPublicKey, encodePoint(decodePoint(s.spendPublicKey).multiplyUnsafe(r)));
      assert.ok(recipientFinds(out, 0, s));
    });

    it('two distinct subaddresses use additional keys (R = r*G)', () => {
      const s1 = subWallet();
      const s2 = subWallet();
      const r = randomScalar();
      const out = tx.generateOutputs([s1, s2], r);
      assert.equal(out.additionalPublicKeys.length, 2);
      assert.deepStrictEqual(out.txPublicKey, secretKeyToPublicKey(r));
      assert.ok(recipientFinds(out, 0, s1));
      assert.ok(recipientFinds(out, 1, s2));
    });

    it('duplicate subaddress is deduped: R = r*D, no additional keys', () => {
      const s = subWallet();
      const r = randomScalar();
      const out = tx.generateOutputs([s, s], r);
      assert.equal(out.additionalPublicKeys.length, 0);
      assert.deepStrictEqual(out.txPublicKey, encodePoint(decodePoint(s.spendPublicKey).multiplyUnsafe(r)));
      assert.ok(recipientFinds(out, 0, s));
      assert.ok(recipientFinds(out, 1, s));
    });

    it('change derives from a*R and stays detectable (single subaddress + change)', () => {
      const s = subWallet();
      const sender = stdWallet();
      const r = randomScalar();
      const change = { ...sender, isChange: true };
      const out = tx.generateOutputs([s, change], r, sender.viewSecret);
      assert.ok(recipientFinds(out, 0, s));
      assert.ok(recipientFinds(out, 1, sender));
    });
  });

  describe('createTransaction', () => {
    // a fake owned output: one-time secret key, amount, mask, and a ring of decoys + the real one
    const makeInput = (amount, ringSize = 11) => {
      const secretKey = randomScalar();
      const publicKey = secretKeyToPublicKey(secretKey);
      const mask = randomScalar();
      const commitment = pedersenCommitment(amount, mask);
      const ring = [];
      for (let j = 0; j < ringSize - 1; j++) {
        ring.push({
          publicKey: secretKeyToPublicKey(randomScalar()),
          commitment: secretKeyToPublicKey(randomScalar()),
          globalIndex: BigInt(1000 + j * 7),
        });
      }
      ring.push({ publicKey, commitment, globalIndex: 9999n });
      return { secretKey, amount, mask, ring };
    };
    const sortedPubs = (ring) => ring.slice()
      .sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1))
      .map((m) => ({ dest: m.publicKey, mask: m.commitment }));
    const stdWallet = () => {
      const viewSecret = randomScalar();
      const spendSecret = randomScalar();
      return {
        viewSecret,
        viewPublicKey: secretKeyToPublicKey(viewSecret),
        spendPublicKey: secretKeyToPublicKey(spendSecret),
        isSubaddress: false,
      };
    };
    const sumPoints = (arr) => arr.reduce((acc, b) => acc.add(decodePoint(b)), Point.ZERO);

    it('builds a valid 2-in 2-out transaction', () => {
      const inputs = [makeInput(2000000n), makeInput(3000000n)];
      const sender = stdWallet();
      const recipient = stdWallet();
      const fee = 10000n;
      const outputs = [
        { ...recipient, amount: 4000000n },
        { ...sender, isChange: true, amount: 990000n },
      ];
      const { bytes } = tx.createTransaction({ inputs, outputs, fee, viewSecretKey: sender.viewSecret });

      // serialization round-trips
      const decoded = transaction.decode(bytes);
      assert.equal(bytesToHex(transaction.encode(decoded)), bytesToHex(bytes));
      assert.equal(decoded.rctSigBase.type, 6);
      assert.equal(decoded.prefix.vin.length, 2);
      assert.equal(decoded.prefix.vout.length, 2);

      const { outPk } = decoded.rctSigBase;
      const { bulletproofsPlus, CLSAGs, pseudoOuts } = decoded.rctSigPrunable;

      // range proof verifies
      assert.ok(verifyBulletproofPlus(bulletproofsPlus[0], outPk));

      // commitments balance: sum(pseudoOuts) == sum(outPk) + fee*H
      const lhs = sumPoints(pseudoOuts);
      const rhs = sumPoints(outPk).add(H.multiplyUnsafe(fee));
      assert.ok(lhs.equals(rhs));

      // each CLSAG verifies against the original ring and the signed message
      const message = tx.getPreMlsagHash(fastHash(txPrefix.encode(decoded.prefix)), decoded.rctSigBase, bulletproofsPlus[0]);
      const ringByKi = new Map();
      for (const input of inputs) {
        const ki = bytesToHex(generateKeyImage(secretKeyToPublicKey(input.secretKey), input.secretKey));
        ringByKi.set(ki, sortedPubs(input.ring));
      }
      decoded.prefix.vin.forEach((vin, i) => {
        const pubs = ringByKi.get(bytesToHex(vin.data.keyImage));
        assert.ok(pubs, 'key image not found among inputs');
        const sig = { s: CLSAGs[i].s, c1: CLSAGs[i].c1, I: vin.data.keyImage, D: CLSAGs[i].D };
        assert.ok(verifyClsag(message, sig, pubs, pseudoOuts[i]));
      });

      // the recipient (output 0) can decode the amount and the commitment matches
      const { txPublicKey } = tx.parseTxExtra(decoded.prefix.extra);
      const derivation = generateKeyDerivation(txPublicKey, recipient.viewSecret);
      const ecdh = decodeRct({ amount: decoded.rctSigBase.ecdhInfo[0] }, outPk[0], 6, 0, derivation);
      assert.equal(ecdh.amount, '4000000');
    });

    it('rejects a payment id with more than one recipient', () => {
      const inputs = [makeInput(5010000n)];
      const outputs = [
        { ...stdWallet(), amount: 2000000n },
        { ...stdWallet(), amount: 3000000n },
      ];
      assert.throws(() => tx.createTransaction({ inputs, outputs, fee: 10000n, paymentId: randomBytes(8) }));
    });

    it('embeds an explicit payment id for a single recipient', () => {
      const inputs = [makeInput(5010000n)];
      const recipient = stdWallet();
      const sender = stdWallet();
      const paymentId = randomBytes(8);
      const outputs = [
        { ...recipient, amount: 4000000n },
        { ...sender, isChange: true, amount: 1000000n },
      ];
      const { bytes } = tx.createTransaction({
        inputs, outputs, fee: 10000n, viewSecretKey: sender.viewSecret, paymentId,
      });
      const { encryptedPaymentId, txPublicKey } = tx.parseTxExtra(transaction.decode(bytes).prefix.extra);
      assert.equal(encryptedPaymentId.length, 8);
      // the recipient recovers it with the tx pub key and its own view secret
      assert.deepStrictEqual(tx.encryptPaymentId(encryptedPaymentId, txPublicKey, recipient.viewSecret), paymentId);
    });
  });

  describe('globalIndexesFromKeyOffsets', () => {
    it('reconstructs absolute indexes with uint64 wraparound (unsorted ring)', () => {
      const mask = (1n << 64n) - 1n;
      // a "negative" relative delta stored as 2^64 - 30 lowers the next index by 30
      assert.deepStrictEqual(tx.globalIndexesFromKeyOffsets([100n, mask - 29n]), [100n, 70n]);
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
