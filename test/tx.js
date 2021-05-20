/* eslint-disable max-len */
import assert from 'assert';
import tx from '../lib/tx.js';
import fs from 'fs/promises';
import { hexToBuffer } from '../lib/helpers.js';

const getTxIdFromHexFixtures = JSON.parse(await fs.readFile('./test/fixtures/get_tx_id_from_hex.json', { encoding: 'utf8' }));

describe('tx', () => {

  describe('parseTxExtra', () => {

    const NIL = Buffer.alloc(0);
    const TX_EXTRA_PADDING_MAX_COUNT = 255;
    const empty = { txPubKey: NIL, encryptedPaymentId: NIL, additionalPubKeys: [] };

    it('should handle empty extra', () => {
      const result = tx.parseTxExtra(Buffer.from([]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only size 1', () => {
      const result = tx.parseTxExtra(Buffer.from([0]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only size 2', () => {
      const result = tx.parseTxExtra(Buffer.from([0, 0]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only max size', () => {
      const result = tx.parseTxExtra(Buffer.alloc(TX_EXTRA_PADDING_MAX_COUNT));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle padding only exceed max size', () => {
      const result = tx.parseTxExtra(Buffer.alloc(TX_EXTRA_PADDING_MAX_COUNT + 1));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle invalid padding only', () => {
      const result = tx.parseTxExtra(Buffer.from([0, 42]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle pub key only', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPubKeys: [] });
    });

    it('should handle extra nonce only', () => {
      const result = tx.parseTxExtra(Buffer.from([2, 1, 42]));
      assert.deepStrictEqual(result, empty);
    });

    it('should handle pub key and padding', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPubKeys: [] });
    });

    it('should handle two pub keys', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL, additionalPubKeys: [] });
    });

    it('should handle pub key with encrypted payment id', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBuffer('0000000000000000', 8), additionalPubKeys: [] });
    });

    it('should handle pub key with encrypted payment id (reverse order)', () => {
      const result = tx.parseTxExtra(Buffer.from([2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBuffer('0000000000000000', 8), additionalPubKeys: [] });
    });

    it('should additional pub keys', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 59, 54, 37, 207, 182, 88, 66, 252, 62, 68, 82, 69, 144, 143, 155, 23, 27, 78, 24, 153, 84, 63, 183, 13, 133, 66, 79, 217, 177, 201, 94, 185,
        4, 3, 252, 23, 118, 225, 66, 173, 231, 164, 173, 94, 0, 189, 39, 164, 128, 1, 63, 6, 196, 93, 90, 200, 8, 7, 211, 96, 149, 0, 189, 210, 108, 242, 152, 112, 95, 250, 198, 110, 246, 61, 103,
        203, 88, 114, 182, 252, 34, 40, 121, 144, 46, 219, 231, 163, 204, 184, 50, 120, 200, 42, 95, 173, 9, 124, 207, 193, 216, 157, 94, 95, 186, 83, 166, 138, 35, 130, 57, 235, 213, 246, 13, 96,
        50, 125, 34, 218, 62, 233, 90, 156, 7, 6, 116, 234, 82, 90]));
      assert.deepStrictEqual(result, {
        txPubKey: hexToBuffer('3b3625cfb65842fc3e445245908f9b171b4e1899543fb70d85424fd9b1c95eb9'),
        encryptedPaymentId: NIL,
        additionalPubKeys: [
          hexToBuffer('fc1776e142ade7a4ad5e00bd27a480013f06c45d5ac80807d3609500bdd26cf2'),
          hexToBuffer('98705ffac66ef63d67cb5872b6fc222879902edbe7a3ccb83278c82a5fad097c'),
          hexToBuffer('cfc1d89d5e5fba53a68a238239ebd5f60d60327d22da3ee95a9c070674ea525a'),
        ],
      });
    });
  });

  describe('getTxIdFromHex', () => {
    it('should work', () => {
      getTxIdFromHexFixtures.forEach((fixture) => {
        const actual = tx.getTxIdFromHex(fixture.hex);
        assert.strictEqual(actual.toString('hex'), fixture.result);
      });
    });
  });

  describe('estimate tx size', () => {
    it('should estimate tx size with 1 in 2 out', () => {
      const size = tx.estimateTxSize(1, 10, 2, 44);
      assert.strictEqual(size, 1460);
    });

    it('should estimate tx size with 2 in 2 out', () => {
      const size = tx.estimateTxSize(2, 10, 2, 44);
      assert.strictEqual(size, 1969);
    });

    it('should estimate tx size with 3 in 3 out', () => {
      const size = tx.estimateTxSize(3, 10, 3, 44);
      assert.strictEqual(size, 2620);
    });
  });

  describe('estimate tx weight', () => {
    it('should estimate tx weight with 1 in 2 out', () => {
      const weight = tx.estimateTxWeight(1, 10, 2, 44);
      assert.strictEqual(weight, 1460);
    });

    it('should estimate tx weight with 2 in 2 out', () => {
      const weight = tx.estimateTxWeight(2, 10, 2, 44);
      assert.strictEqual(weight, 1969);
    });

    it('should estimate tx weight with 3 in 3 out', () => {
      const weight = tx.estimateTxWeight(3, 10, 3, 44);
      assert.strictEqual(weight, 3157);
    });
  });

  describe('estimate tx fee', () => {
    it('should estimate tx fee with 1 in 2 out', () => {
      const fee = tx.estimateFee(1, 10, 2, 44, 6836, 1, 10000);
      assert.strictEqual(fee, '9990000');
    });

    it('should estimate tx fee with 2 in 2 out', () => {
      const fee = tx.estimateFee(2, 10, 2, 44, 6836, 1, 10000);
      assert.strictEqual(fee, '13470000');
    });

    it('should estimate tx fee with 3 in 3 out', () => {
      const fee = tx.estimateFee(3, 10, 3, 44, 6836, 1, 10000);
      assert.strictEqual(fee, '21590000');
    });
  });

});
