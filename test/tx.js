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
    const empty = { txPubKey: NIL, encryptedPaymentId: NIL };

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
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL });
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
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL });
    });

    it('should handle two pub keys', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: NIL });
    });

    it('should handle pub key with encrypted payment id', () => {
      const result = tx.parseTxExtra(Buffer.from([1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
        2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBuffer('0000000000000000', 8) });
    });

    it('should handle pub key with encrypted payment id (reverse order)', () => {
      const result = tx.parseTxExtra(Buffer.from([2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
        80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230]));
      assert.deepStrictEqual(result, { txPubKey: hexToBuffer('1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6'), encryptedPaymentId: hexToBuffer('0000000000000000', 8) });
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
