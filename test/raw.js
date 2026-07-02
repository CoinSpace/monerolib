import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as raw from '../lib/raw.js';
import txFixtures from './fixtures/txs.json' with { type: 'json' };

describe('raw', () => {
  describe('varintBigInt', () => {
    // LEB128, matching monero src/common/varint.h
    const vectors = [
      [0n, '00'],
      [1n, '01'],
      [127n, '7f'],
      [128n, '8001'],
      [255n, 'ff01'],
      [300n, 'ac02'],
      [16384n, '808001'],
      [18446744073709551615n, 'ffffffffffffffffff01'], // uint64 max
    ];

    it('encodes', () => {
      for (const [value, hex] of vectors) {
        assert.equal(bytesToHex(raw.varintBigInt.encode(value)), hex);
      }
    });

    it('decodes', () => {
      for (const [value, hex] of vectors) {
        assert.equal(raw.varintBigInt.decode(hexToBytes(hex)), value);
      }
    });

    it('rejects non-canonical representation', () => {
      assert.throws(() => raw.varintBigInt.decode(hexToBytes('8000')));
    });

    it('rejects values overflowing uint64', () => {
      // 11-byte varint encoding 2^70, beyond uint64
      assert.throws(() => raw.varintBigInt.decode(hexToBytes('8080808080808080808004')));
      assert.throws(() => raw.varintBigInt.encode(2n ** 64n));
    });

    it('encodes bigint only, no type coercion', () => {
      assert.throws(() => raw.varintBigInt.encode(1));
      assert.throws(() => raw.varintBigInt.encode('1'));
      assert.throws(() => raw.varintBigInt.encode(true));
      // the number-level entry stays varintNum
      assert.deepEqual(raw.varintNumber.encode(1), raw.varintBigInt.encode(1n));
    });

    // mirrors monero TEST(varint, equal)
    // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/varint.cpp#L48
    it('round-trips 0..65536', () => {
      for (let i = 0n; i <= 65536n; i++) {
        assert.equal(raw.varintBigInt.decode(raw.varintBigInt.encode(i)), i);
      }
    });
  });

  describe('varintNumber', () => {
    it('round-trips as a number', () => {
      assert.equal(raw.varintNumber.decode(raw.varintNumber.encode(300)), 300);
    });
  });

  describe('keyV', () => {
    it('round-trips a varint-length-prefixed array of keys', () => {
      const keys = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
      const encoded = raw.keyV.encode(keys);
      assert.equal(encoded[0], 2); // length prefix
      assert.deepEqual(raw.keyV.decode(encoded), keys);
    });
  });

  describe('rctBase', () => {
    it('rejects an unknown rct type', () => {
      assert.throws(() => raw.rctBase(1, 1).decode(Uint8Array.of(99)));
    });
  });

  describe('rctPrunable', () => {
    it('rejects an unknown rct type', () => {
      assert.throws(() => raw.rctPrunable(99, 1, 1, 10).decode(new Uint8Array(0)));
    });
  });

  // txPrefix and rctPrunable are exercised by the full transaction round-trip below
  describe('transaction', () => {
    it('decodes and re-encodes whole real transactions byte-identically', () => {
      for (const { hex } of txFixtures) {
        assert.equal(bytesToHex(raw.transaction.encode(raw.transaction.decode(hexToBytes(hex)))), hex);
      }
    });
  });
});
