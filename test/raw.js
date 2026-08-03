import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as raw from '../lib/raw.js';
import blockFixtures from './fixtures/blocks.json' with { type: 'json' };
import prunedTxFixture from './fixtures/monero_oxide_scan.json' with { type: 'json' };
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

    it('rejects transaction versions other than 1 or 2', () => {
      // v3 blob that previously round-tripped as if it were RingCT v2
      assert.throws(() => raw.transaction.decode(hexToBytes('030001ff00000000')), /unsupported version/);
      // and on encode
      assert.throws(() => raw.transaction.encode({
        prefix: {
          version: 3, unlockTime: 0n, vin: [], vout: [], extra: new Uint8Array(0),
        },
      }), /unsupported version/);
    });
  });

  describe('prunedTransaction', () => {
    // a real pruned (base-only) blob, as a prune=true node serves it
    it('decodes and re-encodes a pruned blob byte-identically', () => {
      const bytes = hexToBytes(prunedTxFixture.hex);
      const decoded = raw.prunedTransaction.decode(bytes);
      assert.ok(decoded.prefix && decoded.rctSigBase);
      assert.equal(decoded.rctSigPrunable, undefined); // prunable part is dropped
      assert.equal(bytesToHex(raw.prunedTransaction.encode(decoded)), prunedTxFixture.hex);
    });

    it('the full transaction codec over-reads a pruned blob', () => {
      assert.throws(() => raw.transaction.decode(hexToBytes(prunedTxFixture.hex)));
    });

    it('version 1: prefix only, no signatures', () => {
      const full = raw.transaction.decode(hexToBytes(txFixtures.find((t) => t.label.includes('v1')).hex));
      const pruned = raw.prunedTransaction.encode({ prefix: full.prefix });
      assert.deepEqual(pruned, raw.txPrefix.encode(full.prefix));
      assert.deepEqual(raw.prunedTransaction.decode(pruned), { prefix: full.prefix });
    });
  });

  // block blobs (from /getblocks.bin block_complete_entry.block, see lib/epee.js) round-tripped
  // against real captures - genesis in particular is version 1 (legacy, no rct part on the wire),
  // every other block since RingCT is version 2.
  describe('block', () => {
    it('decodes and re-encodes real block blobs byte-identically', () => {
      for (const { label, hex } of blockFixtures) {
        assert.equal(bytesToHex(raw.block.encode(raw.block.decode(hexToBytes(hex)))), hex, label);
      }
    });

    it('decodes the genesis block as a version 1 (legacy) miner_tx with no rct part', () => {
      const genesis = blockFixtures.find((f) => f.label.includes('genesis'));
      const parsed = raw.block.decode(hexToBytes(genesis.hex));
      assert.equal(parsed.minerTx.prefix.version, 1);
      assert.equal(parsed.minerTx.rctSigBase, undefined);
      assert.deepEqual(parsed.minerTx.signatures, [[]]); // single txin_gen input, 0-length ring signature
      assert.equal(parsed.txHashes.length, 0);
    });

    it('decodes a version 2 (RingCT) miner_tx and any regular transaction hashes', () => {
      const withTxs = blockFixtures.find((f) => f.label.includes('real tx'));
      const parsed = raw.block.decode(hexToBytes(withTxs.hex));
      assert.equal(parsed.minerTx.prefix.version, 2);
      assert.equal(parsed.minerTx.rctSigBase.type, 0); // RCTTypes.Null for coinbase
      assert.equal(parsed.txHashes.length, 1);
      assert.equal(parsed.txHashes[0].length, 32);
    });

    it('rejects a major/minor version above uint8', () => {
      // both fields are uint8_t in monero; varint 256 = 0x80 0x02. bounded on decode and encode.
      assert.throws(() => raw.block.decode(hexToBytes('8002')), /exceeds uint8/); // major
      assert.throws(() => raw.block.decode(hexToBytes('018002')), /exceeds uint8/); // minor (major 1, minor 256)
      // encode trips the offending field before the rest of the struct is reached
      assert.throws(() => raw.block.encode({ majorVersion: 256 }), /exceeds uint8/);
      assert.throws(() => raw.block.encode({ majorVersion: 1, minorVersion: 256 }), /exceeds uint8/);
    });
  });
});
