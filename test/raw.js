import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as raw from '../lib/raw.js';
import blockFixtures from './fixtures/blocks.json' with { type: 'json' };
import clsagTx from './fixtures/clsag_tx.json' with { type: 'json' };
import scanVector from './fixtures/monero_oxide_scan.json' with { type: 'json' };
import txFixtures from './fixtures/txs.json' with { type: 'json' };

// The transaction as monerod prints it in JSON, converted to the decoded form of lib/raw.js.
// https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/src/tests/transaction.rs#L52-L196
function fromMonerodJson(json) {
  const prefix = {
    version: json.version,
    unlockTime: BigInt(json.unlock_time),
    vin: json.vin.map((input) => (input.gen
      ? { TAG: raw.TXIN_GEN_TAG, data: { height: BigInt(input.gen.height) } }
      : {
        TAG: raw.TXIN_TO_KEY_TAG,
        data: {
          amount: BigInt(input.key.amount),
          outputOffsets: input.key.key_offsets.map(BigInt),
          keyImage: hexToBytes(input.key.k_image),
        },
      })),
    vout: json.vout.map(({ amount, target }) => ({
      amount: BigInt(amount),
      target: target.tagged_key
        ? {
          TAG: raw.TXOUT_TO_TAGGED_KEY_TAG,
          data: { key: hexToBytes(target.tagged_key.key), viewTag: parseInt(target.tagged_key.view_tag, 16) },
        }
        : { TAG: raw.TXOUT_TO_KEY_TAG, data: { key: hexToBytes(target.key) } },
    })),
    extra: Uint8Array.from(json.extra),
  };
  if (json.version === 1) {
    // monerod prints the ring signature of an input as one hex string
    return { prefix, signatures: json.signatures.map((hex) => (hex.match(/.{128}/g) ?? []).map(hexToBytes)) };
  }
  const base = json.rct_signatures;
  if (base.type === 0) {
    return {
      prefix, rctSigBase: { type: 0 }, rctSigPrunable: {},
    };
  }
  const prunable = json.rctsig_prunable;
  const keys = (list) => list.map(hexToBytes);
  const bulletproofFields = ['A', 'S', 'T1', 'T2', 'taux', 'mu', 'L', 'R', 'a', 'b', 't'];
  const bulletproofPlusFields = ['A', 'A1', 'B', 'r1', 's1', 'd1', 'L', 'R'];
  const field = (value) => (Array.isArray(value) ? keys(value) : hexToBytes(value));
  const proof = (fields, bp) => Object.fromEntries(fields.map((name) => [name, field(bp[name])]));
  return {
    prefix,
    rctSigBase: {
      type: base.type,
      txnFee: BigInt(base.txnFee),
      ecdhInfo: base.ecdhInfo.map(({ amount }) => ({ amount: hexToBytes(amount) })),
      outPk: keys(base.outPk),
    },
    rctSigPrunable: {
      ...(prunable.bp ? { bulletproofs: prunable.bp.map((bp) => proof(bulletproofFields, bp)) } : {}),
      ...(prunable.bpp ? { bulletproofsPlus: prunable.bpp.map((bp) => proof(bulletproofPlusFields, bp)) } : {}),
      CLSAGs: prunable.CLSAGs.map(({
        s, c1, D,
      }) => ({
        s: keys(s), c1: hexToBytes(c1), D: hexToBytes(D),
      })),
      pseudoOuts: keys(prunable.pseudoOuts),
    },
  };
}

// A version 1 transaction without outputs and extra, with the given inputs and signatures.
const v1Tx = (vin, signatures) => ({
  prefix: {
    version: 1, unlockTime: 0n, vin, vout: [], extra: new Uint8Array(0),
  },
  signatures,
});
const MINER_INPUT = { TAG: raw.TXIN_GEN_TAG, data: { height: 0n } };
const KEY_INPUT = { TAG: raw.TXIN_TO_KEY_TAG, data: {
  amount: 1n, outputOffsets: [12n, 3453n], keyImage: new Uint8Array(32).fill(0x42),
} };
const SIGNATURE = new Uint8Array(64).fill(7);
const sigs = (count) => Array.from({ length: count }, () => SIGNATURE);

const bytesOf = (fixtures, label) => hexToBytes(fixtures.find((fixture) => fixture.label.includes(label)).hex);

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
      // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/serialization.cpp#L158-L173
      [0xff00000000n, '80808080f01f'],
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

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/serialization.cpp#L219-L260
    it('uses the monero encoded length at the 7-bit boundaries', () => {
      const lengths = [
        [0n, 1], [1n, 1], [0x80n, 2], [0xffn, 2], [0x3fffn, 2], [0x40ffn, 3], [0xffffffffffffffffn, 10],
      ];
      for (const [value, length] of lengths) {
        assert.equal(raw.varintBigInt.encode(value).length, length, `${value}`);
      }
    });

    it('rejects non-canonical representation', () => {
      assert.throws(() => {
        raw.varintBigInt.decode(hexToBytes('8000'));
      });
    });

    it('rejects values overflowing uint64', () => {
      // 11-byte varint encoding 2^70, beyond uint64
      assert.throws(() => {
        raw.varintBigInt.decode(hexToBytes('8080808080808080808004'));
      });
      assert.throws(() => {
        raw.varintBigInt.encode(2n ** 64n);
      });
    });

    it('encodes bigint only, no type coercion', () => {
      assert.throws(() => {
        raw.varintBigInt.encode(1);
      });
      assert.throws(() => {
        raw.varintBigInt.encode('1');
      });
      assert.throws(() => {
        raw.varintBigInt.encode(true);
      });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/varint.cpp#L48
    it('round-trips 0..65536', () => {
      for (let i = 0n; i <= 65536n; i++) {
        assert.equal(raw.varintBigInt.decode(raw.varintBigInt.encode(i)), i);
      }
    });
  });

  describe('varintNumber', () => {
    it('encodes a number like varintBigInt', () => {
      assert.equal(bytesToHex(raw.varintNumber.encode(300)), 'ac02');
      assert.equal(raw.varintNumber.decode(hexToBytes('ac02')), 300);
    });
  });

  describe('keyV', () => {
    it('encodes a varint count and the keys', () => {
      const keys = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
      const hex = `02${'01'.repeat(32)}${'02'.repeat(32)}`;
      assert.equal(bytesToHex(raw.keyV.encode(keys)), hex);
      assert.deepEqual(raw.keyV.decode(hexToBytes(hex)), keys);
    });
  });

  describe('rctBaseCoder', () => {
    it('rejects an unknown rct type', () => {
      assert.throws(() => {
        raw.rctBaseCoder(1, 1).decode(Uint8Array.of(99));
      });
      assert.throws(() => {
        raw.rctBaseCoder(1, 1).encode({ type: 99 });
      });
    });
  });

  describe('rctPrunableCoder', () => {
    it('rejects an unknown rct type', () => {
      assert.throws(() => {
        raw.rctPrunableCoder(99, 1, 1, 10).decode(new Uint8Array(0));
      });
      assert.throws(() => {
        raw.rctPrunableCoder(99, 1, 1, 10).encode({});
      });
    });
  });

  describe('fullTransaction', () => {
    for (const { label, hex } of txFixtures) {
      it(`decodes and re-encodes byte-identically: ${label}`, () => {
        assert.equal(bytesToHex(raw.fullTransaction.encode(raw.fullTransaction.decode(hexToBytes(hex)))), hex);
      });
    }

    for (const {
      label, hex, json,
    } of [...txFixtures.filter((fixture) => fixture.json), {
        label: 'monero-oxide clsag_tx', ...clsagTx, json: clsagTx.tx,
      }]) {
      it(`decodes every field as monerod: ${label}`, () => {
        assert.deepEqual(raw.fullTransaction.decode(hexToBytes(hex)), fromMonerodJson(json));
      });
    }

    it('rejects transaction versions other than 1 or 2', () => {
      // v3 blob that previously round-tripped as if it were RingCT v2
      assert.throws(() => {
        raw.fullTransaction.decode(hexToBytes('030001ff00000000'));
      }, /unsupported version/);
      assert.throws(() => {
        raw.fullTransaction.encode({
          prefix: {
            version: 3, unlockTime: 0n, vin: [], vout: [], extra: new Uint8Array(0),
          },
        });
      }, /unsupported version/);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/serialization.cpp#L335-L495
    describe('version 1 signatures', () => {
      it('an empty transaction is 5 bytes', () => {
        assert.equal(bytesToHex(raw.fullTransaction.encode(v1Tx([], []))), '0100000000');
        assert.deepEqual(raw.fullTransaction.decode(hexToBytes('0100000000')), v1Tx([], []));
      });

      it('a miner input has no signature', () => {
        for (const signatures of [[], [[]]]) {
          assert.equal(bytesToHex(raw.fullTransaction.encode(v1Tx([MINER_INPUT], signatures))), '010001ff000000');
        }
        assert.deepEqual(raw.fullTransaction.decode(hexToBytes('010001ff000000')), v1Tx([MINER_INPUT], [[]]));
      });

      it('rejects a signature for a miner input', () => {
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx([MINER_INPUT], [sigs(1)]));
        });
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx([MINER_INPUT], [sigs(1), sigs(1)]));
        });
      });

      it.skip('rejects more signature vectors than miner inputs', () => {
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx([MINER_INPUT], [[], []]));
        });
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx([MINER_INPUT, MINER_INPUT], [[], [], []]));
        });
      });

      it.skip('rejects fewer signature vectors than miner inputs', () => {
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx([MINER_INPUT, MINER_INPUT], [[]]));
        });
      });

      it('accepts two miner inputs with no or two empty signature vectors', () => {
        for (const signatures of [[], [[], []]]) {
          const tx = v1Tx([MINER_INPUT, MINER_INPUT], signatures);
          assert.equal(bytesToHex(raw.fullTransaction.encode(tx)), '010002ff00ff000000');
        }
      });

      it('rejects bytes after a miner transaction', () => {
        assert.throws(() => {
          raw.fullTransaction.decode(hexToBytes(`010001ff000000${'78'.repeat(32)}`));
        });
        assert.throws(() => {
          raw.fullTransaction.decode(hexToBytes(`010001ff000000${'78'.repeat(32)}${'79'.repeat(32)}`));
        });
      });

      it.skip('rejects a signature count that does not match the ring of each key input', () => {
        const vin = [KEY_INPUT, KEY_INPUT];
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx(vin, [sigs(2)]));
        });
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx(vin, [sigs(2), sigs(2), sigs(2)]));
        });
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx(vin, [sigs(1), sigs(2)]));
        });
        assert.throws(() => {
          raw.fullTransaction.encode(v1Tx(vin, [sigs(3), sigs(2)]));
        });
      });

      it('decodes one signature per ring member of each key input, and no other byte count', () => {
        const tx = v1Tx([KEY_INPUT, KEY_INPUT], [sigs(2), sigs(2)]);
        // version 1, unlock time 0, two inputs (tag 02, amount 1, offsets 12 and 3453, key image), no outputs, no extra
        const hex = `010002${`0201020cfd1a${'42'.repeat(32)}`.repeat(2)}0000${'07'.repeat(64 * 4)}`;
        assert.equal(bytesToHex(raw.fullTransaction.encode(tx)), hex);
        assert.deepEqual(raw.fullTransaction.decode(hexToBytes(hex)), tx);
        assert.throws(() => {
          raw.fullTransaction.decode(hexToBytes(hex.slice(0, -64)));
        });
        assert.throws(() => {
          raw.fullTransaction.decode(hexToBytes(`${hex}${'00'.repeat(64)}`));
        });
        assert.throws(() => {
          raw.fullTransaction.decode(hexToBytes(`${hex}${'00'.repeat(32)}`));
        });
      });
    });
  });

  describe('prunedTransaction', () => {
    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/src/tests/transaction.rs#L293-L302
    it('is the start of the full bytes for every version 2 transaction', () => {
      for (const { label, hex } of txFixtures) {
        const full = raw.fullTransaction.decode(hexToBytes(hex));
        if (full.prefix.version !== 2) {
          continue;
        }
        const pruned = bytesToHex(raw.prunedTransaction.encode(full));
        assert.ok(hex.startsWith(pruned), label);
        const { prefix, rctSigBase } = full;
        assert.deepEqual(raw.prunedTransaction.decode(hexToBytes(pruned)), { prefix, rctSigBase });
      }
    });

    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/wallet/src/tests/scan.rs#L119-L167
    it('decodes and re-encodes a real pruned blob byte-identically', () => {
      const decoded = raw.prunedTransaction.decode(hexToBytes(scanVector.hex));
      assert.equal(decoded.rctSigPrunable, undefined);
      assert.equal(bytesToHex(raw.prunedTransaction.encode(decoded)), scanVector.hex);
    });

    it('cannot be decoded as a full transaction', () => {
      assert.throws(() => {
        raw.fullTransaction.decode(hexToBytes(scanVector.hex));
      });
    });

    it('version 1: prefix only, no signatures', () => {
      const bytes = bytesOf(txFixtures, 'v1');
      const full = raw.fullTransaction.decode(bytes);
      const pruned = raw.prunedTransaction.encode({ prefix: full.prefix });
      assert.ok(bytesToHex(bytes).startsWith(bytesToHex(pruned)));
      assert.deepEqual(raw.prunedTransaction.decode(pruned), { prefix: full.prefix });
    });
  });

  describe('block', () => {
    for (const { label, hex } of blockFixtures) {
      it(`decodes and re-encodes byte-identically: ${label}`, () => {
        assert.equal(bytesToHex(raw.block.encode(raw.block.decode(hexToBytes(hex)))), hex);
      });
    }

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/cryptonote_config.h#L236-L237
    it('decodes the genesis block as monero defines it', () => {
      const genesis = raw.block.decode(bytesOf(blockFixtures, 'genesis'));
      assert.equal(genesis.majorVersion, 1);
      assert.equal(genesis.minorVersion, 0);
      assert.equal(genesis.timestamp, 0n);
      assert.deepEqual(genesis.prevId, new Uint8Array(32));
      assert.equal(genesis.nonce, 10000);
      assert.equal(bytesToHex(raw.fullTransaction.encode(genesis.minerTx)), '013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1');
      assert.deepEqual(genesis.minerTx.signatures, [[]]);
      assert.deepEqual(genesis.txHashes, []);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/blockchain_db.cpp#L50-L81
    it('decodes the transaction hashes of a block', () => {
      const parsed = raw.block.decode(bytesOf(blockFixtures, 'one transaction'));
      assert.deepEqual(parsed.txHashes.map(bytesToHex), ['beb76a82ea17400cd6d7f595f70e1667d2018ed8f5a78d1ce07484222618c3cd']);
    });

    it('decodes a version 2 miner transaction with the Null rct type', () => {
      const parsed = raw.block.decode(bytesOf(blockFixtures, 'real tx'));
      assert.equal(parsed.minerTx.prefix.version, 2);
      assert.equal(parsed.minerTx.rctSigBase.type, 0);
    });

    it('rejects a major/minor version above uint8', () => {
      // both fields are uint8_t in monero; varint 256 = 0x80 0x02. bounded on decode and encode.
      assert.throws(() => {
        raw.block.decode(hexToBytes('8002'));
      }, /exceeds uint8/);
      assert.throws(() => {
        raw.block.decode(hexToBytes('018002'));
      }, /exceeds uint8/);
      assert.throws(() => {
        raw.block.encode({ majorVersion: 256 });
      }, /exceeds uint8/);
      assert.throws(() => {
        raw.block.encode({ majorVersion: 1, minorVersion: 256 });
      }, /exceeds uint8/);
    });
  });
});
