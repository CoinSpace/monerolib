import assert from 'node:assert';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import { gammaPicker } from '../lib/decoys.js';

import { withRandomSource } from './helpers/common.js';

// The cumulative rct output count of every block, with perBlock outputs in each block.
const chain = (blocks, perBlock) => Array.from({ length: blocks }, (_, i) => (i + 1) * perBlock);

// The bytes that give each value: randomFloat reads 8 bytes and keeps the top 53 bits, randomInt reads 4 bytes.
const FLOAT = {
  0: hexToBytes('0000000000000000'),
  0.5: hexToBytes('0000000000000080'),
  0.99: hexToBytes('00703d0ad7a370fd'),
};
const INT = {
  0: hexToBytes('00000000'),
  3: hexToBytes('03000000'),
  4: hexToBytes('04000000'),
  600: hexToBytes('58020000'),
};

// One pick that must read exactly these draws, in this order.
function pickWith(offsets, ...draws) {
  const pick = withRandomSource((length) => {
    const draw = draws.shift();
    assert.strictEqual(draw?.length, length, 'unexpected random draw');
    return draw;
  }, () => gammaPicker(offsets)());
  assert.strictEqual(draws.length, 0, 'unread random draws');
  return pick;
}

// A gamma sample reads two floats for Box-Muller and one for the Marsaglia-Tsang test.
// Box-Muller gives 0, so the sample is (shape - 1/3) * scale = (19.28 - 1/3) / 1.61 = 11.768.
const MEDIAN_SAMPLE = [FLOAT[0], FLOAT[0], FLOAT[0]];
// Box-Muller gives -3.03, so the sample is 5.32 and e^5.32 = 205 s is less than the 1200 s unlock time.
const RECENT_SPEND = [FLOAT[0.99], FLOAT[0.5], FLOAT[0]];

// 2000 blocks of 5 outputs: one output every 24 s, and outputs 0..9954 (blocks 0..1990) are unlocked.
const CHAIN = chain(2000, 5);
// CHAIN with 1 output in block 0 and 9 in block 1: the same output count and the same blocks from block 1 on.
const UNEVEN_CHAIN = [1, ...CHAIN.slice(1)];

describe('decoys', () => {
  describe('gammaPicker', () => {
    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L1059-L1102
    it('picks an output of the block at the gamma age', () => {
      // e^11.768 - 1200 = 127870 s is 5327 outputs before output 9954: output 4627 in block 925 (4625..4629)
      assert.strictEqual(pickWith(CHAIN, ...MEDIAN_SAMPLE, INT[3]), 4628);
    });

    it('picks inside the chosen block by the output count of that block', () => {
      // output 4627 in block 925 (4625..4629); draw 4 of 5 outputs, not of the 1 output of block 0
      assert.strictEqual(pickWith(UNEVEN_CHAIN, ...MEDIAN_SAMPLE, INT[4]), 4629);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L1078-L1086
    it('picks a recent spend when the gamma age is less than the unlock time', () => {
      // 600 s of the 1800 s window is 25 outputs before output 9954: output 9929 in block 1985 (9925..9929)
      assert.strictEqual(pickWith(CHAIN, ...RECENT_SPEND, INT[600], INT[4]), 9929);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L1048-L1049
    it('picks at most the newest unlocked output, so the last 9 blocks stay locked', () => {
      // age 0 is output 9954, the last one of block 1990
      assert.strictEqual(pickWith(CHAIN, ...RECENT_SPEND, INT[0], INT[4]), 9954);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L1088-L1090
    it('returns -1 for an age older than the chain', () => {
      // 1000 blocks of 5 outputs unlock 4955 outputs, fewer than the 5327 outputs of the age
      assert.strictEqual(pickWith(chain(1000, 5), ...MEDIAN_SAMPLE), -1);
    });

    it('draws a new gamma sample when the Marsaglia-Tsang test rejects one', () => {
      const rejected = [FLOAT[0.99], FLOAT[0.5], FLOAT[0.99]];
      assert.strictEqual(pickWith(CHAIN, ...rejected, ...MEDIAN_SAMPLE, INT[3]), 4628);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/output_selection.cpp#L112-L134
    it('picks outputs with a median age of 1.3 to 1.4 days, one output per block', () => {
      const offsets = chain(300000, 1);
      const newest = offsets[offsets.length - 1] - 1;
      const pick = gammaPicker(offsets);
      const ages = [];
      for (let i = 0; i < 100000; i++) {
        const index = pick();
        if (index !== -1) {
          ages.push((newest - index) * 120);
        }
      }
      ages.sort((a, b) => a - b);
      assert.ok(ages[0] >= 0 && ages[ages.length - 1] <= offsets.length * 120);
      const median = ages[ages.length >> 1];
      assert.ok(median >= 1.3 * 86400 && median <= 1.4 * 86400, `median ${median / 86400} days`);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L1039-L1052
    it('rejects 10 or fewer blocks of offsets', () => {
      assert.throws(() => {
        gammaPicker(chain(10, 1))();
      });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L1039-L1052
    it('rejects offsets without rct outputs', () => {
      assert.throws(() => {
        gammaPicker(chain(20, 0))();
      });
    });
  });
});
