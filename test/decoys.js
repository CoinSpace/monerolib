import assert from 'node:assert';
import { randomBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as crypto from '../lib/crypto.js';
import { gammaPicker } from '../lib/decoys.js';

describe('decoys', () => {
  const rctOffsets = Array.from({ length: 300000 }, (unused, i) => (i + 1) * 5);
  // outputs in the last SPENDABLE_AGE - 1 blocks are never picked
  const numRctOutputs = rctOffsets[rctOffsets.length - 10];

  it('picks a global index in range, biased toward recent outputs', () => {
    const pick = gammaPicker(rctOffsets);
    const picks = [];
    for (let i = 0; i < 500; i++) {
      const index = pick();
      assert.ok(index === -1 || (index >= 0 && index < numRctOutputs), `out of range: ${index}`);
      if (index !== -1) {
        picks.push(index);
      }
    }
    // the daemon tx_sanity_check needs the ring median at >= 60% of the rct outputs
    picks.sort((a, b) => a - b);
    assert.ok(picks[picks.length >> 1] >= numRctOutputs * 0.6);
  });

  it('draws from the crypto random source', () => {
    // a constant source makes every draw equal, so two picks must agree
    crypto.__mockRandomBytes__((length) => new Uint8Array(length).fill(1));
    try {
      const pick = gammaPicker(rctOffsets);
      const first = pick();
      assert.notStrictEqual(first, -1);
      assert.strictEqual(pick(), first);
    } finally {
      crypto.__mockRandomBytes__(randomBytes);
    }
  });
});
