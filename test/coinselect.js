/* eslint-disable max-len */
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as coinselect from '../lib/coinselect.js';
import * as tx from '../lib/tx.js';

describe('coinselect', () => {
  const RING_SIZE = 16;
  const MIXIN = RING_SIZE - 1;
  const BASE_FEE = 1000n;
  const FEE_QUANTIZATION = 10000n;
  const FEE_MULTIPLIER = 1n;

  // a destination; amount omitted => a sweep target. keys only matter for extra-size classification.
  const addr = (amount, type = 'address') => {
    const d = {
      type, publicSpendKey: randomBytes(32), publicViewKey: randomBytes(32),
    };
    if (amount !== undefined) d.amount = amount;
    return d;
  };

  const select = (candidates, destinations) => coinselect.selectInputs({
    candidates,
    destinations,
    ringSize: RING_SIZE,
    baseFee: BASE_FEE,
    feeQuantization: FEE_QUANTIZATION,
    feeMultiplier: FEE_MULTIPLIER,
  });

  const total = (arr) => arr.reduce((s, x) => s + x.amount, 0n);
  const fixedSum = (dsts) => dsts.reduce((s, d) => s + (d.amount ?? 0n), 0n);

  // the exact fee selectInputs must compute for a given input count and output list
  const feeFor = (nInputs, outputList) => tx.estimateFee(
    nInputs, MIXIN, outputList.length, tx.estimateExtraSize(outputList), BASE_FEE, FEE_MULTIPLIER, FEE_QUANTIZATION
  );

  // Σselected === Σfixed + (change | sweep | 0) + fee  — nothing lost or double-counted
  const assertConserves = (result, destinations) => {
    const out = fixedSum(destinations) + (result.changeAmount ?? result.sweepAmount ?? 0n);
    assert.strictEqual(total(result.selected), out + result.fee, 'conservation');
  };

  describe('normal mode', () => {
    it('single destination, ample funds: one input, change output, no dummy', () => {
      const dst = addr(1_000_000_000_000n);
      const res = select([{ amount: 5_000_000_000_000n }], [dst]);
      assert.equal(res.selected.length, 1);
      assert.ok(res.changeAmount > 0n);
      assert.equal(res.sweepAmount, undefined);
      assert.equal(res.needsDummy, false);
      // fee is for 1 input, 2 outputs (destination + change)
      assert.equal(res.fee, feeFor(1, [dst, { isChange: true }]));
      assertConserves(res, [dst]);
    });

    it('largest-first: picks the fewest (biggest) inputs to cover', () => {
      const dst = addr(1_000_000_000_000n);
      const candidates = [
        { amount: 400_000_000_000n },
        { amount: 900_000_000_000n },
        { amount: 300_000_000_000n },
      ];
      const res = select(candidates, [dst]);
      // 900 alone is not enough; 900 + 400 covers → the two biggest, smallest untouched
      assert.deepEqual(res.selected.map((c) => c.amount).sort(), [400_000_000_000n, 900_000_000_000n]);
      assert.ok(res.changeAmount > 0n);
      assertConserves(res, [dst]);
    });

    it('exact funds (change === 0): no change, dummy needed', () => {
      const dst = addr(1_000_000_000_000n);
      const fee = feeFor(1, [dst, { isChange: true }]);
      const res = select([{ amount: dst.amount + fee }], [dst]);
      assert.equal(res.selected.length, 1);
      assert.equal(res.changeAmount, undefined);
      assert.equal(res.needsDummy, true);
      assert.equal(res.fee, fee);
      assertConserves(res, [dst]);
    });

    it('single subaddress accepts funds that cover the destination, fee, and positive change', () => {
      const dst = addr(1_000_000_000_000n, 'subaddress');
      const fee = feeFor(1, [dst, { isChange: true }]);
      const res = select([{ amount: dst.amount + fee + 1n }], [dst]);
      assert.equal(res.selected.length, 1);
      assert.equal(res.changeAmount, 1n);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, fee);
      assertConserves(res, [dst]);
    });

    it('multiple destinations: change output, no dummy', () => {
      const dsts = [addr(1_000_000_000_000n), addr(2_000_000_000_000n)];
      const res = select([{ amount: 5_000_000_000_000n }], dsts);
      assert.ok(res.changeAmount > 0n);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, feeFor(1, [...dsts, { isChange: true }]));
      assertConserves(res, dsts);
    });

    it('covers a no-change tx but not the extra change-output fee: no change, remainder to fee', () => {
      const dsts = [addr(1_000_000_000_000n), addr(2_000_000_000_000n)]; // 2 outputs, change would be a 3rd
      const feeNoChange = feeFor(1, dsts);
      // exactly enough for the no-change tx; a change output would cost more fee than the leftover
      const res = select([{ amount: fixedSum(dsts) + feeNoChange }], dsts);
      assert.equal(res.selected.length, 1);
      assert.equal(res.changeAmount, undefined);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, feeNoChange);
      assertConserves(res, dsts);
    });

    it('throws when funds cannot cover amount + fee', () => {
      assert.throws(() => select([{ amount: 1_000n }], [addr(1_000_000_000_000n)]), /not enough funds/);
    });
  });

  describe('sweep mode', () => {
    it('single sweep target: spends all, sweepAmount, dummy needed', () => {
      const dst = addr(); // no amount → sweep
      const candidates = [{ amount: 3_000_000_000_000n }, { amount: 2_000_000_000_000n }];
      const res = select(candidates, [dst]);
      assert.equal(res.selected.length, 2); // all candidates
      assert.equal(res.changeAmount, undefined);
      assert.equal(res.needsDummy, true); // one real output → needs a second
      assert.equal(res.fee, feeFor(2, [dst, { isChange: true }]));
      assert.equal(res.sweepAmount, total(candidates) - res.fee);
      assertConserves(res, [dst]);
    });

    it('two sweep targets: no dummy', () => {
      const dsts = [addr(), addr()];
      const candidates = [{ amount: 3_000_000_000_000n }, { amount: 2_000_000_000_000n }];
      const res = select(candidates, dsts);
      assert.equal(res.selected.length, 2);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, feeFor(2, dsts));
      assert.equal(res.sweepAmount, total(candidates) - res.fee);
      assertConserves(res, dsts);
    });

    it('mixed fixed + sweep: fixed honored, remainder is sweepAmount, no change', () => {
      const fixed = addr(1_000_000_000_000n);
      const sweep = addr();
      const candidates = [{ amount: 3_000_000_000_000n }, { amount: 2_000_000_000_000n }];
      const res = select(candidates, [fixed, sweep]);
      assert.equal(res.selected.length, 2);
      assert.equal(res.changeAmount, undefined);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, feeFor(2, [fixed, sweep]));
      assert.equal(res.sweepAmount, total(candidates) - fixed.amount - res.fee);
      assertConserves(res, [fixed, sweep]);
    });

    it('throws when funds cannot cover fixed + fee', () => {
      assert.throws(() => select([{ amount: 1_000n }], [addr(1_000_000_000_000n), addr()]), /not enough funds/);
    });

    it('sweep target can receive 0 (valid amount): sweepAmount === 0', () => {
      const dst = addr(); // sweep
      const fee = feeFor(1, [dst, { isChange: true }]); // 1 input, sweep + dummy
      const res = select([{ amount: fee }], [dst]);
      assert.equal(res.sweepAmount, 0n);
      assert.equal(res.needsDummy, true);
      assert.equal(res.fee, fee);
      assertConserves(res, [dst]);
    });
  });

  describe('validation', () => {
    it('throws on empty destinations', () => {
      assert.throws(() => select([{ amount: 1n }], []), /no destinations/);
    });

    it('throws when a destination is a change output', () => {
      const dst = { ...addr(1_000n), isChange: true };
      assert.throws(() => select([{ amount: 5_000_000_000_000n }], [dst]), /must not include change/);
    });
  });

  describe('fee sensitivity', () => {
    it('a larger ring size yields a larger fee', () => {
      const dst = addr(1_000_000_000_000n);
      const candidates = [{ amount: 5_000_000_000_000n }];
      const small = coinselect.selectInputs({
        candidates, destinations: [dst], ringSize: 4, baseFee: BASE_FEE, feeQuantization: FEE_QUANTIZATION, feeMultiplier: FEE_MULTIPLIER,
      });
      const big = select(candidates, [dst]); // ringSize 16
      assert.ok(big.fee > small.fee);
    });
  });
});
