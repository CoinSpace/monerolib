import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { randomBytes } from '@noble/hashes/utils.js';

import * as coinselect from '../lib/coinselect.js';

describe('coinselect', () => {
  const RING_SIZE = 16;
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
      assert.equal(res.fee, 1_540_000n);
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
      const res = select([{ amount: 1_000_001_540_000n }], [dst]);
      assert.equal(res.selected.length, 1);
      assert.equal(res.changeAmount, undefined);
      assert.equal(res.needsDummy, true);
      assert.equal(res.fee, 1_540_000n);
      assertConserves(res, [dst]);
    });

    it('single subaddress accepts funds that cover the destination, fee, and positive change', () => {
      const dst = addr(1_000_000_000_000n, 'subaddress');
      const res = select([{ amount: 1_000_001_540_001n }], [dst]);
      assert.equal(res.selected.length, 1);
      assert.equal(res.changeAmount, 1n);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, 1_540_000n);
      assertConserves(res, [dst]);
    });

    it('multiple destinations: change output, no dummy', () => {
      const dsts = [addr(1_000_000_000_000n), addr(2_000_000_000_000n)];
      const res = select([{ amount: 5_000_000_000_000n }], dsts);
      assert.ok(res.changeAmount > 0n);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, 2_130_000n);
      assertConserves(res, dsts);
    });

    it('covers a no-change tx but not the extra change-output fee: no change, remainder to fee', () => {
      const dsts = [addr(1_000_000_000_000n), addr(2_000_000_000_000n)]; // 2 outputs, change would be a 3rd
      // exactly enough for the no-change tx; a change output would cost more fee than the leftover
      const res = select([{ amount: 3_000_001_540_000n }], dsts);
      assert.equal(res.selected.length, 1);
      assert.equal(res.changeAmount, undefined);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, 1_540_000n);
      assertConserves(res, dsts);
    });

    it('throws when funds cannot cover amount + fee', () => {
      assert.throws(() => {
        select([{ amount: 1_000n }], [addr(1_000_000_000_000n)]);
      }, /not enough funds/);
    });

    it('not enough funds: error.fee is for the candidates that fit in TX_WEIGHT_TARGET, at least 1 input', () => {
      const dst = addr(1_000_000_000_000n);
      assert.throws(() => {
        select([{ amount: 1_000n }, { amount: 2_000n }], [dst]);
      }, { message: /not enough funds/, fee: 2_220_000n });
      assert.throws(() => {
        select([], [dst]);
      }, { message: /not enough funds/, fee: 1_540_000n });
      assert.throws(() => {
        select(Array.from({ length: 300 }, () => ({ amount: 1_000n })), [dst]);
      }, { message: /not enough funds/, fee: 99_320_000n });
    });

    it('too many small inputs: transaction too large; total too small: not enough funds', () => {
      const candidates = Array.from({ length: 300 }, () => ({ amount: 1_000_000_000n }));
      assert.throws(() => {
        select(candidates, [addr(200_000_000_000n)]);
      }, /transaction too large/);
      assert.throws(() => {
        select(candidates, [addr(301_000_000_000n)]);
      }, /not enough funds/);
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
      assert.equal(res.fee, 2_220_000n);
      assert.equal(res.sweepAmount, total(candidates) - res.fee);
      assertConserves(res, [dst]);
    });

    it('two sweep targets: no dummy', () => {
      const dsts = [addr(), addr()];
      const candidates = [{ amount: 3_000_000_000_000n }, { amount: 2_000_000_000_000n }];
      const res = select(candidates, dsts);
      assert.equal(res.selected.length, 2);
      assert.equal(res.needsDummy, false);
      assert.equal(res.fee, 2_220_000n);
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
      assert.equal(res.fee, 2_220_000n);
      assert.equal(res.sweepAmount, total(candidates) - fixed.amount - res.fee);
      assertConserves(res, [fixed, sweep]);
    });

    it('throws when funds cannot cover fixed + fee', () => {
      assert.throws(() => {
        select([{ amount: 1_000n }], [addr(1_000_000_000_000n), addr()]);
      }, /not enough funds/);
    });

    it('not enough funds: error.fee is for the candidates that fit in TX_WEIGHT_TARGET, at least 1 input', () => {
      const dsts = [addr(1_000_000_000_000n), addr()];
      assert.throws(() => {
        select([{ amount: 1_000n }, { amount: 2_000n }], dsts);
      }, { message: /not enough funds/, fee: 2_220_000n });
      assert.throws(() => {
        select([], dsts);
      }, { message: /not enough funds/, fee: 1_540_000n });
      assert.throws(() => {
        select(Array.from({ length: 300 }, () => ({ amount: 1_000n })), dsts);
      }, { message: /not enough funds/, fee: 99_320_000n });
    });

    it('takes the largest candidates that fit in TX_WEIGHT_TARGET', () => {
      const dst = addr();
      const candidates = Array.from({ length: 300 }, (_, i) => ({
        amount: BigInt((i * 7919) % 300 + 1) * 1_000_000_000n,
      }));
      const res = select(candidates, [dst]);
      assert.equal(res.selected.length, 145);
      const largest = candidates.map((c) => c.amount).sort((a, b) => (b > a ? 1 : -1)).slice(0, 145);
      assert.deepStrictEqual(res.selected.map((c) => c.amount), largest);
      assert.equal(res.fee, 99_320_000n);
      assert.equal(res.sweepAmount, total(res.selected) - res.fee);
      assertConserves(res, [dst]);
    });

    it('uses maxWeight from the caller', () => {
      const dst = addr();
      const candidates = Array.from({ length: 300 }, () => ({ amount: 1_000_000_000n }));
      const res = coinselect.selectInputs({
        candidates,
        destinations: [dst],
        ringSize: RING_SIZE,
        baseFee: BASE_FEE,
        feeQuantization: FEE_QUANTIZATION,
        maxWeight: 7647,
      });
      assert.equal(res.selected.length, 10);
    });

    it('sweep target can receive 0 (valid amount): sweepAmount === 0', () => {
      const dst = addr(); // sweep
      const res = select([{ amount: 1_540_000n }], [dst]);
      assert.equal(res.sweepAmount, 0n);
      assert.equal(res.needsDummy, true);
      assert.equal(res.fee, 1_540_000n);
      assertConserves(res, [dst]);
    });
  });

  describe('validation', () => {
    it('throws on empty destinations', () => {
      assert.throws(() => {
        select([{ amount: 1n }], []);
      }, /no destinations/);
    });

    it('throws when a destination is a change output', () => {
      const dst = { ...addr(1_000n), isChange: true };
      assert.throws(() => {
        select([{ amount: 5_000_000_000_000n }], [dst]);
      }, /must not include change/);
    });
  });

  describe('fee sensitivity', () => {
    it('a larger ring size yields a larger fee', () => {
      const dst = addr(1_000_000_000_000n);
      const candidates = [{ amount: 5_000_000_000_000n }];
      const small = coinselect.selectInputs({
        candidates,
        destinations: [dst],
        ringSize: 4,
        baseFee: BASE_FEE,
        feeQuantization: FEE_QUANTIZATION,
        feeMultiplier: FEE_MULTIPLIER,
      });
      const big = select(candidates, [dst]); // ringSize 16
      assert.ok(big.fee > small.fee);
    });
  });
});
