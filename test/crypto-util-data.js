/* eslint-disable max-len */
import { FpSqrtEven } from '@noble/curves/abstract/modular.js';
import assert from 'node:assert/strict';
import { A, H, INV_EIGHT, fffb1, fffb2, fffb3, fffb4, ma, sqrtm1 } from '../lib/crypto-util-data.js';
import { Fn, Fp, Point, decodePoint, encodePoint, fastHash } from '../lib/crypto-util.js';
import { describe, it } from 'node:test';

// ref10 fe: a field element mod 2^255-19 stored as 10 signed limbs, radix 2^25.5
// (even limbs hold 26 bits, odd 25 bits). Decodes one to a bigint.
const P = 2n ** 255n - 19n;
const OFFSETS = [0n, 26n, 51n, 77n, 102n, 128n, 153n, 179n, 204n, 230n];
const feToBigInt = (limbs) => {
  let value = 0n;
  for (let i = 0; i < 10; i++) {
    value += BigInt(limbs[i]) << OFFSETS[i];
  }
  return ((value % P) + P) % P;
};

describe('crypto-util-data', () => {
  // monero stores the even square root (least significant bit 0), which FpSqrtEven reproduces.
  // https://github.com/monero-project/monero/tree/v0.18.5.0/src/crypto/crypto_ops_builder
  describe('even square root of the formula', () => {
    it('ma = -A', () => {
      assert.equal(ma, Fp.neg(A));
    });

    it('sqrtm1 = sqrt(-1)', () => {
      assert.equal(sqrtm1, FpSqrtEven(Fp, Fp.neg(1n)));
    });

    it('fffb1 = sqrt(-2 * A * (A + 2))', () => {
      assert.equal(fffb1, FpSqrtEven(Fp, Fp.mul(Fp.mul(Fp.add(A, 2n), A), Fp.neg(2n))));
    });

    it('fffb2 = sqrt(2 * A * (A + 2))', () => {
      assert.equal(fffb2, FpSqrtEven(Fp, Fp.mul(Fp.mul(Fp.add(A, 2n), A), 2n)));
    });

    it('fffb3 = sqrt(-sqrt(-1) * A * (A + 2))', () => {
      assert.equal(fffb3, FpSqrtEven(Fp, Fp.mul(Fp.mul(Fp.add(A, 2n), A), Fp.neg(sqrtm1))));
    });

    it('fffb4 = sqrt(sqrt(-1) * A * (A + 2))', () => {
      assert.equal(fffb4, FpSqrtEven(Fp, Fp.mul(Fp.mul(Fp.add(A, 2n), A), sqrtm1)));
    });
  });

  // exact fe constants from monero crypto-ops-data.c
  describe('match monero crypto-ops-data.c', () => {
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L868
    it('ma', () => {
      assert.equal(ma, feToBigInt([-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L38
    it('sqrtm1', () => {
      assert.equal(sqrtm1, feToBigInt([-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L869
    it('fffb1', () => {
      assert.equal(fffb1, feToBigInt([-31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L870
    it('fffb2', () => {
      assert.equal(fffb2, feToBigInt([8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L871
    it('fffb3', () => {
      assert.equal(fffb3, feToBigInt([-13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L872
    it('fffb4', () => {
      assert.equal(fffb4, feToBigInt([-21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324]));
    });
  });

  // verify the hardcoded rct byte constants are mathematically what monero says they are
  describe('rct constants', () => {
    // H = 8 * decodePoint(cn_fast_hash(G)), G the basepoint
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L633
    it('H is the second generator', () => {
      const derived = decodePoint(fastHash(encodePoint(Point.BASE))).clearCofactor();
      assert.ok(H.equals(derived));
    });

    // INV_EIGHT = 1/8 mod l
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.h#L67
    it('INV_EIGHT is 1/8 mod l', () => {
      assert.equal(INV_EIGHT, Fn.inv(8n));
    });
  });
});
