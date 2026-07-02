/* eslint-disable max-len */
import { FpSqrtEven } from '@noble/curves/abstract/modular.js';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import * as cryptoUtil from '../lib/crypto-util.js';
import * as cryptoUtilData from '../lib/crypto-util-data.js';

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
      assert.equal(cryptoUtilData.ma, cryptoUtil.Fp.neg(cryptoUtilData.A));
    });

    it('sqrtm1 = sqrt(-1)', () => {
      assert.equal(cryptoUtilData.sqrtm1, FpSqrtEven(cryptoUtil.Fp, cryptoUtil.Fp.neg(1n)));
    });

    it('fffb1 = sqrt(-2 * A * (A + 2))', () => {
      assert.equal(cryptoUtilData.fffb1, FpSqrtEven(cryptoUtil.Fp, cryptoUtil.Fp.mul(cryptoUtil.Fp.mul(cryptoUtil.Fp.add(cryptoUtilData.A, 2n), cryptoUtilData.A), cryptoUtil.Fp.neg(2n))));
    });

    it('fffb2 = sqrt(2 * A * (A + 2))', () => {
      assert.equal(cryptoUtilData.fffb2, FpSqrtEven(cryptoUtil.Fp, cryptoUtil.Fp.mul(cryptoUtil.Fp.mul(cryptoUtil.Fp.add(cryptoUtilData.A, 2n), cryptoUtilData.A), 2n)));
    });

    it('fffb3 = sqrt(-sqrt(-1) * A * (A + 2))', () => {
      assert.equal(cryptoUtilData.fffb3, FpSqrtEven(cryptoUtil.Fp, cryptoUtil.Fp.mul(cryptoUtil.Fp.mul(cryptoUtil.Fp.add(cryptoUtilData.A, 2n), cryptoUtilData.A), cryptoUtil.Fp.neg(cryptoUtilData.sqrtm1))));
    });

    it('fffb4 = sqrt(sqrt(-1) * A * (A + 2))', () => {
      assert.equal(cryptoUtilData.fffb4, FpSqrtEven(cryptoUtil.Fp, cryptoUtil.Fp.mul(cryptoUtil.Fp.mul(cryptoUtil.Fp.add(cryptoUtilData.A, 2n), cryptoUtilData.A), cryptoUtilData.sqrtm1)));
    });
  });

  // exact fe constants from monero crypto-ops-data.c
  describe('match monero crypto-ops-data.c', () => {
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L868
    it('ma', () => {
      assert.equal(cryptoUtilData.ma, feToBigInt([-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L38
    it('sqrtm1', () => {
      assert.equal(cryptoUtilData.sqrtm1, feToBigInt([-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L869
    it('fffb1', () => {
      assert.equal(cryptoUtilData.fffb1, feToBigInt([-31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L870
    it('fffb2', () => {
      assert.equal(cryptoUtilData.fffb2, feToBigInt([8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L871
    it('fffb3', () => {
      assert.equal(cryptoUtilData.fffb3, feToBigInt([-13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756]));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L872
    it('fffb4', () => {
      assert.equal(cryptoUtilData.fffb4, feToBigInt([-21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324]));
    });
  });

  // verify the hardcoded rct byte constants are mathematically what monero says they are
  describe('rct constants', () => {
    // H = 8 * decodePoint(cn_fast_hash(G)), G the basepoint
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L633
    it('H is the second generator', () => {
      const derived = cryptoUtil.decodePoint(cryptoUtil.fastHash(cryptoUtil.encodePoint(cryptoUtil.Point.BASE))).clearCofactor();
      assert.ok(cryptoUtilData.H.equals(derived));
    });

    // INV_EIGHT = 1/8 mod l
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.h#L67
    it('INV_EIGHT is 1/8 mod l', () => {
      assert.equal(cryptoUtilData.INV_EIGHT, cryptoUtil.Fn.inv(8n));
    });
  });
});
