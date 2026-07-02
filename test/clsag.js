import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as clsag from '../lib/clsag.js';
import * as cryptoUtil from '../lib/crypto-util.js';
import * as helpers from '../lib/helpers.js';
import * as ringct from '../lib/ringct.js';

// Build a valid ring with the real input at `index`, balanced (input amount == pseudoOut amount),
// so that C_nonzero[index] - Cout = z*G with z = inMask - a.
function setup(n, index) {
  const amount = 123456789n;
  const real = cryptoUtil.generateKeys();
  const inMask = cryptoUtil.randomScalar();
  const a = cryptoUtil.randomScalar(); // pseudoOut mask
  const pubs = [];
  for (let i = 0; i < n; i++) {
    if (i === index) {
      pubs.push({ dest: real.pub, mask: ringct.pedersenCommitment(amount, inMask) });
    } else {
      pubs.push({
        dest: cryptoUtil.generateKeys().pub,
        mask: ringct.pedersenCommitment(1n, cryptoUtil.randomScalar()),
      });
    }
  }
  const Cout = ringct.pedersenCommitment(amount, a);
  return { message: randomBytes(32), pubs, inSk: { dest: real.sec, mask: inMask }, a, Cout, index, real };
}

describe('clsag', () => {
  describe('sign + verify round-trip', () => {
    for (const [n, index] of [[1, 0], [2, 0], [2, 1], [11, 0], [11, 5], [11, 10], [16, 15]]) {
      it(`ring size ${n}, real index ${index}`, () => {
        const { message, pubs, inSk, a, Cout } = setup(n, index);
        const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
        assert.equal(sig.s.length, n);
        assert.ok(clsag.verifyClsag(message, sig, pubs, Cout));
      });
    }
  });

  it('proveClsag rejects an invalid signing index', () => {
    const { message, pubs, inSk, a, Cout } = setup(8, 3);
    for (const index of [8, -1, 1.5, NaN, '1']) {
      assert.throws(() => clsag.proveClsag(message, pubs, inSk, a, Cout, index));
    }
    assert.throws(() => clsag.proveClsag(message, [], inSk, a, Cout, 0));
  });

  it('key image matches generateKeyImage', () => {
    const { message, pubs, inSk, a, Cout, index, real } = setup(4, 2);
    const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
    assert.equal(bytesToHex(sig.I), bytesToHex(cryptoUtil.generateKeyImage(real.pub, real.sec)));
  });

  // mirrors monero TEST(ringct, CLSAG)
  // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/ringct.cpp#L141-L300
  describe('rejects invalid signatures', () => {
    // bad inputs at signing time → must fail verification
    it('wrong real index at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, (index + 1) % 8);
      assert.ok(!clsag.verifyClsag(message, sig, pubs, Cout));
    });

    it('wrong commitment mask z at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, { dest: inSk.dest, mask: cryptoUtil.randomScalar() }, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, sig, pubs, Cout));
    });

    it('wrong spend key p at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, { dest: cryptoUtil.randomScalar(), mask: inSk.mask }, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, sig, pubs, Cout));
    });

    it('bad output key P at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      pubs[index] = { dest: cryptoUtil.generateKeys().pub, mask: pubs[index].mask };
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, sig, pubs, Cout));
    });

    it('bad commitment C at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      pubs[index] = { dest: pubs[index].dest, mask: ringct.pedersenCommitment(1n, cryptoUtil.randomScalar()) };
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, sig, pubs, Cout));
    });

    // tampering at verification time → must fail
    it('wrong message', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(randomBytes(32), sig, pubs, Cout));
    });

    it('wrong pseudoOut commitment', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, sig, pubs, ringct.pedersenCommitment(999n, cryptoUtil.randomScalar())));
    });

    it('tampered s scalar', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      sig.s[0] = helpers.encodeInt(cryptoUtil.randomScalar());
      assert.ok(!clsag.verifyClsag(message, sig, pubs, Cout));
    });

    it('wrong number of s elements', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, { ...sig, s: sig.s.slice(0, -1) }, pubs, Cout));
      const extra = helpers.encodeInt(cryptoUtil.randomScalar());
      assert.ok(!clsag.verifyClsag(message, { ...sig, s: [...sig.s, extra] }, pubs, Cout));
      assert.ok(!clsag.verifyClsag(message, { ...sig, s: [] }, pubs, Cout));
    });

    it('tampered c1', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, { ...sig, c1: helpers.encodeInt(cryptoUtil.randomScalar()) }, pubs, Cout));
    });

    it('tampered key image I', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, { ...sig, I: cryptoUtil.generateKeys().pub }, pubs, Cout));
    });

    it('tampered auxiliary key image D', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, { ...sig, D: cryptoUtil.generateKeys().pub }, pubs, Cout));
    });

    it('swapped I and D', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!clsag.verifyClsag(message, { ...sig, I: sig.D, D: sig.I }, pubs, Cout));
    });

    it('D not in main subgroup', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = clsag.proveClsag(message, pubs, inSk, a, Cout, index);
      // add an order-8 torsion point to D (same constant as the monero unit test)
      const torsion = cryptoUtil.decodePoint(
        hexToBytes('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa')
      );
      const D = cryptoUtil.encodePoint(cryptoUtil.decodePoint(sig.D).add(torsion));
      assert.ok(!clsag.verifyClsag(message, { ...sig, D }, pubs, Cout));
    });
  });
});
