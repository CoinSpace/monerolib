import assert from 'node:assert/strict';
import { encodeInt } from '../lib/helpers.js';
import { pedersenCommitment } from '../lib/ringct.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { decodePoint, encodePoint, generateKeyImage, generateKeys, randomScalar } from '../lib/crypto-util.js';
import { describe, it } from 'node:test';
import { proveClsag, verifyClsag } from '../lib/clsag.js';

// Build a valid ring with the real input at `index`, balanced (input amount == pseudoOut amount),
// so that C_nonzero[index] - Cout = z*G with z = inMask - a.
function setup(n, index) {
  const amount = 123456789n;
  const real = generateKeys();
  const inMask = randomScalar();
  const a = randomScalar(); // pseudoOut mask
  const pubs = [];
  for (let i = 0; i < n; i++) {
    if (i === index) {
      pubs.push({ dest: real.pub, mask: pedersenCommitment(amount, inMask) });
    } else {
      pubs.push({ dest: generateKeys().pub, mask: pedersenCommitment(1n, randomScalar()) });
    }
  }
  const Cout = pedersenCommitment(amount, a);
  return { message: randomBytes(32), pubs, inSk: { dest: real.sec, mask: inMask }, a, Cout, index, real };
}

describe('clsag', () => {
  describe('sign + verify round-trip', () => {
    for (const [n, index] of [[1, 0], [2, 0], [2, 1], [11, 0], [11, 5], [11, 10], [16, 15]]) {
      it(`ring size ${n}, real index ${index}`, () => {
        const { message, pubs, inSk, a, Cout } = setup(n, index);
        const sig = proveClsag(message, pubs, inSk, a, Cout, index);
        assert.equal(sig.s.length, n);
        assert.ok(verifyClsag(message, sig, pubs, Cout));
      });
    }
  });

  it('proveClsag rejects an invalid signing index', () => {
    const { message, pubs, inSk, a, Cout } = setup(8, 3);
    for (const index of [8, -1, 1.5, NaN, '1']) {
      assert.throws(() => proveClsag(message, pubs, inSk, a, Cout, index));
    }
    assert.throws(() => proveClsag(message, [], inSk, a, Cout, 0));
  });

  it('key image matches generateKeyImage', () => {
    const { message, pubs, inSk, a, Cout, index, real } = setup(4, 2);
    const sig = proveClsag(message, pubs, inSk, a, Cout, index);
    assert.equal(bytesToHex(sig.I), bytesToHex(generateKeyImage(real.pub, real.sec)));
  });

  // mirrors monero TEST(ringct, CLSAG)
  // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/ringct.cpp#L141-L300
  describe('rejects invalid signatures', () => {
    // bad inputs at signing time → must fail verification
    it('wrong real index at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, (index + 1) % 8);
      assert.ok(!verifyClsag(message, sig, pubs, Cout));
    });

    it('wrong commitment mask z at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, { dest: inSk.dest, mask: randomScalar() }, a, Cout, index);
      assert.ok(!verifyClsag(message, sig, pubs, Cout));
    });

    it('wrong spend key p at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, { dest: randomScalar(), mask: inSk.mask }, a, Cout, index);
      assert.ok(!verifyClsag(message, sig, pubs, Cout));
    });

    it('bad output key P at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      pubs[index] = { dest: generateKeys().pub, mask: pubs[index].mask };
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, sig, pubs, Cout));
    });

    it('bad commitment C at creation', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      pubs[index] = { dest: pubs[index].dest, mask: pedersenCommitment(1n, randomScalar()) };
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, sig, pubs, Cout));
    });

    // tampering at verification time → must fail
    it('wrong message', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(randomBytes(32), sig, pubs, Cout));
    });

    it('wrong pseudoOut commitment', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, sig, pubs, pedersenCommitment(999n, randomScalar())));
    });

    it('tampered s scalar', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      sig.s[0] = encodeInt(randomScalar());
      assert.ok(!verifyClsag(message, sig, pubs, Cout));
    });

    it('wrong number of s elements', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, { ...sig, s: sig.s.slice(0, -1) }, pubs, Cout));
      assert.ok(!verifyClsag(message, { ...sig, s: [...sig.s, encodeInt(randomScalar())] }, pubs, Cout));
      assert.ok(!verifyClsag(message, { ...sig, s: [] }, pubs, Cout));
    });

    it('tampered c1', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, { ...sig, c1: encodeInt(randomScalar()) }, pubs, Cout));
    });

    it('tampered key image I', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, { ...sig, I: generateKeys().pub }, pubs, Cout));
    });

    it('tampered auxiliary key image D', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, { ...sig, D: generateKeys().pub }, pubs, Cout));
    });

    it('swapped I and D', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      assert.ok(!verifyClsag(message, { ...sig, I: sig.D, D: sig.I }, pubs, Cout));
    });

    it('D not in main subgroup', () => {
      const { message, pubs, inSk, a, Cout, index } = setup(8, 3);
      const sig = proveClsag(message, pubs, inSk, a, Cout, index);
      // add an order-8 torsion point to D (same constant as the monero unit test)
      const torsion = decodePoint(hexToBytes('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'));
      const D = encodePoint(decodePoint(sig.D).add(torsion));
      assert.ok(!verifyClsag(message, { ...sig, D }, pubs, Cout));
    });
  });
});
