import assert from 'node:assert/strict';
import {
  bytesToHex,
  hexToBytes,
  randomBytes,
} from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as clsag from '../lib/clsag.js';
import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import * as raw from '../lib/raw.js';
import * as ringct from '../lib/ringct.js';
import * as tx from '../lib/tx.js';
import clsagRingData from './fixtures/clsag_ring_data.json' with { type: 'json' };
import clsagTx from './fixtures/clsag_tx.json' with { type: 'json' };

// Build a valid ring with the real input at `index`, balanced (input amount == pseudoOut amount),
// so that C_nonzero[index] - pseudoOut = z*G with z = inMask - pseudoOutMask.
function setup(n, index) {
  const amount = 123456789n;
  const real = crypto.generateKeys();
  const inMask = crypto.randomScalar();
  const pseudoOutMask = crypto.randomScalar();
  const ring = [];
  for (let i = 0; i < n; i++) {
    if (i === index) {
      ring.push({
        publicKey: real.pub,
        commitment: ringct.pedersenCommitment(amount, inMask),
      });
    } else {
      ring.push({
        publicKey: crypto.generateKeys().pub,
        commitment: ringct.pedersenCommitment(1n, crypto.randomScalar()),
      });
    }
  }
  const pseudoOut = ringct.pedersenCommitment(amount, pseudoOutMask);
  return {
    message: randomBytes(32),
    ring,
    signer: {
      index,
      secretKey: real.sec,
      commitmentScalar: crypto.Fn.sub(inMask, pseudoOutMask),
    },
    pseudoOut,
    real,
  };
}

describe('clsag', () => {
  describe('sign + verify round-trip', () => {
    for (const [n, index] of [[1, 0], [2, 0], [2, 1], [11, 0], [11, 5], [11, 10], [16, 15]]) {
      it(`ring size ${n}, real index ${index}`, () => {
        const {
          message, ring, signer, pseudoOut,
        } = setup(n, index);
        const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
        assert.equal(sig.s.length, n);
        assert.ok(clsag.verifyClsag(message, ring, pseudoOut, sig));
      });
    }
  });

  it('proveClsag rejects an invalid signing index', () => {
    const {
      message, ring, pseudoOut, signer,
    } = setup(8, 3);
    for (const index of [8, -1, 1.5, NaN, '1']) {
      assert.throws(() => clsag.proveClsag(message, ring, pseudoOut, { ...signer, index }));
    }
    assert.throws(() => clsag.proveClsag(message, [], pseudoOut, { ...signer, index: 0 }));
  });

  it('key image matches generateKeyImage', () => {
    const {
      message, ring, signer, pseudoOut, real,
    } = setup(4, 2);
    const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
    assert.equal(bytesToHex(sig.I), bytesToHex(crypto.generateKeyImage(real.pub, real.sec)));
  });

  it('verifies the fixed monero-oxide CLSAG tx vector', () => {
    const parsed = raw.transaction.decode(hexToBytes(clsagTx.hex));
    const message = tx.getPreMlsagHash(
      crypto.fastHash(raw.txPrefix.encode(parsed.prefix)),
      parsed.rctSigBase,
      parsed.rctSigPrunable.bulletproofsPlus[0]
    );
    assert.equal(parsed.prefix.vin.length, clsagRingData.length);
    assert.equal(parsed.rctSigPrunable.CLSAGs.length, clsagRingData.length);
    for (let i = 0; i < clsagRingData.length; i++) {
      const ring = clsagRingData[i].map((out) => ({
        publicKey: hexToBytes(out.key),
        commitment: hexToBytes(out.mask),
      }));
      const sig = {
        ...parsed.rctSigPrunable.CLSAGs[i],
        I: parsed.prefix.vin[i].data.keyImage,
      };
      assert.ok(clsag.verifyClsag(message, ring, parsed.rctSigPrunable.pseudoOuts[i], sig));
    }
  });

  // mirrors monero TEST(ringct, CLSAG)
  // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/ringct.cpp#L141-L300
  describe('rejects invalid signatures', () => {
    // bad inputs at signing time → must fail verification
    it('wrong real index at creation', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(
        message,
        ring,
        pseudoOut,
        { ...signer, index: (signer.index + 1) % 8 }
      );
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, sig));
    });

    it('wrong commitment mask z at creation', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(
        message,
        ring,
        pseudoOut,
        { ...signer, commitmentScalar: crypto.randomScalar() }
      );
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, sig));
    });

    it('wrong spend key p at creation', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(
        message,
        ring,
        pseudoOut,
        { ...signer, secretKey: crypto.randomScalar() }
      );
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, sig));
    });

    it('bad output key P at creation', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      ring[signer.index] = { publicKey: crypto.generateKeys().pub, commitment: ring[signer.index].commitment };
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, sig));
    });

    it('bad commitment C at creation', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      ring[signer.index] = {
        publicKey: ring[signer.index].publicKey,
        commitment: ringct.pedersenCommitment(1n, crypto.randomScalar()),
      };
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, sig));
    });

    // tampering at verification time → must fail
    it('wrong message', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(randomBytes(32), ring, pseudoOut, sig));
    });

    it('wrong pseudoOut commitment', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(
        message,
        ring,
        ringct.pedersenCommitment(999n, crypto.randomScalar()),
        sig
      ));
    });

    it('tampered s scalar', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      sig.s[0] = helpers.encodeInt(crypto.randomScalar());
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, sig));
    });

    it('wrong number of s elements', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, s: sig.s.slice(0, -1) }));
      const extra = helpers.encodeInt(crypto.randomScalar());
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, s: [...sig.s, extra] }));
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, s: [] }));
    });

    it('tampered c1', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(
        message,
        ring,
        pseudoOut,
        { ...sig, c1: helpers.encodeInt(crypto.randomScalar()) }
      ));
    });

    it('tampered key image I', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, I: crypto.generateKeys().pub }));
    });

    it('tampered auxiliary key image D', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, D: crypto.generateKeys().pub }));
    });

    it('swapped I and D', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, {
        ...sig, I: sig.D, D: sig.I,
      }));
    });

    it('D not in main subgroup', () => {
      const {
        message, ring, signer, pseudoOut,
      } = setup(8, 3);
      const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
      // add an order-8 torsion point to D (same constant as the monero unit test)
      const torsion = crypto.decodePoint(
        hexToBytes('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa')
      );
      const D = crypto.encodePoint(crypto.decodePoint(sig.D).add(torsion));
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, D }));
    });
  });
});
