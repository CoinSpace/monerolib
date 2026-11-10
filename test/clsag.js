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
import { constructFixtures } from './helpers/construct.js';
import e89415Ring from './fixtures/bpp_tx_e89415_ring.json' with { type: 'json' };
import txFixtures from './fixtures/txs.json' with { type: 'json' };
import { TORSION_ELEMENTS, addTorsion } from './helpers/common.js';

// The CLSAG message of a decoded BulletproofPlus transaction.
const messageOf = (decoded) => tx.getPreMlsagHash(
  crypto.fastHash(raw.txPrefix.encode(decoded.prefix)),
  decoded.rctSigBase,
  decoded.rctSigPrunable.bulletproofsPlus[0]
);

// The verify arguments of every input of a real transaction, with its rings as { key, mask } hex.
function realInputs(hex, rings) {
  const decoded = raw.fullTransaction.decode(hexToBytes(hex));
  const message = messageOf(decoded);
  return decoded.prefix.vin.map((vin, i) => ({
    message,
    ring: rings[i].map(({ key, mask }) => ({ publicKey: hexToBytes(key), commitment: hexToBytes(mask) })),
    pseudoOut: decoded.rctSigPrunable.pseudoOuts[i],
    signature: { ...decoded.rctSigPrunable.CLSAGs[i], I: vin.data.keyImage },
  }));
}

// https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/src/tests/transaction.rs#L221-L290
const OXIDE_INPUTS = realInputs(clsagTx.hex, clsagRingData);
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/ver_rct_non_semantics_simple_cached.cpp#L215-L238
const E89415_INPUTS = realInputs(txFixtures.find((fixture) => fixture.id === e89415Ring.id).hex, e89415Ring.rings);

const verify = ({
  message, ring, pseudoOut, signature,
}) => clsag.verifyClsag(message, ring, pseudoOut, signature);

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
  describe('verifyClsag on real transactions', () => {
    it('verifies the monero-oxide CLSAG vector', () => {
      assert.equal(OXIDE_INPUTS.length, 2);
      for (const input of OXIDE_INPUTS) {
        assert.ok(verify(input));
      }
    });

    it('verifies the mainnet transaction e89415 of monero', () => {
      assert.ok(verify(E89415_INPUTS[0]));
    });

    it('rejects e89415 when one ring commitment changes', () => {
      const [input] = E89415_INPUTS;
      const commitment = input.ring[5].commitment.slice();
      commitment[0] ^= 1;
      const ring = input.ring.map((member, i) => (i === 5 ? { ...member, commitment } : member));
      assert.ok(!verify({ ...input, ring }));
    });

    for (const fixture of constructFixtures) {
      it(`verifies every CLSAG of ${fixture.label}`, () => {
        const decoded = fixture.decode();
        const message = messageOf(decoded);
        decoded.prefix.vin.forEach((vin, i) => {
          assert.ok(clsag.verifyClsag(message, fixture.ringOf(vin), decoded.rctSigPrunable.pseudoOuts[i], {
            ...decoded.rctSigPrunable.CLSAGs[i], I: vin.data.keyImage,
          }));
        });
      });
    }
  });

  // https://github.com/monero-project/monero/blob/v0.18.5.1/src/ringct/rctSigs.cpp#L872-L895
  describe('verifyClsag rejects malformed signatures of the monero-oxide vector', () => {
    const [input] = OXIDE_INPUTS;
    const IDENTITY = hexToBytes('0100000000000000000000000000000000000000000000000000000000000000');
    const nonCanonical = (scalar) => helpers.encodeInt(helpers.decodeInt(scalar) + crypto.CURVE.n);

    it('rejects an empty ring', () => {
      assert.ok(!verify({
        ...input, ring: [], signature: { ...input.signature, s: [] },
      }));
    });

    it('rejects a non-canonical s scalar', () => {
      const s = input.signature.s.map((scalar, i) => (i === 3 ? nonCanonical(scalar) : scalar));
      assert.ok(!verify({ ...input, signature: { ...input.signature, s } }));
    });

    it('rejects a non-canonical c1', () => {
      assert.ok(!verify({ ...input, signature: { ...input.signature, c1: nonCanonical(input.signature.c1) } }));
    });

    it('rejects the identity as key image', () => {
      assert.ok(!verify({ ...input, signature: { ...input.signature, I: IDENTITY } }));
    });

    it('rejects an auxiliary key image D of small order', () => {
      for (const D of [IDENTITY, ...TORSION_ELEMENTS]) {
        assert.ok(!verify({ ...input, signature: { ...input.signature, D } }));
      }
    });

    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/ringct/clsag/src/tests/mod.rs#L70-L85
    it('rejects a ring member with a torsion component', () => {
      const publicKey = addTorsion(input.ring[0].publicKey, TORSION_ELEMENTS[1]);
      const ring = input.ring.map((member, i) => (i === 0 ? { ...member, publicKey } : member));
      assert.ok(!verify({ ...input, ring }));
    });

    it('rejects a ring member that is not a point', () => {
      const publicKey = new Uint8Array(32).fill(0xff);
      const ring = input.ring.map((member, i) => (i === 0 ? { ...member, publicKey } : member));
      assert.ok(!verify({ ...input, ring }));
    });

    it('rejects a pseudo output that is not a point', () => {
      assert.ok(!verify({ ...input, pseudoOut: new Uint8Array(32).fill(0xff) }));
    });
  });

  describe('proveClsag + verifyClsag round-trip', () => {
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
      assert.throws(() => {
        clsag.proveClsag(message, ring, pseudoOut, { ...signer, index });
      });
    }
    assert.throws(() => {
      clsag.proveClsag(message, [], pseudoOut, { ...signer, index: 0 });
    });
  });

  it('key image matches generateKeyImage', () => {
    const {
      message, ring, signer, pseudoOut, real,
    } = setup(4, 2);
    const sig = clsag.proveClsag(message, ring, pseudoOut, signer);
    assert.equal(bytesToHex(sig.I), bytesToHex(crypto.generateKeyImage(real.pub, real.sec)));
  });

  // mirrors monero TEST(ringct, CLSAG)
  // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/ringct.cpp#L141-L300
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
      // the same order-8 point as the monero unit test
      assert.ok(!clsag.verifyClsag(message, ring, pseudoOut, { ...sig, D: addTorsion(sig.D, TORSION_ELEMENTS[0]) }));
    });
  });
});
