import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { hexToBytes, randomBytes } from '@noble/hashes/utils.js';

import * as bulletproofs from '../lib/bulletproofs.js';
import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import * as raw from '../lib/raw.js';

import clsagTx from './fixtures/clsag_tx.json' with { type: 'json' };
import { constructFixtures } from './helpers/construct.js';
import txs from './fixtures/txs.json' with { type: 'json' };
import { TORSION_ELEMENTS, addTorsion } from './helpers/common.js';

const proofOutputs = (amounts) => amounts.map((amount) => ({ amount, mask: crypto.randomScalar() }));
const nonCanonical = (scalar) => helpers.encodeInt(helpers.decodeInt(scalar) + crypto.CURVE.n);

// Every real transaction of the fixtures with its decoded form.
const realTxs = [
  ...txs.map(({ label, hex }) => ({ label, decoded: raw.fullTransaction.decode(hexToBytes(hex)) })),
  { label: 'monero-oxide clsag_tx', decoded: raw.fullTransaction.decode(hexToBytes(clsagTx.hex)) },
  ...constructFixtures.map(({ label, decode }) => ({ label, decoded: decode() })),
];
const withProof = (field) => realTxs.filter(({ decoded }) => decoded.rctSigPrunable?.[field]);

// https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/ringct/bulletproofs/src/tests/original/mod.rs#L13-L111
const ORIGINAL_BP_PROOF = {
  A: hexToBytes('ef32c0b9551b804decdcb107eb22aa715b7ce259bf3c5cac20e24dfa6b28ac71'),
  S: hexToBytes('e1285960861783574ee2b689ae53622834eb0b035d6943103f960cd23e063fa0'),
  T1: hexToBytes('4ea07735f184ba159d0e0eb662bac8cde3eb7d39f31e567b0fbda3aa23fe5620'),
  T2: hexToBytes('b8390aa4b60b255630d40e592f55ec6b7ab5e3a96bfcdcd6f1cd1d2fc95f441e'),
  taux: hexToBytes('5957dba8ea9afb23d6e81cc048a92f2d502c10c749dc1b2bd148ae8d41ec7107'),
  mu: hexToBytes('923023b234c2e64774b820b4961f7181f6c1dc152c438643e5a25b0bf271bc02'),
  L: [
    'c45f656316b9ebf9d357fb6a9f85b5f09e0b991dd50a6e0ae9b02de3946c9d99',
    '9304d2bf0f27183a2acc58cc755a0348da11bd345485fda41b872fee89e72aac',
    '1bb8b71925d155dd9569f64129ea049d6149fdc4e7a42a86d9478801d922129b',
    '5756a7bf887aa72b9a952f92f47182122e7b19d89e5dd434c747492b00e1c6b7',
    '6e497c910d102592830555356af5ff8340e8d141e3fb60ea24cfa587e964f07d',
    'f4fa3898e7b08e039183d444f3d55040f3c790ed806cb314de49f3068bdbb218',
    '0bbc37597c3ead517a3841e159c8b7b79a5ceaee24b2a9a20350127aab428713',
  ].map(hexToBytes),
  R: [
    '609420ba1702781692e84accfd225adb3d077aedc3cf8125563400466b52dbd9',
    'fb4e1d079e7a2b0ec14f7e2a3943bf50b6d60bc346a54fcf562fb234b342abf8',
    '6ae3ac97289c48ce95b9c557289e82a34932055f7f5e32720139824fe81b12e5',
    'd071cc2ffbdab2d840326ad15f68c01da6482271cae3cf644670d1632f29a15c',
    'e52a1754b95e1060589ba7ce0c43d0060820ebfc0d49dc52884bc3c65ad18af5',
    '41573b06140108539957df71aceb4b1816d2409ce896659aa5c86f037ca5e851',
    'a65970b2cc3c7b08b2b5b739dbc8e71e646783c41c625e2a5b1535e3d2e0f742',
  ].map(hexToBytes),
  a: hexToBytes('0077c5383dea44d3cd1bc74849376bd60679612dc4b945255822457fa0c0a209'),
  b: hexToBytes('fe80cf5756473482581e1d38644007793ddc66fdeb9404ec1689a907e4863302'),
  t: hexToBytes('40dfb08e09249040df997851db311bd6827c26e87d6f0f332c55be8eef10e603'),
};
// the commitments are stored * INV_EIGHT, so recover them with a cofactor multiplication
const ORIGINAL_BP_V = [
  '8e8f23f315edae4f6c2f948d9a861e0ae32d356b933cd11d2f0e031ac744c41f',
  '2829cbd025aa54cd6e1b59a032564f22f0b2e5627f7f2c4297f90da438b5510f',
].map((h) => crypto.encodePoint(crypto.decodePoint(hexToBytes(h)).clearCofactor()));

// The mainnet BulletproofPlus of e89415, the fixed proof that the tamper tests below change.
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/data/txs/bpp_tx_e89415.bin
const E89415 = realTxs.find(({ label }) => label.includes('e89415')).decoded;
const BPP = E89415.rctSigPrunable.bulletproofsPlus[0];
const BPP_V = E89415.rctSigBase.outPk;

describe('Bulletproof+', () => {
  describe('verifyBulletproofPlus', () => {
    for (const { label, decoded } of withProof('bulletproofsPlus')) {
      it(`verifies a real proof: ${label}`, () => {
        const { outPk } = decoded.rctSigBase;
        assert.ok(bulletproofs.verifyBulletproofPlus(outPk, decoded.rctSigPrunable.bulletproofsPlus[0]));
      });
    }

    it('rejects a tampered scalar r1', () => {
      const r1 = helpers.encodeInt(helpers.decodeInt(BPP.r1) + 1n);
      assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, { ...BPP, r1 }));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/ringct/bulletproofs_plus.cc#L824-L827
    it('rejects non-canonical proof scalars', () => {
      for (const field of ['r1', 's1', 'd1']) {
        assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, { ...BPP, [field]: nonCanonical(BPP[field]) }), field);
      }
    });

    it('rejects a tampered point A', () => {
      assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, { ...BPP, A: crypto.secretKeyToPublicKey(1n) }));
    });

    it('rejects wrong commitments', () => {
      assert.ok(!bulletproofs.verifyBulletproofPlus([BPP_V[0], BPP_V[0]], BPP));
    });

    it('rejects no commitments and more than 16 commitments', () => {
      assert.ok(!bulletproofs.verifyBulletproofPlus([], BPP));
      assert.ok(!bulletproofs.verifyBulletproofPlus(Array.from({ length: 17 }, () => BPP_V[0]), BPP));
    });

    it('rejects L and R rounds that do not match the commitment count', () => {
      assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, {
        ...BPP, L: BPP.L.slice(1), R: BPP.R.slice(1),
      }));
    });

    it('rejects a proof point that is not a point', () => {
      assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, { ...BPP, A1: new Uint8Array(32).fill(0xff) }));
    });

    // invalid_torsion: adding any low-order point to V, L, R, A, A1 or B must break verification
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/bulletproofs_plus.cpp#L126-L169
    it('rejects torsioned points', () => {
      for (const torsion of TORSION_ELEMENTS) {
        for (const field of ['A', 'A1', 'B']) {
          assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, { ...BPP, [field]: addTorsion(BPP[field], torsion) }));
        }
        for (const field of ['L', 'R']) {
          const points = BPP[field].map((point, i) => (i === 0 ? addTorsion(point, torsion) : point));
          assert.ok(!bulletproofs.verifyBulletproofPlus(BPP_V, { ...BPP, [field]: points }));
        }
        assert.ok(!bulletproofs.verifyBulletproofPlus([addTorsion(BPP_V[0], torsion), BPP_V[1]], BPP));
      }
    });
  });

  describe('proveRangeBulletproofPlus', () => {
    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/ringct/bulletproofs/src/tests/mod.rs#L9-L58
    for (let n = 1; n <= 16; n++) {
      it(`proves ${n} output(s) that verify`, () => {
        const amounts = Array.from({ length: n }, (_, i) => BigInt(1000 * (i + 1)));
        const { proof, V } = bulletproofs.proveRangeBulletproofPlus(proofOutputs(amounts));
        assert.equal(V.length, n);
        assert.ok(bulletproofs.verifyBulletproofPlus(V, proof));
      });
    }

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/bulletproofs_plus.cpp#L42-L52
    it('proves amount 0 and the max uint64 amount', () => {
      for (const amount of [0n, 2n ** 64n - 1n]) {
        const { proof, V } = bulletproofs.proveRangeBulletproofPlus(proofOutputs([amount]));
        assert.ok(bulletproofs.verifyBulletproofPlus(V, proof));
      }
    });

    // invalid_8 / invalid_31: an out-of-uint64-range amount is still a reduced scalar, so the
    // prover builds a proof, but its 64-bit decomposition no longer matches V and verify fails.
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/bulletproofs_plus.cpp#L99-L113
    it('builds a proof that does not verify for amounts 2^64 and 2^248', () => {
      for (const amount of [2n ** 64n, 2n ** 248n]) {
        const { proof, V } = bulletproofs.proveRangeBulletproofPlus(proofOutputs([amount]));
        assert.ok(!bulletproofs.verifyBulletproofPlus(V, proof));
      }
    });

    it('rejects an amount that is not a reduced scalar', () => {
      assert.throws(() => {
        bulletproofs.proveRangeBulletproofPlus(proofOutputs([crypto.CURVE.n]));
      }, /not a reduced scalar/);
    });

    it('rejects no outputs and more than 16 outputs', () => {
      assert.throws(() => {
        bulletproofs.proveRangeBulletproofPlus([]);
      });
      assert.throws(() => {
        bulletproofs.proveRangeBulletproofPlus(proofOutputs(Array.from({ length: 17 }, () => 0n)));
      });
    });
  });
});

describe('Bulletproof', () => {
  describe('verifyBulletproof', () => {
    it('verifies the monero-oxide vector', () => {
      assert.ok(bulletproofs.verifyBulletproof(ORIGINAL_BP_V, ORIGINAL_BP_PROOF));
    });

    for (const { label, decoded } of withProof('bulletproofs')) {
      it(`verifies a real proof: ${label}`, () => {
        assert.ok(bulletproofs.verifyBulletproof(decoded.rctSigBase.outPk, decoded.rctSigPrunable.bulletproofs[0]));
      });
    }

    it('rejects a non-canonical scalar', () => {
      for (const field of ['taux', 'mu', 'a', 'b', 't']) {
        const proof = { ...ORIGINAL_BP_PROOF, [field]: nonCanonical(ORIGINAL_BP_PROOF[field]) };
        assert.ok(!bulletproofs.verifyBulletproof(ORIGINAL_BP_V, proof), field);
      }
    });

    it('rejects no commitments and more than 16 commitments', () => {
      assert.ok(!bulletproofs.verifyBulletproof([], ORIGINAL_BP_PROOF));
      assert.ok(!bulletproofs.verifyBulletproof(Array.from({ length: 17 }, () => ORIGINAL_BP_V[0]), ORIGINAL_BP_PROOF));
    });

    it('rejects L and R rounds that do not match the commitment count', () => {
      const proof = { ...ORIGINAL_BP_PROOF, L: ORIGINAL_BP_PROOF.L.slice(1) };
      assert.ok(!bulletproofs.verifyBulletproof(ORIGINAL_BP_V, proof));
    });

    it('rejects a random point S', () => {
      assert.ok(!bulletproofs.verifyBulletproof(ORIGINAL_BP_V, { ...ORIGINAL_BP_PROOF, S: randomBytes(32) }));
    });

    // invalid_torsion for original Bulletproofs: torsion in V, L, R, A, S, T1 or T2 must be rejected
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/bulletproofs.cpp#L194-L234
    it('rejects torsioned points', () => {
      for (const torsion of TORSION_ELEMENTS) {
        for (const field of ['A', 'S', 'T1', 'T2']) {
          const proof = { ...ORIGINAL_BP_PROOF, [field]: addTorsion(ORIGINAL_BP_PROOF[field], torsion) };
          assert.ok(!bulletproofs.verifyBulletproof(ORIGINAL_BP_V, proof));
        }
        for (const field of ['L', 'R']) {
          const points = ORIGINAL_BP_PROOF[field].map((point, i) => (i === 0 ? addTorsion(point, torsion) : point));
          assert.ok(!bulletproofs.verifyBulletproof(ORIGINAL_BP_V, { ...ORIGINAL_BP_PROOF, [field]: points }));
        }
        const V = [addTorsion(ORIGINAL_BP_V[0], torsion), ORIGINAL_BP_V[1]];
        assert.ok(!bulletproofs.verifyBulletproof(V, ORIGINAL_BP_PROOF));
      }
    });
  });
});
