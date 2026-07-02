import assert from 'node:assert/strict';
import { transaction } from '../lib/raw.js';
import txs from './fixtures/txs.json' with { type: 'json' };
import { CURVE, decodePoint, encodePoint, randomScalar } from '../lib/crypto-util.js';
import { decodeInt, encodeInt } from '../lib/helpers.js';
import { describe, it } from 'node:test';
import { hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { proveRangeBulletproofPlus, verifyBulletproof, verifyBulletproofPlus } from '../lib/bulletproofs.js';

const masksFor = (amounts) => amounts.map(() => randomScalar());

// low-order points, verbatim from the monero unit test
// https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/bulletproofs_plus.cpp#L115-L124
const TORSION_ELEMENTS = [
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
];

// fixed original-Bulletproof vector generated from monero, ported verbatim
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/tests/original/mod.rs#L13-L111
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
].map((h) => encodePoint(decodePoint(hexToBytes(h)).clearCofactor()));

// mirrors monero tests/unit_tests/bulletproofs_plus.cpp
// https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/bulletproofs_plus.cpp
describe('bulletproofs plus', () => {
  describe('prove + verify round-trip', () => {
    for (const n of [1, 2, 16]) {
      it(`${n} output(s)`, () => {
        const amounts = Array.from({ length: n }, (_, i) => BigInt(1000 * (i + 1)));
        const { proof, V } = proveRangeBulletproofPlus(amounts, masksFor(amounts));
        assert.equal(V.length, n);
        assert.ok(verifyBulletproofPlus(proof, V));
      });
    }
  });

  it('valid for amount 0', () => {
    const { proof, V } = proveRangeBulletproofPlus([0n], masksFor([0n]));
    assert.ok(verifyBulletproofPlus(proof, V));
  });

  it('valid for max uint64 amount', () => {
    const max = [2n ** 64n - 1n];
    const { proof, V } = proveRangeBulletproofPlus(max, masksFor(max));
    assert.ok(verifyBulletproofPlus(proof, V));
  });

  describe('rejects invalid proofs', () => {
    // invalid_8 / invalid_31: an out-of-uint64-range amount is still a reduced scalar, so the
    // prover builds a proof, but its 64-bit decomposition no longer matches V and verify fails.
    // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/bulletproofs_plus.cpp#L99-L113
    for (const amount of [2n ** 64n, 2n ** 248n]) {
      it(`rejects out-of-range amount 2^${amount === 2n ** 64n ? 64 : 248}`, () => {
        const { proof, V } = proveRangeBulletproofPlus([amount], masksFor([amount]));
        assert.ok(!verifyBulletproofPlus(proof, V));
      });
    }

    // bulletproofs_plus_max: proving for more than MAX_COMMITMENTS outputs must throw
    // https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/tests/mod.rs#L37-L53
    it('rejects too many commitments (> 16)', () => {
      const amounts = Array.from({ length: 17 }, () => 0n);
      assert.throws(() => proveRangeBulletproofPlus(amounts, masksFor(amounts)));
    });

    it('tampered scalar r1', () => {
      const amounts = [1000n, 2000n];
      const { proof, V } = proveRangeBulletproofPlus(amounts, masksFor(amounts));
      assert.ok(!verifyBulletproofPlus({ ...proof, r1: encodeInt(randomScalar()) }, V));
    });

    // monero rejects non-canonical (>= l) proof scalars via is_reduced
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L824-L827
    it('rejects non-canonical proof scalars', () => {
      const amounts = [1000n, 2000n];
      const { proof, V } = proveRangeBulletproofPlus(amounts, masksFor(amounts));
      for (const field of ['r1', 's1', 'd1']) {
        const bad = { ...proof, [field]: encodeInt(decodeInt(proof[field]) + CURVE.n) };
        assert.ok(!verifyBulletproofPlus(bad, V));
      }
    });

    it('tampered point A', () => {
      const amounts = [1000n, 2000n];
      const { proof, V } = proveRangeBulletproofPlus(amounts, masksFor(amounts));
      assert.ok(!verifyBulletproofPlus({ ...proof, A: randomBytes(32) }, V));
    });

    it('wrong commitments', () => {
      const amounts = [1000n, 2000n];
      const { proof, V } = proveRangeBulletproofPlus(amounts, masksFor(amounts));
      assert.ok(!verifyBulletproofPlus(proof, [V[0], V[0]]));
    });

    // invalid_torsion: adding any low-order point to V, L, R, A, A1 or B must break verification
    // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/bulletproofs_plus.cpp#L115-L169
    it('rejects torsioned points', () => {
      const amounts = [1000n, 2000n];
      const { proof, V } = proveRangeBulletproofPlus(amounts, masksFor(amounts));
      assert.ok(verifyBulletproofPlus(proof, V));
      for (const xs of TORSION_ELEMENTS) {
        const addT = (b) => encodePoint(decodePoint(b).add(decodePoint(hexToBytes(xs))));
        for (const field of ['A', 'A1', 'B']) {
          assert.ok(!verifyBulletproofPlus({ ...proof, [field]: addT(proof[field]) }, V));
        }
        for (const field of ['L', 'R']) {
          const arr = proof[field].map((b, i) => (i === 0 ? addT(b) : b));
          assert.ok(!verifyBulletproofPlus({ ...proof, [field]: arr }, V));
        }
        assert.ok(!verifyBulletproofPlus(proof, [addT(V[0]), V[1]]));
      }
    });

    // non-canonical scalars in an original Bulletproof (taken from a real on-chain proof)
    it('rejects non-canonical scalars in an original Bulletproof', () => {
      const item = txs.find((t) => [3, 4].includes(transaction.decode(hexToBytes(t.hex)).rctSigBase.type));
      const tx = transaction.decode(hexToBytes(item.hex));
      const proof = tx.rctSigPrunable.bulletproofs[0];
      const { outPk } = tx.rctSigBase;
      assert.ok(verifyBulletproof(proof, outPk));
      const bad = { ...proof, taux: encodeInt(decodeInt(proof.taux) + CURVE.n) };
      assert.ok(!verifyBulletproof(bad, outPk));
    });
  });

  it('verifies the fixed original Bulletproof vector', () => {
    assert.ok(verifyBulletproof(ORIGINAL_BP_PROOF, ORIGINAL_BP_V));
  });

  // invalid_torsion for original Bulletproofs: torsion in V, L, R, A, S, T1 or T2 must be rejected
  // https://github.com/monero-project/monero/blob/v0.18.5.0/tests/unit_tests/bulletproofs.cpp#L194-L234
  it('rejects torsioned points in an original Bulletproof', () => {
    assert.ok(verifyBulletproof(ORIGINAL_BP_PROOF, ORIGINAL_BP_V));
    for (const xs of TORSION_ELEMENTS) {
      const addT = (b) => encodePoint(decodePoint(b).add(decodePoint(hexToBytes(xs))));
      for (const field of ['A', 'S', 'T1', 'T2']) {
        assert.ok(!verifyBulletproof({ ...ORIGINAL_BP_PROOF, [field]: addT(ORIGINAL_BP_PROOF[field]) }, ORIGINAL_BP_V));
      }
      for (const field of ['L', 'R']) {
        const arr = ORIGINAL_BP_PROOF[field].map((b, i) => (i === 0 ? addT(b) : b));
        assert.ok(!verifyBulletproof({ ...ORIGINAL_BP_PROOF, [field]: arr }, ORIGINAL_BP_V));
      }
      assert.ok(!verifyBulletproof(ORIGINAL_BP_PROOF, [addT(ORIGINAL_BP_V[0]), ORIGINAL_BP_V[1]]));
    }
  });

  // byte-exact KAT: verify real on-chain proofs (the commitments are outPk masks)
  describe('verifies real on-chain proofs', () => {
    for (const item of txs) {
      const tx = transaction.decode(hexToBytes(item.hex));
      const { type, outPk } = tx.rctSigBase;
      if (type === 3 || type === 4) { // Bulletproof / Bulletproof2
        it(item.label, () => {
          assert.ok(verifyBulletproof(tx.rctSigPrunable.bulletproofs[0], outPk));
        });
      } else if (type === 6) { // BulletproofPlus
        it(item.label, () => {
          assert.ok(verifyBulletproofPlus(tx.rctSigPrunable.bulletproofsPlus[0], outPk));
        });
      }
    }
  });
});
