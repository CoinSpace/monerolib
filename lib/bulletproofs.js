import { pippenger } from '@noble/curves/abstract/curve.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { encodeInt } from './helpers.js';
import { varintNumber } from './raw.js';
import { COMMITMENT_BITS, MAX_COMMITMENTS } from './config.js';
import {
  Fn,
  Point,
  decodePoint,
  decodeScalar,
  encodePoint,
  fastHash,
  hashToEc,
  hashToScalar,
  randomScalar,
} from './crypto.js';
import { H, INV_EIGHT } from './crypto-data.js';

// Port of monero Bulletproofs+ (prove + verify), structured after monero-oxide
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus

// scalar-vector helpers (arrays of bigint): powers / sum / add / sub / mul / weighted inner product / split
// vector_of_scalar_powers / weighted_inner_product / vector_add / vector_subtract / vector_scalar
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L221-L380
// ScalarVector
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/scalar_vector.rs#L99-L134
const svPowers = (x, len) => {
  const r = [1n];
  for (let i = 1; i < len; i++) {
    r.push(Fn.mul(r[i - 1], x));
  }
  return r.slice(0, len);
};
const svSum = (v) => v.reduce((a, b) => Fn.add(a, b), 0n);
const svAddS = (v, s) => v.map((x) => Fn.add(x, s));
const svSubS = (v, s) => v.map((x) => Fn.sub(x, s));
const svMulS = (v, s) => v.map((x) => Fn.mul(x, s));
const svAdd = (a, b) => a.map((x, i) => Fn.add(x, b[i]));
const svMul = (a, b) => a.map((x, i) => Fn.mul(x, b[i]));
const svWip = (a, b, y) => svSum(svMul(svMul(a, b), y));
const svSplit = (v) => [v.slice(0, v.length / 2), v.slice(v.length / 2)];

// multiexp of [[scalar, Point], ...] via noble's pippenger MSM (scalars reduced into [0, n))
// multiexp
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L89
// multiexp_vartime
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/core.rs#L23
const multiexp = (pairs) => pippenger(Point, pairs.map(([, P]) => P), pairs.map(([s]) => Fn.create(s)));

// padded_pow_of_2: round the commitment count up to a power of 2, inlined in monero as the logM loop
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L534
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/mod.rs#L17
const paddedPow2 = (i) => {
  let n = 1;
  while (n < i) {
    n <<= 1;
  }
  return n;
};

// hash_to_p3
// get_exponent(H, idx) = hash_to_p3(keccak(H || dst || varint(idx)))
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L654
function generatorTable(dst) {
  const preimage = concatBytes(encodePoint(H), utf8ToBytes(dst));
  const exp = (idx) => hashToEc(fastHash(concatBytes(preimage, varintNumber.encode(idx))));
  const Gc = [];
  const Hc = [];
  return {
    G: (i) => (Gc[i] ??= exp(2 * i + 1)),
    H: (i) => (Hc[i] ??= exp(2 * i)),
  };
}
const PLUS = generatorTable('bulletproof_plus');
const ORIG = generatorTable('bulletproof');

// final batch-verifier check: G_gen*g + H_gen*h + Σ table.G(i)*gBold[i] + Σ table.H(i)*hBold[i] + Σ other == 0
// bulletproof_plus_VERIFY final multiexp == identity
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L1097
// InternalBatchVerifier::verify
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/batch_verifier.rs#L25
function finalize(acc, Ggen, Hgen, table) {
  const pairs = [[acc.g, Ggen], [acc.h, Hgen]];
  for (let i = 0; i < acc.gBold.length; i++) {
    pairs.push([acc.gBold[i], table.G(i)]);
  }
  for (let i = 0; i < acc.hBold.length; i++) {
    pairs.push([acc.hBold[i], table.H(i)]);
  }
  pairs.push(...acc.other);
  return multiexp(pairs).is0();
}

// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L153
const TRANSCRIPT = encodePoint(hashToEc(fastHash(utf8ToBytes('bulletproof_plus_transcript'))));

// initial transcript: transcript_update(initial_const, hash_to_scalar(V))
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L584
// initial_transcript
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/transcript.rs#L17
const initialTranscript = (Vc) => hashToScalar(TRANSCRIPT, encodeInt(hashToScalar(...Vc)));

// aL bit-decomposition of each amount, as built in bulletproof_plus_PROVE
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L566-L576
// u64_decompose
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/mod.rs#L78
const u64decompose = (v) => {
  const r = new Array(COMMITMENT_BITS);
  let x = v;
  for (let i = 0; i < COMMITMENT_BITS; i++) {
    r[i] = x & 1n;
    x >>= 1n;
  }
  return r;
};

// challenge_products
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L1026-L1036
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/core.rs#L52
function challengeProducts(ch) {
  const products = new Array(1 << ch.length).fill(1n);
  if (ch.length) {
    products[0] = ch[0][1];
    products[1] = ch[0][0];
    for (let j = 1; j < ch.length; j++) {
      let slots = (1 << (j + 1)) - 1;
      while (slots > 0) {
        products[slots] = Fn.mul(products[slots >> 1], ch[j][0]);
        products[slots - 1] = Fn.mul(products[slots >> 1], ch[j][1]);
        slots -= 2;
      }
    }
  }
  return products;
}

// d_j(j, m): (j-1)*64 zeros, powers(2, 64), (m-j)*64 zeros — d[j*N+i] = z^(2(j+1)) * 2^i
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L610-L624
// d_j
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/aggregate_range_proof.rs#L76
function dj(j, mm) {
  const out = new Array((j - 1) * COMMITMENT_BITS).fill(0n);
  out.push(...svPowers(2n, COMMITMENT_BITS));
  for (let k = 0; k < (mm - j) * COMMITMENT_BITS; k++) {
    out.push(0n);
  }
  return out;
}

// Figure 3 A_hat. Returns null if A fails to decompress (verify path).
// y/z challenges + d vector + d_y, shared by bulletproof_plus_PROVE / _VERIFY
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L594-L639
// compute_A_hat
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/aggregate_range_proof.rs#L88
function computeAHat(commitments, transcript, Abytes) {
  const y = hashToScalar(encodeInt(transcript), Abytes);
  const z = hashToScalar(encodeInt(y));
  let A;
  try {
    A = decodePoint(Abytes).clearCofactor();
  } catch {
    return null;
  }
  const mm = commitments.length; // already padded to a power of 2
  const mn = mm * COMMITMENT_BITS;

  const zPow = [Fn.sqr(z)];
  let d = new Array(mn).fill(0n);
  for (let j = 1; j <= mm; j++) {
    zPow.push(Fn.mul(zPow[zPow.length - 1], zPow[0]));
    d = svAdd(d, svMulS(dj(j, mm), zPow[j - 1]));
  }

  const yPow = svPowers(y, mn + 1).slice(1); // [y, y^2, ..., y^mn]
  const ySum = svSum(yPow);
  const yPowRev = [...yPow].reverse();
  const dYPowRevPlusZ = svAddS(svMul(d, yPowRev), z);
  const yMnPlus1 = Fn.mul(yPowRev[0], y);

  let commitAccum = Point.ZERO;
  for (let j = 0; j < mm; j++) {
    commitAccum = commitAccum.add(commitments[j].multiplyUnsafe(zPow[j]));
  }

  const negZ = Fn.neg(z);
  const terms = [];
  for (let i = 0; i < mn; i++) {
    terms.push([negZ, PLUS.G(i)]);
    terms.push([dYPowRevPlusZ[i], PLUS.H(i)]);
  }
  terms.push([yMnPlus1, commitAccum]);
  terms.push([
    Fn.sub(
      Fn.sub(Fn.mul(ySum, z), Fn.mul(Fn.mul(svSum(d), yMnPlus1), z)),
      Fn.mul(ySum, Fn.sqr(z))
    ),
    H,
  ]);

  return {
    y, z, zPow, dYPowRevPlusZ, yMnPlus1, aHat: A.add(multiexp(terms)),
  };
}

// Weighted inner product proof (Figure 1). g = H, h = G.
// inner-product rounds + A1/B/r1/s1/d1, inlined in bulletproof_plus_PROVE
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L654-L760
// WipStatement::prove
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/weighted_inner_product.rs#L138
function wipProve(n, transcript, a0, b0, alpha0) {
  let gBold = Array.from({ length: n }, (_, i) => PLUS.G(i));
  let hBold = Array.from({ length: n }, (_, i) => PLUS.H(i));
  const yPow = svPowers(transcript.y, n + 1).slice(1); // [y..y^n]
  let yCur = yPow;

  const yInv = [];
  for (let i = 1; i < n; i *= 2) {
    yInv.push(Fn.inv(yPow[i - 1]));
  }

  let a = a0.slice();
  let b = b0.slice();
  let alpha = alpha0;
  let t = transcript.scalar;
  const Lv = [];
  const Rv = [];

  while (gBold.length > 1) {
    const [a1, a2] = svSplit(a);
    const [b1, b2] = svSplit(b);
    const [g1, g2] = svSplit(gBold);
    const [h1, h2] = svSplit(hBold);
    const nHat = g1.length;
    const yNHat = yCur[nHat - 1];
    yCur = yCur.slice(0, nHat);

    const dL = randomScalar();
    const dR = randomScalar();
    const cL = svWip(a1, b2, yCur);
    const cR = svWip(svMulS(a2, yNHat), b1, yCur);
    const yInvNHat = yInv.pop();

    const Lterms = [];
    const a1yi = svMulS(a1, yInvNHat);
    for (let i = 0; i < nHat; i++) {
      Lterms.push([a1yi[i], g2[i]]);
    }
    for (let i = 0; i < nHat; i++) {
      Lterms.push([b2[i], h1[i]]);
    }
    Lterms.push([cL, H], [dL, Point.BASE]);
    const Lb = encodePoint(multiexp(Lterms).multiplyUnsafe(INV_EIGHT));
    Lv.push(Lb);

    const Rterms = [];
    const a2y = svMulS(a2, yNHat);
    for (let i = 0; i < nHat; i++) {
      Rterms.push([a2y[i], g1[i]]);
    }
    for (let i = 0; i < nHat; i++) {
      Rterms.push([b1[i], h2[i]]);
    }
    Rterms.push([cR, H], [dR, Point.BASE]);
    const Rb = encodePoint(multiexp(Rterms).multiplyUnsafe(INV_EIGHT));
    Rv.push(Rb);

    const e = hashToScalar(encodeInt(t), Lb, Rb);
    t = e;
    const invE = Fn.inv(e);
    const eYInv = Fn.mul(e, yInvNHat);
    gBold = Array.from(
      { length: nHat },
      (_, i) => g1[i].multiplyUnsafe(invE).add(g2[i].multiplyUnsafe(eYInv))
    );
    hBold = Array.from(
      { length: nHat },
      (_, i) => h1[i].multiplyUnsafe(e).add(h2[i].multiplyUnsafe(invE))
    );

    a = svAdd(svMulS(a1, e), svMulS(a2, Fn.mul(yNHat, invE)));
    b = svAdd(svMulS(b1, invE), svMulS(b2, e));
    alpha = Fn.add(Fn.add(alpha, Fn.mul(dL, Fn.sqr(e))), Fn.mul(dR, Fn.sqr(invE)));
  }

  const r = randomScalar();
  const s = randomScalar();
  const delta = randomScalar();
  const eta = randomScalar();
  const ry = Fn.mul(r, yPow[0]);

  const Aterms = [
    [r, gBold[0]],
    [s, hBold[0]],
    [Fn.add(Fn.mul(ry, b[0]), Fn.mul(Fn.mul(s, yPow[0]), a[0])), H],
    [delta, Point.BASE],
  ];
  const Ab = encodePoint(multiexp(Aterms).multiplyUnsafe(INV_EIGHT));

  const Bb = encodePoint(multiexp([[Fn.mul(ry, s), H], [eta, Point.BASE]]).multiplyUnsafe(INV_EIGHT));

  const e = hashToScalar(encodeInt(t), Ab, Bb);
  return {
    L: Lv,
    R: Rv,
    A: Ab,
    B: Bb,
    r1: encodeInt(Fn.add(r, Fn.mul(a[0], e))),
    s1: encodeInt(Fn.add(s, Fn.mul(b[0], e))),
    d1: encodeInt(Fn.add(Fn.add(eta, Fn.mul(delta, e)), Fn.mul(alpha, Fn.sqr(e)))),
  };
}

// accumulate a single WIP proof into the batch verifier; returns false on decompress failure
// inner-product verification inlined in bulletproof_plus_VERIFY
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L1010-L1090
// WipStatement::verify
// https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/ringct/bulletproofs/src/plus/weighted_inner_product.rs#L298
function wipVerify(acc, n, P, y, transcript, proof) {
  const lr = Math.log2(n); // n is a power of 2
  if (proof.L.length !== lr || proof.R.length !== lr || n !== (1 << lr)) {
    return false;
  }

  const yPow = svPowers(y, n + 1).slice(1); // [y..y^n]
  const yInvPow = [];
  {
    const iy0 = Fn.inv(yPow[0]);
    yInvPow.push(iy0);
    while (yInvPow.length < n) {
      yInvPow.push(Fn.mul(iy0, yInvPow[yInvPow.length - 1]));
    }
  }

  let t = transcript;
  const eis = [];
  const Ld = [];
  const Rd = [];
  const decomp8 = (b) => decodePoint(b).clearCofactor();
  try {
    for (let i = 0; i < proof.L.length; i++) {
      const e = hashToScalar(encodeInt(t), proof.L[i], proof.R[i]);
      t = e;
      eis.push(e);
      Ld.push(decomp8(proof.L[i]));
      Rd.push(decomp8(proof.R[i]));
    }
    const e = hashToScalar(encodeInt(t), proof.A, proof.B);
    const A = decomp8(proof.A);
    const B = decomp8(proof.B);

    const negESq = Fn.neg(Fn.sqr(e));
    acc.other.push([negESq, P]);

    const challenges = [];
    for (let i = 0; i < eis.length; i++) {
      const ei = eis[i];
      const invEi = Fn.inv(ei);
      challenges.push([ei, invEi]);
      acc.other.push([Fn.mul(negESq, Fn.sqr(ei)), Ld[i]]);
      acc.other.push([Fn.mul(negESq, Fn.sqr(invEi)), Rd[i]]);
    }
    const products = challengeProducts(challenges);

    while (acc.gBold.length < n) {
      acc.gBold.push(0n);
    }
    while (acc.hBold.length < n) {
      acc.hBold.push(0n);
    }

    const r1 = decodeScalar(proof.r1);
    const s1 = decodeScalar(proof.s1);
    const re = Fn.mul(r1, e);
    for (let i = 0; i < n; i++) {
      const productRe = Fn.mul(products[i], re);
      const scalar = i > 0 ? Fn.mul(productRe, yInvPow[i - 1]) : productRe;
      acc.gBold[i] = Fn.add(acc.gBold[i], scalar);
    }
    const se = Fn.mul(s1, e);
    for (let i = 0; i < n; i++) {
      acc.hBold[i] = Fn.add(acc.hBold[i], Fn.mul(se, products[products.length - 1 - i]));
    }

    acc.other.push([Fn.neg(e), A]);
    acc.g = Fn.add(acc.g, Fn.mul(Fn.mul(r1, yPow[0]), s1));
    acc.h = Fn.add(acc.h, decodeScalar(proof.d1));
    acc.other.push([Fn.neg(1n), B]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a Bulletproof+ range proof for the given outputs.
 * Math:
 * V_j = mask_j*G + amount_j*H
 * aL = bits(amounts), aR = aL - 1
 * A = (Σ aL_i*G_i + Σ aR_i*H_i + alpha*G)/8
 * y = H(transcript, A), z = H(y), A_hat = A + fold(V, y, z, d)
 * WIP(aL - z, aR + d*y_rev + z, alpha + y^(mn+1)*Σ z^(2j)*mask_j)
 * bulletproof_plus_PROVE
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L513
 *
 * @param {{
 *   amount: bigint,
 *   mask: bigint
 * }[]} outputs
 * @returns {{
 *   proof: import('./raw.js').BulletproofPlus,
 *   V: Uint8Array[]
 * }} proof + commitments
 */
export function proveRangeBulletproofPlus(outputs) {
  if (outputs.length < 1 || outputs.length > MAX_COMMITMENTS) {
    throw new Error('proveRangeBulletproofPlus: invalid number of outputs');
  }
  // monero only requires each amount to be a reduced scalar (< l); out-of-uint64-range values
  // build a proof that the verifier rejects (the 64-bit decomposition no longer matches V).
  // https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L519
  for (const { amount } of outputs) {
    if (!Fn.isValid(amount)) {
      throw new Error('proveRangeBulletproofPlus: amount is not a reduced scalar');
    }
  }
  const Vreal = outputs.map(({ amount, mask }) => Point.BASE.multiplyUnsafe(mask).add(H.multiplyUnsafe(amount)));

  const Vinv = Vreal.map((v) => v.multiplyUnsafe(INV_EIGHT));
  const transcriptScalar = initialTranscript(Vinv.map(encodePoint));
  const commitments = Vinv.map((P) => P.clearCofactor());
  while (commitments.length < paddedPow2(commitments.length)) {
    commitments.push(Point.ZERO);
  }
  const mm = commitments.length;
  const n = mm * COMMITMENT_BITS;

  const aL = Array.from({ length: mm }, (_, j) => u64decompose(j < outputs.length ? outputs[j].amount : 0n)).flat();
  const aR = svSubS(aL, 1n);

  const alpha0 = randomScalar();
  const Aterms = [];
  for (let i = 0; i < n; i++) {
    Aterms.push([aL[i], PLUS.G(i)]);
  }
  for (let i = 0; i < n; i++) {
    Aterms.push([aR[i], PLUS.H(i)]);
  }
  Aterms.push([alpha0, Point.BASE]);
  const A = encodePoint(multiexp(Aterms).multiplyUnsafe(INV_EIGHT));

  const ah = computeAHat(commitments, transcriptScalar, A);
  const alpha = outputs.reduce(
    (sum, { mask }, j) => Fn.add(sum, Fn.mul(Fn.mul(ah.zPow[j], mask), ah.yMnPlus1)),
    alpha0
  );

  const wip = wipProve(n, { y: ah.y, scalar: ah.z }, svSubS(aL, ah.z), svAdd(aR, ah.dYPowRevPlusZ), alpha);

  return {
    proof: {
      A, A1: wip.A, B: wip.B, r1: wip.r1, s1: wip.s1, d1: wip.d1, L: wip.L, R: wip.R,
    },
    V: Vreal.map(encodePoint),
  };
}

// TODO: batch verification of many proofs at once. monero's verify takes a vector of proofs,
// weights each proof's multiexp by a random factor, sums them into a single multiexp-to-zero, and
// includes the shared Gi/Hi/G/H generators only once across the whole batch - far faster than
// checking each proof separately when validating many transactions.
// bulletproof_plus_VERIFY
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L799

/**
 * Verify a Bulletproof+ range proof against its commitments.
 * Math:
 * y = H(transcript, A), z = H(y), A_hat = A + fold(V, y, z, d)
 * e_i = H(t, L_i, R_i), e = H(t, A1, B)
 * acc.g*H + acc.h*G + Σ gBold_i*G_i + Σ hBold_i*H_i + Σ proof_terms = 0
 * bulletproof_plus_VERIFY
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L799
 *
 * @param {Uint8Array[]} V - 32-byte output commitments
 * @param {import('./raw.js').BulletproofPlus} proof
 * @returns {boolean}
 */
export function verifyBulletproofPlus(V, proof) {
  try {
    if (V.length < 1 || V.length > MAX_COMMITMENTS) {
      return false;
    }
    const Vreal = V.map((v) => decodePoint(v));
    const Vinv = Vreal.map((v) => v.multiplyUnsafe(INV_EIGHT));
    const transcriptScalar = initialTranscript(Vinv.map(encodePoint));
    const commitments = Vinv.map((P) => P.clearCofactor());
    while (commitments.length < paddedPow2(commitments.length)) {
      commitments.push(Point.ZERO);
    }
    const n = commitments.length * COMMITMENT_BITS;

    const ah = computeAHat(commitments, transcriptScalar, proof.A);
    if (!ah) {
      return false;
    }

    const wipProof = {
      L: proof.L, R: proof.R, A: proof.A1, B: proof.B, r1: proof.r1, s1: proof.s1, d1: proof.d1,
    };
    const acc = {
      g: 0n, h: 0n, gBold: [], hBold: [], other: [],
    };
    if (!wipVerify(acc, n, ah.aHat, ah.y, ah.z, wipProof)) {
      return false;
    }

    // batch verifier: g = H, h = G for Bulletproofs+
    return finalize(acc, H, Point.BASE, PLUS);
  } catch {
    return false;
  }
}

// Inner-product verify (Protocol 2), accumulated into the batch verifier.
// bulletproof_VERIFY
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs.cc#L969
function ipVerify(acc, ipRows, transcript, weight, proof, hBoldWeights, u) {
  const lr = Math.log2(ipRows); // ipRows is a power of 2
  if (proof.L.length !== lr || proof.L.length !== proof.R.length) {
    return false;
  }

  let t = transcript;
  const challenges = [];
  for (let i = 0; i < proof.L.length; i++) {
    const e = hashToScalar(encodeInt(t), proof.L[i], proof.R[i]);
    t = e;
    const invE = Fn.inv(e);
    challenges.push([e, invE]);
    acc.other.push([Fn.mul(weight, Fn.sqr(e)), decodePoint(proof.L[i]).clearCofactor()]);
    acc.other.push([Fn.mul(weight, Fn.sqr(invE)), decodePoint(proof.R[i]).clearCofactor()]);
  }
  const products = challengeProducts(challenges);

  const a = decodeScalar(proof.a);
  const b = decodeScalar(proof.b);
  for (let i = 0; i < ipRows; i++) {
    acc.gBold[i] = Fn.sub(acc.gBold[i], Fn.mul(Fn.mul(weight, products[i]), a));
  }
  for (let i = 0; i < ipRows; i++) {
    const term = Fn.mul(Fn.mul(Fn.mul(weight, products[products.length - 1 - i]), b), hBoldWeights[i]);
    acc.hBold[i] = Fn.sub(acc.hBold[i], term);
  }
  acc.h = Fn.sub(acc.h, Fn.mul(Fn.mul(weight, Fn.mul(a, b)), u));
  return true;
}

/**
 * Verify an original Bulletproof range proof (types Bulletproof / Bulletproof2). Verify-only;
 * we never create these.
 * Math:
 * y = H(H(V/8), A, S), z = H(y), x = H(z, z, T1, T2), x_ip = H(x, x, taux, mu, t_hat)
 * t_hat*H + taux*G - (z - z^2)*Σ y^i*H - Σ z^(j+2)*V_j
 *   + Σ z^(j+3)*Σ 2^i*H - x*T1 - x^2*T2 = 0
 * ipVerify(A + x*S - mu*G + x_ip*t_hat*H, L_i, R_i, a, b)
 * bulletproof_VERIFY
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs.cc#L810
 *
 * @param {Uint8Array[]} V - 32-byte output commitments
 * @param {import('./raw.js').Bulletproof} proof
 * @returns {boolean}
 */
export function verifyBulletproof(V, proof) {
  try {
    if (V.length < 1 || V.length > MAX_COMMITMENTS) {
      return false;
    }
    const padded = paddedPow2(V.length);
    const ipRows = padded * COMMITMENT_BITS;
    const acc = {
      g: 0n, h: 0n, gBold: new Array(ipRows).fill(0n), hBold: new Array(ipRows).fill(0n), other: [],
    };

    const Vinv = V.map((v) => decodePoint(v).multiplyUnsafe(INV_EIGHT));
    const transcript = hashToScalar(...Vinv.map(encodePoint));
    const commitments = Vinv.map((P) => P.clearCofactor());

    const y = hashToScalar(encodeInt(transcript), proof.A, proof.S);
    const z = hashToScalar(encodeInt(y));
    const zPow = svPowers(z, 3 + padded);
    const x = hashToScalar(encodeInt(z), encodeInt(z), proof.T1, proof.T2);
    const xIp = hashToScalar(encodeInt(x), encodeInt(x), proof.taux, proof.mu, proof.t);

    const A = decodePoint(proof.A).clearCofactor();
    const S = decodePoint(proof.S).clearCofactor();
    const T1 = decodePoint(proof.T1).clearCofactor();
    const T2 = decodePoint(proof.T2).clearCofactor();

    const yPow = svPowers(y, ipRows);
    const yInvPow = svPowers(Fn.inv(y), ipRows);
    const twos = svPowers(2n, COMMITMENT_BITS);
    const tauX = decodeScalar(proof.taux);
    const mu = decodeScalar(proof.mu);
    const tHat = decodeScalar(proof.t);

    const commitmentWeight = randomScalar();
    const negCommitmentWeight = Fn.neg(commitmentWeight);
    acc.h = Fn.add(acc.h, Fn.mul(commitmentWeight, tHat));
    acc.g = Fn.add(acc.g, Fn.mul(commitmentWeight, tauX));
    acc.h = Fn.add(acc.h, Fn.mul(Fn.mul(negCommitmentWeight, Fn.sub(zPow[1], zPow[2])), svSum(yPow)));
    for (let i = 0; i < commitments.length; i++) {
      acc.other.push([Fn.mul(negCommitmentWeight, zPow[2 + i]), commitments[i]]);
    }
    const twosSum = svSum(twos);
    for (let i = 0; i < padded; i++) {
      acc.h = Fn.add(acc.h, Fn.mul(Fn.mul(commitmentWeight, zPow[3 + i]), twosSum));
    }
    acc.other.push([Fn.mul(negCommitmentWeight, x), T1]);
    acc.other.push([Fn.mul(negCommitmentWeight, Fn.sqr(x)), T2]);

    const innerProductWeight = randomScalar();
    acc.other.push([innerProductWeight, A]);
    acc.other.push([Fn.mul(innerProductWeight, x), S]);
    const weightedZ = Fn.mul(innerProductWeight, zPow[1]);
    const negWeightedZ = Fn.neg(weightedZ);
    for (let i = 0; i < ipRows; i++) {
      acc.hBold[i] = Fn.add(acc.hBold[i], weightedZ);
      acc.gBold[i] = Fn.add(acc.gBold[i], negWeightedZ);
    }
    for (let j = 0; j < padded; j++) {
      for (let i = 0; i < COMMITMENT_BITS; i++) {
        const bitIndex = (j * COMMITMENT_BITS) + i;
        const term = Fn.mul(Fn.mul(Fn.mul(innerProductWeight, yInvPow[bitIndex]), zPow[2 + j]), twos[i]);
        acc.hBold[bitIndex] = Fn.add(acc.hBold[bitIndex], term);
      }
    }
    acc.h = Fn.add(acc.h, Fn.mul(Fn.mul(innerProductWeight, xIp), tHat));
    acc.g = Fn.add(acc.g, Fn.mul(innerProductWeight, Fn.neg(mu)));

    if (!ipVerify(acc, ipRows, xIp, innerProductWeight, proof, yInvPow, xIp)) {
      return false;
    }

    // batch verifier: g = G, h = H for the original Bulletproof
    return finalize(acc, Point.BASE, H, ORIG);
  } catch {
    return false;
  }
}
