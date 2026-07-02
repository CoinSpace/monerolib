import { INV_EIGHT } from './crypto-util-data.js';
import { encodeInt } from './helpers.js';
import {
  Fn,
  Point,
  decodePoint,
  decodeScalar,
  encodePoint,
  hashToEc,
  hashToScalar,
  randomScalar,
} from './crypto-util.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// Domain-separation tags, each a 32-byte block: the ascii tag zero-padded (monero memcpy of len-1).
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L256-L258
const domain = (tag) => {
  const out = new Uint8Array(32);
  out.set(utf8ToBytes(tag));
  return out;
};
const HASH_KEY_CLSAG_AGG_0 = domain('CLSAG_agg_0');
const HASH_KEY_CLSAG_AGG_1 = domain('CLSAG_agg_1');
const HASH_KEY_CLSAG_ROUND = domain('CLSAG_round');

// aggregation scalar: Hs(tag || P || C_nonzero || I || D || C_offset)
const aggHash = (tag, P, Cnonzero, I, D, Cout) =>
  hashToScalar(tag, ...P, ...Cnonzero, I, D, Cout);

/**
 * CLSAG ring signature over a single input (the rct "simple" form).
 * Ports CLSAG_Gen + proveRctCLSAGSimple + the default-device clsag_prepare/hash/sign.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L241-L363
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L764-L791
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L419-L440
 *
 * @param {Uint8Array} message - 32-byte signature message (get_pre_mlsag_hash)
 * @param {{ dest: Uint8Array, mask: Uint8Array }[]} pubs - ring members (output key + commitment)
 * @param {{ dest: bigint, mask: bigint }} inSk - real input secret scalar and commitment mask
 * @param {bigint} a - pseudoOut mask
 * @param {Uint8Array} Cout - 32-byte pseudoOut commitment (C_offset)
 * @param {number} index - real input index in the ring
 * @returns {{ s: Uint8Array[], c1: Uint8Array, I: Uint8Array, D: Uint8Array }}
 */
export function proveClsag(message, pubs, inSk, a, Cout, index) {
  const n = pubs.length;
  if (n < 1 || !Number.isInteger(index) || index < 0 || index >= n) {
    throw new Error('proveClsag: signing index out of range');
  }
  const P = pubs.map((k) => k.dest);
  const Cnonzero = pubs.map((k) => k.mask);
  const CoutPoint = decodePoint(Cout);
  // C[i] = C_nonzero[i] - C_offset (used only for L/R; the hashes use C_nonzero)
  const C = Cnonzero.map((m) => decodePoint(m).subtract(CoutPoint));

  const p = inSk.dest;
  const z = Fn.sub(inSk.mask, a);

  // key images: H = Hp(P[l]), I = p*H, D = z*H
  const H = hashToEc(P[index]);
  const I = H.multiplyUnsafe(p);
  const D = H.multiplyUnsafe(z);
  const Ibytes = encodePoint(I);
  const Dbytes = encodePoint(D.multiplyUnsafe(INV_EIGHT));

  // nonce: aG = a*G, aH = a*H
  const alpha = randomScalar();
  const aG = encodePoint(Point.BASE.multiplyUnsafe(alpha));
  const aH = encodePoint(H.multiplyUnsafe(alpha));

  const muP = aggHash(HASH_KEY_CLSAG_AGG_0, P, Cnonzero, Ibytes, Dbytes, Cout);
  const muC = aggHash(HASH_KEY_CLSAG_AGG_1, P, Cnonzero, Ibytes, Dbytes, Cout);

  // round hash: Hs(tag || P || C_nonzero || C_offset || message || L || R)
  const roundPrefix = concatBytes(HASH_KEY_CLSAG_ROUND, ...P, ...Cnonzero, Cout, message);
  const roundHash = (Lb, Rb) => hashToScalar(roundPrefix, Lb, Rb);

  const s = new Array(n);
  let c1;
  let c = roundHash(aG, aH);

  let i = (index + 1) % n;
  if (i === 0) {
    c1 = c;
  }
  while (i !== index) {
    const si = randomScalar();
    s[i] = encodeInt(si);
    const cp = Fn.mul(muP, c);
    const cc = Fn.mul(muC, c);
    // L = si*G + cp*P[i] + cc*C[i]
    const Lp = Point.BASE.multiplyUnsafe(si).add(decodePoint(P[i]).multiplyUnsafe(cp)).add(C[i].multiplyUnsafe(cc));
    // R = si*Hp(P[i]) + cp*I + cc*D
    const Rp = hashToEc(P[i]).multiplyUnsafe(si).add(I.multiplyUnsafe(cp)).add(D.multiplyUnsafe(cc));
    c = roundHash(encodePoint(Lp), encodePoint(Rp));
    i = (i + 1) % n;
    if (i === 0) {
      c1 = c;
    }
  }

  // s[l] = alpha - c*(mu_P*p + mu_C*z), as device_default clsag_sign (sc_muladd then sc_mulsub)
  const muPpMuCz = Fn.add(Fn.mul(muP, p), Fn.mul(muC, z));
  s[index] = encodeInt(Fn.sub(alpha, Fn.mul(c, muPpMuCz)));

  return { s, c1: encodeInt(c1), I: Ibytes, D: Dbytes };
}

/**
 * Verify a CLSAG signature.
 * Ports verRctCLSAGSimple.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L872-L985
 *
 * @param {Uint8Array} message - 32-byte signature message
 * @param {{ s: Uint8Array[], c1: Uint8Array, I: Uint8Array, D: Uint8Array }} sig
 * @param {{ dest: Uint8Array, mask: Uint8Array }[]} pubs - ring members
 * @param {Uint8Array} Cout - 32-byte pseudoOut commitment (C_offset)
 * @returns {boolean}
 */
export function verifyClsag(message, sig, pubs, Cout) {
  try {
    const n = pubs.length;
    if (n < 1 || sig.s.length !== n) {
      return false;
    }
    const s = sig.s.map((si) => decodeScalar(si, 'Bad signature scalar'));
    const c1 = decodeScalar(sig.c1, 'Bad signature commitment');

    const I = decodePoint(sig.I);
    if (I.is0()) {
      return false;
    }
    // D_8 = scalarmult8(sig.D); the full auxiliary key image
    const D = decodePoint(sig.D).clearCofactor();
    if (D.is0()) {
      return false;
    }

    const P = pubs.map((k) => k.dest);
    const Cnonzero = pubs.map((k) => k.mask);
    const CoutPoint = decodePoint(Cout);

    const muP = aggHash(HASH_KEY_CLSAG_AGG_0, P, Cnonzero, sig.I, sig.D, Cout);
    const muC = aggHash(HASH_KEY_CLSAG_AGG_1, P, Cnonzero, sig.I, sig.D, Cout);

    const roundPrefix = concatBytes(HASH_KEY_CLSAG_ROUND, ...P, ...Cnonzero, Cout, message);

    let c = c1;
    for (let i = 0; i < n; i++) {
      const cp = Fn.mul(muP, c);
      const cc = Fn.mul(muC, c);
      const Ci = decodePoint(Cnonzero[i]).subtract(CoutPoint);
      const Lp = Point.BASE.multiplyUnsafe(s[i]).add(decodePoint(P[i]).multiplyUnsafe(cp)).add(Ci.multiplyUnsafe(cc));
      const Rp = hashToEc(P[i]).multiplyUnsafe(s[i]).add(I.multiplyUnsafe(cp)).add(D.multiplyUnsafe(cc));
      c = hashToScalar(roundPrefix, encodePoint(Lp), encodePoint(Rp));
      if (c === 0n) {
        return false;
      }
    }
    return Fn.sub(c, c1) === 0n;
  } catch {
    return false;
  }
}

export default {
  proveClsag,
  verifyClsag,
};
