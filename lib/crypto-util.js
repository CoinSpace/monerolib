/**
 * crypto.cpp & crypto-ops.c
 *
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';
import { keccak_256 as keccak } from '@noble/hashes/sha3.js';
import { varintNumber } from './raw.js';
import {
  A,
  fffb1,
  fffb2,
  fffb3,
  fffb4,
  ma,
  sqrtm1,
} from './crypto-util-data.js';
import {
  concatBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import {
  decodeInt,
  decodePoint,
  decodeScalar,
  encodeInt,
  encodePoint,
  sqrtRatioCandidate,
} from './helpers.js';

export const { Point } = ed25519;
// Fp: coordinate field (mod p).
// Fn: scalar field (mod n = group order).
export const {
  Fp,
  Fn,
} = Point;
export const CURVE = Point.CURVE();

let DEBUG = false;
if (typeof process !== 'undefined' && process.env) {
  DEBUG = process.env.NODE_ENV !== 'production';
} else if (typeof import.meta !== 'undefined' && import.meta.env) {
  DEBUG = import.meta.env.DEV === true;
}

// TODO remove when node:test mock.module is stable (drops the --experimental-test-module-mocks flag)
// https://nodejs.org/api/test.html#mockmodulespecifier-options
let random = randomBytes;
export function __mockRandomBytes__(mock) {
  random = mock;
}

// reduce a bigint into the coordinate field
const mod = (n) => Fp.create(n);

/**
 * random_scalar / random32_unbiased
 * generate a random unbiased 32-byte (256-bit) integer
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L123-L137
 *
 * @returns {Uint8Array} 32-byte scalar
 */

export function randomScalar() {
  // l = 2^252 + 27742317777372353535851937790883648493.
  // l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
  const limit = CURVE.n * 15n;

  while (true) {
    const buf = random(32);
    let num = decodeInt(buf);
    if (num >= limit) {
      continue;
    }
    // reduceScalar32
    num = Fn.create(num);
    // num may be zero once per 2^252 + 27742317777372353535851937790883648493 variants O_o
    if (num !== 0n) {
      return encodeInt(num);
    }
  }
}

/**
 * generate_keys
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L153-L173
 *
 * @param {Uint8Array} [seed] - optional 32-byte recovery seed; random if omitted
 * @returns {{ sec: Uint8Array, pub: Uint8Array }} reduced secret key and public key
 */

export function generateKeys(seed) {
  const sec = seed ? reduceScalar32(seed) : randomScalar();
  // TODO sec check is redundant in secretKeyToPublicKey
  const pub = secretKeyToPublicKey(sec);
  return { sec, pub };
}

/**
 * cn_fast_hash
 * Keccak-256 (original 0x01 padding, not NIST SHA3)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/hash.c#L53-L57
 *
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte hash
 */

export function fastHash(data) {
  return keccak(data);
}

/**
 * sc_reduce32
 * reduce a 32-byte little-endian integer mod l
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L2433-L2546
 *
 * @param {Uint8Array} scalar - 32-byte little-endian integer
 * @returns {Uint8Array} 32-byte scalar reduced mod l
 */

export function reduceScalar32(scalar) {
  const num = decodeInt(scalar);
  return encodeInt(Fn.create(num));
}

/**
 * sc_check
 * true if the 32-byte scalar is canonical (< l)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L3814-L3824
 *
 * @param {Uint8Array} scalar - 32-byte little-endian integer
 * @returns {boolean} true if scalar < l
 */

export function checkScalar(scalar) {
  try {
    decodeScalar(scalar);
    return true;
  } catch {
    return false;
  }
}

/**
 * hash_to_scalar
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L143-L146
 *
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte scalar
 */

export function hashToScalar(data) {
  const hash = fastHash(data);
  return reduceScalar32(hash);
}

/**
 * check_key
 * true if the 32-byte value decodes to a valid curve point
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L175-L178
 *
 * @param {Uint8Array} data - 32-byte compressed point
 * @returns {boolean} true if it is a valid point
 */

export function checkKey(data) {
  try {
    decodePoint(data);
    return true;
  } catch {
    return false;
  }
}

/**
 * secret_key_to_public_key
 * sec*G
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L180-L188
 *
 * @param {Uint8Array} sec - 32-byte secret scalar (< l)
 * @returns {Uint8Array} 32-byte public key
 * @throws {RangeError} if sec is not a valid scalar
 */

export function secretKeyToPublicKey(sec) {
  const k = decodeScalar(sec, 'Invalid secret key');
  const K = Point.BASE.multiplyUnsafe(k);
  return encodePoint(K);
}

/**
 * generate_key_derivation
 * 8 * (sec * pub)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L190-L203
 *
 * @param {Uint8Array} pub - 32-byte public key
 * @param {Uint8Array} sec - 32-byte secret scalar
 * @returns {Uint8Array} 32-byte key derivation
 * @throws {RangeError} on invalid sec or pub
 */

export function generateKeyDerivation(pub, sec) {
  const s = decodeScalar(sec, 'Invalid secret key');
  const P = decodePoint(pub, 'Invalid public key');
  const P2 = P.multiplyUnsafe(s);
  const P3 = P2.clearCofactor();
  return encodePoint(P3);
}

/**
 * derivation_to_scalar
 * H_s(derivation || varint(output_index))
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L205-L215
 *
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @param {number} index - output index
 * @returns {Uint8Array} 32-byte scalar
 */

export function derivationToScalar(derivation, index) {
  const data = concatBytes(derivation, varintNumber.encode(index));
  return hashToScalar(data);
}

/**
 * derive_public_key
 * base + H_s(derivation || varint(output_index)) * G
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L217-L235
 *
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @param {number} index - output index
 * @param {Uint8Array} pub - 32-byte base public key
 * @returns {Uint8Array} 32-byte derived public key
 * @throws {RangeError} on invalid base
 */

export function derivePublicKey(derivation, index, pub) {
  const P1 = decodePoint(pub, 'Invalid public key');
  const scalar = derivationToScalar(derivation, index);
  const P = Point.BASE.multiplyUnsafe(decodeInt(scalar));
  const P2 = P.add(P1);
  return encodePoint(P2);
}

/**
 * derive_secret_key
 * (base + H_s(derivation || varint(output_index))) mod l
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L237-L243
 *
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @param {number} index - output index
 * @param {Uint8Array} sec - 32-byte base secret scalar
 * @returns {Uint8Array} 32-byte derived secret key
 * @throws {RangeError} on invalid sec
 */

export function deriveSecretKey(derivation, index, sec) {
  const s = decodeScalar(sec, 'Invalid secret key');
  const scalar = derivationToScalar(derivation, index);
  const key = Fn.add(s, decodeInt(scalar));
  return encodeInt(key);
}

/**
 * derive_view_tag
 * first byte of H("view_tag" || derivation || varint(output_index))
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L753-L775
 *
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @param {number} index - output index
 * @returns {Uint8Array} 1-byte view tag
 */

export function deriveViewTag(derivation, index) {
  const data = concatBytes(
    utf8ToBytes('view_tag'),
    derivation,
    varintNumber.encode(index)
  );
  return fastHash(data).slice(0, 1);
}

/**
 * generate_signature
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L290-L317
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} pub - 32-byte public key
 * @param {Uint8Array} sec - 32-byte secret scalar
 * @returns {Uint8Array} 64-byte signature (c || r)
 * @throws {RangeError} if pub does not match sec
 */

export function generateSignature(prefix, pub, sec) {
  if (DEBUG && !equalBytes(secretKeyToPublicKey(sec), pub)) {
    throw new RangeError('Incorrect public key');
  }

  while (true) {
    const k = decodeInt(randomScalar());
    const K = Point.BASE.multiplyUnsafe(k);
    const buf = concatBytes(
      prefix,
      pub,
      encodePoint(K)
    );
    const c = decodeInt(hashToScalar(buf));
    if (c === 0n) {
      continue;
    }
    // sc_mulsub(&sig.r, &sig.c, &unwrap(sec), &k);
    // sc_mulsub(aa, bb, cc):
    // (cc - aa * bb) % l
    const r = Fn.sub(k, Fn.mul(decodeInt(sec), c));
    if (r === 0n) {
      continue;
    }
    return concatBytes(
      encodeInt(c),
      encodeInt(r)
    );
  }
}

/**
 * check_signature
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L319-L341
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} pub - 32-byte public key
 * @param {Uint8Array} sig - 64-byte signature (c || r)
 * @returns {boolean} true if the signature is valid
 */

export function checkSignature(prefix, pub, sig) {
  let P1, c, r;
  try {
    P1 = decodePoint(pub);
    c = decodeScalar(sig.subarray(0, 32));
    r = decodeScalar(sig.subarray(32, 64));
  } catch {
    return false;
  }
  if (c === 0n) {
    return false;
  }
  const P2 = P1.multiplyUnsafe(c).add(Point.BASE.multiplyUnsafe(r));
  if (P2.is0()) {
    return false;
  }
  const buf = concatBytes(
    prefix,
    pub,
    encodePoint(P2)
  );
  return c === decodeInt(hashToScalar(buf));
}

/**
 * ge_fromfe_frombytes_vartime
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L2310-L2424
 * https://github.com/monero-project/monero/blob/v0.18.5.0/tests/crypto/crypto.cpp#L77-L81
 *
 * @param {Uint8Array} data - 32-byte hash
 * @returns {Point} point on the curve
 */

export function hashToPoint(data) {
  /**
   * u - input data
   * v = 2 * u^2
   * w = 2 * u^2 + 1 = v + 1
   * t = w^2 - 2 * A^2 * u^2 = w^2 - A^2 * v
   * x = sqrt( w / w^2 - 2 * A^2 * u^2 ) = sqrt( w / t )
   * x2t = x^2 * t
   *
   * negative = false
   * check = w - x2t
   *
   * if (isnonzero(check)) {
   *   check = w + x2t
   *   if (isnonzero(check)) {
   *     negative = true
   *   } else {
   *     x = x * fe_fffb1
   *   }
   * } else {
   *   x = x * fe_fffb2
   * }
   *
   * let odd;
   * if (!negative) {
   *   odd = false
   *   r = -2 * A * u^2 = -1 * A * v
   *   x = x * u
   * } else {
   *   odd = true
   *   r = -1 * A
   *   check = w - sqrtm1 * x2t
   *   if (isnonzero(check)) {
   *     check = w + sqrtm1 * x2t
   *     if (isnonzero(check)) {
   *       throw Error()
   *     } else {
   *       x = x * fe_fffb3
   *     }
   *   } else {
   *     x = x * fe_fffb4
   *   }
   * }
   *
   * if (x.isOdd() !== odd) {
   *   x = -1 * x
   * }
   *
   * z = r + w
   * y = r - w
   * x = x * z
   * // projective point (X : Y : Z) = (x : y : z), returned without inversion
   */

  const u = mod(decodeInt(data));
  // v = 2 * u^2
  const v = Fp.mul(Fp.sqr(u), 2n);
  // w = 2 * u^2 + 1 = v + 1
  const w = Fp.add(v, 1n);
  // t = w^2 - 2 * A^2 * u^2 = w^2 - A^2 * v
  const t = Fp.sub(Fp.sqr(w), Fp.mul(Fp.sqr(A), v));
  // x = sqrt( w / w^2 - 2 * A^2 * u^2 ) = sqrt( w / t )
  let x = sqrtRatioCandidate(w, t);
  // x^2 * t, invariant across the checks below
  const x2t = Fp.mul(Fp.sqr(x), t);

  let negative = false;

  // check = w - x^2 * t
  if (!Fp.is0(Fp.sub(w, x2t))) {
    // check = w + x^2 * t
    if (!Fp.is0(Fp.add(w, x2t))) {
      negative = true;
    } else {
      // x = x * fe_fffb1
      x = Fp.mul(x, fffb1);
    }
  } else {
    // x = x * fe_fffb2
    x = Fp.mul(x, fffb2);
  }

  let odd;
  let r;
  if (!negative) {
    odd = false;
    // r = -2 * A * u^2 = -1 * A * v
    r = Fp.mul(ma, v);
    // x = x * u
    x = Fp.mul(x, u);
  } else {
    odd = true;
    // r = -1 * A
    r = ma;
    // sqrtm1 * x^2 * t
    const s = Fp.mul(x2t, sqrtm1);
    // check = w - sqrtm1 * x^2 * t
    if (!Fp.is0(Fp.sub(w, s))) {
      // check = w + sqrtm1 * x^2 * t
      if (!Fp.is0(Fp.add(w, s))) {
        throw new TypeError('Invalid point');
      } else {
        x = Fp.mul(x, fffb3);
      }
    } else {
      x = Fp.mul(x, fffb4);
    }
  }

  if (Fp.isOdd(x) !== odd) {
    // x = -1 * x
    x = Fp.neg(x);
  }

  // z = r + w
  const z = Fp.add(r, w);
  // y = r - w
  const y = Fp.sub(r, w);
  // x = x * z
  x = Fp.mul(x, z);

  // (X : Y : Z) -> extended (X*Z : Y*Z : Z^2 : X*Y); no inversion, like monero ge_p2
  return new Point(Fp.mul(x, z), Fp.mul(y, z), Fp.sqr(z), Fp.mul(x, y));
}

/**
 * hash_to_ec
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L611-L619
 *
 * @param {Uint8Array} data - 32-byte public key
 * @returns {Point} 8 * hashToPoint(fastHash(data))
 */

export function hashToEc(data) {
  const hash = fastHash(data);
  const P = hashToPoint(hash);
  return P.clearCofactor();
}

/**
 * generate_key_image
 * sec * hash_to_ec(pub)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L621-L628
 *
 * @param {Uint8Array} pub - 32-byte public key
 * @param {Uint8Array} sec - 32-byte secret scalar
 * @returns {Uint8Array} 32-byte key image
 * @throws {RangeError} if sec is not a valid scalar
 */

export function generateKeyImage(pub, sec) {
  const s = decodeScalar(sec, 'Invalid secret key');
  const P1 = hashToEc(pub);
  const P2 = P1.multiplyUnsafe(s);
  return encodePoint(P2);
}

/**
 * generate_ring_signature
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L645-L709
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} image - 32-byte key image
 * @param {Uint8Array[]} pubs - ring of 32-byte public keys
 * @param {Uint8Array} sec - 32-byte secret scalar
 * @param {number} index - index of the real key in pubs
 * @returns {Uint8Array} signature, 64 bytes per ring member
 * @throws {RangeError|TypeError} on invalid index, image, sec or pubkey
 */

export function generateRingSignature(prefix, image, pubs, sec, index) {
  if (index >= pubs.length) {
    throw new TypeError('Bad index of secret key');
  }
  const P = decodePoint(image, 'Invalid key image');
  const s = decodeScalar(sec, 'Invalid secret key');
  let sum = 0n;
  const ab = new Array(pubs.length);
  const sig = new Array(pubs.length);
  // top level just to pass monero tests
  let k;
  for (let i = 0; i < pubs.length; i++) {
    const pub = pubs[i];
    if (i === index) {
      k = decodeInt(randomScalar());
      const K = Point.BASE.multiplyUnsafe(k);
      const P1 = hashToEc(pub);
      const P2 = P1.multiplyUnsafe(k);
      ab[i] = [
        encodePoint(K),
        encodePoint(P2),
      ];
    } else {
      sig[i] = [randomScalar(), randomScalar()];
      const c = decodeInt(sig[i][0]);
      const r = decodeInt(sig[i][1]);
      const P1 = decodePoint(pub, 'Invalid pubkey');
      const P2 = P1.multiplyUnsafe(c).add(Point.BASE.multiplyUnsafe(r));
      const P3 = hashToEc(pub);
      const P4 = P3.multiplyUnsafe(r).add(P.multiplyUnsafe(c));
      ab[i] = [
        encodePoint(P2),
        encodePoint(P4),
      ];
      sum += c;
    }
  }
  const h = hashToScalar(concatBytes(prefix, ...ab.flat()));
  const c = Fn.sub(decodeInt(h), sum);
  const r = Fn.sub(k, Fn.mul(c, s));
  sig[index] = [encodeInt(c), encodeInt(r)];
  return concatBytes(...sig.flat());
}

/**
 * check_ring_signature
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L711-L751
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} image - 32-byte key image
 * @param {Uint8Array[]} pubs - ring of 32-byte public keys
 * @param {Uint8Array} sig - signature, 64 bytes per ring member
 * @returns {boolean} true if the ring signature is valid
 */

export function checkRingSignature(prefix, image, pubs, sig) {
  let P;
  try {
    P = decodePoint(image);
  } catch {
    return false;
  }
  let sum = 0n;
  const ab = new Array(pubs.length);
  for (let i = 0; i < pubs.length; i++) {
    const pub = pubs[i];
    let c, r;
    try {
      c = decodeScalar(sig.subarray(0 + (i * 64), 32 + (i * 64)));
      r = decodeScalar(sig.subarray(32 + (i * 64), 64 + (i * 64)));
    } catch {
      return false;
    }
    let P1;
    try {
      P1 = decodePoint(pub);
    } catch {
      return false;
    }
    const P2 = P1.multiplyUnsafe(c).add(Point.BASE.multiplyUnsafe(r));
    const P3 = hashToEc(pub);
    const P4 = P3.multiplyUnsafe(r).add(P.multiplyUnsafe(c));
    ab[i] = [
      encodePoint(P2),
      encodePoint(P4),
    ];
    sum += c;
  }
  const h = hashToScalar(concatBytes(prefix, ...ab.flat()));
  return Fn.create(sum) === decodeInt(h);
}

export default {
  randomScalar,
  generateKeys,
  fastHash,
  reduceScalar32,
  hashToScalar,
  checkScalar,
  checkKey,
  secretKeyToPublicKey,
  generateKeyDerivation,
  derivationToScalar,
  derivePublicKey,
  deriveSecretKey,
  deriveViewTag,
  generateSignature,
  checkSignature,
  hashToPoint,
  hashToEc,
  generateKeyImage,
  generateRingSignature,
  checkRingSignature,
};
