/**
 * crypto.cpp & crypto-ops.c
 *
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c
 */
import { equalBytes } from '@noble/curves/utils.js';
import { keccak_256 as keccak } from '@noble/hashes/sha3.js';
import { mod } from '@noble/curves/abstract/modular.js';
import varint from 'varint';
import {
  A,
  CURVE,
  Fp,
  Point,
  fffb1,
  fffb2,
  fffb3,
  fffb4,
  sqrtm1,
} from './crypto-util-data.js';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import {
  decodeInt,
  decodePoint,
  decodeScalar,
  encodeInt,
  encodePoint,
  sqrtRatioCandidate,
} from './helpers.js';

// TODO remove when jest.mockModule will be implemented
// https://github.com/facebook/jest/issues/10025
let random = randomBytes;
export function __mockRandomBytes__(mock) {
  random = mock;
}

/**
 * random_scalar
 * generate a random unbiased 32-byte (256-bit) integer
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L123-L141
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
    num = mod(num, CURVE.n);
    // num may be zero once per 2^252 + 27742317777372353535851937790883648493 variants O_o
    if (num !== 0n) {
      return encodeInt(num);
    }
  }
}

/**
 * generate_keys
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L153-L173
 */

export function generateKeys(seed) {
  const sec = seed ? reduceScalar32(seed) : randomScalar();
  // TODO sec check is redundant in secretKeyToPublicKey
  const pub = secretKeyToPublicKey(sec);
  return { sec, pub };
}

/**
 * cn_fast_hash
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L558-L585
 */

export function fastHash(data) {
  return keccak(data);
}

/**
 * sc_reduce32
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c#L2433
 */

export function reduceScalar32(scalar) {
  const num = decodeInt(scalar);
  return encodeInt(mod(num, CURVE.n));
}

/**
 * sc_check
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c#L3814
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
 * Difference from cpp: we hash whole buffer without boundary be length
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L143-L146
 */

export function hashToScalar(data) {
  const hash = fastHash(data);
  return reduceScalar32(hash);
}

/**
 * check_key
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L175-L178
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
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L180-L188
 */

export function secretKeyToPublicKey(sec) {
  const k = decodeScalar(sec, 'Invalid secret key');
  const K = Point.BASE.multiplyUnsafe(k);
  return encodePoint(K);
}

/**
 * generate_key_derivation
 * Key derivation: 8*(sec*pub)
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L190-L203
 */

export function generateKeyDerivation(pub, sec) {
  const s = decodeScalar(sec, 'Invalid secret key');
  const P = decodePoint(pub, 'Invalid public key');
  const P2 = P.multiplyUnsafe(s);
  const P3 = P2.multiplyUnsafe(8n);
  return encodePoint(P3);
}

/**
 * derivation_to_scalar
 * H_s(derivation || varint(output_index))
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L205-L215
 */

export function derivationToScalar(derivation, index) {
  const data = concatBytes(derivation, Uint8Array.from(varint.encode(index)));
  return hashToScalar(data);
}

/**
 * derive_public_key
 * H_s(derivation || varint(output_index))G + base
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L217-L235
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
 * base + H_s(derivation || varint(output_index))
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L237-L243
 */

export function deriveSecretKey(derivation, index, sec) {
  const s = decodeScalar(sec, 'Invalid secret key');
  const scalar = derivationToScalar(derivation, index);
  const key = mod(s + decodeInt(scalar), CURVE.n);
  return encodeInt(key);
}

/**
 * generate_signature
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L290-L317
 */

export function generateSignature(prefix, pub, sec) {
  // sec checked inside secretKeyToPublicKey
  const expectedPub = secretKeyToPublicKey(sec);
  if (!equalBytes(expectedPub, pub)) {
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
    const r = mod(k - decodeInt(sec) * c, CURVE.n);
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
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L319-L341
 */

export function checkSignature(prefix, pub, sig) {
  const P1 = decodePoint(pub, 'Invalid public key');
  let c, r;
  try {
    c = decodeScalar(sig.subarray(0, 32));
    r = decodeScalar(sig.subarray(32, 64));
  } catch {
    return false;
  }
  if (c === 0n) {
    return false;
  }
  const P2 = P1.multiplyUnsafe(c).add(Point.BASE.multiplyUnsafe(r));
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

  const u = Fp.create(decodeInt(data));
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
    r = Fp.mul(Fp.neg(A), v);
    // x = x * u
    x = Fp.mul(x, u);
  } else {
    odd = true;
    // r = -1 * A
    r = Fp.neg(A);
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

  // monero keeps the projective ge_p2 (X : Y : Z) here without inverting;
  // convert (X : Y : Z) to noble extended coords (X*Z : Y*Z : Z^2 : X*Y).
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
  return P.multiplyUnsafe(8n);
}

/**
 * generate_key_image
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L621-L628
 */

export function generateKeyImage(pub, sec) {
  const s = decodeScalar(sec, 'Invalid secret key');
  const P1 = hashToEc(pub);
  const P2 = P1.multiplyUnsafe(s);
  return encodePoint(P2);
}

/**
 * generate_ring_signature
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L645-L709
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
  const c = mod(decodeInt(h) - sum, CURVE.n);
  const r = mod(k - c * s, CURVE.n);
  sig[index] = [encodeInt(c), encodeInt(r)];
  return concatBytes(...sig.flat());
}

/**
 * check_ring_signature
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L711-L751
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
  return mod(sum, CURVE.n) === decodeInt(h);
}

/*
export function decryptPaymentId(encrypted, txPubKey, privateViewKey) {
  const INTEGRATED_ID_SIZE = 8;
  const ENCRYPTED_PAYMENT_ID_TAIL = (141).toString(16);
  const keyDerivation = generateKeyDerivation(txPubKey, privateViewKey);
  const pidKey = fastHash(keyDerivation + ENCRYPTED_PAYMENT_ID_TAIL).slice(0, INTEGRATED_ID_SIZE * 2);
  return xor8(encrypted, pidKey);
}
*/

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
  generateSignature,
  checkSignature,
  hashToPoint,
  hashToEc,
  generateKeyImage,
  generateRingSignature,
  checkRingSignature,
  //decryptPaymentId,
};
