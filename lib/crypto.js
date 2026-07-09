/**
 * crypto.cpp & crypto-ops.c
 *
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { keccak_256 as keccak } from '@noble/hashes/sha3.js';
import {
  concatBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import { equalBytes, numberToBytesLE } from '@noble/curves/utils.js';

import { HASH_KEY_SUBADDRESS } from './config.js';
import { varintNumber } from './raw.js';
import {
  A,
  fffb1,
  fffb2,
  fffb3,
  fffb4,
  ma,
  sqrtm1,
} from './crypto-data.js';
import {
  decodeInt,
  encodeInt,
  sqrtRatioCandidate,
} from './helpers.js';

/**
 * @typedef {object} SubaddressIndex - account (major) and address (minor)
 * @property {number} major
 * @property {number} minor
 */

export const { Point } = ed25519;
// Fp: coordinate field (mod p).
// Fn: scalar field (mod n = group order).
export const {
  Fp,
  Fn,
} = Point;
export const CURVE = Point.CURVE();

// TODO remove when node:test mock.module is stable (drops the --experimental-test-module-mocks flag)
// https://nodejs.org/api/test.html#mockmodulespecifier-options
let random = randomBytes;
export function __mockRandomBytes__(mock) {
  random = mock;
}

// reduce a bigint into the coordinate field
const mod = (n) => Fp.create(n);

/**
 * Decode little-endian number and verify < l
 */

export function decodeScalar(buf, message) {
  const scalar = decodeInt(buf);
  checkScalar(scalar, message);
  return scalar;
}

/**
 * sc_check
 * throws unless the scalar is canonical (< l)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L3814-L3824
 *
 * @param {bigint} scalar
 * @param {string} [message] - error message thrown when the scalar is not canonical
 * @throws {RangeError} when scalar >= l
 */

export function checkScalar(scalar, message = 'Invalid scalar') {
  if (!Fn.isValid(scalar)) {
    throw new RangeError(message);
  }
}

/**
 * Decode EC point (RFC8032 section 5.1.3 point decompression).
 *
 * ge_frombytes_vartime
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L1334-L1424
 *
 * zip215 = false: canonical RFC8032 decoding that rejects y >= p, like monero.
 *
 * check_key
 * true if the 32-byte value decodes to a valid curve point
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L175-L178
 *
 * @param {Uint8Array} buf - 32-byte compressed point
 * @param {string} [message] - error message thrown when the point is invalid
 * @returns {Point} decoded point
 * @throws {RangeError} when buf is not a valid point
 */

export function decodePoint(buf, message = 'Invalid point') {
  try {
    return Point.fromBytes(buf, false);
  } catch (err) {
    throw new RangeError(message, { cause: err });
  }
}

export function encodePoint(P) {
  return P.toBytes();
}

/**
 * random_scalar / random32_unbiased
 * generate a random unbiased non-zero scalar
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L123-L137
 *
 * @returns {bigint} reduced non-zero scalar
 */

export function randomScalar() {
  // l = 2^252 + 27742317777372353535851937790883648493.
  // l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
  const limit = CURVE.n * 15n;

  for (;;) {
    const num = decodeInt(random(32));
    if (num >= limit) {
      continue;
    }
    const reduced = Fn.create(num);
    // num may be zero once per 2^252 + 27742317777372353535851937790883648493 variants O_o
    if (reduced !== 0n) {
      return reduced;
    }
  }
}

/**
 * generate_keys
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L153-L173
 *
 * @param {Uint8Array} [seed] - optional 32-byte recovery seed; random if omitted
 * @returns {{
 *   sec: bigint,
 *   pub: Uint8Array
 * }} reduced secret scalar and public key
 */

export function generateKeys(seed) {
  const sec = seed ? reduceScalar32(seed) : randomScalar();
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
 * @returns {bigint} scalar reduced mod l
 */

export function reduceScalar32(scalar) {
  return Fn.create(decodeInt(scalar));
}

/**
 * hash_to_scalar: keccak of the concatenated inputs, reduced mod l.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L143-L146
 *
 * @param {...Uint8Array} bufs - data to concatenate and hash
 * @returns {bigint} reduced scalar
 */
export function hashToScalar(...bufs) {
  return reduceScalar32(fastHash(concatBytes(...bufs)));
}

/**
 * secret_key_to_public_key
 * sec*G
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L180-L188
 *
 * @param {bigint} sec - secret scalar
 * @returns {Uint8Array} 32-byte public key
 * @throws {RangeError} if sec is not a canonical scalar
 */

export function secretKeyToPublicKey(sec) {
  checkScalar(sec, 'Invalid secret key');
  const K = Point.BASE.multiplyUnsafe(sec);
  return encodePoint(K);
}

/**
 * generate_key_derivation
 * 8 * (sec * pub)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L190-L203
 *
 * @param {Uint8Array} pub - 32-byte public key
 * @param {bigint} sec - secret scalar
 * @returns {Uint8Array} 32-byte key derivation
 * @throws {RangeError} on invalid sec or pub
 */

export function generateKeyDerivation(pub, sec) {
  checkScalar(sec, 'Invalid secret key');
  const P = decodePoint(pub, 'Invalid public key');
  const P2 = P.multiplyUnsafe(sec);
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
 * @returns {bigint} scalar
 */

export function derivationToScalar(derivation, index) {
  return hashToScalar(derivation, varintNumber.encode(index));
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
  const P = Point.BASE.multiplyUnsafe(scalar);
  const P2 = P.add(P1);
  return encodePoint(P2);
}

/**
 * derive_subaddress_public_key
 * out_key - H_s(derivation || varint(output_index)) * G
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L245-L253
 *
 * @param {Uint8Array} outputKey - 32-byte output public key
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @param {number} index - output index
 * @returns {Uint8Array} 32-byte subaddress spend public key
 * @throws {RangeError} on invalid outputKey
 */

export function deriveSubaddressPublicKey(outputKey, derivation, index) {
  const P1 = decodePoint(outputKey, 'Invalid public key');
  const scalar = derivationToScalar(derivation, index);
  const P = Point.BASE.multiplyUnsafe(scalar);
  const P2 = P1.subtract(P);
  return encodePoint(P2);
}

/**
 * derive_secret_key
 * (base + H_s(derivation || varint(output_index))) mod l
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L237-L243
 *
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @param {number} index - output index
 * @param {bigint} sec - base secret scalar
 * @returns {bigint} derived secret scalar
 * @throws {RangeError} if sec is not a canonical scalar
 */

export function deriveSecretKey(derivation, index, sec) {
  checkScalar(sec, 'Invalid secret key');
  return Fn.add(sec, derivationToScalar(derivation, index));
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
 * Signs a hash with a single keypair. In monero this backs message sign/verify,
 * reserve proofs (spend-key part), authenticated wallet/RPC encryption, and
 * multisig kex / MMS / RPC-payment messages. Not used by tx construction (CLSAG).
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} pub - 32-byte public key
 * @param {bigint} sec - secret scalar
 * @returns {Uint8Array} 64-byte signature (c || r)
 * @throws {RangeError} if pub does not match sec
 */

export function generateSignature(prefix, pub, sec) {
  if (!equalBytes(secretKeyToPublicKey(sec), pub)) {
    throw new RangeError('Incorrect public key');
  }

  while (true) {
    const k = randomScalar();
    const K = Point.BASE.multiplyUnsafe(k);
    const c = hashToScalar(prefix, pub, encodePoint(K));
    if (c === 0n) {
      continue;
    }
    // sc_mulsub(&sig.r, &sig.c, &unwrap(sec), &k);
    // sc_mulsub(aa, bb, cc):
    // (cc - aa * bb) % l
    const r = Fn.sub(k, Fn.mul(sec, c));
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
 * Verifies a generateSignature signature (same features).
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
  return c === hashToScalar(prefix, pub, encodePoint(P2));
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
 * @param {bigint} sec - secret scalar
 * @returns {Uint8Array} 32-byte key image
 * @throws {RangeError} if sec is not a canonical scalar
 */

export function generateKeyImage(pub, sec) {
  checkScalar(sec, 'Invalid secret key');
  const P1 = hashToEc(pub);
  const P2 = P1.multiplyUnsafe(sec);
  return encodePoint(P2);
}

/**
 * get_subaddress_secret_key: m = Hs("SubAddr\0" || a || u32(major) || u32(minor))
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L197-L207
 *
 * @param {bigint} secView - secret view scalar
 * @param {SubaddressIndex} subaddress
 * @returns {bigint} subaddress secret scalar
 * @throws {TypeError} for the main account (0, 0), which has no subaddress secret
 */
export function subaddressSecret(secView, { major, minor }) {
  if (major === 0 && minor === 0) {
    // should never happen
    throw new TypeError('No subaddress secret for the main account (0, 0)');
  }
  return hashToScalar(
    HASH_KEY_SUBADDRESS,
    new Uint8Array(1),
    encodeInt(secView),
    numberToBytesLE(major, 4),
    numberToBytesLE(minor, 4)
  );
}

/**
 * get_subaddress_spend_public_key: D = B + m*G
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L127-L141
 *
 * @param {bigint} secView - secret view scalar
 * @param {Uint8Array} pubSpend - 32-byte public spend key B
 * @param {SubaddressIndex} subaddress
 * @returns {Uint8Array} 32-byte subaddress spend public key
 */
export function subaddressPublicSpendKey(secView, pubSpend, { major, minor }) {
  if (major === 0 && minor === 0) {
    return pubSpend;
  }
  const m = subaddressSecret(secView, { major, minor });
  return encodePoint(decodePoint(pubSpend).add(Point.BASE.multiplyUnsafe(m)));
}

/**
 * The subaddress secret spend scalar d = b + m.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L356-L370
 *
 * @param {bigint} secView - secret view scalar
 * @param {bigint} secSpend - secret spend scalar b
 * @param {SubaddressIndex} subaddress
 * @returns {bigint} subaddress secret spend scalar
 */
export function subaddressSecretSpendKey(secView, secSpend, { major, minor }) {
  if (major === 0 && minor === 0) {
    return secSpend;
  }
  const m = subaddressSecret(secView, { major, minor });
  return Fn.add(secSpend, m);
}

/**
 * get_subaddress: the subaddress public keys (D = B + m*G, C = a*D)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L181-L195
 *
 * @param {bigint} secView - secret view scalar a
 * @param {Uint8Array} pubSpend - 32-byte public spend key B
 * @param {SubaddressIndex} subaddress
 * @returns {{
 *   publicSpendKey: Uint8Array,
 *   publicViewKey: Uint8Array
 * }}
 */
export function subaddressPublicKeys(secView, pubSpend, { major, minor }) {
  if (major === 0 && minor === 0) {
    // should never happen
    return { publicSpendKey: pubSpend, publicViewKey: secretKeyToPublicKey(secView) };
  }
  const m = subaddressSecret(secView, { major, minor });
  const D = decodePoint(pubSpend).add(Point.BASE.multiplyUnsafe(m));
  const C = D.multiplyUnsafe(secView);
  return { publicSpendKey: encodePoint(D), publicViewKey: encodePoint(C) };
}

/**
 * generate_key_image_helper_precomp: one-time secret and its key image for a received output.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L321-L365
 *
 * @param {bigint} secView - secret view scalar
 * @param {bigint} secSpend - secret spend scalar
 * @param {Uint8Array} derivation - 32-byte shared secret (a*R / r*A)
 * @param {number} index - output index in the tx
 * @param {SubaddressIndex} subaddress
 * @returns {{
 *   secret: bigint,
 *   keyImage: Uint8Array
 * }}
 */
export function outputKeyImage(secView, secSpend, derivation, index, { major, minor }) {
  const d = subaddressSecretSpendKey(secView, secSpend, { major, minor });
  const secret = deriveSecretKey(derivation, index, d);
  const keyImage = generateKeyImage(secretKeyToPublicKey(secret), secret);
  return { secret, keyImage };
}

/**
 * generate_ring_signature
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L645-L709
 *
 * The pre-RingCT (CryptoNote) input signature. In monero it also backs the
 * 1-member key-image proofs behind spend/reserve proofs and key image
 * export/import. Not used by modern tx construction (CLSAG).
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} keyImage - 32-byte key image
 * @param {Uint8Array[]} pubs - ring of 32-byte public keys
 * @param {bigint} sec - secret scalar
 * @param {number} index - index of the real key in pubs
 * @returns {Uint8Array} signature, 64 bytes per ring member
 * @throws {RangeError|TypeError} on invalid index, key image, sec or pubkey
 */

export function generateRingSignature(prefix, keyImage, pubs, sec, index) {
  if (index >= pubs.length) {
    throw new TypeError('Bad index of secret key');
  }
  const P = decodePoint(keyImage, 'Invalid key image');
  checkScalar(sec, 'Invalid secret key');
  let sum = 0n;
  const ab = new Array(pubs.length);
  const sig = new Array(pubs.length);
  // top level just to pass monero tests
  let k;
  for (let i = 0; i < pubs.length; i++) {
    const pub = pubs[i];
    if (i === index) {
      k = randomScalar();
      const K = Point.BASE.multiplyUnsafe(k);
      const P1 = hashToEc(pub);
      const P2 = P1.multiplyUnsafe(k);
      ab[i] = [
        encodePoint(K),
        encodePoint(P2),
      ];
    } else {
      const c = randomScalar();
      const r = randomScalar();
      sig[i] = [encodeInt(c), encodeInt(r)];
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
  const h = hashToScalar(prefix, ...ab.flat());
  const c = Fn.sub(h, sum);
  const r = Fn.sub(k, Fn.mul(c, sec));
  sig[index] = [encodeInt(c), encodeInt(r)];
  return concatBytes(...sig.flat());
}

/**
 * check_ring_signature
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.cpp#L711-L751
 *
 * Verifies a generateRingSignature signature (same features).
 *
 * @param {Uint8Array} prefix - 32-byte prefix hash
 * @param {Uint8Array} keyImage - 32-byte key image
 * @param {Uint8Array[]} pubs - ring of 32-byte public keys
 * @param {Uint8Array} sig - signature, 64 bytes per ring member
 * @returns {boolean} true if the ring signature is valid
 */

export function checkRingSignature(prefix, keyImage, pubs, sig) {
  let P;
  try {
    P = decodePoint(keyImage);
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
  const h = hashToScalar(prefix, ...ab.flat());
  return Fn.create(sum) === h;
}
