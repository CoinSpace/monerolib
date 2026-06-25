import { RCTTypes } from './config.js';
import { pow2 } from '@noble/curves/abstract/modular.js';
import {
  CURVE,
  Fp,
  Point,
} from './crypto-util.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';

const RCT_TYPE_VALUES = new Set(Object.values(RCTTypes));

/**
 * True for a known rct signature type.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L337-L339
 */
export function isKnownRctType(type) {
  return RCT_TYPE_VALUES.has(type);
}

/**
 * True for rct types using the compact ecdh format introduced with Bulletproof2:
 * deterministic mask (not serialized) and only the first 8 bytes of the encrypted amount.
 */
export function isV2EcdhType(rctType) {
  return rctType === RCTTypes.Bulletproof2
    || rctType === RCTTypes.CLSAG
    || rctType === RCTTypes.BulletproofPlus;
}

/**
 * Decode little-endian number
 */

export function decodeInt(buf) {
  return bytesToNumberLE(buf);
}

/**
 * Decode little-endian number and veryfy < n
 */

export function decodeScalar(buf, message = 'Invalid scalar') {
  const scalar = decodeInt(buf);
  if (scalar >= CURVE.n) {
    throw new RangeError(message);
  }
  return scalar;
}

/**
 * Encode number to little-endian buffer
 */

export function encodeInt(num) {
  return numberToBytesLE(num, 32);
}

/**
 * Decode EC point (RFC8032 section 5.1.3 point decompression).
 *
 * ge_frombytes_vartime
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L1334-L1424
 *
 * zip215 = false: canonical RFC8032 decoding that rejects y >= p, like monero.
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
 * x^((p-5)/8) via a fixed addition chain, ~2x faster than the generic Fp.pow.
 * Same chain as monero fe_pow22523 and noble ed25519_pow_2_252_3.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L1959-L2021
 *
 * @param {bigint} x - field element
 * @returns {bigint} x^((p-5)/8)
 */
function pow22523(x) {
  const { p } = CURVE;
  const b2 = Fp.mul(Fp.sqr(x), x);
  const b4 = Fp.mul(pow2(b2, 2n, p), b2);
  const b5 = Fp.mul(pow2(b4, 1n, p), x);
  const b10 = Fp.mul(pow2(b5, 5n, p), b5);
  const b20 = Fp.mul(pow2(b10, 10n, p), b10);
  const b40 = Fp.mul(pow2(b20, 20n, p), b20);
  const b80 = Fp.mul(pow2(b40, 40n, p), b40);
  const b160 = Fp.mul(pow2(b80, 80n, p), b80);
  const b240 = Fp.mul(pow2(b160, 80n, p), b80);
  const b250 = Fp.mul(pow2(b240, 10n, p), b10);
  return Fp.mul(pow2(b250, 2n, p), x);
}

/**
 * Square root candidate
 * x = (u/v)^(p+3)/8 = u*v^3*(u*v^7)^(p-5)/8
 *
 * fe_divpowm1
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L1959-L2021
 * https://tools.ietf.org/html/rfc8032#section-5.1.3
 * https://crypto.stackexchange.com/questions/88868/why-computation-of-uv3uv7p-5-8-is-suggested-instead-of-u-vp3-8
 *
 * @param {bigint} u - field element
 * @param {bigint} v - field element
 * @returns {bigint} candidate root of u/v, equal to (u/v)^((p+3)/8)
 */

export function sqrtRatioCandidate(u, v) {
  const v3 = Fp.mul(Fp.sqr(v), v);
  const uv7 = Fp.mul(Fp.mul(Fp.sqr(v3), v), u);
  return Fp.mul(Fp.mul(u, v3), pow22523(uv7));
}

export default {
  decodeInt,
  decodeScalar,
  encodeInt,
  decodePoint,
  encodePoint,
  sqrtRatioCandidate,
  isKnownRctType,
  isV2EcdhType,
};
