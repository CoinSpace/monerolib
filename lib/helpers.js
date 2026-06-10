import varint from 'varint';
import {
  CURVE,
  Fp,
  MAX_UINT_32,
  Point,
} from './crypto-util-data.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';

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
 * Encode unsigned 32 bit int to little-endian buffer
 */

export function encodeUint32(num) {
  if (num > MAX_UINT_32) {
    throw RangeError('Value must not equal or exceed 2^32');
  }
  return numberToBytesLE(BigInt(num), 4);
}

/**
 * Decode EC point (RFC8032 section 5.1.3 point decompression).
 *
 * ge_frombytes_vartime
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops.c#L1334-L1424
 *
 * zip215 = false: canonical RFC8032 decoding that rejects y >= p, like monero.
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
 * Square root candidate
 * x = (u/v)^(p+3)/8 = u*v^3*(u*v^7)^(p-5)/8
 * https://tools.ietf.org/html/rfc8032#section-5.1.3
 * https://crypto.stackexchange.com/questions/88868/why-computation-of-uv3uv7p-5-8-is-suggested-instead-of-u-vp3-8
 */

export function squareRoot(u, v) {
  return Fp.mul(
    Fp.mul(u, Fp.pow(v, 3n)),
    Fp.pow(Fp.mul(u, Fp.pow(v, 7n)), (CURVE.p - 5n) / 8n)
  );
}

export function decodeVarint(buf) {
  const number = varint.decode(buf);
  const length = varint.encodingLength(number);
  return { number, length };
}

export function isBuffer32(buf) {
  return buf instanceof Uint8Array && buf.length === 32;
}

export function isBuffer8(buf) {
  return buf instanceof Uint8Array && buf.length === 8;
}

export default {
  decodeInt,
  decodeScalar,
  encodeInt,
  decodePoint,
  encodePoint,
  squareRoot,
  decodeVarint,
  isBuffer32,
};
