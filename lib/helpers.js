import varint from 'varint';
import {
  CURVE,
  Fp,
  MAX_UINT_32,
  Point,
  sqrtm1,
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
 * Decode EC point
 * https://tools.ietf.org/html/rfc8032#section-5.1.3
 */

export function decodePoint(buf, message = 'Invalid point') {
  const normed = buf.slice();
  const xIsOdd = (normed[normed.length - 1] & 0x80) !== 0;
  normed[normed.length - 1] = normed[normed.length - 1] & ~0x80;

  const y = decodeInt(normed);
  if (y >= CURVE.p) {
    throw new RangeError(message);
  }
  // x^2 = (y^2 - c^2) / (c^2 d y^2 - a) = u / v, c = 1
  const y2 = Fp.sqr(y);
  const u = Fp.sub(y2, 1n);
  const v = Fp.sub(Fp.mul(y2, CURVE.d), CURVE.a);

  let x = squareRoot(u, v);

  if (!Fp.is0(Fp.sub(u, Fp.mul(Fp.sqr(x), v)))) {
    x = Fp.mul(x, sqrtm1);
    if (!Fp.is0(Fp.sub(u, Fp.mul(Fp.sqr(x), v)))) {
      throw new RangeError(message);
    }
  }

  if (x === 0n && xIsOdd) {
    throw new RangeError(message);
  }

  if (Fp.isOdd(x) !== xIsOdd) {
    x = Fp.neg(x);
  }

  return Point.fromAffine({ x, y });
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
