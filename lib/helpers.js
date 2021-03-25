import BN from 'bn.js';
import varint from 'varint';
import {
  ec,
  sqrtm1,
} from './crypto-util-data.js';
/**
 * Decode little-endian number
 */

export function decodeInt(buf) {
  return new BN(buf, 'hex', 'le');
}

/**
 * Decode little-endian number and veryfy < n
 */

export function decodeScalar(buf, message = 'Invalid scalar') {
  const scalar = decodeInt(buf);
  if (scalar.gte(ec.curve.n)) {
    throw new RangeError(message);
  }
  return scalar;
}

/**
 * Encode number to little-endian buffer
 */

export function encodeInt(num) {
  return num.toBuffer('le', 32);
}

/**
 * Decode EC point
 * https://tools.ietf.org/html/rfc8032#section-5.1.3
 */

export function decodePoint(buf, message = 'Invalid point') {
  const normed = Buffer.from(buf);
  const xIsOdd = (normed[normed.length - 1] & 0x80) !== 0;
  normed[normed.length - 1] = normed[normed.length - 1] & ~0x80;

  let y = decodeInt(normed);
  if (y.gte(ec.curve.p)) {
    throw new RangeError(message);
  }
  y = y.toRed(ec.curve.red);
  // x^2 = (y^2 - c^2) / (c^2 d y^2 - a) = u / v
  const y2 = y.redSqr();
  const u = y2.redSub(ec.curve.c2);
  const v = y2.redMul(ec.curve.d).redMul(ec.curve.c2).redSub(ec.curve.a);

  let x = squareRoot(u, v);

  if (!u.redSub(x.redSqr().redMul(v)).isZero()) {
    x = x.redMul(sqrtm1);
    if (!u.redSub(x.redSqr().redMul(v)).isZero()) {
      throw new RangeError(message);
    }
  }

  if (x.fromRed().isZero() && xIsOdd) {
    throw new RangeError(message);
  }

  if (x.fromRed().isOdd() !== xIsOdd) {
    x = x.redNeg();
  }

  return ec.curve.point(x, y);
}

export function encodePoint(P) {
  return Buffer.from(ec.encodePoint(P));
}

/**
 * Square root candidate
 * x = (u/v)^(p+3)/8 = u*v^3*(u*v^7)^(p-5)/8
 * https://tools.ietf.org/html/rfc8032#section-5.1.3
 * https://crypto.stackexchange.com/questions/88868/why-computation-of-uv3uv7p-5-8-is-suggested-instead-of-u-vp3-8
 */

export function squareRoot(u, v) {
  return u.redMul(v.redPow(new BN(3)))
    .redMul(u.redMul(v.redPow(new BN(7))).redPow(ec.curve.p.subn(5).divn(8)));
}

export function hexToBuffer(hex, length = 32) {
  return Buffer.from(hex, 'hex', length);
}

export function decodeVarint(buf) {
  const number = varint.decode(buf);
  const length = varint.encodingLength(number);
  return { number, length };
}

export default {
  decodeInt,
  decodeScalar,
  encodeInt,
  decodePoint,
  encodePoint,
  squareRoot,
  hexToBuffer,
  decodeVarint,
};