/**
 * crypto.cpp & crypto-ops.c
 *
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c
 */
import crypto from 'crypto';
import BN from 'bn.js';
import elliptic from 'elliptic';
import keccak from 'keccak';
import varint from 'varint';
import Debug from 'debug';

const debug = Debug('monerolib:crypto-util');

const ec = new elliptic.eddsa('ed25519');

// TODO remove when jest.mockModule will be implemented
// https://github.com/facebook/jest/issues/10025
let { randomBytes } = crypto;
export function __mockRandomBytes__(mock) {
  randomBytes = mock;
}

// TODO remove when fixed
function fixBufferToArray(buf) {
  // Convert Buffer to Array
  // https://github.com/indutny/elliptic/issues/248
  return Array.from(buf);
}

/**
 * random_scalar
 * generate a random unbiased 32-byte (256-bit) integer
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L123-L141
 */

export function randomScalar() {
  // l = 2^252 + 27742317777372353535851937790883648493.
  // l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
  const limit = ec.curve.n.muln(15);
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const buf = randomBytes(32);
    if (new ec.decodeInt(buf).gte(limit)) {
      continue;
    }
    // scalarReduce32
    const num = ec.decodeInt(buf).umod(ec.curve.n);
    // num may be zero once per 2^252 + 27742317777372353535851937790883648493 variants O_o
    if (!num.isZero()) {
      return num.toBuffer('le', 32);
    }
  }
}

/**
 * generate_keys
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L153-L173
 */

export function generateKeys(seed) {
  const sec = seed ? scalarReduce32(seed) : randomScalar();
  // TODO sec check is redundant in secretKeyToPublicKey
  const pub = secretKeyToPublicKey(sec);
  return { sec, pub };
}

/**
 * cn_fast_hash
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L558-L585
 */

export function fastHash(data) {
  return keccak('keccak256').update(data).digest();
}

/**
 * sc_reduce32
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c#L2433
 */

export function scalarReduce32(scalar) {
  const num = ec.decodeInt(scalar);
  return num.umod(ec.curve.n).toBuffer('le', 32);
}

/**
 * sc_check
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c#L3814
 */

export function scalarCheck(scalar) {
  return ec.decodeInt(scalar).lt(ec.curve.n);
}

/**
 * hash_to_scalar
 * Difference from cpp: we hash whole buffer without boundary be length
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L143-L146
 */

export function hashToScalar(data) {
  const hash = fastHash(data);
  return scalarReduce32(hash);
}

/**
 * check_key
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L175-L178
 */

export function keyCheck(data) {
  try {
    const point = ec.decodePoint(fixBufferToArray(data));
    // TODO remove when fixed https://github.com/indutny/elliptic/issues/250
    if (!data.equals(Buffer.from(ec.encodePoint(point)))) {
      debug('keyCheck invalid point');
      return false;
    }
    const valid = point.validate();
    debug('keyCheck validate: %s', valid);
    return valid;
  } catch (err) {
    debug('keyCheck error: %s', err.message);
    return false;
  }
}

/**
 * secret_key_to_public_key
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L180-L188
 */

export function secretKeyToPublicKey(sec) {
  if (scalarCheck(sec) !== true) {
    throw new RangeError('Invalid secret key');
  }
  const k = ec.decodeInt(sec);
  const K = ec.g.mul(k);
  return Buffer.from(ec.encodePoint(K));
}

/**
 * generate_key_derivation
 * Key derivation: 8*(sec*pub)
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L190-L203
 */

export function generateKeyDerivation(pub, sec) {
  if (scalarCheck(sec) !== true) {
    throw new RangeError('Invalid secret key');
  }
  if (keyCheck(pub) !== true) {
    throw new RangeError('Invalid public key');
  }
  const P = ec.decodePoint(fixBufferToArray(pub));
  const s = ec.decodeInt(sec);
  const P2 = P.mul(s);
  const P3 = P2.mul(new BN('8'));
  return Buffer.from(ec.encodePoint(P3));
}

/**
 * derivation_to_scalar
 * H_s(derivation || varint(output_index))
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L205-L215
 */

export function derivationToScalar(derivation, index) {
  const data = Buffer.concat([derivation, Buffer.from(varint.encode(index))]);
  return hashToScalar(data);
}

/**
 * derive_public_key
 * H_s(derivation || varint(output_index))G + base
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L217-L235
 */

export function derivePublicKey(derivation, index, pub) {
  if (keyCheck(pub) !== true) {
    throw new RangeError('Invalid public key');
  }
  const scalar = derivationToScalar(derivation, index);
  const P = ec.g.mul(ec.decodeInt(scalar));
  const base = ec.decodePoint(fixBufferToArray(pub));
  const P2 = P.add(base);
  return Buffer.from(ec.encodePoint(P2));
}

/**
 * derive_secret_key
 * base + H_s(derivation || varint(output_index))
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L237-L243
 */

export function deriveSecretKey(derivation, index, sec) {
  if (scalarCheck(sec) !== true) {
    throw new RangeError('Invalid secret key');
  }
  const scalar = derivationToScalar(derivation, index);
  return ec.decodeInt(sec)
    .add(ec.decodeInt(scalar))
    .umod(ec.curve.n)
    .toBuffer('le', 32);
}

/**
 * generate_signature
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L290-L317
 */

export function generateSignature(prefix, pub, sec) {
  const expectedPub = secretKeyToPublicKey(sec);
  if (!expectedPub.equals(pub)) {
    throw new RangeError('Incorrect public key');
  }
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const k = randomScalar();
    const K = ec.g.mul(ec.decodeInt(k));
    const buf = Buffer.concat([
      prefix,
      pub,
      Buffer.from(ec.encodePoint(K)),
    ]);
    const c = hashToScalar(buf);
    if (ec.decodeInt(c).isZero()) {
      continue;
    }
    // sc_mulsub(&sig.r, &sig.c, &unwrap(sec), &k);
    // sc_mulsub(aa, bb, cc):
    // (cc - aa * bb) % l
    const r = ec.decodeInt(k)
      .sub(ec.decodeInt(sec).mul(ec.decodeInt(c)))
      .umod(ec.curve.n)
      .toBuffer('le', 32);
    if (ec.decodeInt(r).isZero()) {
      continue;
    }
    return Buffer.concat([c, r]);
  }
}

/**
 * check_signature
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L319-L341
 */

export function checkSignature(prefix, pub, sig) {
  if (keyCheck(pub) !== true) {
    throw new RangeError('Invalid public key');
  }
  const c = sig.slice(0, 32);
  const r = sig.slice(32, 64);
  if (scalarCheck(c) === false || scalarCheck(r) === false || ec.decodeInt(c).isZero()) {
    return false;
  }
  const P1 = ec.decodePoint(fixBufferToArray(pub));
  const P2 = P1.mul(ec.decodeInt(c)).add(ec.g.mul(ec.decodeInt(r)));
  const buf = Buffer.concat([
    prefix,
    pub,
    Buffer.from(ec.encodePoint(P2)),
  ]);
  return ec.decodeInt(c).eq(ec.decodeInt(hashToScalar(buf)));
}

/**
 * Square root candidate
 * x = (u/v)^(p+3)/8 = u*v^3*(u*v^7)^(p-5)/8
 * https://tools.ietf.org/html/rfc8032#section-5.1.3
 * https://crypto.stackexchange.com/questions/88868/why-computation-of-uv3uv7p-5-8-is-suggested-instead-of-u-vp3-8
 */

function squareRoot(u, v) {
  return u.redMul(v.redPow(new BN(3)))
    .redMul(u.redMul(v.redPow(new BN(7))).redPow(ec.curve.p.subn(5).divn(8)));
}

const red = BN.red('p25519');
const A = new BN(486662, 10).toRed(red);

// sqrt(-1)
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L38
const sqrtm1 = new BN(1).toRed(red).redNeg().redSqrt();

// sqrt(-2 * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L869
const fffb1 = A.redAdd(new BN(2).toRed(red))
  .redMul(A)
  .redMul(new BN(2).toRed(red).redNeg())
  .redSqrt();

// sqrt(2 * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L870
const fffb2 = A.redAdd(new BN(2).toRed(red))
  .redMul(A)
  .redMul(new BN(2).toRed(red))
  .redSqrt();

// sqrt(-sqrt(-1) * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L871
const fffb3 = A.redAdd(new BN(2).toRed(red))
  .redMul(A)
  .redMul(sqrtm1.redNeg())
  .redSqrt();

// sqrt(sqrt(-1) * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L872
const fffb4 = A.redAdd(new BN(2).toRed(red))
  .redMul(A)
  .redMul(sqrtm1)
  .redSqrt();

/**
 * ge_fromfe_frombytes_vartime
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c#L2310-L2424
 * https://github.com/monero-project/monero/blob/v0.17.1.9/tests/crypto/crypto.cpp#L47-L51
 */

export function hashToPoint(data) {
  /**
   * u - input data
   * v = 2 * u^2
   * w = 2 * u^2 + 1 = v + 1
   * t = w^2 - 2 * A^2 * u^2 = w^2 - A^2 * v
   * x = sqrt( w / w^2 - 2 * A^2 * u^2 ) = sqrt( w / t )
   *
   * negative = false
   * check = w - x^2 * t
   *
   * if (isnonzero(check)) {
   *   check = w + x^2 * t
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
   *   check = w - sqrtm1 * x^2 * t
   *   if (isnonzero(check)) {
   *     check = w + sqrtm1 * x^2 * t
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
   */

  const u = new BN(data, 'hex', 'le').toRed(red);
  // v = 2 * u^2
  const v = u.redMul(u).redMul(new BN(2).toRed(red));
  // w = 2 * u^2 + 1 = v + 1
  const w = v.redAdd(new BN(1).toRed(red));
  // t = w^2 - 2 * A^2 * u^2 = w^2 - A^2 * v
  const t = w.redMul(w).redSub(A.redMul(A).redMul(v));
  // x = sqrt( w / w^2 - 2 * A^2 * u^2 ) = sqrt( w / t )
  let x = squareRoot(w, t);

  let negative = false;

  // check = w - x^2 * t
  let check = w.redSub(x.redMul(x).redMul(t));

  if (!check.isZero()) {
    // check = w + x^2 * t
    check = w.redAdd(x.redMul(x).redMul(t));
    if (!check.isZero()) {
      negative = true;
    } else {
      // x = x * fe_fffb1
      x = x.redMul(fffb1);
      debug('hashToPoint case #1');
    }
  } else {
    // x = x * fe_fffb2
    x = x.redMul(fffb2);
    debug('hashToPoint case #2');
  }

  let odd;
  let r;
  if (!negative) {
    odd = false;
    // r = -2 * A * u^2 = -1 * A * v
    r = A.redNeg().redMul(v);
    // x = x * u
    x = x.redMul(u);
  } else {
    odd = true;
    // r = -1 * A
    r = A.redNeg();
    // check = w - sqrtm1 * x^2 * t
    check = w.redSub(x.redMul(x).redMul(t).redMul(sqrtm1));
    if (!check.isZero()) {
      // check = w + sqrtm1 * x^2 * t
      check = w.redAdd(x.redMul(x).redMul(t).redMul(sqrtm1));
      if (!check.isZero()) {
        throw new TypeError('Invalid point');
      } else {
        x = x.redMul(fffb3);
        debug('hashToPoint case #3');
      }
    } else {
      x = x.redMul(fffb4);
      debug('hashToPoint case #4');
    }
  }

  if (x.isOdd() !== odd) {
    // x = -1 * x
    x = x.redNeg();
  }

  // z = r + w
  const z = r.redAdd(w);
  // y = r - w
  const y = r.redSub(w);
  // x = x * z
  x = x.redMul(z);

  return ec.curve.point(x, y, z);
}

export default {
  randomScalar,
  generateKeys,
  fastHash,
  scalarReduce32,
  scalarCheck,
  hashToScalar,
  keyCheck,
  secretKeyToPublicKey,
  generateKeyDerivation,
  derivationToScalar,
  derivePublicKey,
  deriveSecretKey,
  generateSignature,
  checkSignature,
  hashToPoint,
};
