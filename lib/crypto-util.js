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
};
