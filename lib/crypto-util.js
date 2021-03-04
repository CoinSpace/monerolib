/**
 * crypto.cpp & crypto-ops.c
 *
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c
 */
import BN from 'bn.js';
import elliptic from 'elliptic';
import keccak from 'keccak';
import varint from 'varint';
import Debug from 'debug';

const debug = Debug('monerolib:crypto-util');

const ec = new elliptic.eddsa('ed25519');

// TODO remove when fixed
function fixBufferToArray(buf) {
  // Convert Buffer to Array
  // https://github.com/indutny/elliptic/issues/248
  return Array.from(buf);
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
  const num = new BN(scalar, 16, 'le');
  return num.umod(ec.curve.n).toBuffer('le', 32);
}

/**
 * sc_check
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c#L3814
 */

export function scalarCheck(scalar) {
  return new BN(scalar, 16, 'le').lt(ec.curve.n);
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
  return new BN(sec, 16, 'le')
    .add(new BN(scalar, 16, 'le'))
    .umod(ec.curve.n)
    .toBuffer('le', 32);
}

export default {
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
};
