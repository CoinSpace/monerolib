/**
 * crypto.cpp & crypto-ops.c
 *
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops.c
 */
import BN from 'bn.js';
import elliptic from 'elliptic';
import keccak from 'keccak';
import Debug from 'debug';

const debug = Debug('monerolib:crypto-util');

const ec = new elliptic.eddsa('ed25519');

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
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto.cpp#L143-L146
 */

export function hashToScalar(data) {
  const hash = fastHash(data);
  return scalarReduce32(hash);
}

export function keyCheck(data) {
  // Convert Buffer to Array
  // https://github.com/indutny/elliptic/issues/248
  const bytes = Array.from(data);
  try {
    const point = ec.decodePoint(bytes);
    const valid = point.validate();
    debug('keyCheck validate: %s', valid);
    return valid;
  } catch (err) {
    debug('keyCheck error: %s', err.message);
    return false;
  }
}

export default {
  fastHash,
  scalarReduce32,
  scalarCheck,
  hashToScalar,
  keyCheck,
};
