import { hexToBytes, randomBytes } from '@noble/hashes/utils.js';

import * as crypto from '../../lib/crypto.js';

/**
 * A tx secret key generator that returns the given keys in order.
 *
 * @param {Array<bigint | Uint8Array>} keys
 * @returns {() => bigint | Uint8Array}
 */
export function fixedKeys(keys) {
  const iterator = keys.values();
  return () => iterator.next().value;
}

/**
 * Run fn with a replaced random source, then restore the CSPRNG.
 *
 * @template T
 * @param {(length: number) => Uint8Array} source
 * @param {() => T} fn
 * @returns {T}
 */
export function withRandomSource(source, fn) {
  crypto.__mockRandomBytes__(source);
  try {
    return fn();
  } finally {
    crypto.__mockRandomBytes__(randomBytes);
  }
}

// The low-order points of monero's invalid_torsion tests.
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/bulletproofs_plus.cpp#L115-L124
export const TORSION_ELEMENTS = [
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
].map(hexToBytes);

/**
 * @param {Uint8Array} point - 32-byte point
 * @param {Uint8Array} torsion - 32-byte low-order point
 * @returns {Uint8Array} point + torsion
 */
export function addTorsion(point, torsion) {
  return crypto.encodePoint(crypto.decodePoint(point).add(crypto.decodePoint(torsion)));
}
