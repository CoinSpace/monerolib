import { equalBytes } from '@noble/curves/utils.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { H } from './crypto-data.js';
import {
  Fn,
  Point,
  derivationToScalar,
  encodePoint,
  fastHash,
  hashToScalar,
} from './crypto.js';
import {
  decodeInt,
  encodeInt,
  isV2EcdhType,
} from './helpers.js';

/**
 * ecdhHash
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L674-L682
 *
 * @param {bigint} key - shared secret scalar
 * @returns {Uint8Array} 32-byte hash
 */

export function ecdhHash(key) {
  const data = concatBytes(
    utf8ToBytes('amount'),
    encodeInt(key)
  );
  return fastHash(data);
}

/**
 * xor8 - xor first 8 bytes from each buffer,
 * leaving the remaining 24 as zeros
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L683-L687
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array} 32-byte buffer
 */

function xorBuffer8(a, b) {
  const buffer = new Uint8Array(32);
  for (let i = 0; i < 8; ++i) {
    buffer[i] = a[i] ^ b[i];
  }
  return buffer;
}

/**
 * genCommitmentMask
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L688-L696
 *
 * @param {bigint} key - shared secret scalar
 * @returns {bigint} commitment mask
 */
export function genCommitmentMask(key) {
  return hashToScalar(utf8ToBytes('commitment_mask'), encodeInt(key));
}

/**
 * ecdhEncode
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L698-L712
 *
 * @param {{ mask?: Uint8Array, amount: Uint8Array }} ecdhInfo - wire mask and amount
 * @param {bigint} key - shared secret scalar
 * @param {number} rctType - one of RCTTypes
 * @returns {{ mask: Uint8Array, amount: Uint8Array }}
 */

export function ecdhEncode(ecdhInfo, key, rctType) {
  const v2 = isV2EcdhType(rctType);
  if (v2) {
    return {
      // zeros
      mask: new Uint8Array(32),
      amount: xorBuffer8(ecdhInfo.amount, ecdhHash(key)),
    };
  } else {
    const first = hashToScalar(encodeInt(key));
    const second = hashToScalar(encodeInt(first));
    return {
      mask: encodeInt(Fn.add(decodeInt(ecdhInfo.mask), first)),
      amount: encodeInt(Fn.add(decodeInt(ecdhInfo.amount), second)),
    };
  }
}

/**
 * ecdhDecode
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L713-L727
 *
 * @param {{ mask?: Uint8Array, amount: Uint8Array }} ecdhInfo - wire mask and amount
 * @param {bigint} key - shared secret scalar
 * @param {number} rctType - one of RCTTypes
 * @returns {{ mask: Uint8Array, amount: Uint8Array }}
 */
export function ecdhDecode(ecdhInfo, key, rctType) {
  const v2 = isV2EcdhType(rctType);
  if (v2) {
    // with deterministic mask
    return {
      mask: encodeInt(genCommitmentMask(key)),
      amount: xorBuffer8(ecdhInfo.amount, ecdhHash(key)),
    };
  } else {
    const first = hashToScalar(encodeInt(key));
    const second = hashToScalar(encodeInt(first));
    return {
      mask: encodeInt(Fn.sub(decodeInt(ecdhInfo.mask), first)),
      amount: encodeInt(Fn.sub(decodeInt(ecdhInfo.amount), second)),
    };
  }
}

/**
 * decodeRct
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L1621-L1645
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L2189-L2204
 *
 * @param {{ mask?: Uint8Array, amount: Uint8Array }} ecdhInfo
 * @param {Uint8Array} outPk - 32-byte output commitment
 * @param {number} rctType - one of RCTTypes
 * @param {number} index - output index
 * @param {Uint8Array} keyDerivation - 32-byte key derivation
 * @returns {{ mask: Uint8Array, amount: string }} mask and decoded amount (decimal string)
 * @throws {Error} if the commitment does not match outPk
 */
export function decodeRct(ecdhInfo, outPk, rctType, index, keyDerivation) {
  const key = derivationToScalar(keyDerivation, index);
  const ecdh = ecdhDecode(ecdhInfo, key, rctType);
  const commit = pedersenCommitment(decodeInt(ecdh.amount), decodeInt(ecdh.mask));
  if (!equalBytes(commit, outPk)) {
    throw new Error('mismatched commitments');
  }
  ecdh.amount = decodeInt(ecdh.amount).toString(10);
  return ecdh;
}

/**
 * Pedersen commitment: mask*G + amount*H
 * addKeys2
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L478-L484
 *
 * @param {bigint} amount - amount scalar
 * @param {bigint} mask - mask scalar
 * @returns {Uint8Array} 32-byte commitment
 */
export function pedersenCommitment(amount, mask) {
  // bG + aH where b = mask, a = amount
  return encodePoint(Point.BASE.multiplyUnsafe(mask).add(H.multiplyUnsafe(amount)));
}

/**
 * zeroCommit: G + amount*H (commitment with mask = 1)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L322-L334
 *
 * @param {bigint} amount - amount in atomic units
 * @returns {Uint8Array} 32-byte commitment
 */
export function zeroCommit(amount) {
  return encodePoint(Point.BASE.add(H.multiplyUnsafe(amount)));
}
