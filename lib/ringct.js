import { equalBytes } from '@noble/curves/utils.js';
import { mod } from '@noble/curves/abstract/modular.js';
import { CURVE, Point } from './crypto-util-data.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  decodeInt,
  decodePoint,
  encodeInt,
  encodePoint,
} from './helpers.js';
import {
  derivationToScalar,
  fastHash,
  hashToScalar,
} from './crypto-util.js';

// rct::H — second generator for Pedersen commitments
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L633
// eslint-disable-next-line max-len
const H = decodePoint(new Uint8Array([0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94]));

/**
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L298-L305
 * @enum {number}
 */
export const RCTTypes = {
  Null: 0,
  Full: 1,
  Simple: 2,
  Bulletproof: 3,
  Bulletproof2: 4,
  CLSAG: 5,
  BulletproofPlus: 6,
};

/**
 * ecdhHash
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L674-L682
 *
 * @param {Uint8Array} buf - 32-byte shared secret
 * @returns {Uint8Array} 32-byte hash
 */

export function ecdhHash(buf) {
  const data = concatBytes(
    utf8ToBytes('amount'),
    buf
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
 * @param {Uint8Array} buf - 32-byte shared secret
 * @returns {Uint8Array} 32-byte commitment mask
 */
function genCommitmentMask(buf) {
  const data = concatBytes(
    utf8ToBytes('commitment_mask'),
    buf
  );
  return hashToScalar(data);
}

/**
 * True for rct types using the compact ecdh format introduced with Bulletproof2:
 * deterministic mask (not serialized) and only the first 8 bytes of the encrypted amount.
 *
 * @param {number} rctType - one of RCTTypes
 * @returns {boolean}
 */
export function isV2EcdhType(rctType) {
  return rctType === RCTTypes.Bulletproof2
    || rctType === RCTTypes.CLSAG
    || rctType === RCTTypes.BulletproofPlus;
}

/**
 * ecdhEncode
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L698-L712
 *
 * @param {{ mask?: Uint8Array, amount: Uint8Array }} ecdhInfo
 * @param {Uint8Array} key - 32-byte shared secret
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
    const first = hashToScalar(key);
    const second = hashToScalar(first);
    return {
      mask: encodeInt(mod(decodeInt(ecdhInfo.mask) + decodeInt(first), CURVE.n)),
      amount: encodeInt(mod(decodeInt(ecdhInfo.amount) + decodeInt(second), CURVE.n)),
    };
  }
}

/**
 * ecdhDecode
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L713-L727
 *
 * @param {{ mask?: Uint8Array, amount: Uint8Array }} ecdhInfo
 * @param {Uint8Array} key - 32-byte shared secret
 * @param {number} rctType - one of RCTTypes
 * @returns {{ mask: Uint8Array, amount: Uint8Array }}
 */
export function ecdhDecode(ecdhInfo, key, rctType) {
  const v2 = isV2EcdhType(rctType);
  if (v2) {
    // with deterministic mask
    return {
      mask: genCommitmentMask(key),
      amount: xorBuffer8(ecdhInfo.amount, ecdhHash(key)),
    };
  } else {
    const first = hashToScalar(key);
    const second = hashToScalar(first);
    return {
      mask: encodeInt(mod(decodeInt(ecdhInfo.mask) - decodeInt(first), CURVE.n)),
      amount: encodeInt(mod(decodeInt(ecdhInfo.amount) - decodeInt(second), CURVE.n)),
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
  const commit = pedersenCommitment(ecdh.amount, ecdh.mask);
  if (!equalBytes(commit, outPk)) {
    throw new Error('mismatched commitments');
  }
  ecdh.amount = decodeInt(ecdh.amount).toString(10);
  return ecdh;
}

/**
 * Pedersen commitment: mask*G + amount*H
 * addKeys2: https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L478-L484
 *
 * @param {Uint8Array} amount - 32-byte scalar
 * @param {Uint8Array} mask - 32-byte scalar
 * @returns {Uint8Array} 32-byte commitment
 */
export function pedersenCommitment(amount, mask) {
  // bG + aH where b = mask, a = amount
  const b = decodeInt(mask);
  const a = decodeInt(amount);
  return encodePoint(Point.BASE.multiplyUnsafe(b).add(H.multiplyUnsafe(a)));
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

export default {
  RCTTypes,
  ecdhEncode,
  ecdhDecode,
  decodeRct,
  pedersenCommitment,
  zeroCommit,
};
