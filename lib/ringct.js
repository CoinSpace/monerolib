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
} from './helpers.js';

// rct signature types
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L298-L305
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
 * An rct signature type: one of the values of RCTTypes.
 * @typedef {(typeof RCTTypes)[keyof typeof RCTTypes]} RctType
 */

const RCT_TYPE_VALUES = new Set(Object.values(RCTTypes));

/**
 * True for a known rct signature type.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L337-L339
 *
 * @param {number} type
 * @returns {boolean}
 */
export function isKnownRctType(type) {
  return RCT_TYPE_VALUES.has(type);
}

/**
 * True for rct types using the compact ecdh format introduced with Bulletproof2:
 * deterministic mask (not serialized) and only the first 8 bytes of the encrypted amount.
 *
 * @param {RctType} rctType
 * @returns {boolean}
 */
export function isV2EcdhType(rctType) {
  return rctType === RCTTypes.Bulletproof2
    || rctType === RCTTypes.CLSAG
    || rctType === RCTTypes.BulletproofPlus;
}

/**
 * ecdhHash
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L674-L682
 *
 * @param {bigint} amountKey - shared secret scalar
 * @returns {Uint8Array} 32-byte hash
 */

export function ecdhHash(amountKey) {
  const data = concatBytes(
    utf8ToBytes('amount'),
    encodeInt(amountKey)
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
 * @param {bigint} amountKey - shared secret scalar
 * @returns {bigint} commitment mask
 */
export function genCommitmentMask(amountKey) {
  return hashToScalar(utf8ToBytes('commitment_mask'), encodeInt(amountKey));
}

/**
 * ecdhEncode
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L698-L712
 *
 * Math:
 * v1 masks both scalars additively with shared-secret hashes:
 * mask' = mask + Hs(k), amount' = amount + Hs(Hs(k)).
 * v2 keeps the mask deterministic from the shared secret and only xor-masks the first 8 amount
 * bytes with H("amount" || k).
 *
 * @param {import('./raw.js').EcdhTuple} ecdhInfo - wire mask and amount
 * @param {bigint} amountKey - shared secret scalar
 * @param {RctType} rctType - one of RCTTypes
 * @returns {import('./raw.js').EcdhTuple}
 */

export function ecdhEncode(ecdhInfo, amountKey, rctType) {
  if (!isKnownRctType(rctType)) {
    throw new Error(`ecdhEncode: unknown rct type ${rctType}`);
  }
  const v2 = isV2EcdhType(rctType);
  if (v2) {
    return {
      // zeros
      mask: new Uint8Array(32),
      amount: xorBuffer8(ecdhInfo.amount, ecdhHash(amountKey)),
    };
  } else {
    const first = hashToScalar(encodeInt(amountKey));
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
 * Math:
 * invert ecdhEncode with the same shared secret.
 * v1 subtracts Hs(k) and Hs(Hs(k)) from the wire mask and amount scalars.
 * v2 recomputes the deterministic commitment mask from k and xor-unmasks the first 8 amount
 * bytes with H("amount" || k).
 *
 * @param {import('./raw.js').EcdhTuple} ecdhInfo - wire mask and amount
 * @param {bigint} amountKey - shared secret scalar
 * @param {RctType} rctType - one of RCTTypes
 * @returns {import('./raw.js').EcdhTuple}
 */
export function ecdhDecode(ecdhInfo, amountKey, rctType) {
  if (!isKnownRctType(rctType)) {
    throw new Error(`ecdhDecode: unknown rct type ${rctType}`);
  }
  const v2 = isV2EcdhType(rctType);
  if (v2) {
    // with deterministic mask
    return {
      mask: encodeInt(genCommitmentMask(amountKey)),
      amount: xorBuffer8(ecdhInfo.amount, ecdhHash(amountKey)),
    };
  } else {
    const first = hashToScalar(encodeInt(amountKey));
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
 * Math:
 * derive the per-output shared scalar k from the key derivation and output index, decrypt the
 * ECDH tuple, then recompute C = mask*G + amount*H and require it to match the serialized outPk
 * commitment before returning the decoded amount.
 *
 * Only for RingCT outputs. A coinbase (miner) output is not RingCT — its on-chain commitment is
 * all-zero (a placeholder), so decoding it here throws; use decodeCoinbase instead.
 *
 * @param {import('./raw.js').EcdhTuple} ecdhInfo
 * @param {Uint8Array} outPk - 32-byte output commitment
 * @param {RctType} rctType - one of RCTTypes
 * @param {number} index - output index
 * @param {Uint8Array} derivation - 32-byte key derivation
 * @returns {{
 *   mask: bigint,
 *   amount: bigint
 * }} decoded mask and amount scalars
 * @throws {Error} if the commitment does not match outPk
 */
export function decodeRct(ecdhInfo, outPk, rctType, index, derivation) {
  if (!isKnownRctType(rctType)) {
    throw new Error(`decodeRct: unknown rct type ${rctType}`);
  }
  const amountKey = derivationToScalar(derivation, index);
  const ecdh = ecdhDecode(ecdhInfo, amountKey, rctType);
  const commit = pedersenCommitment(decodeInt(ecdh.amount), decodeInt(ecdh.mask));
  if (!equalBytes(commit, outPk)) {
    throw new Error('mismatched commitments');
  }
  return { mask: decodeInt(ecdh.mask), amount: decodeInt(ecdh.amount) };
}

/**
 * decodeCoinbase: the "decoded" form of a coinbase (miner) output. Coinbase outputs are not RingCT —
 * the amount is cleartext on-chain and the commitment is the transparent zeroCommit (mask = 1). Use
 * this instead of decodeRct (which expects a real encrypted ecdh tuple and would throw) when the
 * output's on-chain commitment is all-zero.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L322-L334
 *
 * @param {bigint} amount - cleartext coinbase amount in atomic units
 * @returns {{ amount: bigint, mask: bigint, commitment: Uint8Array }} spend-ready fields
 */
export function decodeCoinbase(amount) {
  return {
    amount,
    mask: 1n,
    commitment: zeroCommit(amount),
  };
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
