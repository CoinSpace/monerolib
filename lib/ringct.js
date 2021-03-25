import {
  fastHash,
  hashToScalar,
  scSub,
  xor8,
  derivationToScalar,
} from './crypto-util.js';
import {
  decodeInt,
  decodePoint,
  encodePoint,
} from './helpers.js';
import { ec } from './crypto-util-data.js';

import BN from 'bn.js';

// https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctTypes.h#L253-L260
export const RCTTypes = {
  Null: 0,
  Full: 1,
  Simple: 2,
  Bulletproof: 3,
  Bulletproof2: 4,
  CLSAG: 5,
};

/**
 * ecdhDecode
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L713
 */
export function ecdhDecode(ecdhInfo, key, rctType) {
  const v2 = (rctType === RCTTypes.Bulletproof2 || rctType === RCTTypes.CLSAG);
  if (v2) {
    // with deterministic mask
    const mask = hashToScalar(Buffer.concat([
      Buffer.from('636f6d6d69746d656e745f6d61736b', 'hex'),
      key,
    ])); // "commitment_mask"
    const amtkey = fastHash(Buffer.concat([Buffer.from('616d6f756e74', 'hex'), key])); // "amount"
    const amount = Buffer.concat([
      xor8(ecdhInfo.amount, amtkey.slice(0, 8)),
      Buffer.alloc(24),
    ]);
    return {
      mask,
      amount,
    };
  } else {
    const first = hashToScalar(key);
    const second = hashToScalar(first);
    return {
      mask: scSub(ecdhInfo.mask, first),
      amount: scSub(ecdhInfo.amount, second),
    };
  }
}

/**
 * decodeRct
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctSigs.cpp#L1516
 */
export function decodeRct(ecdhInfo, outPk, rctType, index, keyDerivation) {
  const key = derivationToScalar(keyDerivation, index);
  const ecdh = ecdhDecode(ecdhInfo, key, rctType);
  const commit = pedersenCommitment(ecdh.amount, ecdh.mask);
  if (!commit.equals(outPk)) {
    throw new Error('mismatched commitments');
  }
  ecdh.amount = (new BN(Buffer.from(ecdh.amount).reverse())).toString(10);
  return ecdh;
}

export function pedersenCommitment(amount, mask) {
  // bG + aH where b = mask, a = amount
  const H = decodePoint(Buffer.from('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94', 'hex'));
  const b = decodeInt(mask);
  const a = decodeInt(amount);
  return encodePoint(ec.g.mul(b).add(H.mul(a)));
}

export default {
  RCTTypes,
  ecdhDecode,
  decodeRct,
  pedersenCommitment,
};
