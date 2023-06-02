import { Buffer } from 'buffer';
import { ec } from './crypto-util-data.js';
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

import BN from 'bn.js';

const H = decodePoint(Buffer.from('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94', 'hex'));
const I = decodeInt('0100000000000000000000000000000000000000000000000000000000000000');

// https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctTypes.h#L253-L260
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
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L672-L682
 */

export function ecdhHash(buf) {
  if (typeof buf === 'string') buf = Buffer.from(buf, 'hex');
  const data = Buffer.concat([
    Buffer.from('amount', 'ascii'),
    buf,
  ]);
  return fastHash(data);
}

/**
 * xor8 - xor first 8 bytes from each buffer
 * leaves remaining 24 bytes as zeros
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L683-L687
 */

function xorBuffer8(a, b) {
  if (typeof a === 'string') a = Buffer.from(a, 'hex');
  if (typeof b === 'string') b = Buffer.from(b, 'hex');
  const buffer = Buffer.alloc(32);
  for (let i = 0; i < 8; ++i) {
    buffer[i] = a[i] ^ b[i];
  }
  return buffer;
}

/**
 * genCommitmentMask
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L688-L696
 */
function genCommitmentMask(buf) {
  if (typeof buf === 'string') buf = Buffer.from(buf, 'hex');
  const data = Buffer.concat([
    Buffer.from('commitment_mask', 'ascii'),
    buf,
  ]);
  return hashToScalar(data);
}

/**
 *
 * ecdhEncode
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L698-L712
 */

export function ecdhEncode(ecdhInfo, key, rctType) {
  if (typeof key === 'string') key = Buffer.from(key, 'hex');
  const v2 = (rctType === RCTTypes.Bulletproof2 || rctType === RCTTypes.CLSAG || rctType === RCTTypes.BulletproofPlus);
  if (v2) {
    return {
      // zeros
      mask: Buffer.alloc(32),
      amount: xorBuffer8(ecdhInfo.amount, ecdhHash(key)),
    };
  } else {
    const first = hashToScalar(key);
    const second = hashToScalar(first);
    return {
      mask: encodeInt(decodeInt(ecdhInfo.mask).add(decodeInt(first)).umod(ec.curve.n)),
      amount: encodeInt(decodeInt(ecdhInfo.amount).add(decodeInt(second)).umod(ec.curve.n)),
    };
  }
}

/**
 * ecdhDecode
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L713-L727
 */
export function ecdhDecode(ecdhInfo, key, rctType) {
  if (typeof key === 'string') key = Buffer.from(key, 'hex');
  const v2 = (rctType === RCTTypes.Bulletproof2 || rctType === RCTTypes.CLSAG || rctType === RCTTypes.BulletproofPlus);
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
      mask: encodeInt(decodeInt(ecdhInfo.mask).sub(decodeInt(first)).umod(ec.curve.n)),
      amount: encodeInt(decodeInt(ecdhInfo.amount).sub(decodeInt(second)).umod(ec.curve.n)),
    };
  }
}

/**
 * decodeRct
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctSigs.cpp#L1516-L1539
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/wallet/wallet2.cpp#L1768-L1793
 */
export function decodeRct(ecdhInfo, outPk, rctType, index, keyDerivation) {
  if (typeof outPk === 'string') outPk = Buffer.from(outPk, 'hex');
  const key = derivationToScalar(keyDerivation, index);
  const ecdh = ecdhDecode(ecdhInfo, key, rctType);
  const commit = pedersenCommitment(ecdh.amount, ecdh.mask);
  if (!commit.equals(outPk)) {
    throw new Error('mismatched commitments');
  }
  ecdh.amount = new BN(decodeInt(ecdh.amount)).toString(10);
  return ecdh;
}

export function pedersenCommitment(amount, mask) {
  if (typeof amount === 'string') amount = Buffer.from(amount, 'hex');
  if (typeof mask === 'string') mask = Buffer.from(mask, 'hex');
  // bG + aH where b = mask, a = amount
  const b = decodeInt(mask);
  const a = decodeInt(amount);
  return encodePoint(ec.g.mul(b).add(H.mul(a)));
}

/**
 * zeroCommit
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L322
 */
export function zeroCommit(amount) {
  const a = new BN(amount);
  return encodePoint(ec.g.mul(I).add(H.mul(a)));
}

export default {
  RCTTypes,
  ecdhEncode,
  ecdhDecode,
  decodeRct,
  pedersenCommitment,
  zeroCommit,
};
