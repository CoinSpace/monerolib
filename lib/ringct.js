import { equalBytes } from '@noble/curves/utils.js';
import { mod } from '@noble/curves/abstract/modular.js';
import { CURVE, Point } from './crypto-util-data.js';
import { concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
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

const H = decodePoint(hexToBytes('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'));
const I = 1n;

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
  const data = concatBytes(
    utf8ToBytes('amount'),
    buf
  );
  return fastHash(data);
}

/**
 * xor8 - xor first 8 bytes from each buffer
 * leaves remaining 24 bytes as zeros
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L683-L687
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
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L688-L696
 */
function genCommitmentMask(buf) {
  const data = concatBytes(
    utf8ToBytes('commitment_mask'),
    buf
  );
  return hashToScalar(data);
}

/**
 *
 * ecdhEncode
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L698-L712
 */

export function ecdhEncode(ecdhInfo, key, rctType) {
  const v2 = (rctType === RCTTypes.Bulletproof2 || rctType === RCTTypes.CLSAG || rctType === RCTTypes.BulletproofPlus);
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
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L713-L727
 */
export function ecdhDecode(ecdhInfo, key, rctType) {
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
      mask: encodeInt(mod(decodeInt(ecdhInfo.mask) - decodeInt(first), CURVE.n)),
      amount: encodeInt(mod(decodeInt(ecdhInfo.amount) - decodeInt(second), CURVE.n)),
    };
  }
}

/**
 * decodeRct
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctSigs.cpp#L1516-L1539
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/wallet/wallet2.cpp#L1768-L1793
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

export function pedersenCommitment(amount, mask) {
  // bG + aH where b = mask, a = amount
  const b = decodeInt(mask);
  const a = decodeInt(amount);
  return encodePoint(Point.BASE.multiplyUnsafe(b).add(H.multiplyUnsafe(a)));
}

/**
 * zeroCommit
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/ringct/rctOps.cpp#L322
 */
export function zeroCommit(amount) {
  const a = BigInt(amount);
  return encodePoint(Point.BASE.multiplyUnsafe(I).add(H.multiplyUnsafe(a)));
}

export default {
  RCTTypes,
  ecdhEncode,
  ecdhDecode,
  decodeRct,
  pedersenCommitment,
  zeroCommit,
};
