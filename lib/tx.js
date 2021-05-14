import BN from 'bn.js';
import { fastHash } from './crypto-util.js';
import { decodeVarint } from './helpers.js';
import { RCTTypes } from './ringct.js';

export function getTxIdFromHex(hex) {
  const buf = Buffer.from(hex, 'hex');
  const { prefix, inputsLength, outputsLength } = _getTxPrefix(buf);
  const { base, type } = _getTxBase(buf.slice(prefix.length), inputsLength, outputsLength);

  if (type === RCTTypes.Null) {
    return fastHash(
      Buffer.concat([
        fastHash(prefix),
        fastHash(base),
        Buffer.alloc(32),
      ])
    );
  }

  const prunable = buf.slice(prefix.length + base.length);
  return fastHash(
    Buffer.concat([
      fastHash(prefix),
      fastHash(base),
      fastHash(prunable),
    ])
  );
}

function _getTxPrefix(buf) {
  let i = 0;
  let data = {};
  i += decodeVarint(buf).length; // version
  i += decodeVarint(buf.slice(i)).length; // unlockTime

  data = decodeVarint(buf.slice(i));
  const inputsLength = data.number;
  i += data.length;

  i += _readTxPrefixInputs(buf.slice(i), inputsLength);

  data = decodeVarint(buf.slice(i));
  const outputsLength = data.number;
  i += data.length;
  i += _readTxPrefixOutputs(buf.slice(i), outputsLength);

  data = decodeVarint(buf.slice(i)); // extra
  i += data.length;
  i += data.number;
  return {
    prefix: buf.slice(0, i),
    inputsLength,
    outputsLength,
  };
}

function _readTxPrefixInputs(buf, inputsLength) {
  let start = 0;
  let data;
  if (inputsLength === 1 && buf[start] === 0xff) {
    start++;
    start += decodeVarint(buf.slice(start)).length; // height
    return start;
  }
  for (let i = 0; i < inputsLength; i++) {
    start += decodeVarint(buf.slice(start)).length; // inputType
    start += decodeVarint(buf.slice(start)).length; // amount
    data = decodeVarint(buf.slice(start));
    const keyOffsetsLength = data.number;
    start += data.length;
    for (let j = 0; j < keyOffsetsLength; j++) {
      start += decodeVarint(buf.slice(start)).length;
    }
    start += 32;
  }
  return start;
}

function _readTxPrefixOutputs(buf, outputsLength) {
  let start = 0;
  for (let i = 0; i < outputsLength; i++) {
    start += decodeVarint(buf.slice(start)).length; // amount
    start += decodeVarint(buf.slice(start)).length; // outputType
    start += 32;
  }
  return start;
}

function _getTxBase(buf, inputsLength, outputsLength) {
  let i = 0;
  const data = decodeVarint(buf); // RCTType
  const type = data.number;
  if (type === RCTTypes.Null) {
    return {
      base: Buffer.from('00', 'hex'),
      type,
    };
  }

  i += data.length;
  i += decodeVarint(buf.slice(i)).length; // fee;

  if (type === RCTTypes.Simple) {
    i += 32 * inputsLength;
  }
  if (type === RCTTypes.Bulletproof2 || type === RCTTypes.CLSAG) {
    i += 8 * outputsLength;
  } else {
    i += 64 * outputsLength;
  }
  i += 32 * outputsLength;
  return {
    base: buf.slice(0, i),
    type,
  };
}

/**
 * https://github.com/monero-project/monero/blob/v0.17.1.9/src/cryptonote_basic/tx_extra.h
 */

export function parseTxExtra(buf) {
  const TX_EXTRA_TAG_PADDING = 0x00;
  const TX_EXTRA_TAG_PUBKEY = 0x01;
  const TX_EXTRA_NONCE = 0x02;
  const TX_EXTRA_NONCE_PAYMENT_ID = 0x00;
  const TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 0x01;

  const TX_EXTRA_MERGE_MINING_TAG = 0x03;
  const TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;
  const TX_EXTRA_MYSTERIOUS_MINERGATE_TAG = 0xDE;
  const TX_EXTRA_PADDING_MAX_COUNT = 255;

  const tags = [
    TX_EXTRA_TAG_PUBKEY,
    TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
    TX_EXTRA_NONCE,
    TX_EXTRA_MERGE_MINING_TAG,
    TX_EXTRA_MYSTERIOUS_MINERGATE_TAG,
    TX_EXTRA_TAG_PADDING,
  ];

  let txPubKey = Buffer.alloc(0);
  let encryptedPaymentId = Buffer.alloc(0);
  for (let i = 0; i < buf.length; i++) {
    const item = buf[i];
    const tag = tags.find((tag) => tag === item);
    if (typeof tag === 'undefined') break;
    if (tag === TX_EXTRA_TAG_PUBKEY) {
      i++;
      txPubKey = buf.slice(i, i + 32);
      i += 32 - 1;
      tags.splice(tags.indexOf(TX_EXTRA_TAG_PUBKEY), 1);
    } else if (tag === TX_EXTRA_TAG_ADDITIONAL_PUBKEYS) {
      const size = 32 * buf[i + 1];
      if (isNaN(size)) break;
      i += size;
      tags.splice(tags.indexOf(TX_EXTRA_TAG_ADDITIONAL_PUBKEYS), 1);
    } else if (tag === TX_EXTRA_NONCE) {
      const nonceSize = buf[i + 1];
      if (isNaN(nonceSize)) break;
      i++;
      const nonce = buf.slice(i + 1, i + 1 + nonceSize);
      // parse nonce
      for (let j = 0; j < nonce.length; j++) {
        if (nonce[j] === TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID) {
          j++;
          encryptedPaymentId = nonce.slice(j, j + 8);
          j += 8 - 1;
          continue;
        }
        if (nonce[j] === TX_EXTRA_NONCE_PAYMENT_ID) {
          j++;
          j += 32 - 1;
          continue;
        }
      }
      i += nonceSize;
      tags.splice(tags.indexOf(TX_EXTRA_NONCE), 1);
    } else if (tag === TX_EXTRA_MERGE_MINING_TAG) {
      const size = buf[i + 1];
      if (isNaN(size)) break;
      i += size;
      tags.splice(tags.indexOf(TX_EXTRA_MERGE_MINING_TAG), 1);
    } else if (tag === TX_EXTRA_MYSTERIOUS_MINERGATE_TAG) {
      const size = buf[i + 1];
      if (isNaN(size)) break;
      i += size;
      tags.splice(tags.indexOf(TX_EXTRA_MYSTERIOUS_MINERGATE_TAG), 1);
    } else if (tag === TX_EXTRA_TAG_PADDING) {
      for (let j = 1; j < TX_EXTRA_PADDING_MAX_COUNT; j++) {
        if (buf[i+1] !== TX_EXTRA_TAG_PADDING) break;
        i++;
      }
      tags.splice(tags.indexOf(TX_EXTRA_TAG_PADDING), 1);
    }
    if (!tags.length) break;
  }

  return { txPubKey, encryptedPaymentId };
}

export function globalIndexesFromKeyOffsets(keyOffsets) {
  const globalIndexes = keyOffsets.slice();
  for (let i = 1; i < globalIndexes.length; i++) {
    globalIndexes[i] += globalIndexes[i - 1];
  }
  return globalIndexes;
}

/**
 * Estimate transaction size (only RCT)
 *
 * estimate_rct_tx_size
 * estimate_tx_size
 *
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L870
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L814
 *
 * @param {Number} inputs
 * @param {Number} mixin
 * @param {Number} outputs
 * @param {Number} extra
 * @param {Boolean} bulletproof - true by default
 * @param {Boolean} clsag - true by default
 * @returns Number
 */

export function estimateTxSize(inputs, mixin, outputs, extra, bulletproof = true, clsag = true) {
  let size = 0;

  // tx prefix

  // first few bytes
  size += 1 + 6;

  // vin
  size += inputs * (1+6+(mixin+1)*2+32);

  // vout
  size += outputs * (6+32);

  // extra
  size += extra;

  // rct signatures

  // type
  size += 1;

  // rangeSigs
  if (bulletproof) {
    let logPaddedOutputs = 0;
    while ((1<<logPaddedOutputs) < outputs) {
      ++logPaddedOutputs;
    }
    size += (2 * (6 + logPaddedOutputs) + 4 + 5) * 32 + 3;
  } else {
    size += (2*64*32+32+64*32) * outputs;
  }

  // MGs/CLSAGs
  if (clsag) {
    size += inputs * (32 * (mixin+1) + 64);
  } else {
    size += inputs * (64 * (mixin+1) + 32);
  }

  // mixRing - not serialized, can be reconstructed
  /* size += 2 * 32 * (mixin+1) * n_inputs; */

  // pseudoOuts
  size += 32 * inputs;
  // ecdhInfo
  size += 8 * outputs;
  // outPk - only commitment is saved
  size += 32 * outputs;
  // txnFee
  size += 4;

  return size;
}

/**
 *
 * Estimate transaction weight (only RCT)
 *
 * estimate_tx_weight
 *
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L878
 *
 * @param {Number} inputs
 * @param {Number} mixin
 * @param {Number} outputs
 * @param {Number} extra
 * @param {Boolean} bulletproof
 * @param {Boolean} clsag
 * @returns Number
 */

export function estimateTxWeight(inputs, mixin, outputs, extra, bulletproof = true, clsag = true) {
  let size = estimateTxSize(inputs, mixin, outputs, extra, bulletproof, clsag);
  if (bulletproof && outputs > 2) {
    const bpBase = 368;
    let logPaddedOutputs = 2;
    while ((1<<logPaddedOutputs) < outputs) {
      ++logPaddedOutputs;
    }
    const nlr = 2 * (6 + logPaddedOutputs);
    const bpSize = 32 * (9 + nlr);
    // ~~ is Math.floor
    const bpClawback = ~~((bpBase * (1<<logPaddedOutputs) - bpSize) * 4 / 5);
    size += bpClawback;
  }
  return size;
}

/**
 *
 * calculate_fee_from_weight
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L328
 *
 * @param {Number} weight
 * @param {Number} baseFee
 * @param {Number} feeMultiplier
 * @param {Number} feeQuantization
 * @returns String
 */

export function calculateFeeFromWeight(weight, baseFee, feeMultiplier, feeQuantization) {
  const fee = new BN(baseFee, 10).muln(weight * feeMultiplier)
    .addn(feeQuantization - 1)
    .divn(feeQuantization)
    .muln(feeQuantization);
  return fee.toString(10);
}

/**
 *
 * Estimate transaction fee
 *
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L7399
 *
 * Parameters use_per_byte_fee and use_rct from sources are removed
 * and considered to be true in this implementation
 *
 * @param {Number} inputs
 * @param {Number} mixin
 * @param {Number} outputs
 * @param {Number} extra
 * @param {Number|String} baseFee
 * @param {Number|String} feeMultiplier
 * @param {Number} feeQuantization - 1, 5, 25, 1000
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L7425
 * @param {Boolean} bulletproof
 * @param {Boolean} clsag
 * @returns String
 */
export function estimateFee(inputs, mixin, outputs, extra, baseFee, feeMultiplier, feeQuantization,
  bulletproof = true, clsag = true) {
  if (typeof baseFee === 'string') {
    baseFee = parseInt(baseFee, 10);
  }
  if (typeof feeQuantization === 'string') {
    feeQuantization = parseInt(feeQuantization, 10);
  }
  const weight = estimateTxWeight(inputs, mixin, outputs, extra, bulletproof, clsag);
  return calculateFeeFromWeight(weight, baseFee, feeMultiplier, feeQuantization);
}

export default {
  getTxIdFromHex,
  parseTxExtra,
  globalIndexesFromKeyOffsets,
  estimateTxSize,
  estimateTxWeight,
  calculateFeeFromWeight,
  estimateFee,
};
