import { RCTTypes } from './config.js';
import { equalBytes } from '@noble/curves/utils.js';
import { proveClsag } from './clsag.js';
import { proveRangeBulletproofPlus } from './bulletproofs.js';
import {
  Fn,
  derivationToScalar,
  derivePublicKey,
  deriveViewTag,
  fastHash,
  generateKeyDerivation,
  generateKeyImage,
  randomScalar,
  secretKeyToPublicKey,
} from './crypto-util.js';
import {
  TX_EXTRA_NONCE,
  TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID,
  TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
  TX_EXTRA_TAG_PUBKEY,
  rctBase,
  rctPrunable,
  transaction,
  txExtra,
  txParams,
  txPrefix,
} from './raw.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { decodeInt, decodePoint, encodeInt, encodePoint } from './helpers.js';
import { ecdhEncode, genCommitmentMask, pedersenCommitment } from './ringct.js';

/**
 * Transaction id: keccak(keccak(prefix) || keccak(rctSigBase) || keccak(rctSigPrunable)). The
 * prunable hash is replaced by 32 zero bytes for the Null rct type.
 * calculate_transaction_hash
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L138-L175
 *
 * @param {string} hex - full transaction hex
 * @returns {Uint8Array} 32-byte transaction id
 */
export function getTxIdFromHex(hex) {
  const tx = transaction.decode(hexToBytes(hex));
  const { type } = tx.rctSigBase;
  const { inputs, outputs, mixin } = txParams(tx.prefix);
  const prefix = fastHash(txPrefix.encode(tx.prefix));
  const base = fastHash(rctBase(inputs, outputs).encode(tx.rctSigBase));
  const prunable = type === RCTTypes.Null
    ? new Uint8Array(32)
    : fastHash(rctPrunable(type, inputs, outputs, mixin).encode(tx.rctSigPrunable));
  return fastHash(concatBytes(prefix, base, prunable));
}

/**
 * Build tx_extra: tx public key (0x01), additional public keys (0x04), encrypted payment id
 * nonce (0x02), emitted in the order produced by monero sort_tx_extra.
 * sort_tx_extra
 * tx_extra tags
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L603-L664
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/tx_extra.h#L34-L45
 *
 * @param {{ txPublicKey: Uint8Array, additionalPublicKeys?: Uint8Array[], encryptedPaymentId?: Uint8Array }} fields
 * @returns {Uint8Array} tx_extra bytes
 */
export function buildTxExtra({ txPublicKey, additionalPublicKeys = [], encryptedPaymentId }) {
  const fields = [{ tag: TX_EXTRA_TAG_PUBKEY, data: txPublicKey }];
  if (additionalPublicKeys.length) {
    fields.push({ tag: TX_EXTRA_TAG_ADDITIONAL_PUBKEYS, data: additionalPublicKeys });
  }
  if (encryptedPaymentId) {
    // nonce = TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID (0x01) || 8-byte encrypted id
    const nonce = concatBytes(Uint8Array.of(TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID), encryptedPaymentId);
    fields.push({ tag: TX_EXTRA_NONCE, data: nonce });
  }
  return txExtra.encode(fields);
}

/**
 * Extracts tx public key, additional pub keys and encrypted payment id from tx_extra.
 * A subset of monero parse_tx_extra (only the fields we need).
 *
 * tx_extra tags
 * parse_tx_extra
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/tx_extra.h#L34-L45
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L567-L586
 *
 * @param {Uint8Array} buf - tx_extra bytes
 * @returns {{ txPublicKey: Uint8Array, encryptedPaymentId: Uint8Array, additionalPublicKeys: Uint8Array[] }}
 */

export function parseTxExtra(buf) {
  // fold the first occurrence of each field we care about into the result; an encrypted payment id
  // is exactly TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID (0x01) || 8 bytes
  // get_encrypted_payment_id_from_tx_extra_nonce
  // https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L830-L838
  let haveTxPublicKey = false;
  let haveAdditionalPublicKeys = false;
  let haveEncryptedPaymentId = false;
  return txExtra.decode(buf).reduce((acc, { tag, data }) => {
    if (tag === TX_EXTRA_TAG_PUBKEY && !haveTxPublicKey) {
      acc.txPublicKey = data;
      haveTxPublicKey = true;
    } else if (tag === TX_EXTRA_TAG_ADDITIONAL_PUBKEYS && !haveAdditionalPublicKeys) {
      acc.additionalPublicKeys = data;
      haveAdditionalPublicKeys = true;
    } else if (tag === TX_EXTRA_NONCE && !haveEncryptedPaymentId
      && data.length === 9 && data[0] === TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID) {
      acc.encryptedPaymentId = data.slice(1, 9);
      haveEncryptedPaymentId = true;
    }
    return acc;
  }, { txPublicKey: new Uint8Array(32), encryptedPaymentId: new Uint8Array(0), additionalPublicKeys: [] });
}

/**
 * encrypt_payment_id: paymentId XOR keccak(derivation || 0x8d)[:8], where derivation = tx_key * A.
 * Symmetric, so the same function decrypts. Operates on the 8-byte short (encrypted) payment id.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L354-L370
 *
 * @param {Uint8Array} paymentId - 8-byte payment id
 * @param {Uint8Array} viewPublicKey - 32-byte recipient view public key
 * @param {Uint8Array} txSecretKey - 32-byte tx secret key
 * @returns {Uint8Array} 8-byte encrypted payment id
 */
export function encryptPaymentId(paymentId, viewPublicKey, txSecretKey) {
  const derivation = generateKeyDerivation(viewPublicKey, txSecretKey);
  const pad = fastHash(concatBytes(derivation, Uint8Array.of(0x8d)));
  const out = paymentId.slice();
  for (let i = 0; i < 8; i++) {
    out[i] ^= pad[i];
  }
  return out;
}

/**
 * get_pre_mlsag_hash: the message CLSAG signs.
 * keccak(prefixHash || keccak(rctSigBase) || keccak(BP+ fields)). The commitments V are omitted
 * (they are recovered from outPk.mask, already hashed inside rctSigBase).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L600-L688
 *
 * @param {Uint8Array} prefixHash - 32-byte tx prefix hash (rv.message)
 * @param {object} rctSigBase - decoded rctSigBase (type, txnFee, ecdhInfo, outPk)
 * @param {{ A, A1, B, r1, s1, d1, L, R }} bulletproofPlus
 * @returns {Uint8Array} 32-byte message
 */
export function getPreMlsagHash(prefixHash, rctSigBase, bulletproofPlus) {
  // inputs is unused for the BulletproofPlus base (pseudoOuts live in rctSigPrunable)
  const baseHash = fastHash(rctBase(0, rctSigBase.ecdhInfo.length).encode(rctSigBase));
  const { A, A1, B, r1, s1, d1, L, R } = bulletproofPlus;
  const bpHash = fastHash(concatBytes(A, A1, B, r1, s1, d1, ...L, ...R));
  return fastHash(concatBytes(prefixHash, baseHash, bpHash));
}

// rct::scalarmultKey: s*P with no cofactor clearing (unlike generate_key_derivation, which is 8*s*P)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L208-L215
const scalarmultKey = (P, s) => encodePoint(decodePoint(P).multiplyUnsafe(decodeInt(s)));

/**
 * Build the transaction outputs: tx public key, optional additional public keys, the tagged-key
 * vout entries and the per-output amount keys (the ecdh/derivation scalars).
 * Ports the output half of construct_tx_with_tx_key + generate_output_ephemeral_keys.
 * construct_tx_with_tx_key
 * generate_output_ephemeral_keys
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L415-L468
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L294-L352
 *
 * Change must be flagged (isChange): it derives from a*R like the sender's wallet, which differs
 * from a normal r*A destination when R = r*D (the single-subaddress case).
 *
 * @param {{ viewPublicKey, spendPublicKey, isSubaddress?, isChange? }[]} destinations
 * @param {Uint8Array} txSecretKey - 32-byte tx secret key (r)
 * @param {Uint8Array} viewSecretKey - 32-byte sender view secret key (for change outputs)
 * @returns {{ txPublicKey, additionalPublicKeys, vout, amountKeys }}
 */
export function generateOutputs(destinations, txSecretKey, viewSecretKey) {
  // classify unique, non-change destinations (matches classify_addresses)
  const seen = new Set();
  let numStd = 0;
  let numSub = 0;
  let singleSub = null;
  for (const d of destinations) {
    if (d.isChange) {
      continue;
    }
    const id = bytesToHex(d.spendPublicKey) + bytesToHex(d.viewPublicKey);
    if (seen.has(id)) {
      continue;
    }
    seen.add(id);
    if (d.isSubaddress) {
      numSub++;
      singleSub = d;
    } else {
      numStd++;
    }
  }

  // single subaddress recipient: tx pubkey is R = r*D; otherwise R = r*G
  const txPublicKey = (numStd === 0 && numSub === 1)
    ? scalarmultKey(singleSub.spendPublicKey, txSecretKey)
    : secretKeyToPublicKey(txSecretKey);
  const needAdditional = numSub > 0 && (numStd > 0 || numSub > 1);

  const additionalPublicKeys = [];
  const vout = [];
  const amountKeys = [];
  destinations.forEach((d, i) => {
    let additionalSecretKey;
    if (needAdditional) {
      additionalSecretKey = randomScalar();
      additionalPublicKeys.push(d.isSubaddress
        ? scalarmultKey(d.spendPublicKey, additionalSecretKey)
        : secretKeyToPublicKey(additionalSecretKey));
    }
    let derivation;
    if (d.isChange) {
      derivation = generateKeyDerivation(txPublicKey, viewSecretKey); // a*R
    } else {
      const secret = (d.isSubaddress && needAdditional) ? additionalSecretKey : txSecretKey;
      derivation = generateKeyDerivation(d.viewPublicKey, secret); // r*A (or s*C for subaddress)
    }
    amountKeys.push(derivationToScalar(derivation, i));
    const key = derivePublicKey(derivation, i, d.spendPublicKey);
    const viewTag = deriveViewTag(derivation, i)[0];
    // txout_to_tagged_key (0x03); amount is zeroed for rct
    vout.push({ amount: 0n, target: { TAG: 0x03, data: { key, viewTag } } });
  });

  return { txPublicKey, additionalPublicKeys, vout, amountKeys };
}

// absolute_output_offsets_to_relative: ascending global indexes -> relative deltas
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L1545-L1555
function absoluteToRelative(sortedIndexes) {
  const relative = sortedIndexes.slice();
  for (let i = relative.length - 1; i > 0; i--) {
    relative[i] -= relative[i - 1];
  }
  return relative;
}

// descending byte compare, matching monero's memcmp(k0, k1) > 0 key-image sort
function compareBytesDesc(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return b[i] - a[i];
    }
  }
  return 0;
}

/**
 * get_destination_view_key_pub: the view key used to encrypt a payment id. Returns the single
 * non-change recipient's view key (the change key if there is only change), or null if there is
 * more than one distinct recipient.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L219-L239
 */
function destinationViewKeyForPid(destinations) {
  let picked = null;
  let changeViewKey = null;
  for (const d of destinations) {
    if (d.isChange) {
      changeViewKey = d.viewPublicKey;
      continue;
    }
    if (d.amount === 0n) {
      continue;
    }
    const samePicked = picked && equalBytes(picked.spendPublicKey, d.spendPublicKey)
      && equalBytes(picked.viewPublicKey, d.viewPublicKey);
    if (samePicked) {
      continue;
    }
    if (picked) {
      return null;
    }
    picked = d;
  }
  return picked ? picked.viewPublicKey : changeViewKey;
}

/**
 * Build and sign a regular RingCT transaction of the current network type
 * (RCTTypeBulletproofPlus: CLSAG signatures + Bulletproof+ range proofs).
 * Ports construct_tx_with_tx_key + genRctSimple.
 * construct_tx_with_tx_key
 * genRctSimple
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L241-L651
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L1105-L1293
 *
 * The caller supplies, per input, the one-time secret key, amount and commitment mask of the real
 * output plus the ring members (decoys + the real one). Decoy selection is out of scope.
 *
 * @param {object} params
 * @param {{ secretKey: Uint8Array, amount: bigint, mask: Uint8Array, ring: { publicKey: Uint8Array, commitment: Uint8Array, globalIndex: bigint }[] }[]} params.inputs
 * @param {{ viewPublicKey: Uint8Array, spendPublicKey: Uint8Array, amount: bigint, isSubaddress?: boolean, isChange?: boolean }[]} params.outputs
 * @param {bigint} params.fee
 * @param {Uint8Array} [params.viewSecretKey] - sender view secret, required if any output is change
 * @param {Uint8Array} [params.paymentId] - 8-byte short payment id (integrated address)
 * @param {bigint} [params.unlockTime]
 * @param {Uint8Array} [params.txSecretKey] - tx secret key r (random if omitted)
 * @returns {{ tx: object, bytes: Uint8Array }}
 */
export function createTransaction({
  inputs, outputs, fee, viewSecretKey, paymentId, unlockTime = 0n, txSecretKey = randomScalar(),
}) {
  const sumIn = inputs.reduce((s, i) => s + i.amount, 0n);
  const sumOut = outputs.reduce((s, o) => s + o.amount, 0n);
  if (sumIn !== sumOut + fee) {
    throw new Error('createTransaction: inputs do not balance outputs + fee');
  }

  const { txPublicKey, additionalPublicKeys, vout, amountKeys } = generateOutputs(outputs, txSecretKey, viewSecretKey);

  // explicit payment id, or a dummy short one for the usual <= 2 output transfer
  const viewKeyForPid = destinationViewKeyForPid(outputs);
  let encryptedPaymentId;
  if (paymentId) {
    if (!viewKeyForPid) {
      throw new Error('createTransaction: a payment id requires exactly one recipient');
    }
    encryptedPaymentId = encryptPaymentId(paymentId, viewKeyForPid, txSecretKey);
  } else if (outputs.length <= 2 && viewKeyForPid) {
    encryptedPaymentId = encryptPaymentId(new Uint8Array(8), viewKeyForPid, txSecretKey);
  }
  const extra = buildTxExtra({ txPublicKey, additionalPublicKeys, encryptedPaymentId });

  // inputs: key image, ring sorted by global index, relative key offsets
  const ins = inputs.map((input) => {
    const realPublicKey = secretKeyToPublicKey(input.secretKey);
    const ring = input.ring.slice().sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1));
    const realIndex = ring.findIndex((m) => equalBytes(m.publicKey, realPublicKey));
    if (realIndex < 0) {
      throw new Error('createTransaction: the input secret key does not match any ring member');
    }
    return {
      keyImage: generateKeyImage(realPublicKey, input.secretKey),
      keyOffsets: absoluteToRelative(ring.map((m) => m.globalIndex)),
      realIndex,
      pubs: ring.map((m) => ({ dest: m.publicKey, mask: m.commitment })),
      inSk: { dest: input.secretKey, mask: input.mask },
      amount: input.amount,
    };
  });
  ins.sort((a, b) => compareBytesDesc(a.keyImage, b.keyImage));

  const vin = ins.map((i) => ({ TAG: 0x02, data: { amount: 0n, keyOffsets: i.keyOffsets, keyImage: i.keyImage } }));
  const prefix = { version: 2, unlockTime, vin, vout, extra };
  const prefixHash = fastHash(txPrefix.encode(prefix));

  // range proof over the output amounts; the masks are deterministic from the amount keys
  const masks = amountKeys.map((k) => genCommitmentMask(k));
  const { proof, V } = proveRangeBulletproofPlus(outputs.map((o) => o.amount), masks);

  // ecdh: encrypt amounts (v2 deterministic mask, 8-byte amount)
  const ecdhInfo = outputs.map((o, i) => {
    const tuple = { mask: masks[i], amount: encodeInt(o.amount) };
    return ecdhEncode(tuple, amountKeys[i], RCTTypes.BulletproofPlus).amount.slice(0, 8);
  });

  // pseudoOut masks balance the output masks: last = sum(out) - sum(other pseudo)
  const sumOutMask = masks.reduce((s, m) => Fn.add(s, decodeInt(m)), 0n);
  const pseudoMasks = [];
  let sumPseudo = 0n;
  for (let i = 0; i < ins.length - 1; i++) {
    const m = decodeInt(randomScalar());
    pseudoMasks.push(m);
    sumPseudo = Fn.add(sumPseudo, m);
  }
  pseudoMasks.push(Fn.sub(sumOutMask, sumPseudo));
  const pseudoOuts = ins.map((inp, i) => pedersenCommitment(encodeInt(inp.amount), encodeInt(pseudoMasks[i])));

  const rctSigBase = { type: RCTTypes.BulletproofPlus, txnFee: fee, ecdhInfo, outPk: V };
  const message = getPreMlsagHash(prefixHash, rctSigBase, proof);
  const CLSAGs = ins.map((inp, i) => {
    const mask = encodeInt(pseudoMasks[i]);
    const { s, c1, D } = proveClsag(message, inp.pubs, inp.inSk, mask, pseudoOuts[i], inp.realIndex);
    return { s, c1, D };
  });

  const tx = { prefix, rctSigBase, rctSigPrunable: { bulletproofsPlus: [proof], CLSAGs, pseudoOuts } };
  return { tx, bytes: transaction.encode(tx) };
}

/**
 * relative_output_offsets_to_absolute
 * Cumulative sum with uint64 wraparound (an unsorted ring has "negative" deltas stored as 2^64 - k,
 * so the running sum must wrap exactly like monero's uint64).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L1537-L1543
 *
 * @param {bigint[]} keyOffsets - relative key offsets
 * @returns {bigint[]} absolute global output indexes
 */
export function globalIndexesFromKeyOffsets(keyOffsets) {
  const MASK = (1n << 64n) - 1n;
  const globalIndexes = keyOffsets.map(BigInt);
  globalIndexes[0] = BigInt(globalIndexes[0]);
  for (let i = 1; i < globalIndexes.length; i++) {
    globalIndexes[i] = (globalIndexes[i] + globalIndexes[i - 1]) & MASK;
  }
  return globalIndexes.map(Number);
}

/**
 * Estimate transaction size (only RCT)
 *
 * estimate_rct_tx_size
 * estimate_tx_size
 *
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L785
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L844
 *
 * @param {Number} inputs
 * @param {Number} mixin
 * @param {Number} outputs
 * @param {Number} extra
 * @param {Boolean} bulletproof - true by default
 * @param {Boolean} clsag - true by default
 * @param {Boolean} bulletproofPlus - true by default
 * @param {Boolean} useViewTags - true by default
 * @returns Number
 */

export function estimateTxSize(inputs, mixin, outputs, extra,
  bulletproof = true, clsag = true, bulletproofPlus = true, useViewTags = true) {
  let size = 0;

  // tx prefix

  // first few bytes
  size += 1 + 6;

  // vin
  size += inputs * (1 + 6 + (mixin + 1) * 2 + 32);

  // vout
  size += outputs * (6 + 32);

  // extra
  size += extra;

  // rct signatures

  // type
  size += 1;

  // rangeSigs
  if (bulletproof || bulletproofPlus) {
    let logPaddedOutputs = 0;
    while ((1 << logPaddedOutputs) < outputs) {
      ++logPaddedOutputs;
    }
    size += (2 * (6 + logPaddedOutputs) + (bulletproofPlus ? 6 : (4 + 5))) * 32 + 3;
  } else {
    size += (2 * 64 * 32 + 32 + 64 * 32) * outputs;
  }

  // MGs/CLSAGs
  if (clsag) {
    size += inputs * (32 * (mixin + 1) + 64);
  } else {
    size += inputs * (64 * (mixin + 1) + 32);
  }

  if (useViewTags) {
    size += outputs * 1;
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
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L852
 *
 * @param {Number} inputs
 * @param {Number} mixin
 * @param {Number} outputs
 * @param {Number} extra
 * @param {Boolean} bulletproof
 * @param {Boolean} clsag
 * @param {Boolean} bulletproofPlus
 * @param {Boolean} useViewTags
 * @returns Number
 */

export function estimateTxWeight(inputs, mixin, outputs, extra,
  bulletproof = true, clsag = true, bulletproofPlus = true, useViewTags = true) {
  let size = estimateTxSize(inputs, mixin, outputs, extra, bulletproof, clsag, bulletproofPlus, useViewTags);
  if ((bulletproof || bulletproofPlus) && outputs > 2) {
    const bpBase = (32 * ((bulletproofPlus ? 6 : 9) + 7 * 2)) / 2;
    let logPaddedOutputs = 2;
    while ((1 << logPaddedOutputs) < outputs) {
      ++logPaddedOutputs;
    }
    const nlr = 2 * (6 + logPaddedOutputs);
    const bpSize = 32 * ((bulletproofPlus ? 6 : 9) + nlr);
    // ~~ is Math.floor
    const bpClawback = ~~((bpBase * (1 << logPaddedOutputs) - bpSize) * 4 / 5);
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
  const quantization = BigInt(feeQuantization);
  const fee = (BigInt(baseFee) * BigInt(weight * feeMultiplier) + (quantization - 1n))
    / quantization
    * quantization;
  return fee.toString(10);
}

/**
 *
 * Estimate transaction fee
 *
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L7282
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
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L7308
 * @param {Boolean} bulletproof
 * @param {Boolean} clsag
 * @param {Boolean} bulletproofPlus
 * @returns String
 */
export function estimateFee(inputs, mixin, outputs, extra, baseFee, feeMultiplier, feeQuantization,
  bulletproof = true, clsag = true, bulletproofPlus = true, useViewTags = true) {
  if (typeof baseFee === 'string') {
    baseFee = parseInt(baseFee, 10);
  }
  if (typeof feeQuantization === 'string') {
    feeQuantization = parseInt(feeQuantization, 10);
  }
  const weight = estimateTxWeight(inputs, mixin, outputs, extra, bulletproof, clsag, bulletproofPlus, useViewTags);
  return calculateFeeFromWeight(weight, baseFee, feeMultiplier, feeQuantization);
}

export default {
  getTxIdFromHex,
  parseTxExtra,
  encryptPaymentId,
  buildTxExtra,
  getPreMlsagHash,
  generateOutputs,
  createTransaction,
  globalIndexesFromKeyOffsets,
  estimateTxSize,
  estimateTxWeight,
  calculateFeeFromWeight,
  estimateFee,
};
