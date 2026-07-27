import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';

import { MAX_COMMITMENTS } from './config.js';
import { assertUint64 } from './helpers.js';
import { encodeInt } from './helpers.js';
import { proveClsag } from './clsag.js';
import { proveRangeBulletproofPlus } from './bulletproofs.js';
import {
  Fn,
  decodePoint,
  derivationToScalar,
  derivePublicKey,
  deriveViewTag,
  encodePoint,
  fastHash,
  generateKeyDerivation,
  generateKeyImage,
  randomScalar,
  secretKeyToPublicKey,
} from './crypto.js';
import {
  RCTTypes,
  ecdhEncode,
  genCommitmentMask,
  pedersenCommitment,
} from './ringct.js';
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

/**
 * @typedef {object} RingMember
 * @property {Uint8Array} publicKey
 * @property {Uint8Array} commitment
 * @property {bigint} globalIndex - the output's absolute on-chain index
 */

/**
 * @typedef {object} TxInput - a spendable output: a scanOutput result plus its on-chain index and decoys
 * @property {bigint} secretKey - the output one-time secret key
 * @property {bigint} amount
 * @property {bigint} mask - the output commitment mask (blinding scalar)
 * @property {Uint8Array} commitment - the output commitment C
 * @property {bigint} globalIndex - the output's absolute on-chain index
 * @property {RingMember[]} decoys - the other ring members (ringSize - 1 of them)
 */

/**
 * @typedef {object} Destination - a recipient: a decoded address plus an amount
 * @property {'address'|'subaddress'|'integratedaddress'} type
 * @property {Uint8Array} publicSpendKey
 * @property {Uint8Array} publicViewKey
 * @property {bigint} amount
 * @property {boolean} [isChange] - the sender's own change output (derived via 8*a*R)
 * @property {Uint8Array} [paymentID] - 8-byte payment id, embedded when type is 'integratedaddress'
 */

/**
 * @typedef {object} GeneratedOutput - per-destination ephemeral output data
 * @property {Uint8Array} key - the output one-time public key
 * @property {number} viewTag
 * @property {bigint} amountKey - the ecdh/derivation scalar
 * @property {bigint} amount
 */

/**
 * @typedef {object} PreparedInput - a signing-ready input: ring assembled and sorted, key image computed
 * @property {bigint} secretKey
 * @property {bigint} amount
 * @property {bigint} mask
 * @property {RingMember[]} ring
 * @property {number} realIndex
 * @property {Uint8Array} keyImage
 * @property {bigint[]} keyOffsets
 */

/**
 * @typedef {object} TransactionParams
 * @property {TxInput[]} inputs
 * @property {Destination[]} outputs
 * @property {bigint} [secretViewKey] - sender view secret scalar, required if any output is change
 * @property {bigint} [unlockTime]
 * @property {bigint} [txSecretKey] - tx secret scalar r (random if omitted)
 */

/**
 * @typedef {object} TxExtra - the recognized tx_extra fields
 * @property {Uint8Array} txPublicKey
 * @property {Uint8Array[]} [additionalPublicKeys]
 * @property {Uint8Array} [encryptedPaymentId]
 */

/**
 * Transaction id: keccak(keccak(prefix) || keccak(rctSigBase) || keccak(rctSigPrunable)). The
 * prunable hash is replaced by 32 zero bytes for the Null rct type.
 * calculate_transaction_hash
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L138-L175
 *
 * @param {Uint8Array} bytes - full transaction bytes
 * @returns {Uint8Array} 32-byte transaction id
 */
export function getTxId(bytes) {
  const tx = transaction.decode(bytes);
  // version 1 (pre-RingCT): the id is keccak of the whole serialized transaction
  if (tx.prefix.version === 1) {
    return fastHash(bytes);
  }
  const { type } = tx.rctSigBase;
  const {
    inputs, outputs, mixin,
  } = txParams(tx.prefix);
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
 * @param {TxExtra} fields
 * @returns {Uint8Array} tx_extra bytes
 */
export function buildTxExtra({
  txPublicKey, additionalPublicKeys = [], encryptedPaymentId,
}) {
  /** @type {import('./raw.js').TxExtraField[]} */
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
 * @returns {TxExtra}
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
  }, {
    txPublicKey: new Uint8Array(32), encryptedPaymentId: new Uint8Array(0), additionalPublicKeys: [],
  });
}

/**
 * encrypt_payment_id: paymentId XOR keccak(derivation || 0x8d)[:8], where derivation = 8*tx_key*A.
 * Symmetric, so the same function decrypts. Operates on the 8-byte short (encrypted) payment id.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L354-L370
 *
 * @param {Uint8Array} paymentId - 8-byte payment id
 * @param {Uint8Array} publicViewKey - 32-byte recipient view public key
 * @param {bigint} txSecretKey - tx secret scalar
 * @returns {Uint8Array} 8-byte encrypted payment id
 */
export function encryptPaymentId(paymentId, publicViewKey, txSecretKey) {
  const derivation = generateKeyDerivation(publicViewKey, txSecretKey);
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
 * @param {import('./raw.js').RctSigBase} rctSigBase
 * @param {import('./raw.js').BulletproofPlus} bulletproofPlus
 * @returns {Uint8Array} 32-byte message
 */
export function getPreMlsagHash(prefixHash, rctSigBase, bulletproofPlus) {
  // inputs is unused for the BulletproofPlus base (pseudoOuts live in rctSigPrunable)
  const baseHash = fastHash(rctBase(0, rctSigBase.ecdhInfo.length).encode(rctSigBase));
  const {
    A, A1, B, r1, s1, d1, L, R,
  } = bulletproofPlus;
  const bpHash = fastHash(concatBytes(A, A1, B, r1, s1, d1, ...L, ...R));
  return fastHash(concatBytes(prefixHash, baseHash, bpHash));
}

// rct::scalarmultKey: s*P with no cofactor clearing (unlike generate_key_derivation, which is 8*s*P)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.cpp#L208-L215
const scalarmultKey = (P, s) => encodePoint(decodePoint(P).multiplyUnsafe(s));

// classify_addresses
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L87-L110
// counts distinct standard vs subaddress recipients among unique, non-change destinations, and
// (if exactly one) which subaddress destination.
function classifyDestinations(destinations) {
  const seen = new Set();
  let numStd = 0;
  let numSub = 0;
  let singleSub = null;
  for (const destination of destinations) {
    if (destination.isChange) {
      continue;
    }
    const id = bytesToHex(destination.publicSpendKey) + bytesToHex(destination.publicViewKey);
    if (seen.has(id)) {
      continue;
    }
    seen.add(id);
    if (destination.type === 'subaddress') {
      numSub++;
      singleSub = destination;
    } else {
      numStd++;
    }
  }
  // more than one distinct subaddress destination, or a mix of subaddress and standard
  const needAdditional = numSub > 0 && (numStd > 0 || numSub > 1);
  return {
    numStd,
    numSub,
    singleSub,
    needAdditional,
  };
}

/**
 * Build the transaction outputs: tx public key, optional additional public keys, and one record per
 * destination { key, viewTag, amountKey, amount } (the output one-time key, its view tag, the
 * ecdh/derivation scalar and the amount).
 * Ports the output half of construct_tx_with_tx_key + generate_output_ephemeral_keys.
 * construct_tx_with_tx_key
 * generate_output_ephemeral_keys
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L415-L468
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L294-L352
 *
 * Math (per output i, effective tx pubkey R):
 * R = r*G, or r*D for a single subaddress recipient (D its spend key)
 * D_i = 8*r*A_i (8*s_i*C_i via an additional subaddress key; 8*a_sender*R for change)
 * P_i = Hs(D_i || i)*G + B_i, amountKey_i = Hs(D_i || i), viewTag_i = H("view_tag" || D_i || i)[0]
 *
 * Change must be flagged (isChange): it derives from 8*a_sender*R like the sender's wallet, which
 * differs from a normal 8*r*A destination when R = r*D (the single-subaddress case).
 *
 * @param {Destination[]} destinations
 * @param {bigint} txSecretKey - tx secret scalar (r)
 * @param {bigint} [secretViewKey] - sender view secret scalar, required if any output is change
 * @returns {{
 *   txPublicKey: Uint8Array,
 *   additionalPublicKeys: Uint8Array[],
 *   outputs: GeneratedOutput[]
 * }}
 */
export function generateOutputs(destinations, txSecretKey, secretViewKey) {
  const {
    numStd, numSub, singleSub, needAdditional,
  } = classifyDestinations(destinations);

  // single subaddress recipient: tx pubkey is R = r*D; otherwise R = r*G
  const txPublicKey = (numStd === 0 && numSub === 1)
    ? scalarmultKey(singleSub.publicSpendKey, txSecretKey)
    : secretKeyToPublicKey(txSecretKey);

  const additionalPublicKeys = [];
  const outputs = destinations.map((destination, i) => {
    let additionalSecretKey;
    if (needAdditional) {
      additionalSecretKey = randomScalar();
      additionalPublicKeys.push(destination.type === 'subaddress'
        ? scalarmultKey(destination.publicSpendKey, additionalSecretKey)
        : secretKeyToPublicKey(additionalSecretKey));
    }
    let derivation;
    if (destination.isChange) {
      derivation = generateKeyDerivation(txPublicKey, secretViewKey); // 8*a*R
    } else {
      const ephemeralSecretKey = (destination.type === 'subaddress' && needAdditional)
        ? additionalSecretKey : txSecretKey;
      derivation = generateKeyDerivation(destination.publicViewKey, ephemeralSecretKey); // 8*r*A (or 8*s*C for subaddress)
    }
    return {
      key: derivePublicKey(derivation, i, destination.publicSpendKey),
      viewTag: deriveViewTag(derivation, i)[0],
      amountKey: derivationToScalar(derivation, i),
      amount: destination.amount,
    };
  });

  return {
    txPublicKey,
    additionalPublicKeys,
    outputs,
  };
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
 * Prepare each spendable input for signing: assemble the ring (real member + decoys) sorted by
 * global index, compute the key image and relative key offsets, then order the inputs by key image
 * (descending), matching monero's vin sort.
 *
 * @param {TxInput[]} inputs
 * @returns {PreparedInput[]}
 */
function prepareInputs(inputs) {
  return inputs.map((input) => {
    const publicKey = secretKeyToPublicKey(input.secretKey);
    const real = {
      publicKey,
      commitment: input.commitment,
      globalIndex: input.globalIndex,
    };
    const ring = [real, ...input.decoys].sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1));
    return {
      secretKey: input.secretKey,
      amount: input.amount,
      mask: input.mask,
      ring,
      realIndex: ring.indexOf(real),
      keyImage: generateKeyImage(publicKey, input.secretKey),
      keyOffsets: absoluteToRelative(ring.map((member) => member.globalIndex)),
    };
  }).sort((a, b) => compareBytesDesc(a.keyImage, b.keyImage));
}

/**
 * Build and sign a regular RingCT transaction of the current network type
 * (RCTTypeBulletproofPlus: CLSAG signatures + Bulletproof+ range proofs), returning the decoded
 * transaction object (use createTransaction to get the serialized bytes).
 * Math:
 * Σ input.amount = Σ output.amount + fee
 * output_j: mask_j = Hs("commitment_mask" || amount_key_j), V_j = mask_j*G + amount_j*H
 * ecdh_j = Enc(amount_j, amount_key_j), prefixHash = H(txPrefix(vin, vout, extra))
 * pseudoOut_i = pseudoMask_i*G + input_i.amount*H, Σ pseudoMask_i = Σ mask_j
 * message = H(prefixHash || H(rctSigBase) || H(BP+))
 * CLSAG_i signs (ring_i, pseudoOut_i) with (secretKey_i, inputMask_i - pseudoMask_i)
 * Ports construct_tx_with_tx_key + genRctSimple.
 * construct_tx_with_tx_key
 * genRctSimple
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L241-L651
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L1105-L1293
 *
 * Each input is a spendable output (a scanOutput result) plus its on-chain globalIndex and its decoy
 * ring members; prepareTransaction assembles and sorts in the real ring member itself. Decoy
 * selection is out of scope.
 *
 * The fee is not passed in: it is the remainder, fee = Σ input.amount − Σ output.amount (so the
 * caller controls it purely by how much change it keeps).
 *
 * @param {TransactionParams} params
 * @returns {import('./raw.js').Transaction} the decoded transaction
 */
export function prepareTransaction({
  inputs,
  outputs,
  secretViewKey,
  unlockTime = 0n,
  txSecretKey = randomScalar(),
}) {
  if (inputs.length < 1) {
    throw new Error('createTransaction: empty inputs');
  }
  // monero requires at least two outputs; a single-output tx is rejected on-chain
  // (HF_VERSION_MIN_2_OUTPUTS, "has fewer than two outputs")
  // https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/blockchain.cpp#L3249-L3257
  if (outputs.length < 2) {
    throw new Error('createTransaction: a transaction needs at least two outputs');
  }
  // a Bulletproof+ aggregates at most MAX_COMMITMENTS outputs
  if (outputs.length > MAX_COMMITMENTS) {
    throw new Error('createTransaction: too many outputs');
  }
  // payment id: tx_extra holds a single nonce, so at most one address may carry a payment id
  if (outputs.filter((output) => output.type === 'integratedaddress').length > 1) {
    throw new Error('createTransaction: multiple addresses with payment ids');
  }
  assertUint64('unlockTime', unlockTime);
  inputs.forEach((input, i) => {
    assertUint64(`inputs[${i}].amount`, input.amount);
    assertUint64(`inputs[${i}].globalIndex`, input.globalIndex);
    input.decoys.forEach((decoy, j) => assertUint64(`inputs[${i}].decoys[${j}].globalIndex`, decoy.globalIndex));
  });
  outputs.forEach((output, i) => assertUint64(`outputs[${i}].amount`, output.amount));

  // the fee is the remainder: everything not sent to an output goes to the miner
  const sumIn = inputs.reduce((sum, input) => sum + input.amount, 0n);
  const sumOut = outputs.reduce((sum, output) => sum + output.amount, 0n);
  if (sumOut > sumIn) {
    throw new Error('createTransaction: outputs exceed inputs');
  }
  const fee = sumIn - sumOut;
  assertUint64('fee', fee);

  // outputs: ephemeral keys, deterministic masks, range proof, encrypted amounts, tagged-key vout
  const generated = generateOutputs(outputs, txSecretKey, secretViewKey);
  const masks = generated.outputs.map((output) => genCommitmentMask(output.amountKey));
  const { proof, V: outPk } = proveRangeBulletproofPlus(
    generated.outputs.map((output, i) => ({ amount: output.amount, mask: masks[i] }))
  );
  const ecdhInfo = generated.outputs.map((output) => {
    return {
      amount: ecdhEncode({ amount: encodeInt(output.amount) }, output.amountKey, RCTTypes.BulletproofPlus)
        .amount.slice(0, 8),
    };
  });
  // txout_to_tagged_key (0x03); amount is zeroed for rct
  const vout = generated.outputs.map((output) => ({
    amount: 0n, target: { TAG: 0x03, data: { key: output.key, viewTag: output.viewTag } },
  }));

  // Encrypt the payment id: a real id to the integrated recipient's own view key, or a dummy on a
  // small (<= 2 output) transfer so payment-id txs don't stand out. Both use encryptPaymentId (id XOR mask).
  let encryptedPaymentId;
  const integrated = outputs.find((output) => output.type === 'integratedaddress');
  if (integrated) {
    encryptedPaymentId = encryptPaymentId(integrated.paymentID, integrated.publicViewKey, txSecretKey);
  } else if (outputs.length <= 2) {
    // encrypt to the recipient so it decrypts to the [0;8] dummy; only fall back to change when there
    // is no recipient (self-send). Encrypting to change while a recipient exists would make the
    // recipient decrypt garbage, revealing non-standard software. A simplified get_destination_view_key_pub
    // (count == 0 ? change : recipient), dropping its recipient dedup/counting:
    // https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_core/cryptonote_tx_utils.cpp#L219-L239
    const target = outputs.find((output) => !output.isChange) ?? outputs.find((output) => output.isChange);
    encryptedPaymentId = encryptPaymentId(new Uint8Array(8), target.publicViewKey, txSecretKey);
  }
  const extra = buildTxExtra({
    txPublicKey: generated.txPublicKey,
    additionalPublicKeys: generated.additionalPublicKeys,
    encryptedPaymentId,
  });

  // inputs: ring assembled + sorted, key images, ordered by key image
  const preparedInputs = prepareInputs(inputs);
  const vin = preparedInputs.map((input) => ({
    TAG: 0x02,
    data: {
      amount: 0n,
      keyOffsets: input.keyOffsets,
      keyImage: input.keyImage,
    },
  }));
  const prefix = {
    version: 2,
    unlockTime,
    vin,
    vout,
    extra,
  };
  const prefixHash = fastHash(txPrefix.encode(prefix));

  // pseudoOut masks balance the output masks: last = sum(out) - sum(other pseudo)
  const sumOutMask = masks.reduce((sum, mask) => Fn.add(sum, mask), 0n);
  const pseudoMasks = [];
  let sumPseudo = 0n;
  for (let i = 0; i < preparedInputs.length - 1; i++) {
    const pseudoMask = randomScalar();
    pseudoMasks.push(pseudoMask);
    sumPseudo = Fn.add(sumPseudo, pseudoMask);
  }
  pseudoMasks.push(Fn.sub(sumOutMask, sumPseudo));
  const pseudoOuts = preparedInputs.map((input, i) => pedersenCommitment(input.amount, pseudoMasks[i]));

  const rctSigBase = {
    type: RCTTypes.BulletproofPlus,
    txnFee: fee,
    ecdhInfo,
    outPk,
  };
  const message = getPreMlsagHash(prefixHash, rctSigBase, proof);
  const CLSAGs = preparedInputs.map((input, i) => {
    const {
      s, c1, D,
    } = proveClsag(message, input.ring, pseudoOuts[i], {
      index: input.realIndex,
      secretKey: input.secretKey,
      commitmentScalar: Fn.sub(input.mask, pseudoMasks[i]),
    });
    return {
      s, c1, D,
    };
  });

  return {
    prefix,
    rctSigBase,
    rctSigPrunable: {
      bulletproofsPlus: [proof],
      CLSAGs,
      pseudoOuts,
    },
  };
}

/**
 * Build, sign and serialize a transaction. Thin wrapper over prepareTransaction that encodes the
 * result to wire bytes.
 *
 * @param {TransactionParams} params
 * @returns {Uint8Array} the serialized transaction
 */
export function createTransaction(params) {
  return transaction.encode(prepareTransaction(params));
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
 * Estimate the tx_extra byte size for the full output list (destinations plus change/padding, if
 * any) - the `extra` param estimateTxSize/estimateTxWeight/estimateFee need. Mirrors buildTxExtra's
 * actual layout; takes the same complete list generateOutputs does (no destination is implicit).
 *
 * @param {Destination[]} destinations - every output the tx will have
 * @returns {number} tx_extra byte size
 */
export function estimateExtraSize(destinations) {
  const { needAdditional } = classifyDestinations(destinations);
  const hasIntegrated = destinations.some((destination) => destination.type === 'integratedaddress');
  let size = 33; // tag (1) + tx public key (32)
  if (needAdditional) {
    size += 2 + 32 * destinations.length; // tag (1) + varint count (1) + 32 per additional pubkey
  }
  if (hasIntegrated || destinations.length <= 2) {
    size += 11; // tag (1) + varint length (1) + nonce (1-byte sub-tag + 8-byte payment id)
  }
  return size;
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
 * calculate_fee_from_weight: quantized weight-based fee.
 * fee = q * ceil(weight * baseFee * feeMultiplier / q), where q = feeQuantization > 0
 * https://github.com/monero-project/monero/blob/v0.17.2.0/src/wallet/wallet2.cpp#L328
 *
 * @param {Number} weight
 * @param {bigint} baseFee - per-weight base fee, atomic units
 * @param {bigint} feeMultiplier - priority multiplier (1, 4, 20, 166, ...)
 * @param {bigint} feeQuantization - fee quantization mask, e.g. 10000; must be > 0
 * @returns {bigint}
 */

export function calculateFeeFromWeight(weight, baseFee, feeMultiplier, feeQuantization) {
  const fee = (BigInt(weight) * baseFee * feeMultiplier + (feeQuantization - 1n))
    / feeQuantization
    * feeQuantization;
  return fee;
}

/**
 *
 * Estimate transaction fee
 *
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L7282
 * https://github.com/monero-project/monero/blob/v0.18.0.0/src/wallet/wallet2.cpp#L7308
 *
 * Parameters use_per_byte_fee and use_rct from sources are removed
 * and considered to be true in this implementation
 *
 * @param {Number} inputs
 * @param {Number} mixin
 * @param {Number} outputs
 * @param {Number} extra
 * @param {bigint} baseFee
 * @param {bigint} feeMultiplier - priority multiplier (1, 4, 20, 166, ...)
 * @param {bigint} feeQuantization - fee quantization mask, e.g. 10000; must be > 0
 * @param {Boolean} bulletproof
 * @param {Boolean} clsag
 * @param {Boolean} bulletproofPlus
 * @returns {bigint}
 */
export function estimateFee(inputs, mixin, outputs, extra, baseFee, feeMultiplier, feeQuantization,
  bulletproof = true, clsag = true, bulletproofPlus = true, useViewTags = true) {
  const weight = estimateTxWeight(inputs, mixin, outputs, extra, bulletproof, clsag, bulletproofPlus, useViewTags);
  return calculateFeeFromWeight(weight, baseFee, feeMultiplier, feeQuantization);
}
