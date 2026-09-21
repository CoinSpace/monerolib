import * as P from 'micro-packed';

import { assertUint64 } from './helpers.js';
import {
  RCTTypes,
  isKnownRctType,
  isV2EcdhType,
} from './ringct.js';

/**
 * LEB128 varint over a uint64, as a bigint (amounts, fee, unlock_time).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/common/varint.h
 */
export const varintBigInt = P.wrap({
  encodeStream: (w, value) => {
    let v = value;
    while (v >= 0x80n) {
      w.byte(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    w.byte(Number(v));
  },
  decodeStream: (r) => {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; ; i++) {
      const b = r.byte();
      // reject values that overflow uint64, like monero read_varint (EVARINT_OVERFLOW)
      if (shift + 7n >= 64n && b >= 1 << Number(64n - shift)) {
        throw r.err('varint: overflows uint64');
      }
      result |= BigInt(b & 0x7f) << shift;
      shift += 7n;
      if ((b & 0x80) === 0) {
        if (i > 0 && b === 0) {
          throw r.err('varint: non-canonical representation');
        }
        return result;
      }
    }
  },
  // checked on both encode and decode
  validate: (value) => {
    if (typeof value !== 'bigint') {
      throw new Error(`varint: expected bigint, got ${typeof value}`);
    }
    assertUint64('varint', value);
    return value;
  },
});

/** Same varint as a JS number, for vector lengths and small counts. */
export const varintNumber = P.apply(varintBigInt, P.coders.numberBigint);

export function checkUint8(value) {
  if (value < 0 || value > 0xff) {
    throw new Error(`varint: value ${value} exceeds uint8`);
  }
  return value;
}

/** Varint bounded to a uint8, for block major/minor version (both uint8_t in monero). */
export const varintUint8 = P.apply(varintNumber, { encode: checkUint8, decode: checkUint8 });

/**
 * A 32-byte key (point or scalar).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L79
 */
export const key = P.bytes(32);

/**
 * Monero keyV: std::vector<key>. The vector serializer writes its length as a varint.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L89
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/serialization/binary_archive.h#L221
 */
export const keyV = P.array(varintNumber, key);

/**
 * Transaction inputs/outputs and prefix.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L63-L189
 *
 * vin and the output target are boost::variant; serialization writes a single tag byte first.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L572-L579
 */

// binary_archive variant tags for txin_v / txout_target_v
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L572-L579
export const TXIN_GEN_TAG = 0xff;
export const TXIN_TO_KEY_TAG = 0x02;
export const TXOUT_TO_KEY_TAG = 0x02;
export const TXOUT_TO_TAGGED_KEY_TAG = 0x03;

// txin_to_key: amount, key_offsets, k_image. Monero's `key_offsets` is a misnomer - it holds
// relative output-index offsets, not key offsets - so we expose it as `outputOffsets`.
export const txinToKey = P.struct({
  amount: varintBigInt,
  outputOffsets: P.array(varintNumber, varintBigInt),
  keyImage: key,
});

// txin_gen: miner input, only the block height
export const txinGen = P.struct({ height: varintBigInt });

export const txin = /** @type {import('micro-packed').CoderType<Vin>} */ (P.tag(P.U8, {
  [TXIN_TO_KEY_TAG]: txinToKey,
  [TXIN_GEN_TAG]: txinGen,
}));

// txout_to_key: key
export const txoutToKey = P.struct({ key });

// txout_to_tagged_key: key + 1-byte view_tag
export const txoutToTaggedKey = P.struct({ key, viewTag: P.U8 });

/**
 * @typedef {object} TxoutTarget
 * @property {number} TAG
 * @property {ReturnType<typeof txoutToKey.decode> | ReturnType<typeof txoutToTaggedKey.decode>} data
 */

export const txoutTarget = /** @type {import('micro-packed').CoderType<TxoutTarget>} */ (P.tag(P.U8, {
  [TXOUT_TO_KEY_TAG]: txoutToKey,
  [TXOUT_TO_TAGGED_KEY_TAG]: txoutToTaggedKey,
}));

// tx_out: amount, target
export const txout = P.struct({ amount: varintBigInt, target: txoutTarget });

export const txPrefix = P.struct({
  version: varintNumber,
  unlockTime: varintBigInt,
  vin: P.array(varintNumber, txin),
  vout: P.array(varintNumber, txout),
  extra: P.bytes(varintNumber),
});

// tx_extra field tags and the nonce sub-type marker
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/tx_extra.h#L34-L45
export const TX_EXTRA_TAG_PADDING = 0x00;
export const TX_EXTRA_TAG_PUBKEY = 0x01;
export const TX_EXTRA_NONCE = 0x02;
export const TX_EXTRA_MERGE_MINING_TAG = 0x03;
export const TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;
export const TX_EXTRA_MYSTERIOUS_MINERGATE_TAG = 0xDE;
export const TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 0x01;

// the bytes after the 1-byte tag, per field type
export const txExtraFieldCoders = {
  [TX_EXTRA_TAG_PUBKEY]: key,
  [TX_EXTRA_NONCE]: P.bytes(varintNumber),
  [TX_EXTRA_MERGE_MINING_TAG]: P.bytes(varintNumber),
  [TX_EXTRA_TAG_ADDITIONAL_PUBKEYS]: P.array(varintNumber, key),
  [TX_EXTRA_MYSTERIOUS_MINERGATE_TAG]: P.bytes(varintNumber),
};

/**
 * @typedef {object} TxExtraField - a tag and its payload bytes or additional public keys
 * @property {number} tag
 * @property {Uint8Array | Uint8Array[]} data
 */

/**
 * Decode tx_extra as an ordered list of { tag, data } fields with no count prefix.
 * An unknown tag or incomplete field ends parsing; the rest of the buffer is consumed and omitted from the result.
 * The padding tag stores all remaining bytes as its payload without validation.
 * txPrefix.extra keeps the original bytes so full transaction serialization preserves them.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L567-L586
 */
export const txExtra = P.wrap({
  encodeStream: (w, fields) => {
    for (const { tag, data } of fields) {
      P.U8.encodeStream(w, tag);
      if (tag === TX_EXTRA_TAG_PADDING) {
        w.bytes(data);
      } else {
        txExtraFieldCoders[tag].encodeStream(w, data);
      }
    }
  },
  decodeStream: (r) => {
    const fields = [];
    while (!r.isEnd()) {
      const tag = P.U8.decodeStream(r);
      if (tag === TX_EXTRA_TAG_PADDING) {
        // padding is a run of zero bytes to the end of the buffer
        fields.push({ tag, data: r.bytes(r.leftBytes) });
        break;
      }
      const coder = txExtraFieldCoders[tag];
      if (!coder) {
        break; // unknown tag: stop
      }
      try {
        fields.push({ tag, data: coder.decodeStream(r) });
      } catch {
        break; // truncated field: stop
      }
    }
    // best-effort: consume any trailing bytes we stopped on, so decode() sees the buffer as used up
    if (!r.isEnd()) {
      r.bytes(r.leftBytes);
    }
    return fields;
  },
});

/**
 * @typedef {object} EcdhTuple - the wire ecdh amount tuple
 * @property {Uint8Array} [mask] - 32 bytes; absent for Bulletproof2, CLSAG, and BulletproofPlus
 * @property {Uint8Array} amount - 8 bytes for Bulletproof2, CLSAG, and BulletproofPlus; 32 bytes for older types
 */

// ecdhTuple before Bulletproof2: full mask + full amount scalars
export const ecdhTupleV1 = P.struct({ mask: key, amount: key });

// since Bulletproof2 the mask is deterministic (not saved) and only the first 8 bytes
// of the encrypted amount are stored
export const ecdhAmountV2 = P.bytes(8);

// one ecdh entry as an EcdhTuple: v1 = {mask, amount} scalars; v2 = {amount} (8 bytes, no mask)
export const ecdhEntryCoder = (type) => P.wrap({
  encodeStream: (w, e) => (isV2EcdhType(type)
    ? ecdhAmountV2.encodeStream(w, e.amount)
    : ecdhTupleV1.encodeStream(w, e)),
  decodeStream: (r) => (isV2EcdhType(type)
    ? { amount: ecdhAmountV2.decodeStream(r) }
    : ecdhTupleV1.decodeStream(r)),
});

/**
 * rctSigBase: type, txnFee, pseudoOuts (Simple only), ecdhInfo, outPk (mask only).
 * The arrays have no length prefix; their counts come from the transaction prefix.
 * RCTTypes.Null contains only the type byte.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L333-L403
 *
 * @param {number} inputs - vin.length
 * @param {number} outputs - vout.length
 */
export function rctBaseCoder(inputs, outputs) {
  return P.wrap({
    encodeStream: (w, v) => {
      if (!isKnownRctType(v.type)) {
        throw w.err(`rctBase: unknown rct type ${v.type}`);
      }
      P.U8.encodeStream(w, v.type);
      if (v.type === RCTTypes.Null) {
        return;
      }
      varintBigInt.encodeStream(w, v.txnFee);
      if (v.type === RCTTypes.Simple) {
        P.array(inputs, key).encodeStream(w, v.pseudoOuts);
      }
      P.array(outputs, ecdhEntryCoder(v.type)).encodeStream(w, v.ecdhInfo);
      P.array(outputs, key).encodeStream(w, v.outPk);
    },
    decodeStream: (r) => {
      const type = P.U8.decodeStream(r);
      if (!isKnownRctType(type)) {
        throw r.err(`rctBase: unknown rct type ${type}`);
      }
      if (type === RCTTypes.Null) {
        return { type };
      }
      const res = { type, txnFee: varintBigInt.decodeStream(r) };
      if (type === RCTTypes.Simple) {
        res.pseudoOuts = P.array(inputs, key).decodeStream(r);
      }
      res.ecdhInfo = P.array(outputs, ecdhEntryCoder(type)).decodeStream(r);
      res.outPk = P.array(outputs, key).decodeStream(r);
      return res;
    },
  });
}

/**
 * @typedef {object} BulletproofPlus - serialized Bulletproof+ fields; commitments V are not included
 * @property {Uint8Array} A
 * @property {Uint8Array} A1
 * @property {Uint8Array} B
 * @property {Uint8Array} r1
 * @property {Uint8Array} s1
 * @property {Uint8Array} d1
 * @property {Uint8Array[]} L
 * @property {Uint8Array[]} R
 */

// BulletproofPlus range proof; L/R are varint-length-prefixed (FIELD)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L264-L275
export const bulletproofPlus = P.struct({
  A: key, A1: key, B: key, r1: key, s1: key, d1: key,
  L: keyV, R: keyV,
});

/**
 * @typedef {object} Bulletproof - serialized original Bulletproof fields; commitments V are not included
 * @property {Uint8Array} A
 * @property {Uint8Array} S
 * @property {Uint8Array} T1
 * @property {Uint8Array} T2
 * @property {Uint8Array} taux
 * @property {Uint8Array} mu
 * @property {Uint8Array[]} L
 * @property {Uint8Array[]} R
 * @property {Uint8Array} a
 * @property {Uint8Array} b
 * @property {Uint8Array} t
 */

// original Bulletproof range proof
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L229-L242
export const bulletproof = P.struct({
  A: key, S: key, T1: key, T2: key, taux: key, mu: key,
  L: keyV, R: keyV,
  a: key, b: key, t: key,
});

// key64: fixed array of 64 keys, no length prefix
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L153
export const key64 = P.array(64, key);

/**
 * @typedef {object} RangeSig - a Borromean range proof
 * @property {object} asig
 * @property {Uint8Array[]} asig.s0
 * @property {Uint8Array[]} asig.s1
 * @property {Uint8Array} asig.ee
 * @property {Uint8Array[]} Ci
 */

// Borromean range proof
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L155-L209
export const rangeSig = P.struct({
  asig: P.struct({
    s0: key64, s1: key64, ee: key,
  }),
  Ci: key64,
});

/**
 * @typedef {object} Clsag - serialized CLSAG fields
 * @property {Uint8Array[]} s
 * @property {Uint8Array} c1
 * @property {Uint8Array} D
 */

// CLSAG signature; in rctSigPrunable s is written without a length prefix, with size mixin + 1
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L495-L526
export const clsagCoder = (mixin) => P.struct({
  s: P.array(mixin + 1, key),
  c1: key,
  D: key,
});

/**
 * @typedef {object} MgSig - serialized MLSAG fields
 * @property {Uint8Array[][]} ss
 * @property {Uint8Array} cc
 */

// MLSAG signature; in rctSigPrunable ss is written without size prefixes as a (mixin+1) x cols matrix
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L537-L579
export const mgCoder = (mixin, cols) => P.struct({
  ss: P.array(mixin + 1, P.array(cols, key)),
  cc: key,
});

/**
 * rctSigPrunable: range proofs, ring signatures, and pseudoOuts for Bulletproof-family types.
 * The type and counts come from the base and prefix; this section does not repeat them.
 * RCTTypes.Null has no bytes and decodes to an empty object.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L426-L601
 *
 * @param {import('./ringct.js').RctType} type
 * @param {number} inputs - vin.length
 * @param {number} outputs - vout.length
 * @param {number} mixin - ring size minus one; zero for a miner input
 */
export function rctPrunableCoder(type, inputs, outputs, mixin) {
  const isBp = type === RCTTypes.Bulletproof;
  const isBpPlus = type === RCTTypes.BulletproofPlus;
  const isClsagOrPlus = type === RCTTypes.CLSAG || isBpPlus;
  const isBpFamily = isBp || type === RCTTypes.Bulletproof2 || type === RCTTypes.CLSAG;
  // "simple"-family types put one MLSAG per input with a 2-wide matrix
  const simpleFamily = type === RCTTypes.Simple || isBp || type === RCTTypes.Bulletproof2;
  const mgElements = simpleFamily ? inputs : 1;
  const mgCols = (simpleFamily ? 1 : inputs) + 1;
  const hasTailPseudoOuts = isBpFamily || isBpPlus;

  const rangeProofs = isBpPlus
    ? P.array(varintNumber, bulletproofPlus)
    : (isBpFamily ? P.array(isBp ? P.U32LE : varintNumber, bulletproof) : P.array(outputs, rangeSig));
  const signatures = isClsagOrPlus
    ? P.array(inputs, clsagCoder(mixin))
    : P.array(mgElements, mgCoder(mixin, mgCols));
  const pseudoOuts = P.array(inputs, key);

  return P.wrap({
    encodeStream: (w, v) => {
      if (!isKnownRctType(type)) {
        throw w.err(`rctPrunable: unknown rct type ${type}`);
      }
      if (type === RCTTypes.Null) {
        return;
      }
      rangeProofs.encodeStream(w, isBpPlus ? v.bulletproofsPlus : (isBpFamily ? v.bulletproofs : v.rangeSigs));
      signatures.encodeStream(w, isClsagOrPlus ? v.CLSAGs : v.MGs);
      if (hasTailPseudoOuts) {
        pseudoOuts.encodeStream(w, v.pseudoOuts);
      }
    },
    decodeStream: (r) => {
      if (!isKnownRctType(type)) {
        throw r.err(`rctPrunable: unknown rct type ${type}`);
      }
      if (type === RCTTypes.Null) {
        return {};
      }
      const res = {};
      if (isBpPlus) {
        res.bulletproofsPlus = rangeProofs.decodeStream(r);
      } else if (isBpFamily) {
        res.bulletproofs = rangeProofs.decodeStream(r);
      } else {
        res.rangeSigs = rangeProofs.decodeStream(r);
      }
      if (isClsagOrPlus) {
        res.CLSAGs = signatures.decodeStream(r);
      } else {
        res.MGs = signatures.decodeStream(r);
      }
      if (hasTailPseudoOuts) {
        res.pseudoOuts = pseudoOuts.decodeStream(r);
      }
      return res;
    },
  });
}

// rct counts that are not in the byte stream: inputs/outputs and the ring size minus one (mixin), the latter
// taken from the first input (miner txin_gen has none), as monero does here:
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L309-L310
export const txParams = (prefix) => ({
  inputs: prefix.vin.length,
  outputs: prefix.vout.length,
  mixin: prefix.vin[0].TAG === TXIN_TO_KEY_TAG ? prefix.vin[0].data.outputOffsets.length - 1 : 0,
});

/**
 * @typedef {object} KeyVin - a key input (0x02)
 * @property {typeof TXIN_TO_KEY_TAG} TAG
 * @property {object} data
 * @property {bigint} data.amount
 * @property {bigint[]} data.outputOffsets
 * @property {Uint8Array} data.keyImage
 */

/**
 * @typedef {object} MinerVin - a miner input (0xff)
 * @property {typeof TXIN_GEN_TAG} TAG
 * @property {object} data
 * @property {bigint} data.height
 */

/**
 * @typedef {KeyVin | MinerVin} Vin
 */

/**
 * @typedef {object} Vout - an output with a key target (0x02) or a key target with a view tag (0x03)
 * @property {bigint} amount
 * @property {object} target
 * @property {number} target.TAG
 * @property {object} target.data
 * @property {Uint8Array} target.data.key
 * @property {number} [target.data.viewTag]
 */

/**
 * @typedef {object} TxPrefix
 * @property {number} version
 * @property {bigint} unlockTime
 * @property {Vin[]} vin
 * @property {Vout[]} vout
 * @property {Uint8Array} extra - tx_extra bytes
 */

/**
 * @typedef {object} RctSigBase
 * @property {import('./ringct.js').RctType} type - one of RCTTypes
 * @property {bigint} [txnFee] - absent for Null
 * @property {EcdhTuple[]} [ecdhInfo] - per-output encrypted amounts; absent for Null
 * @property {Uint8Array[]} [outPk] - per-output commitments; absent for Null
 * @property {Uint8Array[]} [pseudoOuts] - Simple only; Bulletproof-family types store these in the prunable part
 */

/**
 * @typedef {object} RctSigPrunable - fields depend on the RingCT type; empty for Null
 * @property {RangeSig[]} [rangeSigs] - Full and Simple
 * @property {Bulletproof[]} [bulletproofs] - Bulletproof, Bulletproof2, and CLSAG
 * @property {BulletproofPlus[]} [bulletproofsPlus] - BulletproofPlus
 * @property {MgSig[]} [MGs] - Full, Simple, Bulletproof, and Bulletproof2
 * @property {Clsag[]} [CLSAGs] - CLSAG and BulletproofPlus
 * @property {Uint8Array[]} [pseudoOuts] - Bulletproof, Bulletproof2, CLSAG, and BulletproofPlus
 */

/**
 * @typedef {object} Transaction - a decoded full or pruned transaction of version 1 or 2
 * @property {TxPrefix} prefix
 * @property {Uint8Array[][]} [signatures] - full version 1 only; one array per input, empty for a miner input
 * @property {RctSigBase} [rctSigBase] - version 2 only
 * @property {RctSigPrunable} [rctSigPrunable] - full version 2 only; empty for Null
 */

// crypto::signature: a legacy (pre-RingCT) ring signature entry (c, r), 32 bytes each.
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.h#L54-L58
export const signature = P.bytes(64);

/**
 * Version 1 signatures: one array per input, with no length prefixes.
 * Each key input uses its own outputOffsets.length; each miner input uses an empty array.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L257-L290
 *
 * @param {TxPrefix} prefix
 */
export function txSignaturesCoder(prefix) {
  return P.wrap({
    encodeStream: (w, sigs) => {
      prefix.vin.forEach((vin, i) => {
        const size = vin.TAG === TXIN_TO_KEY_TAG ? vin.data.outputOffsets.length : 0;
        P.array(size, signature).encodeStream(w, sigs[i] ?? []);
      });
    },
    decodeStream: (r) => prefix.vin.map(
      (vin) => P.array(vin.TAG === TXIN_TO_KEY_TAG ? vin.data.outputOffsets.length : 0, signature).decodeStream(r)
    ),
  });
}

/**
 * Create a coder for transaction version 1 or 2.
 * Pruned transactions omit version 1 signatures or version 2 rctSigPrunable; the prefix and version 2 base remain.
 * The prefix supplies input/output counts and the ring size for rctBaseCoder and rctPrunableCoder.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L242-L341
 *
 * @param {boolean} pruned - omit the prunable part on encode and do not read it on decode
 */
export function transactionCoder(pruned) {
  return P.wrap({
    encodeStream: (w, tx) => {
      txPrefix.encodeStream(w, tx.prefix);
      if (tx.prefix.version === 1) {
        if (!pruned) {
          txSignaturesCoder(tx.prefix).encodeStream(w, tx.signatures ?? []);
        }
        return;
      }
      // monero permits only versions 1 and 2 (CURRENT_TRANSACTION_VERSION)
      // https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L184
      if (tx.prefix.version !== 2) {
        throw w.err(`transaction: unsupported version ${tx.prefix.version}`);
      }
      const {
        inputs, outputs, mixin,
      } = txParams(tx.prefix);
      rctBaseCoder(inputs, outputs).encodeStream(w, tx.rctSigBase);
      if (!pruned) {
        rctPrunableCoder(tx.rctSigBase.type, inputs, outputs, mixin).encodeStream(w, tx.rctSigPrunable);
      }
    },
    decodeStream: (r) => {
      const prefix = txPrefix.decodeStream(r);
      if (prefix.version === 1) {
        return pruned ? { prefix } : { prefix, signatures: txSignaturesCoder(prefix).decodeStream(r) };
      }
      if (prefix.version !== 2) {
        throw r.err(`transaction: unsupported version ${prefix.version}`);
      }
      const {
        inputs, outputs, mixin,
      } = txParams(prefix);
      const rctSigBase = rctBaseCoder(inputs, outputs).decodeStream(r);
      if (pruned) {
        return { prefix, rctSigBase };
      }
      const rctSigPrunable = rctPrunableCoder(rctSigBase.type, inputs, outputs, mixin).decodeStream(r);
      return {
        prefix, rctSigBase, rctSigPrunable,
      };
    },
  });
}

// a whole transaction: prefix + (v1 signatures | v2 rctSigBase + rctSigPrunable)
export const fullTransaction = transactionCoder(false);

// a pruned transaction: the base only (prefix, plus rctSigBase for v2), as a pruned node serves it.
// getTxId cannot run on a pruned blob (the txid hashes the prunable part).
export const prunedTransaction = transactionCoder(true);

/**
 * A block blob from COMMAND_RPC_GET_BLOCKS_FAST's block_complete_entry (/getblocks.bin).
 * Block versions and timestamps use Monero LEB128 varints; the RPC wrapper uses the separate epee format.
 * minerTx uses fullTransaction: version 1 has no RingCT base; version 2 has RCTTypes.Null.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L457-L506
 */
export const block = P.struct({
  majorVersion: varintUint8,
  minorVersion: varintUint8,
  timestamp: varintBigInt,
  prevId: key,
  nonce: P.U32LE,
  minerTx: fullTransaction,
  txHashes: P.array(varintNumber, key),
});
