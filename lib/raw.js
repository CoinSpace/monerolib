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

function checkUint8(value) {
  if (value < 0 || value > 0xff) {
    throw new Error(`varint: value ${value} exceeds uint8`);
  }
  return value;
}

/** Varint bounded to a uint8, for block major/minor version (both uint8_t in monero). */
const varintUint8 = P.apply(varintNumber, { encode: checkUint8, decode: checkUint8 });

/**
 * A 32-byte key (point or scalar).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L79
 */
export const key = P.bytes(32);

/**
 * monero keyV: std::vector<key>. The varint length prefix comes from the generic vector
 * serializer (binary_archive::begin_array writes the size via serialize_varint).
 * keyV
 * begin_array
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L89
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/serialization/binary_archive.h#L221
 */
export const keyV = P.array(varintNumber, key);

/**
 * Transaction inputs/outputs and prefix.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L63-L189
 *
 * vin and the output target are boost::variant; serialization writes a single tag byte first.
 * Variant tags
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L572-L579
 */

// txin_to_key (tag 0x02): amount, key_offsets, k_image
export const txinToKey = P.struct({
  amount: varintBigInt,
  keyOffsets: P.array(varintNumber, varintBigInt),
  keyImage: key,
});

// txin_gen (tag 0xff): miner input, only the block height
export const txinGen = P.struct({ height: varintBigInt });

// P.tag types TAG as the literal variant key (2 | 255); widen it to number so hand-built
// prefixes (with plain-number tags) are assignable without a cast at the encode call.
export const txin = /**
 * @type {import('micro-packed').CoderType<{
 *   TAG: number,
 *   data: { amount: bigint, keyOffsets: bigint[], keyImage: Uint8Array } | { height: bigint }
 * }>}
 */ (P.tag(P.U8, {
    0x02: txinToKey,
    0xff: txinGen,
  }));

// txout_to_key (tag 0x02): key
export const txoutToKey = P.struct({ key });

// txout_to_tagged_key (tag 0x03): key + 1-byte view_tag
export const txoutToTaggedKey = P.struct({ key, viewTag: P.U8 });

export const txoutTarget = /**
 * @type {import('micro-packed').CoderType<{
 *   TAG: number,
 *   data: { key: Uint8Array } | { key: Uint8Array, viewTag: number }
 * }>}
 */ (P.tag(P.U8, {
    0x02: txoutToKey,
    0x03: txoutToTaggedKey,
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
const txExtraFieldCoder = {
  [TX_EXTRA_TAG_PUBKEY]: key,
  [TX_EXTRA_NONCE]: P.bytes(varintNumber),
  [TX_EXTRA_MERGE_MINING_TAG]: P.bytes(varintNumber),
  [TX_EXTRA_TAG_ADDITIONAL_PUBKEYS]: P.array(varintNumber, key),
  [TX_EXTRA_MYSTERIOUS_MINERGATE_TAG]: P.bytes(varintNumber),
};

/**
 * @typedef {{ tag: number, data: Uint8Array | Uint8Array[] }} TxExtraField - a tag byte plus its
 *   payload (a key, raw bytes, or a list of keys for additional pubkeys)
 */

/**
 * tx_extra: a sequence of tagged fields with no count prefix, parsed until the buffer ends, as an
 * ordered list of { tag, data }. tx_extra is not consensus-validated, so decoding is best-effort:
 * it stops at the first unknown tag or truncated field (like monero sort_tx_extra allow_partial).
 * Kept separate from txPrefix.extra (opaque bytes) so the whole-tx round-trip stays byte-exact.
 * parse_tx_extra
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L567-L586
 */
export const txExtra = P.wrap({
  encodeStream: (w, fields) => {
    for (const { tag, data } of fields) {
      P.U8.encodeStream(w, tag);
      if (tag === TX_EXTRA_TAG_PADDING) {
        w.bytes(data);
      } else {
        txExtraFieldCoder[tag].encodeStream(w, data);
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
      const coder = txExtraFieldCoder[tag];
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
 * @property {Uint8Array} [mask] - absent (zeroed) for v2 rct types
 * @property {Uint8Array} amount
 */

// ecdhTuple before Bulletproof2: full mask + full amount scalars
const ecdhTupleV1 = P.struct({ mask: key, amount: key });

// since Bulletproof2 the mask is deterministic (not saved) and only the first 8 bytes
// of the encrypted amount are stored
const ecdhAmountV2 = P.bytes(8);

// one ecdh entry as an EcdhTuple: v1 = {mask, amount} scalars; v2 = {amount} (8 bytes, no mask)
const ecdhEntry = (type) => P.wrap({
  encodeStream: (w, e) => (isV2EcdhType(type)
    ? ecdhAmountV2.encodeStream(w, e.amount)
    : ecdhTupleV1.encodeStream(w, e)),
  decodeStream: (r) => (isV2EcdhType(type)
    ? { amount: ecdhAmountV2.decodeStream(r) }
    : ecdhTupleV1.decodeStream(r)),
});

/**
 * rctSigBase: type, txnFee, pseudoOuts (Simple only), ecdhInfo, outPk (mask only).
 * The pseudoOuts/ecdhInfo/outPk arrays carry no length prefix; their counts come from the
 * prefix (inputs = vin.length, outputs = vout.length), so this is a factory over those counts.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L333-L403
 */
export function rctBase(inputs, outputs) {
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
      P.array(outputs, ecdhEntry(v.type)).encodeStream(w, v.ecdhInfo);
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
      res.ecdhInfo = P.array(outputs, ecdhEntry(type)).decodeStream(r);
      res.outPk = P.array(outputs, key).decodeStream(r);
      return res;
    },
  });
}

/**
 * @typedef {object} BulletproofPlus - a Bulletproof+ range proof
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
const bulletproofPlus = P.struct({
  A: key, A1: key, B: key, r1: key, s1: key, d1: key,
  L: keyV, R: keyV,
});

/**
 * @typedef {object} Bulletproof - an original (pre-plus) range proof
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
const bulletproof = P.struct({
  A: key, S: key, T1: key, T2: key, taux: key, mu: key,
  L: keyV, R: keyV,
  a: key, b: key, t: key,
});

// key64: fixed array of 64 keys, no length prefix
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L153
const key64 = P.array(64, key);

// Borromean range proof
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L155-L209
const rangeSig = P.struct({
  asig: P.struct({
    s0: key64, s1: key64, ee: key,
  }),
  Ci: key64,
});

// CLSAG signature; in rctSigPrunable s is written without a length prefix, with size mixin + 1
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L495-L526
const clsagCoder = (mixin) => P.struct({
  s: P.array(mixin + 1, key),
  c1: key,
  D: key,
});

// MLSAG signature; in rctSigPrunable ss is written without size prefixes as a (mixin+1) x cols matrix
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L537-L579
const mgCoder = (mixin, cols) => P.struct({
  ss: P.array(mixin + 1, P.array(cols, key)),
  cc: key,
});

/**
 * rctSigPrunable: range proofs + ring signatures + (bp/clsag) pseudoOuts.
 * The layout depends on type/inputs/outputs/mixin, none of which are in the byte stream, so this
 * is a factory over those values (matches the serialize_rctsig_prunable signature).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L426-L601
 */
export function rctPrunable(type, inputs, outputs, mixin) {
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

// rct counts that are not in the byte stream: inputs/outputs and the ring size (mixin), the latter
// taken from the first input (miner txin_gen has none), as monero does here:
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L309-L310
export const txParams = (prefix) => ({
  inputs: prefix.vin.length,
  outputs: prefix.vout.length,
  mixin: prefix.vin[0].TAG === 0x02 ? prefix.vin[0].data.keyOffsets.length - 1 : 0,
});

/**
 * @typedef {object} Vin - a key input (txin_to_key, tag 0x02)
 * @property {number} TAG
 * @property {{ amount: bigint, keyOffsets: bigint[], keyImage: Uint8Array }} data
 */

/**
 * @typedef {object} Vout - an output: amount + tagged target (txout_to_tagged_key, tag 0x03)
 * @property {bigint} amount
 * @property {{ TAG: number, data: { key: Uint8Array, viewTag?: number } }} target
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
 * @property {bigint} txnFee
 * @property {EcdhTuple[]} ecdhInfo - per-output ecdh entries ({amount} for v2, {mask, amount} for v1)
 * @property {Uint8Array[]} outPk - per-output commitments
 * @property {Uint8Array[]} [pseudoOuts] - only for the Simple type; bp/bp+ keep them in the prunable part
 */

/**
 * @typedef {object} RctSigPrunable
 * @property {BulletproofPlus[]} bulletproofsPlus
 * @property {{ s: Uint8Array[], c1: Uint8Array, D: Uint8Array }[]} CLSAGs
 * @property {Uint8Array[]} pseudoOuts
 */

/**
 * @typedef {object} Transaction - a decoded transaction.
 * version 1 (legacy, pre-RingCT) txs have no rct part at all and carry `signatures` instead;
 * version >= 2 txs carry `rctSigBase`/`rctSigPrunable` instead.
 * @property {TxPrefix} prefix
 * @property {Uint8Array[][]} [signatures] - version 1 only: one ring signature array per vin
 * @property {RctSigBase} [rctSigBase] - version >= 2 only
 * @property {RctSigPrunable} [rctSigPrunable] - version >= 2 only
 */

// crypto::signature: a legacy (pre-RingCT) ring signature entry (c, r), 32 bytes each.
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto.h#L54-L58
const signature = P.bytes(64);

/**
 * version 1's "signatures" section: one ring signature array per vin, sized off that same vin's
 * own key_offsets (mixin+1) with no separate length prefix - txin_gen (coinbase) contributes a
 * zero-length array. Needed for genesis/pre-RingCT blocks, which every chain has at height 0.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L257-L290
 */
function txSignatures(prefix) {
  return P.wrap({
    encodeStream: (w, sigs) => {
      prefix.vin.forEach((vin, i) => {
        const size = vin.TAG === 0x02 ? vin.data.keyOffsets.length : 0;
        P.array(size, signature).encodeStream(w, sigs[i] ?? []);
      });
    },
    decodeStream: (r) => prefix.vin.map(
      (vin) => P.array(vin.TAG === 0x02 ? vin.data.keyOffsets.length : 0, signature).decodeStream(r)
    ),
  });
}

/**
 * A whole transaction: prefix, then either version 1's legacy ring signatures or (version >= 2)
 * rctSigBase + rctSigPrunable. rctBase/rctPrunable are factory coders parameterized by counts
 * from the prefix (the rct arrays carry no length prefix), mirroring monero
 * serialize_rctsig_base/prunable.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L242-L322
 */
export const transaction = P.wrap({
  encodeStream: (w, tx) => {
    txPrefix.encodeStream(w, tx.prefix);
    if (tx.prefix.version === 1) {
      txSignatures(tx.prefix).encodeStream(w, tx.signatures ?? []);
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
    rctBase(inputs, outputs).encodeStream(w, tx.rctSigBase);
    rctPrunable(tx.rctSigBase.type, inputs, outputs, mixin).encodeStream(w, tx.rctSigPrunable);
  },
  decodeStream: (r) => {
    const prefix = txPrefix.decodeStream(r);
    if (prefix.version === 1) {
      return { prefix, signatures: txSignatures(prefix).decodeStream(r) };
    }
    if (prefix.version !== 2) {
      throw r.err(`transaction: unsupported version ${prefix.version}`);
    }
    const {
      inputs, outputs, mixin,
    } = txParams(prefix);
    const rctSigBase = rctBase(inputs, outputs).decodeStream(r);
    const rctSigPrunable = rctPrunable(rctSigBase.type, inputs, outputs, mixin).decodeStream(r);
    return {
      prefix,
      rctSigBase,
      rctSigPrunable,
    };
  },
});

/**
 * A block's raw blob, as returned embedded in COMMAND_RPC_GET_BLOCKS_FAST's block_complete_entry
 * (monerod's /getblocks.bin). major/minor version and timestamp use monero's own LEB128 varint
 * (the same varintNumber/varintBigInt as everywhere else in this file - unrelated to the epee
 * wire format that wraps the RPC call itself, see lib/epee.js). miner_tx is an ordinary
 * transaction (coinbase: rct type Null), decodable with the `transaction` coder above.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_basic.h#L326-L344
 */
export const block = P.struct({
  majorVersion: varintUint8,
  minorVersion: varintUint8,
  timestamp: varintBigInt,
  prevId: key,
  nonce: P.U32LE,
  minerTx: transaction,
  txHashes: P.array(varintNumber, key),
});
