import * as P from 'micro-packed';

/**
 * monerod's binary RPC wire format ("epee portable storage"), used by bin2 endpoints like
 * /getblocks.bin. Distinct from the monero-specific LEB128 varint in raw.js - this is a
 * general-purpose, self-describing (type-tagged) container format, closer to a binary JSON.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/contrib/epee/include/storages/portable_storage_base.h
 */

const SIGNATURE_A = 0x01011101;
const SIGNATURE_B = 0x01020101;
const FORMAT_VERSION = 0x01;

export const Tag = {
  INT64: 1,
  INT32: 2,
  INT16: 3,
  INT8: 4,
  UINT64: 5,
  UINT32: 6,
  UINT16: 7,
  UINT8: 8,
  DOUBLE: 9,
  STRING: 10,
  BOOL: 11,
  OBJECT: 12,
  ARRAY: 13,
};

const ARRAY_FLAG = 0x80;

// scalar (non-string/object/array) type tags map 1:1 onto existing micro-packed primitives
const SCALAR_CODER = {
  [Tag.INT64]: P.I64LE,
  [Tag.UINT64]: P.U64LE,
  [Tag.INT32]: P.I32LE,
  [Tag.UINT32]: P.U32LE,
  [Tag.INT16]: P.I16LE,
  [Tag.UINT16]: P.U16LE,
  [Tag.INT8]: P.I8,
  [Tag.UINT8]: P.U8,
  [Tag.DOUBLE]: P.F64LE,
  [Tag.BOOL]: P.bool,
};

// epee's own varint, unrelated to monero's LEB128 (lib/raw.js varintBigInt): the low 2 bits of
// the first byte pick the encoded width (0=1B, 1=2B, 2=4B, 3=8B), the value is the rest shifted
// right by 2. Used for section field counts and string/array lengths.
const PACKED_SIZE_BY_MARKER = [1, 2, 4, 8];

function packedSizeFor(v) {
  if (v <= 63n) return 1;
  if (v <= 16383n) return 2;
  if (v <= 1073741823n) return 4;
  return 8;
}

const epeeVarint = P.wrap({
  encodeStream: (w, value) => {
    const v = BigInt(value);
    if (v < 0n) {
      throw w.err('epee varint: negative value');
    }
    const size = packedSizeFor(v);
    const marker = PACKED_SIZE_BY_MARKER.indexOf(size);
    let packed = (v << 2n) | BigInt(marker);
    for (let i = 0; i < size; i++) {
      w.byte(Number(packed & 0xffn));
      packed >>= 8n;
    }
  },
  decodeStream: (r) => {
    const first = r.byte();
    const size = PACKED_SIZE_BY_MARKER[first & 0b11];
    let packed = BigInt(first);
    for (let i = 1; i < size; i++) {
      packed |= BigInt(r.byte()) << BigInt(8 * i);
    }
    return packed >> 2n;
  },
});

const epeeVarintNumber = P.apply(epeeVarint, P.coders.numberBigint);

function decodeString(r) {
  const len = epeeVarintNumber.decodeStream(r);
  return r.bytes(len);
}

function encodeString(w, bytes) {
  epeeVarintNumber.encodeStream(w, bytes.length);
  w.bytes(bytes);
}

// portable storage recursion limit, matching monero EPEE_PORTABLE_STORAGE_RECURSION_LIMIT_INTERNAL
// https://github.com/monero-project/monero/blob/v0.18.5.0/contrib/epee/include/storages/portable_storage_from_bin.h#L42
const RECURSION_LIMIT = 100;

function decodeValue(r, tag, depth) {
  if (tag === Tag.STRING) {
    return decodeString(r);
  }
  if (tag === Tag.OBJECT) {
    return decodeSection(r, depth + 1);
  }
  const coder = SCALAR_CODER[tag];
  if (!coder) {
    // Tag.ARRAY (nested array-of-array, deprecated epee container) is not produced by
    // get_blocks.bin's response shape and is intentionally unsupported here.
    throw r.err(`epee: unsupported value type tag ${tag}`);
  }
  return coder.decodeStream(r);
}

function decodeEntry(r, depth) {
  const tag = r.byte();
  if (tag & ARRAY_FLAG) {
    const elementTag = tag & ~ARRAY_FLAG;
    const count = epeeVarintNumber.decodeStream(r);
    const items = new Array(count);
    for (let i = 0; i < count; i++) {
      items[i] = decodeValue(r, elementTag, depth);
    }
    return items;
  }
  return decodeValue(r, tag, depth);
}

function decodeSection(r, depth) {
  if (depth > RECURSION_LIMIT) {
    throw r.err('epee: recursion limit exceeded');
  }
  const count = epeeVarintNumber.decodeStream(r);
  const obj = Object.create(null);
  for (let i = 0; i < count; i++) {
    const nameLen = r.byte();
    if (nameLen === 0) {
      throw r.err('epee: empty section field name');
    }
    const name = new TextDecoder().decode(r.bytes(nameLen));
    if (name in obj) {
      throw r.err(`epee: duplicate section field name ${name}`);
    }
    obj[name] = decodeEntry(r, depth);
  }
  return obj;
}

// Encoding only needs to cover COMMAND_RPC_GET_BLOCKS_FAST's request shape: a flat section of
// uint64/bool/raw-bytes fields. The wire type is inferred from the JS value (bigint -> UINT64,
// boolean -> BOOL, Uint8Array/string -> STRING); nested objects/arrays are not needed and are
// not supported for encoding (only for decoding the response).
function encodeValue(w, value) {
  if (typeof value === 'bigint') {
    w.byte(Tag.UINT64);
    P.U64LE.encodeStream(w, value);
    return;
  }
  if (typeof value === 'boolean') {
    w.byte(Tag.BOOL);
    P.bool.encodeStream(w, value);
    return;
  }
  if (value instanceof Uint8Array) {
    w.byte(Tag.STRING);
    encodeString(w, value);
    return;
  }
  if (typeof value === 'string') {
    w.byte(Tag.STRING);
    encodeString(w, new TextEncoder().encode(value));
    return;
  }
  throw w.err(`epee: cannot encode value of type ${typeof value}`);
}

function encodeSection(w, obj) {
  const names = Object.keys(obj);
  epeeVarintNumber.encodeStream(w, names.length);
  for (const name of names) {
    const nameBytes = new TextEncoder().encode(name);
    w.byte(nameBytes.length);
    w.bytes(nameBytes);
    encodeValue(w, obj[name]);
  }
}

const portableStorage = P.wrap({
  encodeStream: (w, obj) => {
    P.U32LE.encodeStream(w, SIGNATURE_A);
    P.U32LE.encodeStream(w, SIGNATURE_B);
    P.U8.encodeStream(w, FORMAT_VERSION);
    encodeSection(w, obj);
  },
  decodeStream: (r) => {
    const signatureA = P.U32LE.decodeStream(r);
    const signatureB = P.U32LE.decodeStream(r);
    const version = P.U8.decodeStream(r);
    if (signatureA !== SIGNATURE_A || signatureB !== SIGNATURE_B || version !== FORMAT_VERSION) {
      throw r.err('epee: bad portable storage header');
    }
    return decodeSection(r, 0);
  },
});

/** Encodes a flat object of bigint/boolean/Uint8Array/string fields into an epee request. */
export function encode(obj) {
  return portableStorage.encode(obj);
}

/** Decodes an epee-encoded response into a plain JS object (bigint for 64-bit ints, Uint8Array for strings). */
export function decode(bytes) {
  return portableStorage.decode(bytes);
}
