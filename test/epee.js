import assert from 'node:assert/strict';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
} from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as epee from '../lib/epee.js';
import getblocksFixtures from './fixtures/getblocks.json' with { type: 'json' };

describe('epee', () => {
  describe('encode', () => {
    it('encodes the COMMAND_RPC_GET_BLOCKS_FAST request byte-identically to a real capture', () => {
      const [{ requestHex }] = getblocksFixtures;
      const genesisHash = hexToBytes('418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3');
      const req = epee.encode({
        block_ids: genesisHash,
        start_height: 0n,
        prune: false,
        no_miner_tx: false,
        max_block_count: 3n,
      });
      assert.equal(bytesToHex(req), requestHex);
    });

    it('rejects values it cannot infer a wire type for', () => {
      assert.throws(() => epee.encode({ x: [1, 2] }));
      assert.throws(() => epee.encode({ x: null }));
    });
  });

  describe('decode', () => {
    it('decodes a real get_blocks.bin response captured from a live regtest node', () => {
      const [{ responseHex }] = getblocksFixtures;
      const res = epee.decode(hexToBytes(responseHex));
      assert.equal(res.status.length, 2); // "OK" as raw bytes (Uint8Array)
      assert.equal(Buffer.from(res.status).toString(), 'OK');
      assert.equal(res.current_height, 1770n);
      assert.equal(res.start_height, 0n);
      assert.equal(res.blocks.length, 3);
      for (const block of res.blocks) {
        assert.ok(block.block instanceof Uint8Array);
      }
      // output_indices exercises 3 levels of nesting: array of objects, each containing an array
      // of objects, each containing an array of uint64 - the actual shape get_blocks.bin returns.
      assert.equal(res.output_indices.length, 3);
      assert.equal(typeof res.output_indices[0].indices[0].indices[0], 'bigint');
    });

    it('rejects a bad header signature', () => {
      const bytes = hexToBytes('00000000000000000100');
      assert.throws(() => epee.decode(bytes));
    });

    it('round-trips the encoder-inferred types (bigint, bool, bytes)', () => {
      const encoded = epee.encode({
        a: 1n, b: true, c: new Uint8Array([1, 2, 3]),
      });
      const decoded = epee.decode(encoded);
      assert.equal(decoded.a, 1n);
      assert.equal(decoded.b, true);
      assert.deepEqual(decoded.c, new Uint8Array([1, 2, 3]));
    });

    // build a portable-storage blob by hand: header + a section of { name, tag, value } fields.
    // field count and name lengths stay small so their prefixes are a single byte.
    const HEADER = epee.encode({}).subarray(0, 9); // signatures + format version
    const storage = (fields) => concatBytes(
      HEADER,
      Uint8Array.of(fields.length << 2), // epee varint: section field count
      ...fields.flatMap(({
        name, tag, value,
      }) => {
        const nameBytes = new TextEncoder().encode(name);
        return [Uint8Array.of(nameBytes.length), nameBytes, Uint8Array.of(tag), value];
      })
    );
    const scalar = (tag, size, write) => {
      const value = new Uint8Array(size);
      write(new DataView(value.buffer));
      return { tag, value };
    };

    it('decodes every scalar tag from explicit bytes', () => {
      const decoded = epee.decode(storage([
        {
          name: 'i8', tag: epee.Tag.INT8, value: Uint8Array.of(0xff),
        },
        { name: 'i16', ...scalar(epee.Tag.INT16, 2, (dv) => dv.setInt16(0, -2, true)) },
        { name: 'i32', ...scalar(epee.Tag.INT32, 4, (dv) => dv.setInt32(0, -3, true)) },
        { name: 'i64', ...scalar(epee.Tag.INT64, 8, (dv) => dv.setBigInt64(0, -4n, true)) },
        {
          name: 'u8', tag: epee.Tag.UINT8, value: Uint8Array.of(200),
        },
        { name: 'u16', ...scalar(epee.Tag.UINT16, 2, (dv) => dv.setUint16(0, 256, true)) },
        { name: 'u32', ...scalar(epee.Tag.UINT32, 4, (dv) => dv.setUint32(0, 70000, true)) },
        { name: 'u64', ...scalar(epee.Tag.UINT64, 8, (dv) => dv.setBigUint64(0, 123n, true)) },
        { name: 'd', ...scalar(epee.Tag.DOUBLE, 8, (dv) => dv.setFloat64(0, 1.5, true)) },
        {
          name: 'bool', tag: epee.Tag.BOOL, value: Uint8Array.of(1),
        },
      ]));
      assert.equal(decoded.i8, -1);
      assert.equal(decoded.i16, -2);
      assert.equal(decoded.i32, -3);
      assert.equal(decoded.u8, 200);
      assert.equal(decoded.u16, 256);
      assert.equal(decoded.u32, 70000);
      assert.equal(decoded.u64, 123n);
      assert.equal(decoded.bool, true);
      assert.equal(decoded.i64, -4n);
      assert.equal(decoded.d, 1.5);
    });

    it('rejects an empty section field name', () => {
      assert.throws(() => epee.decode(storage([
        {
          name: '', tag: epee.Tag.UINT8, value: Uint8Array.of(1),
        },
      ])), /empty section field name/);
    });

    it('rejects a duplicate section field name', () => {
      assert.throws(() => epee.decode(storage([
        {
          name: 'a', tag: epee.Tag.UINT8, value: Uint8Array.of(1),
        },
        {
          name: 'a', tag: epee.Tag.UINT8, value: Uint8Array.of(2),
        },
      ])), /duplicate section field name/);
    });

    it('rejects nesting past the recursion limit', () => {
      let inner = Uint8Array.of(0x00); // innermost: an empty section (0 fields)
      for (let i = 0; i < 101; i++) {
        inner = concatBytes(
          Uint8Array.of(1 << 2), // 1 field
          Uint8Array.of(1), new TextEncoder().encode('a'),
          Uint8Array.of(epee.Tag.OBJECT),
          inner
        );
      }
      assert.throws(() => epee.decode(concatBytes(HEADER, inner)), /recursion limit/);
    });

    it('stores a __proto__ field as a safe own property', () => {
      const decoded = epee.decode(storage([
        {
          name: '__proto__', tag: epee.Tag.UINT8, value: Uint8Array.of(42),
        },
      ]));
      assert.equal(Object.getPrototypeOf(decoded), null);
      assert.equal(Object.getOwnPropertyDescriptor(decoded, '__proto__').value, 42);
    });
  });
});
