import assert from 'node:assert/strict';
import {
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as epee from '../lib/epee.js';
import blockFixtures from './fixtures/blocks.json' with { type: 'json' };
import getblocksFixtures from './fixtures/getblocks.json' with { type: 'json' };

// Signatures 0x01011101 and 0x01020101 in little-endian, then format version 1.
// https://github.com/monero-project/monero/blob/v0.18.5.1/docs/PORTABLE_STORAGE.md#header
const HEADER = '011101010101020101';

const hexOf = (text) => bytesToHex(utf8ToBytes(text));

// The decoder makes null-prototype sections, so the expected sections must have the same prototype.
const section = (fields) => Object.assign(Object.create(null), fields);

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

    // https://github.com/monero-project/monero/blob/v0.18.5.1/docs/PORTABLE_STORAGE.md#strings
    it('encodes a section key and a string as the monero spec shows them', () => {
      assert.equal(bytesToHex(epee.encode({ Howdy: 'Howdy' })), `${HEADER}04${'05486f776479'}0a${'14486f776479'}`);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/docs/PORTABLE_STORAGE.md#represenations-of-example-values
    it('encodes 1, 2 and 4 byte string lengths as the monero spec shows them', () => {
      for (const [length, varint] of [[0, '00'], [7, '1c'], [101, '9501'], [17000, 'a2090100']]) {
        const value = new Uint8Array(length).fill(0x61);
        assert.equal(bytesToHex(epee.encode({ a: value })), `${HEADER}040161${'0a'}${varint}${bytesToHex(value)}`, `${length}`);
      }
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/docs/PORTABLE_STORAGE.md#byte-sizes
    it('switches the length size at the limits of the monero spec table', () => {
      for (const [length, varint] of [[63, 'fc'], [64, '0101'], [16383, 'fdff'], [16384, '02000100']]) {
        const value = new Uint8Array(length).fill(0x61);
        const hex = `${HEADER}040161${'0a'}${varint}${bytesToHex(value)}`;
        assert.equal(bytesToHex(epee.encode({ a: value })), hex, `${length}`);
        assert.deepEqual(epee.decode(hexToBytes(hex)).a, value);
      }
    });

    it('encodes a bool', () => {
      const hex = [
        HEADER, '08',
        '0174', '0b', '01', // t
        '0166', '0b', '00', // f
      ].join('');
      assert.equal(bytesToHex(epee.encode({ t: true, f: false })), hex);
    });

    it('rejects values it cannot infer a wire type for', () => {
      assert.throws(() => {
        epee.encode({ x: [1, 2] });
      });
      assert.throws(() => {
        epee.encode({ x: null });
      });
      assert.throws(() => {
        epee.encode({ x: 1 });
      });
    });
  });

  describe('decode', () => {
    it('decodes a real get_blocks.bin response captured from a live regtest node', () => {
      const [{ responseHex }] = getblocksFixtures;
      const res = epee.decode(hexToBytes(responseHex));
      assert.deepEqual(res.status, utf8ToBytes('OK'));
      assert.equal(res.current_height, 1770n);
      assert.equal(res.start_height, 0n);
      // the first two block blobs are the genesis and height 1 fixtures of blocks.json
      assert.equal(res.blocks.length, 3);
      assert.equal(bytesToHex(res.blocks[0].block), blockFixtures[0].hex);
      assert.equal(bytesToHex(res.blocks[1].block), blockFixtures[1].hex);
      assert.deepEqual(res.output_indices, [
        section({ indices: [section({ indices: [0n] })] }),
        section({ indices: [section({ indices: [0n] })] }),
        section({ indices: [section({ indices: [1n] })] }),
      ]);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/docs/PORTABLE_STORAGE.md#overall-example
    it('decodes the overall example of the monero spec', () => {
      const hex = '011101010101020101140b73686f72745f71756f74650a8447697665206d65206c696265727479206f722067697665206d65206465617468210a6c6f6e675f71756f74650a41014d6f6e65726f206973206d6f7265207468616e206a757374206120746563686e6f6c6f67792e204974277320616c736f20776861742074686520746563686e6f6c6f6779207374616e647320666f722e107369676e65645f33326269745f696e7402825133010e61727261795f6f665f626f6f6c738b10010001010e6e65737465645f73656374696f6e0c0806646f75626c65099a99999999991bc012756e7369676e65645f36346269745f696e7405c771acb5af98329a';
      assert.deepEqual(epee.decode(hexToBytes(hex)), section({
        short_quote: utf8ToBytes('Give me liberty or give me death!'),
        long_quote: utf8ToBytes('Monero is more than just a technology. It\'s also what the technology stands for.'),
        signed_32bit_int: 20140418,
        array_of_bools: [true, false, true, true],
        nested_section: section({
          double: -6.9,
          unsigned_64bit_int: 11111111111111111111n,
        }),
      }));
    });

    it('decodes every integer tag, with negative signed values', () => {
      const hex = [
        HEADER, '1c',
        '026938', '04', 'ff', // i8
        '03693136', '03', 'feff', // i16
        '03693332', '02', 'fdffffff', // i32
        '03693634', '01', 'fcffffffffffffff', // i64
        '027538', '08', 'c8', // u8
        '03753136', '07', '0001', // u16
        '03753332', '06', '70110100', // u32
      ].join('');
      assert.deepEqual(epee.decode(hexToBytes(hex)), section({
        i8: -1, i16: -2, i32: -3, i64: -4n, u8: 200, u16: 256, u32: 70000,
      }));
    });

    it('decodes a bool', () => {
      const hex = [
        HEADER, '08',
        '0174', '0b', '01', // t
        '0166', '0b', '00', // f
      ].join('');
      assert.deepEqual(epee.decode(hexToBytes(hex)), section({ t: true, f: false }));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/data/fuzz/load-from-binary/BINARY1
    it('decodes an empty section', () => {
      assert.deepEqual(epee.decode(hexToBytes(`${HEADER}00`)), section({}));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/epee_serialization.cpp#L39-L48
    it('decodes two keys', () => {
      assert.deepEqual(epee.decode(hexToBytes(`${HEADER}08${'0161'}0b00${'0162'}0b00`)), section({ a: false, b: false }));
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/epee_serialization.cpp#L50-L59
    it('rejects a duplicate key', () => {
      assert.throws(() => {
        epee.decode(hexToBytes(`${HEADER}08${'0161'}0b00${'0161'}0b00`));
      }, /duplicate section field name/);
    });

    it('rejects a bad header signature', () => {
      assert.throws(() => {
        epee.decode(hexToBytes('00000000000000000100'));
      });
    });

    it('rejects an empty key', () => {
      assert.throws(() => {
        epee.decode(hexToBytes(`${HEADER}04${'00'}0801`));
      }, /empty section field name/);
    });

    it('rejects an unknown type tag', () => {
      assert.throws(() => {
        epee.decode(hexToBytes(`${HEADER}04${'0161'}0e00`));
      });
    });

    it('rejects an untyped array, which monero does not produce', () => {
      assert.throws(() => {
        epee.decode(hexToBytes(`${HEADER}04${'0161'}0d00`));
      });
    });

    it('rejects truncated data', () => {
      assert.throws(() => {
        epee.decode(hexToBytes(`${HEADER}04${'0161'}0a14${hexOf('How')}`));
      });
    });

    // An 8-byte string length (7942319744 from the spec table) with no string bytes after it.
    it('rejects a string length larger than the data', () => {
      assert.throws(() => {
        epee.decode(hexToBytes(`${HEADER}04${'0161'}0a03ba986507000000`));
      });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/contrib/epee/include/storages/portable_storage_from_bin.h#L39-L43
    it('rejects nesting past the recursion limit', () => {
      const hex = `${HEADER}${`04${'0161'}0c`.repeat(101)}00`;
      assert.throws(() => {
        epee.decode(hexToBytes(hex));
      }, /recursion limit/);
    });

    it('stores a __proto__ key as a safe own property', () => {
      const decoded = epee.decode(hexToBytes(`${HEADER}04${'09'}${hexOf('__proto__')}082a`));
      assert.equal(Object.getPrototypeOf(decoded), null);
      assert.equal(Object.getOwnPropertyDescriptor(decoded, '__proto__').value, 42);
    });
  });
});
