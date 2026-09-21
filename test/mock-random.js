import { keccakP } from '@noble/hashes/sha3.js';

import * as crypto from '../lib/crypto.js';

/**
 * Install monero's unit-test random source: a 200-byte keccak state filled with 42, permuted once
 * per draw. Every call restarts the stream, so a test that depends on the first draw must install
 * it again.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/tests/crypto/random.c#L35-L37
 */
export function mockRandomBytes() {
  const state = new Uint32Array(new Int8Array(200)
    .fill(42)
    .buffer);

  crypto.__mockRandomBytes__((length) => {
    keccakP(state);
    const buf = new Uint8Array(state.buffer);
    return buf.subarray(0, length);
  });
}
