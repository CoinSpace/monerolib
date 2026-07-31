# monerolib

[![Build](https://github.com/CoinSpace/monerolib/actions/workflows/ci.yml/badge.svg)](https://github.com/CoinSpace/monerolib/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/npm/dm/monerolib)](https://www.npmjs.com/package/monerolib)
[![Version](https://img.shields.io/npm/v/monerolib?label=version)](https://www.npmjs.com/package/monerolib)
[![License](https://img.shields.io/github/license/CoinSpace/monerolib?color=blue)](https://github.com/CoinSpace/monerolib/blob/master/LICENSE)

Stateless, bigint-native Monero primitives. ESM.

## Install
```
npm i monerolib
```

## Modules

| import | what |
|---|---|
| `wallet` | keys, addresses/subaddresses, output scanning, transaction creation |
| `tx` | build/sign RingCT (Bulletproof+) transactions, fees, tx id |
| `address` | base58 address encode/decode (`address(nettype)`) |
| `crypto` | ed25519 ops, hashes, key images, derivations |
| `ringct` | ecdh amounts, commitments, `RCTTypes`, `decodeRct` |
| `decoys` | `gammaPicker` — decoy selection by the reference gamma distribution |
| `coinselect` | `selectInputs` — input selection + fee/change estimation; a sweep target (no `amount`) reports the max sendable |
| `helpers` | scalar encode/decode, `assertUint64` |
| `raw` | wire serialization + tx/block typedefs |
| `epee` | monerod binary RPC format (`/getblocks.bin`) |

Every function has JSDoc that links the exact monero v0.18.5.0 (and monero-oxide) source it ports.

## Usage

```js
import { wallet, coinselect, decoys, address } from 'monerolib';

// keys
const keys = wallet.keysFromSeed(seed);
const addr = wallet.getSubaddress(keys, { major: 0, minor: 0 });

// scan a chain output you might own
const lookup = wallet.subaddressLookup(keys, majorCount, minorCount);
const owned = wallet.scanOutput(keys, output, lookup);

// attach ring decoys to each spendable input (ring size is fixed at 16)
const pick = decoys.gammaPicker(rctOffsets);
for (const input of inputs) input.decoys = pickDecoys(pick, 15, input.globalIndex);

// estimate the fee and the max sendable — a sweep target has no `amount`
const { fee, sweepAmount } = coinselect.selectInputs({
  candidates: inputs,
  destinations: [address('mainnet').decode(recipient)],
  ringSize: 16, baseFee, feeQuantization,
});

// create + sign — picks inputs, appends change/dummy; returns the decoded tx and its hex
const { json, hex } = wallet.createTransaction({
  inputs,
  outputs: [{ ...address('mainnet').decode(recipient), amount }],
  keys, baseFee, feeQuantization,
});
```

`wallet.createTransaction` is the high-level builder; `tx.prepareTransaction` / `tx.createTransaction`
are the low-level primitives (exact `inputs`/`outputs`, see the typedefs in `lib/tx.js`).

## Tests

`node --test`. Type-checked with `npm run typecheck`, linted with `npx eslint`.
