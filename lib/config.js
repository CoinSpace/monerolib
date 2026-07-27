import { utf8ToBytes } from '@noble/hashes/utils.js';
/**
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h
 */

// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L244
export const HASH_KEY_SUBADDRESS = utf8ToBytes('SubAddr');

// https://github.com/monero-project/monero/blob/v0.18.5.0/src/common/base58.cpp#L52
export const ADDRESS_CHECKSUM_SIZE = 4;

// maxM: max outputs aggregated into one Bulletproof(+) (BULLETPROOF_PLUS_MAX_OUTPUTS)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L204
export const MAX_COMMITMENTS = 16;

// maxN: bits in the range (amount is uint64)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/bulletproofs_plus.cc#L67
export const COMMITMENT_BITS = 64;

// blocks a coinbase output must age before it is spendable (CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L44
export const COINBASE_UNLOCK_WINDOW = 60;

// blocks a regular output must age before it is spendable (CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L49
export const DEFAULT_SPENDABLE_AGE = 10;

// consensus ring size since HF 15 (v0.18): exactly 16 (mixin 15), min == max, so it is not a choice
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L8666-L8688
export const RING_SIZE = 16;

// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L227-L229
const CONFIG_MAINNET = {
  CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX: 18,
  CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX: 19,
  CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX: 42,
};

// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L285-L287
const CONFIG_STAGENET = {
  CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX: 24,
  CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX: 25,
  CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX: 36,
};

// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L270-L272
const CONFIG_TESTNET = {
  CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX: 53,
  CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX: 54,
  CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX: 63,
};

/**
 * @typedef {'mainnet' | 'stagenet' | 'testnet' | 'regtest'} Nettype
 */

/**
 * @typedef {object} NetworkConfig - base58 address prefixes for a network
 * @property {number} CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX
 * @property {number} CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX
 * @property {number} CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX
 */

/**
 * @param {Nettype} nettype
 * @returns {NetworkConfig}
 * @throws {TypeError} on an unknown network type
 */
export function getConfig(nettype) {
  switch (nettype) {
    case 'mainnet': {
      return { ...CONFIG_MAINNET };
    }
    case 'stagenet': {
      return { ...CONFIG_STAGENET };
    }
    case 'testnet': {
      return { ...CONFIG_TESTNET };
    }
    case 'regtest': {
      return { ...CONFIG_MAINNET };
    }
    default: {
      throw new TypeError(`Invalid network type: ${nettype}`);
    }
  }
}
