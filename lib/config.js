import { utf8ToBytes } from '@noble/hashes/utils.js';
/**
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h
 */

const CONFIG_COMMON = {
  // https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L244
  HASH_KEY_SUBADDRESS: utf8ToBytes('SubAddr'),
  // https://github.com/monero-project/monero/blob/v0.18.5.0/src/common/base58.cpp#L52
  ADDRESS_CHECKSUM_SIZE: 4,
};

const CONFIG_MAINNET = {
  CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX: Uint8Array.from([18]),
  CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX: Uint8Array.from([19]),
  CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX: Uint8Array.from([42]),
};

const CONFIG_STAGENET = {
  CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX: Uint8Array.from([24]),
  CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX: Uint8Array.from([25]),
  CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX: Uint8Array.from([36]),
};

const CONFIG_TESTNET = {
  CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX: Uint8Array.from([53]),
  CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX: Uint8Array.from([54]),
  CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX: Uint8Array.from([63]),
};

export function getConfig(nettype) {
  switch (nettype) {
    case 'mainnet': {
      return {
        ...CONFIG_COMMON,
        ...CONFIG_MAINNET,
      };
    }
    case 'stagenet': {
      return {
        ...CONFIG_COMMON,
        ...CONFIG_STAGENET,
      };
    }
    case 'testnet': {
      return {
        ...CONFIG_COMMON,
        ...CONFIG_TESTNET,
      };
    }
    case 'regtest': {
      return {
        ...CONFIG_COMMON,
        ...CONFIG_MAINNET,
      };
    }
    default: {
      throw new TypeError(`Invalid network type: ${nettype}`);
    }
  }
}
