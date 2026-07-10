import { keccak_256 as keccak } from '@noble/hashes/sha3.js';
import { abytes, concatBytes } from '@noble/hashes/utils.js';
import { base58xmr, utils } from '@scure/base';

import { ADDRESS_CHECKSUM_SIZE, getConfig } from './config.js';

/**
 * @typedef {'address' | 'integratedaddress' | 'subaddress'} AddressType
 */
/** @type {AddressType[]} */
const TYPES = ['address', 'integratedaddress', 'subaddress'];

const coder = utils.chain(
  utils.checksum(ADDRESS_CHECKSUM_SIZE, (data) => keccak(data)),
  base58xmr
);

/**
 * @typedef {object} AddressDescriptor
 * @property {AddressType} type
 * @property {Uint8Array} publicSpendKey
 * @property {Uint8Array} publicViewKey
 * @property {Uint8Array} [paymentID]
 */

/**
 * @param {import('./config.js').Nettype} [nettype]
 * @returns {import('@scure/base').Coder<AddressDescriptor, string>}
 */
export function address(nettype = 'mainnet') {
  const config = getConfig(nettype);
  const prefixes = {
    address: config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    integratedaddress: config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    subaddress: config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
  };
  return {
    /**
     * @param {AddressDescriptor} descriptor
     * @returns {string} base58 address
     */
    encode({ type, publicSpendKey, publicViewKey, paymentID }) {
      const prefix = prefixes[type];
      if (prefix === undefined) {
        throw new TypeError(`Unsupported address type '${type}'`);
      }
      abytes(publicSpendKey, 32, 'public spend key');
      abytes(publicViewKey, 32, 'public view key');
      const parts = [Uint8Array.of(prefix), publicSpendKey, publicViewKey];
      if (type === 'integratedaddress') {
        abytes(paymentID, 8, 'payment id');
        parts.push(paymentID);
      }
      return coder.encode(concatBytes(...parts));
    },
    /**
     * @param {string} str - base58 address
     * @returns {AddressDescriptor}
     */
    decode(str) {
      let data;
      try {
        data = coder.decode(str);
      } catch (err) {
        if (err.message === 'base58xmr: wrong padding') {
          throw new TypeError('Incorrect address string', { cause: err });
        }
        if (err.message === 'Invalid checksum') {
          throw new TypeError('Invalid address checksum', { cause: err });
        }
        throw err;
      }
      for (const type of TYPES) {
        if (data[0] !== prefixes[type]) {
          continue;
        }
        const publicSpendKey = data.subarray(1, 33);
        const publicViewKey = data.subarray(33, 65);
        if (type === 'integratedaddress') {
          const paymentID = data.subarray(65, 73);
          return { type, publicSpendKey, publicViewKey, paymentID };
        }
        return { type, publicSpendKey, publicViewKey };
      }
      throw new TypeError('Invalid address prefix');
    },
  };
}
