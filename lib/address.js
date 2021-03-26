import base58 from 'base58-monero';
import { getConfig } from './config.js';
import { fastHash } from './crypto-util.js';
import { isBuffer32 } from './helpers.js';

export default class Address {
  constructor(publicSpendKey, publicViewKey, isSubaddress = false, nettype = 'mainnet') {
    if (typeof publicSpendKey === 'string') publicSpendKey = Buffer.from(publicSpendKey, 'hex');
    if (typeof publicViewKey === 'string') publicViewKey = Buffer.from(publicViewKey, 'hex');
    if (!isBuffer32(publicSpendKey)) {
      throw new TypeError('Invalid pablic spend key');
    }
    if (!isBuffer32(publicViewKey)) {
      throw new TypeError('Invalid pablic view key');
    }
    this.publicSpendKey = publicSpendKey;
    this.publicViewKey = publicViewKey;
    this.isSubaddress = isSubaddress;
    this.nettype = nettype;
  }

  toString() {
    const config = getConfig(this.nettype);
    const prefix = this.isSubaddress ?
      config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX :
      config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    const data = Buffer.concat([
      prefix,
      this.publicSpendKey,
      this.publicViewKey,
    ]);
    const checksum = fastHash(data).slice(0, config.ADDRESS_CHECKSUM_SIZE);
    return base58.encode(Buffer.concat([data, checksum]));
  }

  static fromString(str, nettype = 'mainnet') {
    const config = getConfig(nettype);
    const decoded = base58.decode(str);
    if (decoded.length < config.ADDRESS_CHECKSUM_SIZE) {
      throw new TypeError('Incorrect address string');
    }
    const data = decoded.slice(0, decoded.length - config.ADDRESS_CHECKSUM_SIZE);
    const actualChecksum = decoded.slice(decoded.length - config.ADDRESS_CHECKSUM_SIZE);
    const expectedChecksum = fastHash(data).slice(0, config.ADDRESS_CHECKSUM_SIZE);

    if (!expectedChecksum.equals(actualChecksum)) {
      throw new TypeError('Invalid address checksum');
    }
    const prefix = data.slice(0, 1);
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX)) {
      return new Address(data.slice(1, 32 + 1), data.slice(32 + 1, 32 + 1 + 32), false, nettype);
    }
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX)) {
      return new Address(data.slice(1, 32 + 1), data.slice(32 + 1, 32 + 1 + 32), true, nettype);
    }
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX)) {
      throw new Error('Not implemented');
    }
    throw new TypeError('Invalid address prefix');
  }
}
