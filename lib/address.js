import base58 from 'base58-monero';
import { getConfig } from './config.js';
import { fastHash } from './crypto-util.js';
import { isBuffer32 } from './helpers.js';

export default class Address {
  #isSubaddress;
  #nettype;
  #secretSpendKey;
  #publicSpendKey;
  // we don't need secretViewKey
  #publicViewKey;
  #index;

  get isViewOnly() {
    return !this.#secretSpendKey;
  }

  get secretSpendKey() {
    if (!this.#secretSpendKey) {
      throw new TypeError('Address in view only mode');
    }
    return this.#secretSpendKey;
  }

  get publicSpendKey() {
    return this.#publicSpendKey;
  }

  get publicViewKey() {
    return this.#publicViewKey;
  }

  get index() {
    if (!this.#index) {
      throw new TypeError('Index of address unknown');
    }
    return this.#index;
  }

  get isSubaddress() {
    return this.#isSubaddress;
  }

  get nettype() {
    return this.#nettype;
  }

  constructor({ secretSpendKey, publicSpendKey, publicViewKey }, index, isSubaddress = false, nettype = 'mainnet') {
    if (typeof secretSpendKey === 'string') secretSpendKey = Buffer.from(secretSpendKey, 'hex');
    if (typeof publicSpendKey === 'string') publicSpendKey = Buffer.from(publicSpendKey, 'hex');
    if (typeof publicViewKey === 'string') publicViewKey = Buffer.from(publicViewKey, 'hex');
    if (!isBuffer32(publicSpendKey)) {
      throw new TypeError('Invalid pablic spend key');
    }
    if (!isBuffer32(publicViewKey)) {
      throw new TypeError('Invalid pablic view key');
    }
    if (secretSpendKey && !isBuffer32(secretSpendKey)) {
      throw new TypeError('Invalid secret spend key');
    }

    this.#publicSpendKey = publicSpendKey;
    this.#publicViewKey = publicViewKey;
    if (secretSpendKey) {
      this.#secretSpendKey = secretSpendKey;
    }
    if (index && index.major !== undefined && index.minor !== undefined) {
      this.#index = index;
    }
    this.#isSubaddress = isSubaddress;
    this.#nettype = nettype;
  }

  toString() {
    const config = getConfig(this.#nettype);
    const prefix = this.#isSubaddress ?
      config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX :
      config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    const data = Buffer.concat([
      prefix,
      this.#publicSpendKey,
      this.#publicViewKey,
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
      return new Address({
        publicSpendKey: data.slice(1, 32 + 1),
        publicViewKey: data.slice(32 + 1, 32 + 1 + 32),
      }, null, false, nettype);
    }
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX)) {
      return new Address({
        publicSpendKey: data.slice(1, 32 + 1),
        publicViewKey: data.slice(32 + 1, 32 + 1 + 32),
      }, null, true, nettype);
    }
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX)) {
      throw new Error('Not implemented');
    }
    throw new TypeError('Invalid address prefix');
  }
}
