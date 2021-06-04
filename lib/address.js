import base58 from 'base58-monero';
import { getConfig } from './config.js';
import { fastHash } from './crypto-util.js';
import { isBuffer32, isBuffer8 } from './helpers.js';

export default class Address {
  #type;
  #nettype;
  #secretSpendKey;
  #publicSpendKey;
  // we don't need secretViewKey
  #publicViewKey;
  #paymentID;
  #index;
  #types = ['address', 'integratedaddress', 'subaddress'];

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

  get paymentID() {
    if (this.#type !== 'integratedaddress') {
      throw new TypeError('Address does not have payment ID');
    }
    return this.#paymentID;
  }

  get index() {
    if (!this.#index) {
      throw new TypeError('Index of address unknown');
    }
    return this.#index;
  }

  get type() {
    return this.#type;
  }

  get nettype() {
    return this.#nettype;
  }

  constructor({ secretSpendKey, publicSpendKey, publicViewKey, paymentID }, { index, type, nettype = 'mainnet' }) {
    if (typeof secretSpendKey === 'string') secretSpendKey = Buffer.from(secretSpendKey, 'hex');
    if (typeof publicSpendKey === 'string') publicSpendKey = Buffer.from(publicSpendKey, 'hex');
    if (typeof publicViewKey === 'string') publicViewKey = Buffer.from(publicViewKey, 'hex');
    if (typeof paymentID === 'string') paymentID = Buffer.from(paymentID, 'hex');

    if (!this.#types.includes(type)) {
      throw new TypeError(`Unsupported address type '${type}'`);
    }
    this.#type = type;
    this.#nettype = nettype;

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
    if (this.#type === 'integratedaddress') {
      if (isBuffer8(paymentID)) {
        this.#paymentID = paymentID;
      } else {
        throw new TypeError('Invalid payment ID');
      }
    }
    if (index && index.major !== undefined && index.minor !== undefined) {
      this.#index = index;
    }
  }

  toString() {
    const config = getConfig(this.#nettype);
    let data;
    if (this.#type === 'address') {
      data = Buffer.concat([
        config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
        this.#publicSpendKey,
        this.#publicViewKey,
      ]);
    } else if (this.#type === 'subaddress') {
      data = Buffer.concat([
        config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
        this.#publicSpendKey,
        this.#publicViewKey,
      ]);
    } else if (this.#type === 'integratedaddress') {
      data = Buffer.concat([
        config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        this.#publicSpendKey,
        this.#publicViewKey,
        this.#paymentID,
      ]);
    }
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
      }, { type: 'address', nettype });
    }
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX)) {
      return new Address({
        publicSpendKey: data.slice(1, 32 + 1),
        publicViewKey: data.slice(32 + 1, 32 + 1 + 32),
      }, { type: 'subaddress', nettype });
    }
    if (prefix.equals(config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX)) {
      return new Address({
        publicSpendKey: data.slice(1, 32 + 1),
        publicViewKey: data.slice(32 + 1, 32 + 1 + 32),
        paymentID: data.slice(32 + 1 + 32, 32 + 1 + 32 + 8),
      }, { type: 'integratedaddress', nettype });
    }
    throw new TypeError('Invalid address prefix');
  }
}
