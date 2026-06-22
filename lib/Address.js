import { equalBytes } from '@noble/curves/utils.js';
import { keccak_256 as keccak } from '@noble/hashes/sha3.js';
import { ADDRESS_CHECKSUM_SIZE, getConfig } from './config.js';
import { abytes, concatBytes } from '@noble/hashes/utils.js';
import { base58xmr, utils } from '@scure/base';

function base58xmrCheck(checksumSize) {
  return utils.chain(
    utils.checksum(checksumSize, (data) => keccak(data)),
    base58xmr
  );
}

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
    if (!this.#types.includes(type)) {
      throw new TypeError(`Unsupported address type '${type}'`);
    }
    this.#type = type;
    this.#nettype = nettype;

    abytes(publicSpendKey, 32, 'public spend key');
    abytes(publicViewKey, 32, 'public view key');
    if (secretSpendKey) {
      abytes(secretSpendKey, 32, 'secret spend key');
    }

    this.#publicSpendKey = publicSpendKey;
    this.#publicViewKey = publicViewKey;
    if (secretSpendKey) {
      this.#secretSpendKey = secretSpendKey;
    }
    if (this.#type === 'integratedaddress') {
      abytes(paymentID, 8, 'payment id');
      this.#paymentID = paymentID;
    }
    if (index && index.major !== undefined && index.minor !== undefined) {
      this.#index = index;
    }
  }

  toString() {
    const config = getConfig(this.#nettype);
    let data;
    if (this.#type === 'address') {
      data = concatBytes(
        config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
        this.#publicSpendKey,
        this.#publicViewKey
      );
    } else if (this.#type === 'subaddress') {
      data = concatBytes(
        config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
        this.#publicSpendKey,
        this.#publicViewKey
      );
    } else if (this.#type === 'integratedaddress') {
      data = concatBytes(
        config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        this.#publicSpendKey,
        this.#publicViewKey,
        this.#paymentID
      );
    }
    return base58xmrCheck(ADDRESS_CHECKSUM_SIZE).encode(data);
  }

  static fromString(str, nettype = 'mainnet') {
    const config = getConfig(nettype);
    let data;
    try {
      data = base58xmrCheck(ADDRESS_CHECKSUM_SIZE).decode(str);
    } catch (err) {
      if (err.message === 'base58xmr: wrong padding') {
        throw new TypeError('Incorrect address string', { cause: err });
      }
      if (err.message === 'Invalid checksum') {
        throw new TypeError('Invalid address checksum', { cause: err });
      }
      throw err;
    }
    const prefix = data.subarray(0, 1);
    if (equalBytes(prefix, config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX)) {
      return new Address({
        publicSpendKey: data.subarray(1, 32 + 1),
        publicViewKey: data.subarray(32 + 1, 32 + 1 + 32),
      }, { type: 'address', nettype });
    }
    if (equalBytes(prefix, config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX)) {
      return new Address({
        publicSpendKey: data.subarray(1, 32 + 1),
        publicViewKey: data.subarray(32 + 1, 32 + 1 + 32),
      }, { type: 'subaddress', nettype });
    }
    if (equalBytes(prefix, config.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX)) {
      return new Address({
        publicSpendKey: data.subarray(1, 32 + 1),
        publicViewKey: data.subarray(32 + 1, 32 + 1 + 32),
        paymentID: data.subarray(32 + 1 + 32, 32 + 1 + 32 + 8),
      }, { type: 'integratedaddress', nettype });
    }
    throw new TypeError('Invalid address prefix');
  }
}
