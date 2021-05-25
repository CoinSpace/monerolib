import {
  fastHash,
  generateKeys,
  hashToScalar,
  secretKeyToPublicKey,
} from './crypto-util.js';
import { ec } from './crypto-util-data.js';
import {
  decodeInt,
  encodeInt,
  encodeUint32,
  decodePoint,
  encodePoint,
  isBuffer32,
} from './helpers.js';
import Address from './address.js';
import { getConfig } from './config.js';

export default class Wallet {
  #config;
  #nettype;
  #seed;
  #secretSpendKey;
  #publicSpendKey;
  #secretViewKey;
  #publicViewKey;

  get nettype() {
    return this.#nettype;
  }

  get seed() {
    if (!this.#seed) {
      throw new TypeError('Wallet in view only mode');
    }
    return this.#seed;
  }

  get secretSpendKey() {
    if (!this.#secretSpendKey) {
      throw new TypeError('Wallet in view only mode');
    }
    return this.#secretSpendKey;
  }

  get publicSpendKey() {
    return this.#publicSpendKey;
  }

  get secretViewKey() {
    return this.#secretViewKey;
  }

  get publicViewKey() {
    return this.#publicViewKey;
  }

  get isViewOnly() {
    return !this.#secretSpendKey;
  }

  /**
   * wallet2::generate
   * https://github.com/monero-project/monero/blob/v0.17.1.9/src/wallet/wallet2.cpp#L4600-L4840
   */

  constructor({ seed, secretSpendKey, secretViewKey, publicSpendKey, nettype = 'mainnet' } = {}) {
    this.#config = getConfig(nettype || 'mainnet');
    this.#nettype = nettype || 'mainnet';

    if (seed) {
      if (typeof seed === 'string') seed = Buffer.from(seed, 'hex');
      // Generate wallet from seed
      if (!isBuffer32(seed)) {
        throw TypeError('Incorrect seed');
      }
      this.#seed = seed;
      const { sec: secretSpendKey, pub: publicSpendKey } = generateKeys(seed);
      // supports only deterministic wallet
      const { sec: secretViewKey, pub: publicViewKey } = generateKeys(fastHash(secretSpendKey));

      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = publicSpendKey;

      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = publicViewKey;
    } else if (secretSpendKey && secretViewKey) {
      if (typeof secretSpendKey === 'string') secretSpendKey = Buffer.from(secretSpendKey, 'hex');
      if (typeof secretViewKey === 'string') secretViewKey = Buffer.from(secretViewKey, 'hex');
      // Generate wallet from secret keys pair
      if (!isBuffer32(secretSpendKey)) {
        throw TypeError('Incorrect secret spend key');
      }
      if (!isBuffer32(secretViewKey)) {
        throw TypeError('Incorrect secret view key');
      }
      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = secretKeyToPublicKey(secretSpendKey);
      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = secretKeyToPublicKey(secretViewKey);
    } else if (publicSpendKey && secretViewKey) {
      if (typeof publicSpendKey === 'string') publicSpendKey = Buffer.from(publicSpendKey, 'hex');
      if (typeof secretViewKey === 'string') secretViewKey = Buffer.from(secretViewKey, 'hex');
      // Generate watch/view only wallet
      if (!isBuffer32(publicSpendKey)) {
        throw TypeError('Incorrect public spend key');
      }
      if (!isBuffer32(secretViewKey)) {
        throw TypeError('Incorrect secret view key');
      }
      this.#publicSpendKey = publicSpendKey;
      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = secretKeyToPublicKey(secretViewKey);
    } else {
      // Generate random wallet
      const { sec: secretSpendKey, pub: publicSpendKey } = generateKeys();
      // supports only deterministic wallet
      const { sec: secretViewKey, pub: publicViewKey } = generateKeys(fastHash(secretSpendKey));

      this.#seed = secretSpendKey;

      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = publicSpendKey;

      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = publicViewKey;
    }
  }

  getAddress() {
    return new Address({
      secretSpendKey: this.#secretSpendKey, // undefined for view only
      publicSpendKey: this.#publicSpendKey,
      publicViewKey: this.#publicViewKey,
    }, { major: 0, minor: 0 }, false, this.#nettype);
  }

  // it is not a key!
  getSubaddressSecret(major, minor) {
    const data = Buffer.concat([
      this.#config.HASH_KEY_SUBADDRESS,
      Buffer.alloc(1),
      this.#secretViewKey,
      encodeUint32(major),
      encodeUint32(minor),
    ]);
    return hashToScalar(data);
  }

  getSubaddress(major = 0, minor = 0) {
    if (major === 0 && minor === 0) {
      return this.getAddress();
    } else {
      const m = decodeInt(this.getSubaddressSecret(major, minor));
      if (this.#secretSpendKey) {
        const b = decodeInt(this.#secretSpendKey);
        const d = b.add(m).umod(ec.curve.n);
        const D = ec.curve.g.mul(d);
        const C = D.mul(decodeInt(this.#secretViewKey));
        return new Address({
          secretSpendKey: encodeInt(d),
          publicSpendKey: encodePoint(D),
          publicViewKey: encodePoint(C),
        }, { major, minor }, true, this.#nettype);
      } else {
        const M = ec.curve.g.mul(m);
        const B = decodePoint(this.#publicSpendKey);
        const D = B.add(M);
        const C = D.mul(decodeInt(this.#secretViewKey));
        return new Address({
          publicSpendKey: encodePoint(D),
          publicViewKey: encodePoint(C),
        }, { major, minor }, true, this.#nettype);
      }
    }
  }

  addressFromString(str) {
    return Address.fromString(str, this.#nettype);
  }
}
